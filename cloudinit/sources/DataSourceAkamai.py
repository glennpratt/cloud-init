import binascii
import json
import logging
import socket
import threading
import time
from base64 import b64decode
from contextlib import suppress as noop
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from cloudinit import sources, url_helper, util
from cloudinit.net import find_fallback_nic, get_interfaces_by_mac
from cloudinit.net.dhcp import (
    Dhcpcd,
    NoDHCPLeaseError,
    maybe_perform_dhcp_discovery,
)
from cloudinit.net.ephemeral import (
    EphemeralDHCPv4,
    EphemeralIPNetwork,
    EphemeralIPv6Network,
)
from cloudinit.sources.helpers.akamai import (
    get_dmi_config,
    get_local_instance_id,
    is_on_akamai,
)

LOG = logging.getLogger(__name__)


BUILTIN_DS_CONFIG = {
    "base_urls": {
        "ipv4": "http://169.254.169.254",
        "ipv6": "http://[fd00:a9fe:a9fe::1]",
    },
    "paths": {
        "token": "/v1/token",
        "metadata": "/v1/instance",
        "userdata": "/v1/user-data",
    },
    # configures the behavior of the datasource
    "allow_local_stage": True,
    "allow_init_stage": True,
    "allow_dhcp": True,
    "allow_ipv4": True,
    "allow_ipv6": True,
    # mac address prefixes for interfaces that we would prefer to use for
    # local-stage initialization
    "preferred_mac_prefixes": [
        "f2:3",
    ],
}


# How long the local stage waits for a route to the IPv6 metadata service.
# The route comes from a router advertisement; until one arrives every request
# fails with "Network is unreachable".
IPV6_ROUTE_TIMEOUT = 20.0
IPV6_ROUTE_POLL_INTERVAL = 0.1


class MetadataAvailabilityResult(Enum):
    """
    Used to indicate how this instance should behave based on the availability
    of metadata to it
    """

    NOT_AVAILABLE = 0
    AVAILABLE = 1
    DEFER = 2


class DataSourceAkamai(sources.DataSource):
    dsname = "Akamai"
    local_stage = False

    def __init__(self, sys_cfg, distro, paths):
        LOG.debug("Setting up Akamai DataSource")
        sources.DataSource.__init__(self, sys_cfg, distro, paths)
        self.metadata = dict()

        # build our config
        self.ds_cfg = util.mergemanydict(
            [
                get_dmi_config(),
                util.get_cfg_by_path(
                    sys_cfg,
                    ["datasource", "Akamai"],
                    {},
                ),
                BUILTIN_DS_CONFIG,
            ],
        )

    def _build_url(self, path_name: str, use_v6: bool = False) -> str:
        """
        Looks up the path for a given name and returns a full url for it.  If
        use_v6 is passed in, the IPv6 base url is used; otherwise the IPv4 url
        is used unless IPv4 is not allowed in ds_cfg
        """
        if path_name not in self.ds_cfg["paths"]:
            raise ValueError("Unknown path name {}".format(path_name))

        version_key = "ipv4"
        if use_v6 or not self.ds_cfg["allow_ipv4"]:
            version_key = "ipv6"

        base_url = self.ds_cfg["base_urls"][version_key]
        path = self.ds_cfg["paths"][path_name]

        return "{}{}".format(base_url, path)

    def _should_fetch_data(self) -> MetadataAvailabilityResult:
        """
        Returns whether metadata should be retrieved at this stage, at the next
        stage, or never, in the form of a MetadataAvailabilityResult.
        """
        if (
            not self.ds_cfg["allow_ipv4"] and not self.ds_cfg["allow_ipv6"]
        ) or (
            not self.ds_cfg["allow_local_stage"]
            and not self.ds_cfg["allow_init_stage"]
        ):
            # if we're not allowed to fetch data, we shouldn't try
            LOG.info("Configuration prohibits fetching metadata.")
            return MetadataAvailabilityResult.NOT_AVAILABLE

        if self.local_stage:
            return self._should_fetch_data_local()
        else:
            return self._should_fetch_data_network()

    def _should_fetch_data_local(self) -> MetadataAvailabilityResult:
        """
        Returns whether metadata should be retrieved during the local stage, or
        if it should wait for the init stage.
        """
        if not self.ds_cfg["allow_local_stage"]:
            # if this stage is explicitly disabled, don't attempt to fetch here
            LOG.info("Configuration prohibits local stage setup")
            return MetadataAvailabilityResult.DEFER

        if not self.ds_cfg["allow_dhcp"] and not self.ds_cfg["allow_ipv6"]:
            # without dhcp, we can't fetch during the local stage over IPv4.
            # If we're not allowed to use IPv6 either, then we can't init
            # during this stage
            LOG.info(
                "Configuration does not allow for ephemeral network setup."
            )
            return MetadataAvailabilityResult.DEFER

        return MetadataAvailabilityResult.AVAILABLE

    def _should_fetch_data_network(self) -> MetadataAvailabilityResult:
        """
        Returns whether metadata should be fetched during the init stage.
        """
        if not self.ds_cfg["allow_init_stage"]:
            # if this stage is explicitly disabled, don't attempt to fetch here
            LOG.info("Configuration does not allow for init stage setup")
            return MetadataAvailabilityResult.DEFER

        return MetadataAvailabilityResult.AVAILABLE

    def _get_local_interface(self):
        """
        Returns the interface to reach the metadata service through in the
        local stage: the first with a preferred MAC address prefix, or else
        the fallback interface.
        """
        # find the first interface that isn't lo or a vlan interface
        interfaces = get_interfaces_by_mac()
        preferred_prefixes = self.ds_cfg["preferred_mac_prefixes"]
        for mac, inf in interfaces.items():
            # try to match on the preferred mac prefixes
            if any([mac.startswith(prefix) for prefix in preferred_prefixes]):
                return inf

        LOG.warning(
            "Failed to find default interface, attempting DHCP on "
            "fallback interface"
        )
        return find_fallback_nic()

    def _wait_for_ipv6_route(
        self, deadline: float, stop: Optional[threading.Event] = None
    ) -> bool:
        """
        Waits until the deadline (a time.monotonic() value) for a route to
        the IPv6 metadata service, or until stop is set, and returns whether
        there is one. Connecting a UDP socket looks up the route without
        sending anything.
        """
        host = urlparse(self.ds_cfg["base_urls"]["ipv6"]).hostname
        stop = stop or threading.Event()
        while True:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                try:
                    sock.connect((host, 80))
                    return True
                except OSError as e:
                    error = e
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                LOG.info("No route to the IPv6 metadata service: %s", error)
                return False
            if stop.wait(min(IPV6_ROUTE_POLL_INTERVAL, remaining)):
                return False

    def _can_race_local_networks(self) -> bool:
        """
        Returns whether the local stage can try IPv6 and IPv4 at once: both
        are allowed, and DHCP discovery leaves the interface unconfigured
        until we set up the lease ourselves.
        """
        if not (
            self.ds_cfg["allow_ipv6"]
            and self.ds_cfg["allow_ipv4"]
            and self.ds_cfg["allow_dhcp"]
        ):
            return False
        try:
            dhcp_client = self.distro.dhcp_client
        except NoDHCPLeaseError:
            return False
        # dhcpcd configures the address it obtains itself, so stopping it
        # early would leave it behind; set up one network at a time instead.
        return not isinstance(dhcp_client, Dhcpcd)

    def _race_local_networks(self) -> List[Tuple[Any, bool]]:
        """
        Sets up the local stage's network by racing IPv6 against IPv4: waits
        for a route to the IPv6 metadata service while DHCPv4 discovery runs
        in the background. Neither changes the interface's addresses, so the
        one that loses is stopped with nothing to undo. Returns network
        context managers to try in order, the winner first.
        """
        interface = self._get_local_interface()
        result: Dict[str, Any] = {}
        discovered = threading.Event()

        def discover():
            try:
                result["lease"] = maybe_perform_dhcp_discovery(
                    self.distro, interface
                )
            except NoDHCPLeaseError as e:
                LOG.info("DHCPv4 discovery on %s failed: %s", interface, e)
            finally:
                discovered.set()

        start = time.monotonic()
        deadline = start + IPV6_ROUTE_TIMEOUT
        # bringing the link up makes the kernel solicit a router
        # advertisement
        with EphemeralIPv6Network(self.distro, interface):
            worker = threading.Thread(target=discover, daemon=True)
            worker.start()
            route = self._wait_for_ipv6_route(deadline, stop=discovered)
            if not route and "lease" not in result:
                # DHCPv4 failed; IPv6 may still come
                route = self._wait_for_ipv6_route(deadline)
            if not discovered.is_set():
                self.distro.dhcp_client.kill_dhcp_client()
            worker.join()

        elapsed = time.monotonic() - start
        if route:
            LOG.info("Using IPv6 for metadata (route after %.1fs)", elapsed)
            return [
                (noop(), True),
                (EphemeralIPNetwork(self.distro, interface, ipv4=True), False),
            ]
        if "lease" in result:
            LOG.info("Using IPv4 for metadata (lease after %.1fs)", elapsed)
            return [
                (
                    EphemeralDHCPv4(
                        self.distro, interface, lease=result["lease"]
                    ),
                    False,
                )
            ]
        return []

    def _get_network_context_managers(
        self,
    ) -> List[Tuple[Union[Any, EphemeralIPNetwork], bool]]:
        """
        Returns a list of context managers which should be tried when setting
        up a network context.  If we're running in init mode, this return a
        noop since networking should already be configured.
        """
        network_context_managers: List[
            Tuple[Union[Any, EphemeralIPNetwork], bool]
        ] = []
        if self.local_stage:
            # at this stage, networking isn't up yet.  To support that, we need
            # an ephemeral network

            interface = self._get_local_interface()

            network_context_managers = []

            if self.ds_cfg["allow_ipv6"]:
                network_context_managers.append(
                    (
                        EphemeralIPNetwork(
                            self.distro,
                            interface,
                            ipv4=False,
                            ipv6=True,
                        ),
                        True,
                    ),
                )

            if self.ds_cfg["allow_ipv4"] and self.ds_cfg["allow_dhcp"]:
                network_context_managers.append(
                    (
                        EphemeralIPNetwork(
                            self.distro,
                            interface,
                            ipv4=True,
                        ),
                        False,
                    )
                )
        else:
            if self.ds_cfg["allow_ipv6"]:
                network_context_managers.append(
                    (
                        noop(),
                        True,
                    ),
                )

            if self.ds_cfg["allow_ipv4"]:
                network_context_managers.append(
                    (
                        noop(),
                        False,
                    ),
                )

        return network_context_managers

    def _fetch_metadata(self, use_v6: bool = False) -> bool:
        """
        Runs through the sequence of requests necessary to retrieve our
        metadata and user data, creating a token for use in doing so, capturing
        the results.
        """
        try:
            # retrieve a token for future requests
            token_response = url_helper.readurl(
                self._build_url("token", use_v6=use_v6),
                request_method="PUT",
                timeout=30,
                sec_between=2,
                retries=4,
                headers={
                    "Metadata-Token-Expiry-Seconds": "300",
                },
            )
            if token_response.code != 200:
                LOG.info(
                    "Fetching token returned %s; not fetching data",
                    token_response.code,
                )
                return True

            token = str(token_response)

            # fetch general metadata
            metadata = url_helper.readurl(
                self._build_url("metadata", use_v6=use_v6),
                timeout=30,
                sec_between=2,
                retries=2,
                headers={
                    "Accept": "application/json",
                    "Metadata-Token": token,
                },
            )
            self.metadata = json.loads(str(metadata))

            # fetch user data
            userdata = url_helper.readurl(
                self._build_url("userdata", use_v6=use_v6),
                timeout=30,
                sec_between=2,
                retries=2,
                headers={
                    "Metadata-Token": token,
                },
            )
            self.userdata_raw = str(userdata)
            try:
                self.userdata_raw = b64decode(self.userdata_raw)
            except binascii.Error as e:
                LOG.warning("Failed to base64 decode userdata due to %s", e)
        except url_helper.UrlError as e:
            # we failed to retrieve data with an exception; log the error and
            # return false, indicating that we should retry using a different
            # network if possible. This is not a warning: another network may
            # still succeed, and _get_data warns if none does.
            LOG.info(
                "Failed to retrieve metadata using IPv%s due to %s",
                "6" if use_v6 else "4",
                e,
            )
            return False

        return True

    def _get_data(self) -> bool:
        """
        Overrides _get_data in the DataSource class to actually retrieve data
        """
        LOG.debug("Getting data from Akamai DataSource")

        if not is_on_akamai():
            LOG.info("Not running on Akamai, not running.")
            return False

        local_instance_id = get_local_instance_id()
        self.metadata = {
            "instance-id": local_instance_id,
        }
        availability = self._should_fetch_data()

        if availability != MetadataAvailabilityResult.AVAILABLE:
            if availability == MetadataAvailabilityResult.NOT_AVAILABLE:
                LOG.info(
                    "Metadata is not available, returning local data only."
                )
                return True

            LOG.info(
                "Configured not to fetch data at this stage; waiting for "
                "a later stage."
            )
            return False

        if self.local_stage and self._can_race_local_networks():
            network_context_managers = self._race_local_networks()
        else:
            network_context_managers = self._get_network_context_managers()
        for manager, use_v6 in network_context_managers:
            with manager:
                # In the local stage IPv6 needs a router advertisement before
                # it can reach the metadata service; don't spend the request
                # retries waiting for one.
                if (
                    use_v6
                    and self.local_stage
                    and not self._wait_for_ipv6_route(
                        time.monotonic() + IPV6_ROUTE_TIMEOUT
                    )
                ):
                    continue
                done = self._fetch_metadata(use_v6=use_v6)
                if done:
                    # fix up some field names
                    self.metadata["instance-id"] = self.metadata.get(
                        "id",
                        local_instance_id,
                    )
                    break
        else:
            # even if we failed to reach the metadata service this loop, we
            # still have the locally-available metadata (namely the instance id
            # and cloud name), and by accepting just that we ensure that
            # cloud-init won't run on our next boot
            LOG.warning(
                "Failed to contact metadata service, falling back to local "
                "metadata only."
            )

        return True

    def check_instance_id(self, sys_cfg) -> bool:
        """
        A local-only check to see if the instance id matches the id we see on
        the system
        """
        return sources.instance_id_matches_system_uuid(
            self.get_instance_id(), "system-serial-number"
        )


class DataSourceAkamaiLocal(DataSourceAkamai):
    """
    A subclass of DataSourceAkamai that runs the same functions, but during the
    init-local stage.  This allows configuring networking via cloud-init, as
    networking hasn't been configured yet.
    """

    local_stage = True


datasources = [
    # run in init-local if possible
    (DataSourceAkamaiLocal, (sources.DEP_FILESYSTEM,)),
    # if not, run in init
    (
        DataSourceAkamai,
        (
            sources.DEP_FILESYSTEM,
            sources.DEP_NETWORK,
        ),
    ),
]


# cloudinit/sources/__init__.py will look for and call this when deciding if
# we're a valid DataSource for the stage its running
def get_datasource_list(depends) -> List[sources.DataSource]:
    return sources.list_from_depends(depends, datasources)
