import logging
import threading
from contextlib import suppress
from typing import Any, Dict, List, Optional, Union
from unittest import mock

import pytest

from cloudinit import url_helper
from cloudinit.net.dhcp import (
    Dhcpcd,
    IscDhclient,
    NoDHCPLeaseError,
    NoDHCPLeaseMissingDhclientError,
    Udhcpc,
)
from cloudinit.sources.DataSourceAkamai import (
    DataSourceAkamai,
    DataSourceAkamaiLocal,
    MetadataAvailabilityResult,
)


class TestDataSourceAkamai:
    """
    Test cases for DataSourceAkamai
    """

    def _get_datasource(
        self, ds_cfg: Optional[Dict[str, Any]] = None, local: bool = False
    ) -> Union[DataSourceAkamai, DataSourceAkamaiLocal]:
        """
        Creates a test DataSource configured as provided
        """
        if ds_cfg is None:
            ds_cfg = {}

        # set up our system config with the config provided here
        sys_cfg = {
            "datasource": {
                "Akamai": ds_cfg,
            }
        }

        # patch read_dmi_data, even when not in a container
        with mock.patch(
            "cloudinit.dmi.read_dmi_data",
            return_value="",
        ):
            if local:
                ds: Union[DataSourceAkamai, DataSourceAkamaiLocal] = (
                    DataSourceAkamaiLocal(sys_cfg, None, None)
                )
            else:
                ds = DataSourceAkamai(sys_cfg, None, None)

        return ds

    @pytest.mark.parametrize(
        "path_name,use_v6,ds_cfg,expected_url",
        (
            # normal paths
            ("token", False, {}, "http://169.254.169.254/v1/token"),
            ("metadata", False, {}, "http://169.254.169.254/v1/instance"),
            ("userdata", False, {}, "http://169.254.169.254/v1/user-data"),
            # normal paths, force v6
            ("metadata", True, {}, "http://[fd00:a9fe:a9fe::1]/v1/instance"),
            ("token", True, {}, "http://[fd00:a9fe:a9fe::1]/v1/token"),
            ("userdata", True, {}, "http://[fd00:a9fe:a9fe::1]/v1/user-data"),
            # overrides
            (
                "token",
                False,
                {"allow_ipv4": False},
                "http://[fd00:a9fe:a9fe::1]/v1/token",
            ),
            (
                "token",
                False,
                {"paths": {"token": "/changed"}},
                "http://169.254.169.254/changed",
            ),
            (
                "token",
                False,
                {"base_urls": {"ipv4": "http://12.34.56.78"}},
                "http://12.34.56.78/v1/token",
            ),
        ),
    )
    def test_build_url(
        self,
        path_name: str,
        use_v6: bool,
        ds_cfg: Dict[str, Any],
        expected_url: str,
    ):
        """
        Tests that _build_url returns the expected URLs for various
        configurations
        """
        ds = self._get_datasource(ds_cfg=ds_cfg)
        result = ds._build_url(path_name, use_v6=use_v6)
        assert (
            result == expected_url
        ), f"Unexpected URL {result} for {path_name}"

    @pytest.mark.parametrize(
        "local_stage,ds_cfg,expected_result",
        (
            # normal config
            (True, {}, MetadataAvailabilityResult.AVAILABLE),
            (False, {}, MetadataAvailabilityResult.AVAILABLE),
            # disable dhcp
            (
                True,
                {"allow_dhcp": False},
                MetadataAvailabilityResult.AVAILABLE,
            ),
            (
                True,
                {"allow_dhcp": False, "allow_ipv6": False},
                MetadataAvailabilityResult.DEFER,
            ),
            (
                False,
                {"allow_dhcp": False},
                MetadataAvailabilityResult.AVAILABLE,
            ),
            (
                False,
                {"allow_dhcp": False, "allow_ipv6": False},
                MetadataAvailabilityResult.AVAILABLE,
            ),
            # disable stages
            (
                True,
                {"allow_local_stage": False},
                MetadataAvailabilityResult.DEFER,
            ),
            (
                False,
                {"allow_local_stage": False},
                MetadataAvailabilityResult.AVAILABLE,
            ),
            (
                True,
                {"allow_init_stage": False},
                MetadataAvailabilityResult.AVAILABLE,
            ),
            (
                False,
                {"allow_init_stage": False},
                MetadataAvailabilityResult.DEFER,
            ),
            # disable all network types
            (
                True,
                {"allow_ipv4": False, "allow_ipv6": False},
                MetadataAvailabilityResult.NOT_AVAILABLE,
            ),
            (
                False,
                {"allow_ipv4": False, "allow_ipv6": False},
                MetadataAvailabilityResult.NOT_AVAILABLE,
            ),
            # disable all stages
            (
                True,
                {"allow_local_stage": False, "allow_init_stage": False},
                MetadataAvailabilityResult.NOT_AVAILABLE,
            ),
            (
                False,
                {"allow_local_stage": False, "allow_init_stage": False},
                MetadataAvailabilityResult.NOT_AVAILABLE,
            ),
        ),
    )
    def test_should_fetch_data(
        self, local_stage: bool, ds_cfg: Dict[str, Any], expected_result: bool
    ):
        """
        Tests if _should_fetch_data returns the expected values based on the
        configuration of the DataSource
        """
        ds = self._get_datasource(ds_cfg=ds_cfg, local=local_stage)
        result = ds._should_fetch_data()

        assert (
            result == expected_result
        ), f"Unexpected result '{result}' for should fetch data!"

    @pytest.mark.parametrize(
        "local_stage,ds_cfg,expected_manager_config,expected_interface",
        (
            # local stage - these use context managers
            (
                True,
                {},
                [((False, True), True), ((True, False), False)],
                "eth0",
            ),
            (True, {"allow_ipv4": False}, [((False, True), True)], "eth0"),
            (True, {"allow_ipv6": False}, [((True, False), False)], "eth0"),
            (True, {"allow_ipv4": False, "allow_ipv6": False}, [], "eth0"),
            (
                True,
                {"preferred_mac_prefixes": ["12:34:"]},
                [((False, True), True), ((True, False), False)],
                "eth1",
            ),
            # init stage - these use the noop suppress
            (False, {}, [(None, True), (None, False)], "eth0"),
            (False, {"allow_ipv4": False}, [(None, True)], "eth0"),
            (False, {"allow_ipv6": False}, [(None, False)], "eth0"),
            (
                False,
                {"allow_ipv4": False, "allow_ipv6": False},
                [],
                "eth0",
            ),
            (
                False,
                {"preferred_mac_prefixes": ["12:34:"]},
                [(None, True), (None, False)],
                "eth1",
            ),
        ),
    )
    @mock.patch("cloudinit.sources.DataSourceAkamai.get_interfaces_by_mac")
    def test_get_network_context_managers(
        self,
        get_interfaces_by_mac,
        local_stage: bool,
        ds_cfg: Dict[str, Any],
        expected_manager_config: List,
        expected_interface: str,
    ):
        """
        Tests that _get_network_context_managers returns the expected set of
        context managers
        """
        ds = self._get_datasource(ds_cfg=ds_cfg, local=local_stage)

        # set up fake mac addresses for our interfaces
        get_interfaces_by_mac.return_value = {
            "f2:3a:bc:de:f0:12": "eth0",
            "12:34:56:78:90:ab": "eth1",
        }

        result = ds._get_network_context_managers()

        assert len(result) == len(
            expected_manager_config
        ), f"Expected {len(expected_manager_config)}, got {result}"

        # make sure the results are what we expected
        for rx, ex in zip(result, expected_manager_config):
            r, rv6 = rx
            e, ev6 = ex
            if e is None:
                assert isinstance(
                    r, suppress
                ), f"Expected contextlib.suppress, got {r}"
                assert rv6 == ev6
            else:
                ipv4, ipv6 = e
                assert r.ipv4 == ipv4, f"Expected {r} to support ipv4"
                assert r.ipv6 == ipv6, f"Expected {r} to support ipv6"
                assert rv6 == ev6

    @pytest.mark.parametrize(
        "use_v6,userdata,decoded_userdata,case",
        (
            (
                False,
                "dGVzdGluZyBlbmNvZGVkIHVzZXJkYXRh",
                b"testing encoded userdata",
                "base64-encoded ASCII plaintext, IPv4 request",
            ),
            (
                True,
                "dGVzdGluZyBlbmNvZGVkIHVzZXJkYXRh",
                b"testing encoded userdata",
                "base64-encoded ASCII plaintext, IPv6 request",
            ),
            (
                False,
                "H4sIAAAAAAACAytJLS7hAgDGNbk7BQAAAA==",
                b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03+I-.\xe1\x02\x00\xc65\xb9;\x05\x00\x00\x00",
                "base64-encoded gzipped data",
            ),
            (
                False,
                "dGVzdDHwn4yKdGVzdDI=",
                "test1\N{WATER WAVE}test2".encode("utf-8"),
                "base64-encoded Unicode text",
            ),
        ),
    )
    @mock.patch("cloudinit.url_helper.readurl")
    def test_fetch_metadata(
        self,
        readurl,
        use_v6: bool,
        userdata: str,
        decoded_userdata: str,
        case: str,
    ):
        """
        Tests that making requests sends the expected requests in the expected
        order
        """
        # the responses, in the order we expect the calls
        readurl.side_effect = [
            # to PUT /v1/token
            mock.MagicMock(code=200, __str__=lambda _: "test-token"),
            # to GET /v1/instance; truncated for brevity
            '{"id": 123}',
            # to GET /v1/user-data
            userdata,
        ]

        # if we're asked to force using v6, we should see the hostname of the
        # urls change
        host = "[fd00:a9fe:a9fe::1]" if use_v6 else "169.254.169.254"

        ds = self._get_datasource()
        ds._fetch_metadata(use_v6=use_v6)

        assert readurl.call_count == 3
        assert ds.metadata == {"id": 123}
        assert ds.userdata_raw == decoded_userdata, f"Failed to decode {case}"

        assert readurl.mock_calls == [
            mock.call(
                f"http://{host}/v1/token",
                request_method="PUT",
                timeout=30,
                sec_between=2,
                retries=4,
                headers={
                    "Metadata-Token-Expiry-Seconds": "300",
                },
            ),
            mock.call(
                f"http://{host}/v1/instance",
                timeout=30,
                sec_between=2,
                retries=2,
                headers={
                    "Accept": "application/json",
                    "Metadata-Token": "test-token",
                },
            ),
            mock.call(
                f"http://{host}/v1/user-data",
                timeout=30,
                sec_between=2,
                retries=2,
                headers={
                    "Metadata-Token": "test-token",
                },
            ),
        ]

    @pytest.mark.parametrize(
        "ipv4_works,expected_warnings",
        (
            (True, []),
            (
                False,
                [
                    (
                        "Failed to contact metadata service, falling back to "
                        "local metadata only."
                    )
                ],
            ),
        ),
    )
    @mock.patch(
        "cloudinit.sources.DataSourceAkamai.get_local_instance_id",
        return_value="123",
    )
    @mock.patch(
        "cloudinit.sources.DataSourceAkamai.is_on_akamai", return_value=True
    )
    @mock.patch("cloudinit.url_helper.readurl")
    def test_get_data_network_fallback_logging(
        self,
        readurl,
        _is_on_akamai,
        _get_local_instance_id,
        ipv4_works: bool,
        expected_warnings: List[str],
        caplog,
    ):
        """
        Tests that a network that fails is logged without a warning while
        another network may still work, and that only failing on every
        network is a warning
        """

        def fake_readurl(url, **kwargs):
            if "[fd00:" in url or not ipv4_works:
                raise url_helper.UrlError(
                    OSError("Network is unreachable"), url=url
                )
            if url.endswith("/v1/token"):
                return mock.MagicMock(code=200, __str__=lambda _: "test-token")
            if url.endswith("/v1/instance"):
                return '{"id": 123}'
            return ""

        readurl.side_effect = fake_readurl

        # init stage, so no ephemeral networking is set up
        ds = self._get_datasource()
        with caplog.at_level(logging.INFO):
            assert ds._get_data()

        warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelno >= logging.WARNING
        ]
        assert warnings == expected_warnings
        assert "Failed to retrieve metadata using IPv6" in caplog.text

    @pytest.mark.parametrize(
        "ds_cfg,dhcp_client,expected",
        (
            ({}, Udhcpc, True),
            ({}, IscDhclient, True),
            # dhcpcd configures the address it obtains
            ({}, Dhcpcd, False),
            ({}, NoDHCPLeaseMissingDhclientError(), False),
            ({"allow_ipv6": False}, Udhcpc, False),
            ({"allow_ipv4": False}, Udhcpc, False),
            ({"allow_dhcp": False}, Udhcpc, False),
        ),
    )
    def test_can_race_local_networks(
        self, ds_cfg: Dict[str, Any], dhcp_client, expected: bool
    ):
        """
        Tests that the local stage only races IPv6 against DHCPv4 when both
        are allowed and DHCP discovery leaves the interface unconfigured
        """
        ds = self._get_datasource(ds_cfg=ds_cfg, local=True)
        ds.distro = mock.MagicMock()
        if isinstance(dhcp_client, Exception):
            type(ds.distro).dhcp_client = mock.PropertyMock(
                side_effect=dhcp_client
            )
        else:
            ds.distro.dhcp_client = mock.create_autospec(
                dhcp_client, instance=True
            )
        assert ds._can_race_local_networks() is expected

    @pytest.mark.parametrize(
        "route_after,dhcp,expected_networks,expect_kill",
        (
            # the route arrives while DHCPv4 discovery is still waiting
            (0.05, "slow", [("noop", True), ("dhcp", False)], True),
            # DHCPv4 gets a lease while there is still no route
            (None, "lease", [("lease", False)], False),
            # DHCPv4 fails; the route arrives afterwards
            (0.05, "fail", [("noop", True), ("dhcp", False)], False),
            # neither
            (None, "fail", [], False),
        ),
    )
    @mock.patch("cloudinit.sources.DataSourceAkamai.IPV6_ROUTE_TIMEOUT", 0.5)
    @mock.patch("cloudinit.sources.DataSourceAkamai.EphemeralIPv6Network")
    @mock.patch("cloudinit.sources.DataSourceAkamai.EphemeralIPNetwork")
    @mock.patch("cloudinit.sources.DataSourceAkamai.EphemeralDHCPv4")
    @mock.patch("cloudinit.sources.DataSourceAkamai.socket.socket")
    @mock.patch(
        "cloudinit.sources.DataSourceAkamai.maybe_perform_dhcp_discovery"
    )
    @mock.patch("cloudinit.sources.DataSourceAkamai.get_interfaces_by_mac")
    def test_race_local_networks(
        self,
        get_interfaces_by_mac,
        dhcp_discovery,
        socket_cls,
        ephemeral_dhcpv4,
        ephemeral_ip_network,
        ephemeral_ipv6,
        route_after: Optional[float],
        dhcp: str,
        expected_networks: List,
        expect_kill: bool,
    ):
        """
        Tests that the local stage uses whichever of IPv6 and DHCPv4 is ready
        first, and stops a DHCPv4 discovery that loses
        """
        get_interfaces_by_mac.return_value = {"f2:3a:bc:de:f0:12": "eth0"}
        lease = {"interface": "eth0", "fixed-address": "192.0.2.10"}
        killed = threading.Event()

        def discover(distro, interface):
            assert interface == "eth0"
            if dhcp == "lease":
                return lease
            if dhcp == "slow":
                # blocks until the client is killed
                assert killed.wait(5)
            raise NoDHCPLeaseError()

        dhcp_discovery.side_effect = discover

        route_ready = threading.Event()
        if route_after is not None:
            threading.Timer(route_after, route_ready.set).start()

        def connect(address):
            assert address == ("fd00:a9fe:a9fe::1", 80)
            if not route_ready.is_set():
                raise OSError(101, "Network is unreachable")

        socket_cls.return_value.__enter__.return_value.connect.side_effect = (
            connect
        )

        ds = self._get_datasource(local=True)
        ds.distro = mock.MagicMock()
        ds.distro.dhcp_client.kill_dhcp_client.side_effect = killed.set

        networks = ds._race_local_networks()

        names = {
            id(ephemeral_ip_network.return_value): "dhcp",
            id(ephemeral_dhcpv4.return_value): "lease",
        }
        assert [
            (
                "noop" if isinstance(m, suppress) else names[id(m)],
                use_v6,
            )
            for m, use_v6 in networks
        ] == expected_networks
        assert ds.distro.dhcp_client.kill_dhcp_client.called is expect_kill
        ephemeral_ipv6.assert_called_once_with(ds.distro, "eth0")
        if dhcp == "lease":
            ephemeral_dhcpv4.assert_called_once_with(
                ds.distro, "eth0", lease=lease
            )

    @pytest.mark.parametrize("ipv6_route", (True, False))
    @mock.patch(
        "cloudinit.sources.DataSourceAkamai.get_local_instance_id",
        return_value="123",
    )
    @mock.patch(
        "cloudinit.sources.DataSourceAkamai.is_on_akamai", return_value=True
    )
    @mock.patch("cloudinit.sources.DataSourceAkamai.EphemeralIPNetwork")
    @mock.patch("cloudinit.sources.DataSourceAkamai.get_interfaces_by_mac")
    @mock.patch("cloudinit.url_helper.readurl")
    def test_get_data_local_ipv6_only_waits_for_route(
        self,
        readurl,
        get_interfaces_by_mac,
        _ephemeral,
        _is_on_akamai,
        _get_local_instance_id,
        ipv6_route: bool,
    ):
        """
        Tests that without IPv4 the local stage only requests metadata over
        IPv6 once there is a route to it
        """
        get_interfaces_by_mac.return_value = {"f2:3a:bc:de:f0:12": "eth0"}

        def fake_readurl(url, **kwargs):
            if url.endswith("/v1/token"):
                return mock.MagicMock(code=200, __str__=lambda _: "test-token")
            if url.endswith("/v1/instance"):
                return '{"id": 123}'
            return ""

        readurl.side_effect = fake_readurl

        ds = self._get_datasource(ds_cfg={"allow_ipv4": False}, local=True)
        with mock.patch.object(
            ds, "_wait_for_ipv6_route", return_value=ipv6_route
        ):
            assert ds._get_data()

        if ipv6_route:
            assert readurl.call_count == 3
            assert ds.metadata["instance-id"] == 123
        else:
            readurl.assert_not_called()
            assert ds.metadata["instance-id"] == "123"
