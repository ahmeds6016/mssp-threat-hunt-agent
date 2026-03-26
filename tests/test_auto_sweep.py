"""Tests for AutoSweepScheduler — IOC-to-client matching and sweep generation."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.intel.auto_sweep import AutoSweepScheduler, ClientProfile
from mssp_hunt_agent.intel.models import NormalizedIOC


def _make_ioc(value: str, ioc_type: str = "ip") -> NormalizedIOC:
    return NormalizedIOC(
        ioc_type=ioc_type,
        value=value,
        source_feed="test-feed",
        first_seen="2024-01-01T00:00:00Z",
        last_seen="2024-06-01T00:00:00Z",
    )


@pytest.fixture
def scheduler() -> AutoSweepScheduler:
    return AutoSweepScheduler(max_iocs_per_sweep=50)


@pytest.fixture
def profiles() -> list[ClientProfile]:
    return [
        ClientProfile(
            client_name="ClientA",
            data_sources=["Firewall logs", "VPN logs"],
            supported_ioc_types=["ip", "domain"],
            time_range="2024-12-01 to 2024-12-31",
        ),
        ClientProfile(
            client_name="ClientB",
            data_sources=["EDR", "Email gateway"],
            supported_ioc_types=["hash_sha256", "email", "url"],
            time_range="2024-12-01 to 2024-12-31",
        ),
    ]


class TestIOCMatching:
    def test_match_by_type(self, scheduler: AutoSweepScheduler, profiles: list[ClientProfile]) -> None:
        iocs = [_make_ioc("1.2.3.4", "ip"), _make_ioc("evil.com", "domain")]
        matches = scheduler.match_iocs_to_clients(iocs, profiles)

        assert "ClientA" in matches
        assert len(matches["ClientA"]) == 2
        # ClientB doesn't support ip/domain
        assert "ClientB" not in matches

    def test_match_hash_to_edr_client(self, scheduler: AutoSweepScheduler, profiles: list[ClientProfile]) -> None:
        iocs = [_make_ioc("a" * 64, "hash_sha256")]
        matches = scheduler.match_iocs_to_clients(iocs, profiles)

        assert "ClientA" not in matches
        assert "ClientB" in matches
        assert len(matches["ClientB"]) == 1

    def test_exclusions_respected(self, scheduler: AutoSweepScheduler) -> None:
        profile = ClientProfile(
            client_name="ExcludedClient",
            data_sources=["Firewall"],
            supported_ioc_types=["ip"],
            exclusions={"8.8.8.8"},
        )
        iocs = [_make_ioc("8.8.8.8", "ip"), _make_ioc("1.2.3.4", "ip")]
        matches = scheduler.match_iocs_to_clients(iocs, [profile])

        assert len(matches["ExcludedClient"]) == 1
        assert matches["ExcludedClient"][0].value == "1.2.3.4"

    def test_no_matches(self, scheduler: AutoSweepScheduler, profiles: list[ClientProfile]) -> None:
        iocs = [_make_ioc("nobody@nowhere.com", "user_agent")]
        matches = scheduler.match_iocs_to_clients(iocs, profiles)

        assert len(matches) == 0

    def test_max_iocs_per_sweep(self) -> None:
        scheduler = AutoSweepScheduler(max_iocs_per_sweep=3)
        profile = ClientProfile(
            client_name="LimitedClient",
            data_sources=["Firewall"],
            supported_ioc_types=["ip"],
        )
        iocs = [_make_ioc(f"10.0.0.{i}", "ip") for i in range(10)]
        matches = scheduler.match_iocs_to_clients(iocs, [profile])

        assert len(matches["LimitedClient"]) == 3


class TestSweepGeneration:
    def test_generates_sweep_inputs(self, scheduler: AutoSweepScheduler, profiles: list[ClientProfile]) -> None:
        iocs = [_make_ioc("1.2.3.4", "ip"), _make_ioc("evil.com", "domain")]
        sweeps = scheduler.generate_sweep_inputs(iocs, profiles)

        # ClientA matches, ClientB does not
        assert len(sweeps) == 1
        sweep = sweeps[0]
        assert sweep.client_name == "ClientA"
        assert len(sweep.iocs) == 2
        assert sweep.time_range == "2024-12-01 to 2024-12-31"
        assert "Firewall logs" in sweep.available_data_sources
        assert "Auto-sweep" in sweep.sweep_objective

    def test_multiple_clients(self, scheduler: AutoSweepScheduler) -> None:
        profiles = [
            ClientProfile(
                client_name="C1",
                data_sources=["Firewall"],
                supported_ioc_types=["ip"],
            ),
            ClientProfile(
                client_name="C2",
                data_sources=["Proxy"],
                supported_ioc_types=["ip", "domain"],
            ),
        ]
        iocs = [_make_ioc("1.2.3.4", "ip")]
        sweeps = scheduler.generate_sweep_inputs(iocs, profiles)

        assert len(sweeps) == 2
        names = {s.client_name for s in sweeps}
        assert names == {"C1", "C2"}

    def test_no_sweeps_when_no_matches(self, scheduler: AutoSweepScheduler, profiles: list[ClientProfile]) -> None:
        iocs = [_make_ioc("nobody", "user_agent")]
        sweeps = scheduler.generate_sweep_inputs(iocs, profiles)

        assert len(sweeps) == 0

    def test_ioc_entries_have_correct_types(self, scheduler: AutoSweepScheduler) -> None:
        profile = ClientProfile(
            client_name="TypeCheck",
            data_sources=["EDR"],
            supported_ioc_types=["ip", "domain", "hash_sha256"],
        )
        iocs = [
            _make_ioc("1.2.3.4", "ip"),
            _make_ioc("evil.com", "domain"),
            _make_ioc("a" * 64, "hash_sha256"),
        ]
        sweeps = scheduler.generate_sweep_inputs(iocs, [profile])

        assert len(sweeps) == 1
        types = {e.ioc_type.value for e in sweeps[0].iocs}
        assert types == {"ip", "domain", "hash_sha256"}

    def test_context_includes_feed_name(self, scheduler: AutoSweepScheduler) -> None:
        profile = ClientProfile(
            client_name="CtxCheck",
            data_sources=["Firewall"],
            supported_ioc_types=["ip"],
        )
        iocs = [_make_ioc("1.2.3.4", "ip")]
        sweeps = scheduler.generate_sweep_inputs(iocs, [profile])

        assert "test-feed" in sweeps[0].iocs[0].context
