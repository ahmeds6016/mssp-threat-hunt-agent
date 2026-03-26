"""Auto-sweep scheduler — match new IOCs to clients and generate sweep requests."""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from mssp_hunt_agent.intel.models import NormalizedIOC
from mssp_hunt_agent.models.ioc_models import IOCEntry, IOCHuntInput, IOCType
from mssp_hunt_agent.policy.engine import PolicyEngine
from mssp_hunt_agent.policy.models import PolicyAction

if TYPE_CHECKING:
    from mssp_hunt_agent.config import HuntAgentConfig

logger = logging.getLogger(__name__)

# Map normalized ioc_type strings to IOCType enum values
_TYPE_MAP: dict[str, IOCType] = {
    "ip": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "hash_md5": IOCType.HASH_MD5,
    "hash_sha256": IOCType.HASH_SHA256,
    "hash_sha1": IOCType.HASH_SHA1,
    "email": IOCType.EMAIL,
    "url": IOCType.URL,
    "user_agent": IOCType.USER_AGENT,
}


class ClientProfile:
    """Lightweight client descriptor for IOC matching."""

    def __init__(
        self,
        client_name: str,
        data_sources: list[str],
        supported_ioc_types: list[str] | None = None,
        time_range: str = "last 7 days",
        exclusions: set[str] | None = None,
    ) -> None:
        self.client_name = client_name
        self.data_sources = data_sources
        self.supported_ioc_types = supported_ioc_types or [
            "ip", "domain", "hash_md5", "hash_sha256", "url",
        ]
        self.time_range = time_range
        self.exclusions = exclusions or set()


class AutoSweepScheduler:
    """Matches new IOCs against client profiles and generates sweep inputs."""

    def __init__(self, max_iocs_per_sweep: int = 100) -> None:
        self._max_iocs = max_iocs_per_sweep

    def match_iocs_to_clients(
        self,
        new_iocs: list[NormalizedIOC],
        client_profiles: list[ClientProfile],
    ) -> dict[str, list[NormalizedIOC]]:
        """Return a mapping of client_name → relevant IOCs.

        An IOC is relevant to a client if the client supports that IOC type
        and the IOC is not in the client's exclusion list.
        """
        matches: dict[str, list[NormalizedIOC]] = {}

        for profile in client_profiles:
            relevant: list[NormalizedIOC] = []
            for ioc in new_iocs:
                if ioc.ioc_type not in profile.supported_ioc_types:
                    continue
                if ioc.value in profile.exclusions:
                    continue
                relevant.append(ioc)

            if relevant:
                matches[profile.client_name] = relevant[:self._max_iocs]

        return matches

    def generate_sweep_inputs(
        self,
        new_iocs: list[NormalizedIOC],
        client_profiles: list[ClientProfile],
        config: HuntAgentConfig | None = None,
    ) -> list[IOCHuntInput]:
        """Generate IOCHuntInput objects for each client with matching IOCs.

        When *config* is provided and the policy engine is enabled, each
        client's auto-sweep is checked against its policy rules.  Sweeps
        denied by policy are silently skipped.
        """
        matches = self.match_iocs_to_clients(new_iocs, client_profiles)
        sweep_inputs: list[IOCHuntInput] = []

        # Build policy engine if config is provided
        policy: PolicyEngine | None = None
        if config is not None and config.policy_engine_enabled:
            policy = PolicyEngine(config)

        for profile in client_profiles:
            client_iocs = matches.get(profile.client_name, [])
            if not client_iocs:
                continue

            # Policy gate — check if auto-sweep is allowed for this client
            if policy is not None:
                decision = policy.evaluate_auto_sweep(
                    client_name=profile.client_name,
                    ioc_count=len(client_iocs),
                )
                if decision.action == PolicyAction.AUTO_DENY.value:
                    logger.info(
                        "Auto-sweep denied for %s: %s",
                        profile.client_name,
                        decision.reason,
                    )
                    continue
                if decision.action == PolicyAction.REQUIRE_APPROVAL.value:
                    logger.info(
                        "Auto-sweep for %s requires approval (skipping in auto mode): %s",
                        profile.client_name,
                        decision.reason,
                    )
                    continue

            ioc_entries = []
            for ioc in client_iocs:
                ioc_type_enum = _TYPE_MAP.get(ioc.ioc_type)
                if not ioc_type_enum:
                    continue
                ioc_entries.append(
                    IOCEntry(
                        value=ioc.value,
                        ioc_type=ioc_type_enum,
                        context=ioc.context or f"From feed: {ioc.source_feed}",
                        source=ioc.source_feed,
                        tags=ioc.tags,
                    )
                )

            if not ioc_entries:
                continue

            sweep_inputs.append(
                IOCHuntInput(
                    client_name=profile.client_name,
                    iocs=ioc_entries,
                    time_range=profile.time_range,
                    available_data_sources=profile.data_sources,
                    sweep_objective=f"Auto-sweep: {len(ioc_entries)} IOCs from feed ingestion",
                    pre_enrich=True,
                )
            )
            logger.info(
                "Generated auto-sweep for %s: %d IOCs",
                profile.client_name,
                len(ioc_entries),
            )

        return sweep_inputs
