"""Abstract SIEM adapter — the contract every SIEM integration must satisfy."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mssp_hunt_agent.models.hunt_models import ExabeamQuery
from mssp_hunt_agent.models.result_models import QueryResult


class SIEMAdapter(ABC):
    """Contract that every SIEM integration must satisfy."""

    @abstractmethod
    def execute_query(self, query: ExabeamQuery) -> QueryResult:
        """Execute a single KQL/search query and return structured results."""

    @abstractmethod
    def test_connection(self) -> bool:
        """Return True if the adapter can reach the backend."""

    @abstractmethod
    def get_adapter_name(self) -> str:
        """Human-readable name for audit logs."""


# Backward-compatibility alias — keeps existing imports working
ExabeamAdapter = SIEMAdapter
