"""Backward-compatibility shim — re-exports SIEMAdapter as ExabeamAdapter."""

# The real abstract base has moved to adapters.base (SIEMAdapter).
# This module is kept so existing test imports don't break during the Sentinel pivot.
from mssp_hunt_agent.adapters.base import SIEMAdapter as ExabeamAdapter  # noqa: F401

__all__ = ["ExabeamAdapter"]
