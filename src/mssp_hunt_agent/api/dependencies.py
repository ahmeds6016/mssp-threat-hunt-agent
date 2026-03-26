"""Dependency injection helpers for the FastAPI application."""

from __future__ import annotations

from functools import lru_cache

from mssp_hunt_agent.config import HuntAgentConfig


@lru_cache(maxsize=1)
def get_config() -> HuntAgentConfig:
    """Singleton config built from environment variables."""
    config = HuntAgentConfig.from_env()
    # API always persists by default
    config.persist = True
    return config


def get_database():
    """Get a HuntDatabase instance from current config."""
    from mssp_hunt_agent.persistence.database import HuntDatabase
    config = get_config()
    return HuntDatabase(config.db_path)
