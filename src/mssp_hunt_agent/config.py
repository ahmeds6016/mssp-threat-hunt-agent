"""Centralised runtime configuration for the hunt agent."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, model_validator


class HuntAgentConfig(BaseModel):
    """All tuneable knobs live here. Values are read from env vars at startup."""

    # Execution modes
    mock_mode: bool = True
    approval_required: bool = True

    # Adapter mode: "mock" or "real"
    adapter_mode: str = "mock"

    # Paths
    output_dir: Path = Path("output")
    enrichment_cache_dir: Path = Path(".cache/enrichment")

    # Query defaults
    max_query_results: int = 1000
    query_timeout_seconds: int = 30

    # Microsoft Sentinel / Azure Log Analytics
    sentinel_workspace_id: str = ""        # Log Analytics workspace GUID
    sentinel_subscription_id: str = ""    # Azure subscription ID
    sentinel_resource_group: str = ""     # Resource group name
    sentinel_workspace_name: str = ""     # Workspace name (human-readable)
    azure_tenant_id: str = ""             # AAD tenant ID
    azure_client_id: str = ""             # Service principal app ID
    azure_client_secret: str = ""         # Service principal secret

    # Threat-intel providers (comma-separated names: mock, virustotal, abuseipdb)
    intel_providers: list[str] = Field(default_factory=lambda: ["mock"])
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # Pivots
    allow_pivots: bool = False
    max_pivot_queries: int = 5

    # Persistence
    persist: bool = False
    db_path: Path = Path(".hunt_agent.db")
    blob_connection_string: str = ""  # Azure Blob Storage for durable state
    blob_container_name: str = "agent-state"

    # API
    api_enabled: bool = False

    # LLM reasoning (Azure OpenAI)
    llm_enabled: bool = False
    azure_openai_endpoint: str = ""
    azure_openai_key: str = ""
    azure_openai_deployment: str = "gpt-5.3-chat"
    azure_openai_api_version: str = "2024-12-01-preview"

    # Policy engine / autonomy
    policy_engine_enabled: bool = False
    autonomy_level: str = "level_1"  # level_0 | level_1 | level_2 | level_3
    max_auto_queries: int = 20       # max queries before requiring approval (0=no limit)
    max_auto_iocs: int = 50          # max IOCs per auto-sweep before requiring approval
    auto_sweep_enabled: bool = False # allow automatic IOC sweeps

    # Agent controller
    default_client_name: str = ""        # Pre-configured client name
    agent_enabled: bool = False          # Enable NL agent controller
    agent_llm_fallback: bool = True      # Fall back to rules if LLM unavailable
    agent_max_chain_steps: int = 10      # Max reasoning steps per prompt
    agent_thinking_visible: bool = True  # Include thinking trace in response

    # Agent loop (agentic V6 — GPT-4o tool-calling loop)
    agent_loop_max_iterations: int = 12
    agent_loop_max_kql_results: int = 200
    agent_loop_timeout_seconds: int = 120

    # Open-source data caches (no API keys — all public GitHub)
    cve_cache_dir: str = ".cache/cve"
    mitre_cache_dir: str = ".cache/mitre"
    mitre_cache_ttl_days: int = 7
    sentinel_rules_cache_dir: str = ".cache/sentinel_rules"
    sentinel_rules_enabled: bool = True

    # SharePoint delivery
    sharepoint_enabled: bool = False
    sharepoint_tenant_id: str = ""
    sharepoint_client_id: str = ""
    sharepoint_client_secret: str = ""
    sharepoint_site_id: str = ""
    sharepoint_drive_id: str = ""

    @model_validator(mode="after")
    def _validate_real_mode(self) -> "HuntAgentConfig":
        """Require Sentinel credentials when adapter_mode is 'real'."""
        if self.adapter_mode == "real":
            missing = []
            if not self.azure_tenant_id:
                missing.append("AZURE_TENANT_ID")
            if not self.azure_client_id:
                missing.append("AZURE_CLIENT_ID")
            if not self.azure_client_secret:
                missing.append("AZURE_CLIENT_SECRET")
            if not self.sentinel_workspace_id:
                missing.append("SENTINEL_WORKSPACE_ID")
            if missing:
                raise ValueError(
                    f"adapter_mode='real' requires: {', '.join(missing)}"
                )
        # Require Azure OpenAI credentials when LLM is enabled
        if self.llm_enabled:
            missing = []
            if not self.azure_openai_endpoint:
                missing.append("AZURE_OPENAI_ENDPOINT")
            if not self.azure_openai_key:
                missing.append("AZURE_OPENAI_KEY")
            if missing:
                raise ValueError(
                    f"llm_enabled=True requires: {', '.join(missing)}"
                )
        # Sync mock_mode with adapter_mode for backward compat
        if self.adapter_mode == "real":
            self.mock_mode = False
        return self

    @classmethod
    def from_env(cls) -> "HuntAgentConfig":
        """Build config from environment variables (or fall back to defaults)."""
        adapter_mode = os.getenv("HUNT_ADAPTER_MODE", "mock").lower()

        # Parse intel providers
        intel_raw = os.getenv("HUNT_INTEL_PROVIDERS", "mock")
        intel_providers = [p.strip() for p in intel_raw.split(",") if p.strip()]

        return cls(
            mock_mode=os.getenv("HUNT_MOCK_MODE", "true").lower() == "true",
            approval_required=os.getenv("HUNT_APPROVAL_REQUIRED", "true").lower() == "true",
            adapter_mode=adapter_mode,
            output_dir=Path(os.getenv("HUNT_OUTPUT_DIR", "output")),
            enrichment_cache_dir=Path(os.getenv("HUNT_CACHE_DIR", ".cache/enrichment")),
            max_query_results=int(os.getenv("HUNT_MAX_RESULTS", "1000")),
            query_timeout_seconds=int(os.getenv("HUNT_QUERY_TIMEOUT", "30")),
            # Sentinel / Azure
            sentinel_workspace_id=os.getenv("SENTINEL_WORKSPACE_ID", ""),
            sentinel_subscription_id=os.getenv("SENTINEL_SUBSCRIPTION_ID", ""),
            sentinel_resource_group=os.getenv("SENTINEL_RESOURCE_GROUP", ""),
            sentinel_workspace_name=os.getenv("SENTINEL_WORKSPACE_NAME", ""),
            azure_tenant_id=os.getenv("AZURE_TENANT_ID", ""),
            azure_client_id=os.getenv("AZURE_CLIENT_ID", ""),
            azure_client_secret=os.getenv("AZURE_CLIENT_SECRET", ""),
            # TI
            intel_providers=intel_providers,
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            allow_pivots=os.getenv("HUNT_ALLOW_PIVOTS", "false").lower() == "true",
            max_pivot_queries=int(os.getenv("HUNT_MAX_PIVOT_QUERIES", "5")),
            api_enabled=os.getenv("HUNT_API_ENABLED", "false").lower() == "true",
            persist=os.getenv("HUNT_PERSIST", "false").lower() == "true",
            db_path=Path(os.getenv("HUNT_DB_PATH", ".hunt_agent.db")),
            blob_connection_string=os.getenv("BLOB_CONNECTION_STRING", ""),
            blob_container_name=os.getenv("BLOB_CONTAINER_NAME", "agent-state"),
            # LLM
            llm_enabled=os.getenv("HUNT_LLM_ENABLED", "false").lower() == "true",
            azure_openai_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT", ""),
            azure_openai_key=os.getenv("AZURE_OPENAI_KEY", ""),
            azure_openai_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5.3-chat"),
            azure_openai_api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
            # Policy
            policy_engine_enabled=os.getenv("HUNT_POLICY_ENABLED", "false").lower() == "true",
            autonomy_level=os.getenv("HUNT_AUTONOMY_LEVEL", "level_1"),
            max_auto_queries=int(os.getenv("HUNT_MAX_AUTO_QUERIES", "20")),
            max_auto_iocs=int(os.getenv("HUNT_MAX_AUTO_IOCS", "50")),
            auto_sweep_enabled=os.getenv("HUNT_AUTO_SWEEP_ENABLED", "false").lower() == "true",
            # Agent
            default_client_name=os.getenv("HUNT_DEFAULT_CLIENT", ""),
            agent_enabled=os.getenv("HUNT_AGENT_ENABLED", "false").lower() == "true",
            agent_llm_fallback=os.getenv("HUNT_AGENT_LLM_FALLBACK", "true").lower() == "true",
            agent_max_chain_steps=int(os.getenv("HUNT_AGENT_MAX_STEPS", "10")),
            agent_thinking_visible=os.getenv("HUNT_AGENT_THINKING_VISIBLE", "true").lower() == "true",
            # Agent loop (V6)
            agent_loop_max_iterations=int(os.getenv("HUNT_AGENT_LOOP_MAX_ITER", "12")),
            agent_loop_max_kql_results=int(os.getenv("HUNT_AGENT_LOOP_MAX_KQL", "200")),
            agent_loop_timeout_seconds=int(os.getenv("HUNT_AGENT_LOOP_TIMEOUT", "120")),
            cve_cache_dir=os.getenv("HUNT_CVE_CACHE_DIR", ".cache/cve"),
            mitre_cache_dir=os.getenv("HUNT_MITRE_CACHE_DIR", ".cache/mitre"),
            mitre_cache_ttl_days=int(os.getenv("HUNT_MITRE_CACHE_TTL_DAYS", "7")),
            sentinel_rules_cache_dir=os.getenv("HUNT_SENTINEL_RULES_CACHE_DIR", ".cache/sentinel_rules"),
            sentinel_rules_enabled=os.getenv("HUNT_SENTINEL_RULES_ENABLED", "true").lower() == "true",
            # SharePoint
            sharepoint_enabled=os.getenv("HUNT_SHAREPOINT_ENABLED", "false").lower() == "true",
            sharepoint_tenant_id=os.getenv("SHAREPOINT_TENANT_ID", ""),
            sharepoint_client_id=os.getenv("SHAREPOINT_CLIENT_ID", ""),
            sharepoint_client_secret=os.getenv("SHAREPOINT_CLIENT_SECRET", ""),
            sharepoint_site_id=os.getenv("SHAREPOINT_SITE_ID", ""),
            sharepoint_drive_id=os.getenv("SHAREPOINT_DRIVE_ID", ""),
        )
