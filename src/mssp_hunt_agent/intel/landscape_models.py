"""Data models for threat landscape correlation."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class KEVEntry(BaseModel):
    """CISA Known Exploited Vulnerability catalog entry."""
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    date_added: str
    due_date: str
    known_ransomware_use: str = "Unknown"
    short_description: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)


class ExploitEntry(BaseModel):
    """Public exploit reference."""
    exploit_id: str
    cve_id: str = ""
    title: str
    platform: str = ""
    severity: str = "medium"
    published_date: str = ""


class ThreatCorrelation(BaseModel):
    """Correlation between an active threat and a client's detection capability."""
    threat_id: str  # CVE or exploit ID
    threat_name: str
    client_name: str
    can_detect: bool = False
    detection_sources: list[str] = Field(default_factory=list)
    missing_sources: list[str] = Field(default_factory=list)
    coverage_score: float = 0.0
    mitre_techniques: list[str] = Field(default_factory=list)


class LandscapeAlert(BaseModel):
    """Actionable alert for a client blind spot."""
    alert_id: str
    severity: str = "high"
    threat_id: str
    threat_name: str
    client_name: str
    message: str
    missing_sources: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class LandscapeReport(BaseModel):
    """Full threat landscape correlation report."""
    total_threats_analyzed: int = 0
    total_correlations: int = 0
    alerts: list[LandscapeAlert] = Field(default_factory=list)
    correlations: list[ThreatCorrelation] = Field(default_factory=list)
    clients_at_risk: list[str] = Field(default_factory=list)
