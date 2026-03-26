"""Analytics package — KPIs, rollup reports, per-client tuning."""

from mssp_hunt_agent.analytics.models import (
    ClientKPIs,
    WeeklyRollup,
    MonthlyRollup,
    TuningRule,
    ClientTuningConfig,
)
from mssp_hunt_agent.analytics.kpi_engine import KPIEngine
from mssp_hunt_agent.analytics.rollup_reports import (
    generate_weekly_rollup,
    generate_monthly_rollup,
)

__all__ = [
    "ClientKPIs",
    "WeeklyRollup",
    "MonthlyRollup",
    "TuningRule",
    "ClientTuningConfig",
    "KPIEngine",
    "generate_weekly_rollup",
    "generate_monthly_rollup",
]
