"""Executor stage — run approved KQL queries through the SIEM adapter."""

from __future__ import annotations

import logging

from mssp_hunt_agent.adapters.base import SIEMAdapter
from mssp_hunt_agent.models.hunt_models import ExabeamQuery, HuntPlan
from mssp_hunt_agent.models.result_models import QueryResult

logger = logging.getLogger(__name__)


def execute_approved_queries(
    plan: HuntPlan,
    adapter: SIEMAdapter,
) -> list[QueryResult]:
    """Execute every approved query in the plan and collect results.

    Queries that are not approved are skipped.
    Errors on individual queries are captured in the result — they do not
    crash the whole run.
    """
    results: list[QueryResult] = []

    all_queries = _collect_queries(plan)
    approved = [q for q in all_queries if q.approved]

    if not approved:
        logger.warning("No approved queries to execute.")
        return results

    for query in approved:
        try:
            result = adapter.execute_query(query)
            results.append(result)
            logger.info(
                "Query %s executed — %d results in %d ms",
                query.query_id,
                result.result_count,
                result.execution_time_ms,
            )
        except Exception as exc:
            logger.error("Query %s failed: %s", query.query_id, exc)
            results.append(
                QueryResult(
                    query_id=query.query_id,
                    query_text=query.query_text,
                    status="error",
                    error_message=str(exc),
                )
            )

    return results


def _collect_queries(plan: HuntPlan) -> list[ExabeamQuery]:
    """Flatten all queries from every step in the plan."""
    queries: list[ExabeamQuery] = []
    for step in plan.hunt_steps:
        queries.extend(step.queries)
    return queries
