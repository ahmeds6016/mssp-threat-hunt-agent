"""CLI entry point — interactive intake, file-based runs, plan-only mode."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from mssp_hunt_agent.config import HuntAgentConfig
from mssp_hunt_agent.models.hunt_models import HuntPlan, SafetyFlag
from mssp_hunt_agent.models.input_models import HuntInput, HuntType, Priority
from mssp_hunt_agent.models.ioc_models import IOCEntry, IOCHuntInput, IOCType
from mssp_hunt_agent.models.profile_models import ClientTelemetryProfile, ProfileInput
from mssp_hunt_agent.pipeline.orchestrator import (
    IOCPipelineResult,
    PipelineResult,
    ProfilePipelineResult,
    run_ioc_pipeline,
    run_pipeline,
    run_profile_pipeline,
)

app = typer.Typer(
    name="hunt-agent",
    help="MSSP Hunt Agent — analyst-assisted threat hunting pipeline",
    add_completion=False,
    invoke_without_command=True,
)
clients_app = typer.Typer(help="Manage MSSP clients")
runs_app = typer.Typer(help="Query hunt run history")
analytics_app = typer.Typer(help="Analytics and KPI reporting")
policy_app = typer.Typer(help="Policy engine and autonomy controls")
app.add_typer(clients_app, name="clients")
app.add_typer(runs_app, name="runs")
app.add_typer(analytics_app, name="analytics")
app.add_typer(policy_app, name="policy")
console = Console()

# ── Commands ──────────────────────────────────────────────────────────


@app.command("run")
def run(
    input_file: Path = typer.Option(
        None, "--input", "-i", help="JSON file with hunt inputs (non-interactive mode)"
    ),
    mode: str = typer.Option(
        "hypothesis", "--mode", "-m",
        help="Hunt mode: 'hypothesis' (default), 'ioc' (indicator-driven sweep), or 'profile' (telemetry profiling)",
    ),
    plan_only: bool = typer.Option(
        False, "--plan-only", "-p", help="Generate plan only, do not execute"
    ),
    no_approve: bool = typer.Option(
        False, "--no-approve", help="Skip interactive approval (auto-approve safe queries)"
    ),
    output_dir: Path = typer.Option(
        Path("output"), "--output", "-o", help="Output directory for artefacts"
    ),
    profile_file: Path = typer.Option(
        None, "--profile",
        help="Path to a saved client_telemetry_profile.json to tailor hypothesis hunt queries",
    ),
    adapter: str = typer.Option(
        "mock", "--adapter", "-a",
        help="Adapter mode: 'mock' (synthetic data) or 'real' (live Microsoft Sentinel)",
    ),
    intel_providers: str = typer.Option(
        "", "--intel-providers",
        help="Comma-separated TI providers: mock, virustotal, abuseipdb",
    ),
    allow_pivots: bool = typer.Option(
        False, "--allow-pivots",
        help="Enable result-driven pivot queries (1-hop, bounded)",
    ),
    persist: bool = typer.Option(
        False, "--persist",
        help="Persist run results to local SQLite database",
    ),
    llm: bool = typer.Option(
        False, "--llm",
        help="Enable LLM-powered reasoning (requires Azure OpenAI credentials)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
) -> None:
    """Run a threat hunt — interactively or from a JSON input file."""
    _setup_logging(verbose)

    config = HuntAgentConfig.from_env()
    config.output_dir = output_dir
    if no_approve:
        config.approval_required = False
    if adapter != "mock":
        config.adapter_mode = adapter
        config.mock_mode = adapter != "real"
    if intel_providers:
        config.intel_providers = [p.strip() for p in intel_providers.split(",") if p.strip()]
    if allow_pivots:
        config.allow_pivots = True
    if persist:
        config.persist = True
    if llm:
        config.llm_enabled = True

    version_label = "[bold cyan]MSSP Hunt Agent v0.4.0[/bold cyan]"
    console.print(Panel(version_label, expand=False))

    if config.adapter_mode == "real":
        console.print(Panel(
            "[bold red]WARNING: LIVE MODE[/bold red] — Queries will execute against Microsoft Sentinel.\n"
            "Ensure AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and "
            "SENTINEL_WORKSPACE_ID are set and the service principal has Log Analytics Reader access.",
            border_style="red",
            expand=False,
        ))

    if mode == "ioc":
        _run_ioc_mode(input_file, config, plan_only)
    elif mode == "profile":
        _run_profile_mode(input_file, config, plan_only)
    else:
        _run_hypothesis_mode(input_file, config, plan_only, profile_file)


def _run_hypothesis_mode(
    input_file: Path | None,
    config: HuntAgentConfig,
    plan_only: bool,
    profile_file: Path | None = None,
) -> None:
    """Hypothesis-driven hunt path."""
    console.print("[bold]Mode:[/bold] Hypothesis-Driven Hunt\n")

    if input_file:
        hunt_input = _load_input_file(input_file)
    else:
        hunt_input = _interactive_intake()

    # Optionally load a saved telemetry profile
    client_profile: ClientTelemetryProfile | None = None
    if profile_file:
        client_profile = _load_profile_json(profile_file)
        if client_profile:
            console.print(
                f"[bold green]Loaded profile:[/bold green] {client_profile.profile_id} "
                f"({client_profile.source_count} sources)\n"
            )

    console.print()
    console.print("[bold green]Inputs captured.[/bold green] Starting pipeline...\n")

    approval_cb = _cli_approval if config.approval_required else None
    result = run_pipeline(
        hunt_input=hunt_input,
        config=config,
        approval_callback=approval_cb,
        plan_only=plan_only,
        client_profile=client_profile,
    )
    _print_summary(result)


def _run_ioc_mode(
    input_file: Path | None,
    config: HuntAgentConfig,
    plan_only: bool,
) -> None:
    """Indicator-driven / IOC sweep path."""
    console.print("[bold]Mode:[/bold] Indicator-Driven / IOC Sweep\n")

    if input_file:
        ioc_input = _load_ioc_input_file(input_file)
    else:
        ioc_input = _interactive_ioc_intake()

    console.print()
    console.print("[bold green]IOCs captured.[/bold green] Starting IOC sweep pipeline...\n")

    approval_cb = _cli_approval if config.approval_required else None
    result = run_ioc_pipeline(
        ioc_input=ioc_input,
        config=config,
        approval_callback=approval_cb,
        plan_only=plan_only,
    )
    _print_ioc_summary(result)


def _run_profile_mode(
    input_file: Path | None,
    config: HuntAgentConfig,
    plan_only: bool,
) -> None:
    """Client telemetry profiling path."""
    console.print("[bold]Mode:[/bold] Client Telemetry Profiling\n")

    if input_file:
        profile_input = _load_profile_input_file(input_file)
    else:
        profile_input = _interactive_profile_intake()

    console.print()
    console.print("[bold green]Profile inputs captured.[/bold green] Starting profiling pipeline...\n")

    approval_cb = _cli_approval if config.approval_required else None
    result = run_profile_pipeline(
        profile_input=profile_input,
        config=config,
        approval_callback=approval_cb,
        plan_only=plan_only,
    )
    _print_profile_summary(result)


# ── Interactive intake ────────────────────────────────────────────────


def _interactive_intake() -> HuntInput:
    """Walk the analyst through a guided Q&A to collect hunt context."""
    console.print("\n[bold]--- Hunt Intake ---[/bold]\n")

    client_name = Prompt.ask("[cyan]Client name[/cyan]")
    while not client_name.strip():
        client_name = Prompt.ask("[red]Client name is required.[/red] Client name")

    hunt_objective = Prompt.ask(
        "[cyan]Hunt objective[/cyan] (e.g. 'Detect credential abuse from foreign IPs')"
    )
    while not hunt_objective.strip():
        hunt_objective = Prompt.ask("[red]Hunt objective is required.[/red] Hunt objective")

    hunt_hypothesis = Prompt.ask(
        "[cyan]Hunt hypothesis[/cyan] (e.g. 'Compromised VPN creds used from Eastern Europe')"
    )
    while not hunt_hypothesis.strip():
        hunt_hypothesis = Prompt.ask("[red]Hunt hypothesis is required.[/red] Hypothesis")

    time_range = Prompt.ask(
        "[cyan]Time range[/cyan] (e.g. '2024-01-01 to 2024-01-31')"
    )
    while not time_range.strip():
        time_range = Prompt.ask("[red]Time range is required.[/red] Time range")

    ds_raw = Prompt.ask(
        "[cyan]Available data sources[/cyan] (comma-separated, e.g. 'Azure AD sign-in logs, VPN logs, MFA logs')"
    )
    while not ds_raw.strip():
        ds_raw = Prompt.ask("[red]At least one data source is required.[/red] Data sources")
    available_data_sources = [s.strip() for s in ds_raw.split(",") if s.strip()]

    gaps_raw = Prompt.ask(
        "[cyan]Telemetry gaps[/cyan] (comma-separated, or press Enter to skip)", default=""
    )
    telemetry_gaps = [s.strip() for s in gaps_raw.split(",") if s.strip()]

    # Hunt type
    console.print("\n[bold]Hunt type:[/bold] identity / endpoint / network / cloud")
    ht = Prompt.ask("[cyan]Hunt type[/cyan]", default="identity")
    hunt_type = HuntType(ht) if ht in [e.value for e in HuntType] else HuntType.IDENTITY

    # Optional fields
    console.print("\n[dim]--- Optional fields (press Enter to skip) ---[/dim]\n")
    industry = Prompt.ask("[cyan]Industry[/cyan]", default="Not provided")

    assets_raw = Prompt.ask("[cyan]Key assets[/cyan] (comma-separated)", default="")
    key_assets = [s.strip() for s in assets_raw.split(",") if s.strip()]

    priority_str = Prompt.ask("[cyan]Priority[/cyan] (Low/Medium/High)", default="Medium")
    priority = Priority(priority_str) if priority_str in [e.value for e in Priority] else Priority.MEDIUM

    tech_raw = Prompt.ask(
        "[cyan]ATT&CK techniques[/cyan] (comma-separated IDs, e.g. 'T1078, T1110')", default=""
    )
    attack_techniques = [s.strip() for s in tech_raw.split(",") if s.strip()]

    benign_raw = Prompt.ask("[cyan]Known benign patterns[/cyan] (comma-separated)", default="")
    known_benign = [s.strip() for s in benign_raw.split(",") if s.strip()]

    exclusions_raw = Prompt.ask("[cyan]Exclusions[/cyan] (comma-separated)", default="")
    exclusions = [s.strip() for s in exclusions_raw.split(",") if s.strip()]

    incidents_raw = Prompt.ask("[cyan]Prior related incidents[/cyan] (comma-separated)", default="")
    prior_incidents = [s.strip() for s in incidents_raw.split(",") if s.strip()]

    analyst_notes = Prompt.ask("[cyan]Analyst notes[/cyan]", default="Not provided")

    constraints_raw = Prompt.ask("[cyan]Constraints[/cyan] (comma-separated)", default="")
    constraints = [s.strip() for s in constraints_raw.split(",") if s.strip()]

    return HuntInput(
        client_name=client_name,
        hunt_objective=hunt_objective,
        hunt_hypothesis=hunt_hypothesis,
        time_range=time_range,
        available_data_sources=available_data_sources,
        telemetry_gaps=telemetry_gaps,
        hunt_type=hunt_type,
        industry=industry,
        key_assets=key_assets,
        priority=priority,
        attack_techniques=attack_techniques,
        known_benign_patterns=known_benign,
        exclusions=exclusions,
        prior_related_incidents=prior_incidents,
        analyst_notes=analyst_notes,
        constraints=constraints,
    )


# ── Interactive IOC intake ────────────────────────────────────────────


def _interactive_ioc_intake() -> IOCHuntInput:
    """Walk the analyst through IOC collection."""
    console.print("\n[bold]--- IOC Sweep Intake ---[/bold]\n")

    client_name = Prompt.ask("[cyan]Client name[/cyan]")
    while not client_name.strip():
        client_name = Prompt.ask("[red]Client name is required.[/red] Client name")

    sweep_objective = Prompt.ask(
        "[cyan]Sweep objective[/cyan]", default="IOC sweep / retro hunt"
    )

    time_range = Prompt.ask("[cyan]Time range[/cyan] (e.g. '2024-01-01 to 2024-01-31')")
    while not time_range.strip():
        time_range = Prompt.ask("[red]Time range is required.[/red] Time range")

    ds_raw = Prompt.ask(
        "[cyan]Available data sources[/cyan] (comma-separated)"
    )
    while not ds_raw.strip():
        ds_raw = Prompt.ask("[red]At least one data source is required.[/red] Data sources")
    data_sources = [s.strip() for s in ds_raw.split(",") if s.strip()]

    gaps_raw = Prompt.ask("[cyan]Telemetry gaps[/cyan] (comma-separated, or Enter to skip)", default="")
    gaps = [s.strip() for s in gaps_raw.split(",") if s.strip()]

    # Collect IOCs
    console.print("\n[bold]IOC types:[/bold] ip, domain, hash_md5, hash_sha1, hash_sha256, email, url, user_agent")
    console.print("[dim]Enter IOCs one at a time. Type 'done' when finished.[/dim]\n")

    iocs: list[IOCEntry] = []
    while True:
        value = Prompt.ask("[cyan]IOC value[/cyan] (or 'done')")
        if value.strip().lower() == "done":
            break
        if not value.strip():
            continue

        ioc_type_str = Prompt.ask(
            "[cyan]IOC type[/cyan]",
            choices=["ip", "domain", "hash_md5", "hash_sha1", "hash_sha256", "email", "url", "user_agent"],
            default="ip",
        )
        context = Prompt.ask("[cyan]Context[/cyan] (optional)", default="")

        iocs.append(IOCEntry(
            value=value.strip(),
            ioc_type=IOCType(ioc_type_str),
            context=context,
        ))
        console.print(f"  [green]Added {ioc_type_str}: {value.strip()}[/green]")

    if not iocs:
        console.print("[red]No IOCs provided. Exiting.[/red]")
        raise typer.Exit(1)

    pre_enrich = Confirm.ask("[cyan]Pre-enrich IOCs via threat intel before sweep?[/cyan]", default=True)
    analyst_notes = Prompt.ask("[cyan]Analyst notes[/cyan]", default="Not provided")

    return IOCHuntInput(
        client_name=client_name,
        iocs=iocs,
        time_range=time_range,
        available_data_sources=data_sources,
        telemetry_gaps=gaps,
        sweep_objective=sweep_objective,
        pre_enrich=pre_enrich,
        analyst_notes=analyst_notes,
    )


# ── Interactive profile intake ────────────────────────────────────────


def _interactive_profile_intake() -> ProfileInput:
    """Walk the analyst through guided Q&A for profiling."""
    console.print("\n[bold]--- Telemetry Profiling Intake ---[/bold]\n")

    client_name = Prompt.ask("[cyan]Client name[/cyan]")
    while not client_name.strip():
        client_name = Prompt.ask("[red]Client name is required.[/red] Client name")

    time_range = Prompt.ask(
        "[cyan]Time range to profile[/cyan] (e.g. '2024-11-01 to 2024-11-30')"
    )
    while not time_range.strip():
        time_range = Prompt.ask("[red]Time range is required.[/red] Time range")

    ds_raw = Prompt.ask(
        "[cyan]Declared data sources[/cyan] (comma-separated, or press Enter to discover)", default=""
    )
    declared = [s.strip() for s in ds_raw.split(",") if s.strip()]

    console.print("\n[bold]Hunt types to assess:[/bold] identity / endpoint / network / cloud")
    ht_raw = Prompt.ask(
        "[cyan]Hunt types of interest[/cyan] (comma-separated, or Enter for all)", default=""
    )
    if ht_raw.strip():
        hunt_types = [
            HuntType(h.strip())
            for h in ht_raw.split(",")
            if h.strip() in [e.value for e in HuntType]
        ]
    else:
        hunt_types = list(HuntType)

    analyst_notes = Prompt.ask("[cyan]Analyst notes[/cyan]", default="Not provided")

    return ProfileInput(
        client_name=client_name,
        time_range=time_range,
        declared_data_sources=declared,
        hunt_types_of_interest=hunt_types,
        analyst_notes=analyst_notes,
    )


# ── Input file loading ────────────────────────────────────────────────


def _load_input_file(path: Path) -> HuntInput:
    """Load and validate a JSON input file."""
    if not path.exists():
        console.print(f"[red]Input file not found:[/red] {path}")
        raise typer.Exit(1)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return HuntInput(**data)
    except Exception as exc:
        console.print(f"[red]Failed to parse input file:[/red] {exc}")
        raise typer.Exit(1)


def _load_ioc_input_file(path: Path) -> IOCHuntInput:
    """Load and validate an IOC hunt JSON input file."""
    if not path.exists():
        console.print(f"[red]Input file not found:[/red] {path}")
        raise typer.Exit(1)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return IOCHuntInput(**data)
    except Exception as exc:
        console.print(f"[red]Failed to parse IOC input file:[/red] {exc}")
        raise typer.Exit(1)


def _load_profile_input_file(path: Path) -> ProfileInput:
    """Load and validate a profile JSON input file."""
    if not path.exists():
        console.print(f"[red]Input file not found:[/red] {path}")
        raise typer.Exit(1)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ProfileInput(**data)
    except Exception as exc:
        console.print(f"[red]Failed to parse profile input file:[/red] {exc}")
        raise typer.Exit(1)


def _load_profile_json(path: Path) -> ClientTelemetryProfile | None:
    """Load a saved client_telemetry_profile.json for planner integration."""
    if not path.exists():
        console.print(f"[yellow]Profile file not found:[/yellow] {path}")
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ClientTelemetryProfile(**data)
    except Exception as exc:
        console.print(f"[yellow]Failed to parse profile file:[/yellow] {exc}")
        return None


# ── Output summaries ──────────────────────────────────────────────────


def _print_summary(result: PipelineResult) -> None:
    console.print()
    if result.stopped_at:
        console.print(f"[yellow]Pipeline stopped at: {result.stopped_at}[/yellow]")

    if result.output_dir:
        console.print(Panel(f"[bold green]Artefacts saved to:[/bold green] {result.output_dir}", expand=False))

    if result.executive_summary:
        console.print("\n[bold]Key Findings:[/bold]")
        for f in result.executive_summary.key_findings:
            console.print(f"  • {f}")

    if result.analyst_report:
        console.print(f"\n[bold]Escalation:[/bold] {result.analyst_report.escalation_recommendation}")

    if result.query_results:
        total_events = sum(qr.result_count for qr in result.query_results)
        console.print(f"\n[bold]Queries executed:[/bold] {len(result.query_results)}")
        console.print(f"[bold]Total events returned:[/bold] {total_events}")

    if result.enrichments:
        mal = sum(1 for e in result.enrichments if e.verdict == "malicious")
        sus = sum(1 for e in result.enrichments if e.verdict == "suspicious")
        console.print(f"[bold]Enrichments:[/bold] {len(result.enrichments)} total, {mal} malicious, {sus} suspicious")

    console.print()


def _print_ioc_summary(result: IOCPipelineResult) -> None:
    console.print()
    if result.stopped_at:
        console.print(f"[yellow]Pipeline stopped at: {result.stopped_at}[/yellow]")

    if result.output_dir:
        console.print(Panel(f"[bold green]Artefacts saved to:[/bold green] {result.output_dir}", expand=False))

    if result.ioc_batch:
        console.print(f"\n[bold]IOCs:[/bold] {len(result.ioc_batch.valid)} valid, "
                       f"{len(result.ioc_batch.invalid)} invalid, "
                       f"{result.ioc_batch.dedup_removed} deduped")

    if result.sweep_result:
        sr = result.sweep_result
        console.print(f"[bold]Sweep:[/bold] {sr.total_hits} hits / {sr.total_misses} misses "
                       f"out of {sr.total_iocs_searched} searched")
        if sr.hits:
            console.print("\n[bold]IOC Hits:[/bold]")
            for hit in sr.hits:
                console.print(
                    f"  [red]HIT[/red] {hit.ioc_type} '{hit.ioc_value}' — "
                    f"{hit.hit_count} events, hosts: {', '.join(hit.affected_hosts[:3])}"
                )

    if result.ioc_report:
        console.print(f"\n[bold]Escalation:[/bold] {result.ioc_report.escalation_recommendation}")

    if result.pre_enrichments:
        mal = sum(1 for e in result.pre_enrichments if e.verdict == "malicious")
        sus = sum(1 for e in result.pre_enrichments if e.verdict == "suspicious")
        console.print(f"[bold]Pre-enrichment:[/bold] {len(result.pre_enrichments)} total, {mal} malicious, {sus} suspicious")

    console.print()


def _print_profile_summary(result: ProfilePipelineResult) -> None:
    console.print()
    if result.stopped_at:
        console.print(f"[yellow]Pipeline stopped at: {result.stopped_at}[/yellow]")

    if result.output_dir:
        console.print(Panel(
            f"[bold green]Profile artefacts saved to:[/bold green] {result.output_dir}",
            expand=False,
        ))

    if result.client_profile:
        p = result.client_profile
        console.print(f"\n[bold]Client:[/bold] {p.client_name}")
        console.print(f"[bold]Sources Discovered:[/bold] {p.source_count}")
        console.print(f"[bold]Total Events:[/bold] {p.total_event_count:,}")

        if p.is_simulated:
            console.print("[yellow]NOTE: Profile built from SIMULATED data[/yellow]")

        console.print("\n[bold]Hunt Readiness:[/bold]")
        table = Table(show_header=True)
        table.add_column("Hunt Type", style="cyan", width=12)
        table.add_column("Readiness", width=10)
        table.add_column("Coverage", width=10)
        table.add_column("Sources", width=40)

        for cap in p.capabilities:
            color = {"Green": "green", "Yellow": "yellow", "Red": "red"}.get(
                cap.readiness.value, "white"
            )
            table.add_row(
                cap.hunt_type.value,
                f"[{color}]{cap.readiness.value}[/{color}]",
                f"{cap.coverage_pct:.0f}%",
                ", ".join(cap.available_sources[:3]) or "None",
            )

        console.print(table)

        if p.declared_vs_discovered_gaps:
            console.print("\n[bold yellow]Declared but not found:[/bold yellow]")
            for gap in p.declared_vs_discovered_gaps:
                console.print(f"  - {gap}")

        if p.recency_warnings:
            console.print("\n[bold yellow]Stale sources:[/bold yellow]")
            for w in p.recency_warnings:
                console.print(f"  - {w}")

    console.print()


# ── Approval callback ────────────────────────────────────────────────


def _cli_approval(plan: HuntPlan) -> bool:
    """Display the hunt plan and ask for approval before execution."""
    console.print(Panel("[bold yellow]HUNT PLAN — REVIEW REQUIRED[/bold yellow]", expand=False))

    console.print(f"\n[bold]Plan ID:[/bold] {plan.plan_id}")
    console.print(f"[bold]Client:[/bold] {plan.client_name}")
    console.print(f"[bold]Hunt type:[/bold] {plan.hunt_type}")
    console.print(f"[bold]Objective:[/bold] {plan.objective}")
    console.print(
        f"[bold]Telemetry:[/bold] {plan.telemetry_assessment.readiness.value} "
        f"— {plan.telemetry_assessment.rationale}"
    )

    # Show hypotheses
    for hyp in plan.hypotheses:
        console.print(f"\n[bold]Hypothesis:[/bold] {hyp.description}")
        console.print(f"  Tactics: {', '.join(hyp.attack_tactics)}")
        console.print(f"  Techniques: {', '.join(hyp.attack_techniques) or 'None provided'}")
        console.print(f"  Source: {hyp.technique_source}")

    # Show queries and safety flags
    console.print("\n[bold]Planned Queries:[/bold]")
    table = Table(show_header=True)
    table.add_column("ID", style="cyan", width=12)
    table.add_column("Intent", width=18)
    table.add_column("Description", width=50)
    table.add_column("Safety", width=15)

    for step in plan.hunt_steps:
        for q in step.queries:
            flag_summary = _summarise_flags(q.safety_flags)
            table.add_row(q.query_id, q.intent.value, q.description, flag_summary)

    console.print(table)

    # Show queries with errors
    error_queries = [
        q
        for step in plan.hunt_steps
        for q in step.queries
        if any(f.severity == "error" for f in q.safety_flags)
    ]
    if error_queries:
        console.print(
            f"\n[bold red]{len(error_queries)} query/queries have safety ERRORS "
            f"and will NOT be executed.[/bold red]"
        )
        for q in error_queries:
            for f in q.safety_flags:
                if f.severity == "error":
                    console.print(f"  [{q.query_id}] {f.rule}: {f.message}")

    console.print()
    return Confirm.ask("[bold yellow]Approve and execute?[/bold yellow]", default=True)


def _summarise_flags(flags: list[SafetyFlag]) -> str:
    if not flags:
        return "[green]CLEAN[/green]"
    errors = sum(1 for f in flags if f.severity == "error")
    warnings = sum(1 for f in flags if f.severity == "warning")
    parts = []
    if errors:
        parts.append(f"[red]{errors}E[/red]")
    if warnings:
        parts.append(f"[yellow]{warnings}W[/yellow]")
    return " ".join(parts)


# ── Persistence subcommands ────────────────────────────────────────────


@clients_app.command("list")
def clients_list(
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """List all managed clients in the database."""
    from mssp_hunt_agent.persistence.database import HuntDatabase

    db = HuntDatabase(db_path)
    clients = db.list_clients()
    db.close()

    if not clients:
        console.print("[yellow]No clients found in database.[/yellow]")
        return

    table = Table(title="Managed Clients", show_header=True)
    table.add_column("Client ID", style="cyan", width=20)
    table.add_column("Name", width=25)
    table.add_column("Industry", width=20)
    table.add_column("Onboarded", width=22)

    for c in clients:
        table.add_row(c.client_id, c.client_name, c.industry, c.onboarded_at[:19] if c.onboarded_at else "")

    console.print(table)


@clients_app.command("stats")
def clients_stats(
    client_name: str = typer.Argument(help="Client name to show stats for"),
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """Show aggregated stats for a specific client."""
    from mssp_hunt_agent.persistence.database import HuntDatabase

    db = HuntDatabase(db_path)
    stats = db.get_client_stats(client_name)
    db.close()

    if not stats:
        console.print(f"[red]Client '{client_name}' not found.[/red]")
        raise typer.Exit(1)

    console.print(Panel(f"[bold cyan]Client Stats: {client_name}[/bold cyan]", expand=False))
    console.print(f"  [bold]Total runs:[/bold] {stats.total_runs}")
    console.print(f"  [bold]Hypothesis:[/bold] {stats.hypothesis_runs}")
    console.print(f"  [bold]IOC sweeps:[/bold] {stats.ioc_runs}")
    console.print(f"  [bold]Profiles:[/bold] {stats.profile_runs}")
    console.print(f"  [bold]Total findings:[/bold] {stats.total_findings}")
    console.print(f"  [bold]High confidence:[/bold] {stats.high_confidence_findings}")
    if stats.last_run_at:
        console.print(f"  [bold]Last run:[/bold] {stats.last_run_at[:19]}")
    if stats.last_profile_at:
        console.print(f"  [bold]Last profile:[/bold] {stats.last_profile_at[:19]}")


@runs_app.command("list")
def runs_list(
    client: str = typer.Option(None, "--client", "-c", help="Filter by client name"),
    hunt_type: str = typer.Option(None, "--type", "-t", help="Filter by hunt type"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max rows to show"),
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """List hunt runs from the database."""
    from mssp_hunt_agent.persistence.database import HuntDatabase

    db = HuntDatabase(db_path)
    runs = db.get_runs(client_name=client, hunt_type=hunt_type, limit=limit)
    db.close()

    if not runs:
        console.print("[yellow]No runs found.[/yellow]")
        return

    table = Table(title="Hunt Runs", show_header=True)
    table.add_column("Run ID", style="cyan", width=16)
    table.add_column("Client", width=18)
    table.add_column("Type", width=14)
    table.add_column("Mode", width=6)
    table.add_column("Status", width=10)
    table.add_column("Findings", width=9, justify="right")
    table.add_column("Queries", width=9, justify="right")
    table.add_column("Started", width=20)

    for r in runs:
        status_style = {"completed": "green", "failed": "red", "stopped": "yellow"}.get(r.status, "white")
        table.add_row(
            r.run_id,
            r.client_name,
            r.hunt_type,
            r.execution_mode,
            f"[{status_style}]{r.status}[/{status_style}]",
            str(r.findings_count),
            str(r.queries_executed),
            r.started_at[:19] if r.started_at else "",
        )

    console.print(table)


# ── Analytics subcommands ─────────────────────────────────────────────


@analytics_app.command("kpis")
def analytics_kpis(
    client: str = typer.Option(None, "--client", "-c", help="Filter by client name"),
    period: str = typer.Option("all", "--period", "-p", help="Period filter: 'all', '2024-12', '2024-W48'"),
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """Show KPIs for one or all clients."""
    from mssp_hunt_agent.analytics.kpi_engine import KPIEngine
    from mssp_hunt_agent.persistence.database import HuntDatabase

    db = HuntDatabase(db_path)
    engine = KPIEngine(db)

    if client:
        kpis = engine.client_kpis(client, period)
        if not kpis:
            console.print(f"[red]Client '{client}' not found or has no runs.[/red]")
            db.close()
            raise typer.Exit(1)
        kpi_list = [kpis]
    else:
        kpi_list = engine.all_client_kpis(period)

    db.close()

    if not kpi_list:
        console.print("[yellow]No KPI data found.[/yellow]")
        return

    table = Table(title=f"Hunt KPIs (period={period})", show_header=True)
    table.add_column("Client", style="cyan", width=20)
    table.add_column("Hunts", width=7, justify="right")
    table.add_column("Findings", width=9, justify="right")
    table.add_column("High-Conf", width=10, justify="right")
    table.add_column("Hit Rate", width=10, justify="right")
    table.add_column("Queries", width=9, justify="right")
    table.add_column("Events", width=9, justify="right")

    for k in kpi_list:
        table.add_row(
            k.client_name,
            str(k.total_hunts),
            str(k.total_findings),
            str(k.high_confidence_findings),
            f"{k.hit_rate * 100:.1f}%",
            str(k.total_queries),
            str(k.total_events),
        )

    console.print(table)


@analytics_app.command("rollup")
def analytics_rollup(
    rollup_type: str = typer.Option("monthly", "--type", "-t", help="Rollup type: 'weekly' or 'monthly'"),
    period: str = typer.Option("", "--period", "-p", help="Period: '2024-W48' (weekly) or '2024-12' (monthly)"),
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """Generate a weekly or monthly rollup report."""
    from mssp_hunt_agent.analytics.rollup_reports import (
        generate_monthly_rollup,
        generate_weekly_rollup,
    )
    from mssp_hunt_agent.persistence.database import HuntDatabase

    db = HuntDatabase(db_path)

    if rollup_type == "weekly":
        rollup, md = generate_weekly_rollup(db, period=period or None)
    else:
        rollup, md = generate_monthly_rollup(db, period=period or None)

    db.close()
    console.print(md)


# ── Policy subcommands ────────────────────────────────────────────────


@policy_app.command("list")
def policy_list(
    client: str = typer.Option("*", "--client", "-c", help="Client name ('*' for all)"),
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """List active policy rules."""
    from mssp_hunt_agent.persistence.database import HuntDatabase

    db = HuntDatabase(db_path)
    rows = db._conn.execute(
        "SELECT * FROM policy_rules WHERE enabled = 1 ORDER BY client_name, action_category"
    ).fetchall()
    db.close()

    if not rows:
        console.print("[yellow]No policy rules found.[/yellow]")
        return

    table = Table(title="Policy Rules", show_header=True)
    table.add_column("Rule ID", style="cyan", width=16)
    table.add_column("Client", width=14)
    table.add_column("Category", width=18)
    table.add_column("Action", width=18)
    table.add_column("Limits", width=20)
    table.add_column("Reason", width=30)

    for r in rows:
        limits = []
        if r["max_queries"]:
            limits.append(f"q<={r['max_queries']}")
        if r["max_iocs"]:
            limits.append(f"ioc<={r['max_iocs']}")
        if r["max_time_range_days"]:
            limits.append(f"d<={r['max_time_range_days']}")
        table.add_row(
            r["rule_id"],
            r["client_name"],
            r["action_category"],
            r["policy_action"],
            ", ".join(limits) or "-",
            r["reason"][:30],
        )

    console.print(table)


@policy_app.command("add")
def policy_add(
    client: str = typer.Option("*", "--client", "-c", help="Client name ('*' for global)"),
    category: str = typer.Option(..., "--category", help="Action category (e.g. run_hunt, auto_sweep)"),
    action: str = typer.Option(..., "--action", "-a", help="Policy action: auto_approve, require_approval, auto_deny"),
    max_queries: int = typer.Option(0, "--max-queries", help="Max queries before escalation (0=unlimited)"),
    max_iocs: int = typer.Option(0, "--max-iocs", help="Max IOCs before escalation (0=unlimited)"),
    max_days: int = typer.Option(0, "--max-days", help="Max time range in days (0=unlimited)"),
    reason: str = typer.Option("", "--reason", "-r", help="Reason for this rule"),
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """Add a new policy rule."""
    import uuid as _uuid
    from datetime import datetime, timezone

    from mssp_hunt_agent.persistence.database import HuntDatabase

    db = HuntDatabase(db_path)
    rule_id = f"POL-{_uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    db._conn.execute(
        "INSERT INTO policy_rules "
        "(rule_id, client_name, action_category, policy_action, "
        "max_queries, max_iocs, max_time_range_days, reason, enabled, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
        (rule_id, client, category, action, max_queries, max_iocs, max_days, reason, now),
    )
    db._conn.commit()
    db.close()

    console.print(f"[green]Added policy rule:[/green] {rule_id}")
    console.print(f"  Client: {client}, Category: {category}, Action: {action}")


@policy_app.command("remove")
def policy_remove(
    rule_id: str = typer.Argument(help="Rule ID to remove"),
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """Remove a policy rule by ID."""
    from mssp_hunt_agent.persistence.database import HuntDatabase

    db = HuntDatabase(db_path)
    cursor = db._conn.execute("DELETE FROM policy_rules WHERE rule_id = ?", (rule_id,))
    db._conn.commit()
    deleted = cursor.rowcount > 0
    db.close()

    if deleted:
        console.print(f"[green]Removed rule {rule_id}[/green]")
    else:
        console.print(f"[red]Rule {rule_id} not found.[/red]")


@policy_app.command("audit")
def policy_audit(
    client: str = typer.Option(None, "--client", "-c", help="Filter by client name"),
    action: str = typer.Option(None, "--action", "-a", help="Filter by policy action"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max rows to show"),
    db_path: Path = typer.Option(
        Path(".hunt_agent.db"), "--db", help="Path to SQLite database"
    ),
) -> None:
    """Show the autonomy audit log."""
    from mssp_hunt_agent.persistence.database import HuntDatabase
    from mssp_hunt_agent.policy.audit import AuditLogger

    db = HuntDatabase(db_path)
    audit_logger = AuditLogger(db)
    entries = audit_logger.get_entries(client_name=client, action=action, limit=limit)
    db.close()

    if not entries:
        console.print("[yellow]No audit entries found.[/yellow]")
        return

    table = Table(title="Autonomy Audit Log", show_header=True)
    table.add_column("Entry ID", style="cyan", width=16)
    table.add_column("Client", width=14)
    table.add_column("Category", width=18)
    table.add_column("Decision", width=18)
    table.add_column("Reason", width=30)
    table.add_column("Timestamp", width=20)

    for e in entries:
        action_style = {
            "auto_approve": "green",
            "require_approval": "yellow",
            "auto_deny": "red",
        }.get(e.policy_decision.action, "white")
        table.add_row(
            e.entry_id,
            e.client_name,
            e.action_category,
            f"[{action_style}]{e.policy_decision.action}[/{action_style}]",
            e.policy_decision.reason[:30],
            e.timestamp[:19] if e.timestamp else "",
        )

    console.print(table)


# ── Logging ───────────────────────────────────────────────────────────


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


if __name__ == "__main__":
    app()
