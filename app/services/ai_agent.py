"""AI Agent service - reasoning layer over patch events.

Takes a :class:`PatchEvent` plus its CVE threat intelligence and asks a local
LLM (Ollama) to produce a concise, action-oriented briefing or answer
follow-up questions about the event.

Design principles:
- Advisory only. The AI never executes lifecycle transitions or mutates
  state. It writes markdown into ``AIAnalysis`` rows; humans still drive.
- Grounded. The prompt always pins the model to the real numbers (severity
  counts, CVSS scores, KEV hits). No free-form hallucinated vulns.
- Local + private. All inference happens on the user's machine. No CVE data
  or company context ever leaves localhost.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import (
    AIAnalysis,
    CVEIntelligence,
    PatchEvent,
    Severity,
    SnapshotType,
    Vulnerability,
)
from app.services.cve_enrichment import compute_risk_score, get_intel_map
from app.services.diff import (
    compute_fixed_vulnerabilities,
    count_by_severity,
    extract_before_after_vulnerabilities,
)
from app.services.ollama_client import (
    OllamaError,
    OllamaResult,
    chat,
    generate,
    is_available,
)

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = (
    "You are a senior vulnerability-management analyst reviewing CVE exposure "
    "across enterprise security and IT-operations software (e.g. Nessus Manager, "
    "Trend Micro, Grafana, Burp Suite, Tenable Security Center, ServiceNow). "
    "Be concise, factual, and action-oriented. "
    "NEVER invent CVE IDs, CVSS scores, or exploitation data that is not in "
    "the context. Use the exact numbers you are given. Name the specific service "
    "and CVE IDs in every recommendation — never say 'EC2 AMI' or generic cloud "
    "references unless they are explicitly in the data. Format answers in "
    "markdown with short bullet lists. Prefer 4-8 bullets over long paragraphs. "
    "If the data is sparse, say so. You advise humans; you never execute or "
    "promote anything."
)


# ---------------------------------------------------------------------------
# Context builders
# ---------------------------------------------------------------------------


def _top_risky_cves(
    vulns: List[Vulnerability],
    intel_map: Dict[str, CVEIntelligence],
    limit: int = 5,
) -> List[Dict[str, object]]:
    """Sort vulnerabilities by composite risk score and return the top N.

    Keeps summaries short to minimize prompt tokens (critical for CPU inference).
    """
    scored: List[Dict[str, object]] = []
    seen: set = set()
    for v in vulns:
        if not v.cve or v.cve in seen:
            continue
        seen.add(v.cve)
        intel = intel_map.get(v.cve)
        scored.append(
            {
                "cve": v.cve,
                "severity": v.severity.value,
                "risk_score": compute_risk_score(intel),
                "cvss": getattr(intel, "cvss_v3_score", None) if intel else None,
                "epss": getattr(intel, "epss_score", None) if intel else None,
                "is_kev": getattr(intel, "is_kev", False) if intel else False,
                "summary": (
                    (getattr(intel, "description", None) or "")[:90]
                    if intel
                    else ""
                ),
            }
        )
    scored.sort(key=lambda item: item["risk_score"], reverse=True)
    return scored[:limit]


def build_context(db: Session, patch_event: PatchEvent) -> Dict[str, object]:
    """Gather all numbers and intel the model needs into a single dict."""
    snapshots = list(patch_event.snapshots)
    split = extract_before_after_vulnerabilities(snapshots)
    before_vulns = split[SnapshotType.BEFORE]
    after_vulns = split[SnapshotType.AFTER]
    fixed_vulns = compute_fixed_vulnerabilities(before_vulns, after_vulns)

    all_cves = [v.cve for v in before_vulns + after_vulns if v.cve]
    intel_map = get_intel_map(db, all_cves)

    before_counts = count_by_severity(before_vulns)
    after_counts = count_by_severity(after_vulns)
    fixed_counts = count_by_severity(fixed_vulns)

    def sev_dict(counts: Dict[Severity, int]) -> Dict[str, int]:
        return {s.value: counts.get(s, 0) for s in Severity}

    kev_before = sum(
        1
        for v in before_vulns
        if v.cve and intel_map.get(v.cve) and intel_map[v.cve].is_kev
    )
    kev_after = sum(
        1
        for v in after_vulns
        if v.cve and intel_map.get(v.cve) and intel_map[v.cve].is_kev
    )

    effectiveness = (
        round(len(fixed_vulns) / len(before_vulns) * 100, 1)
        if before_vulns
        else 0.0
    )

    return {
        "service": patch_event.service.name if patch_event.service else "unknown",
        "environment": patch_event.environment.value
        if patch_event.environment
        else "unknown",
        "ami_id": patch_event.ami_id,
        "patch_date": (
            patch_event.patch_date.isoformat() if patch_event.patch_date else None
        ),
        "current_state": patch_event.current_state_code,
        "counts": {
            "before": len(before_vulns),
            "after": len(after_vulns),
            "fixed": len(fixed_vulns),
            "remaining": len(after_vulns),
        },
        "severity_before": sev_dict(before_counts),
        "severity_after": sev_dict(after_counts),
        "severity_fixed": sev_dict(fixed_counts),
        "effectiveness_pct": effectiveness,
        "kev_before": kev_before,
        "kev_after": kev_after,
        "top_remaining": _top_risky_cves(after_vulns, intel_map, limit=5),
        "top_fixed": _top_risky_cves(fixed_vulns, intel_map, limit=3),
    }


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------


def _briefing_prompt(ctx: Dict[str, object]) -> str:
    """Render the context as a compact prompt for the briefing.

    Kept deliberately short so CPU inference on an 8B model completes in a
    reasonable time (30-60s on modern laptops).
    """
    return (
        "Analyze this patch event. Use ONLY these facts.\n\n"
        f"Service: {ctx['service']} ({ctx['environment']}) — scan ID: {ctx['ami_id']}\n"
        f"Diff: {ctx['counts']['before']} → {ctx['counts']['after']} vulns "
        f"({ctx['counts']['fixed']} fixed, {ctx['effectiveness_pct']}% effective)\n"
        f"Severity after: {ctx['severity_after']}\n"
        f"CISA KEV (actively exploited) before/after: "
        f"{ctx['kev_before']} / {ctx['kev_after']}\n\n"
        "Top remaining CVEs:\n"
        + _format_cve_list(ctx["top_remaining"])  # type: ignore[arg-type]
        + "Top fixed CVEs:\n"
        + _format_cve_list(ctx["top_fixed"])  # type: ignore[arg-type]
        + "\nWrite a short briefing in markdown, in this order:\n"
        f"**Summary**: 2 sentences about {ctx['service']} specifically.\n"
        "**Fixed**: 3 bullets citing CVE IDs, note any KEV.\n"
        "**Still matters**: 3 bullets citing CVE IDs, focus on KEV and high EPSS.\n"
        f"**Next action**: 1 sentence naming {ctx['service']} and the specific CVE or risk to address.\n"
        "**Verdict:** one of LOW / MEDIUM / HIGH / CRITICAL.\n"
    )


def _format_cve_list(cves: List[Dict[str, object]]) -> str:
    if not cves:
        return "- (none)\n"
    lines = []
    for c in cves:
        cvss = c.get("cvss")
        epss = c.get("epss")
        kev = " KEV" if c.get("is_kev") else ""
        cvss_s = f"CVSS {cvss}" if cvss is not None else ""
        epss_s = (
            f"EPSS {epss * 100:.0f}%"
            if isinstance(epss, (int, float))
            else ""
        )
        summary = str(c.get("summary") or "").strip()
        parts = [c["cve"], c["severity"], cvss_s, epss_s, kev]
        head = " ".join(str(p) for p in parts if p)
        lines.append(f"- {head}: {summary}" if summary else f"- {head}")
    return "\n".join(lines) + "\n"



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_patch_briefing(
    db: Session, patch_event: PatchEvent, *, force: bool = False
) -> AIAnalysis:
    """Generate (or refresh) an AI briefing for a patch event.

    Persisted as an :class:`AIAnalysis` row of type ``BRIEFING``. If a briefing
    already exists and ``force`` is False, the cached row is returned.
    """
    if not force:
        existing = (
            db.query(AIAnalysis)
            .filter(
                AIAnalysis.patch_event_id == patch_event.id,
                AIAnalysis.analysis_type == "BRIEFING",
            )
            .order_by(AIAnalysis.created_at.desc())
            .first()
        )
        if existing:
            return existing

    if not is_available():
        raise OllamaError(
            "Local Ollama daemon is not reachable. Install Ollama and run "
            "`ollama pull llama3.1:8b`, then try again."
        )

    ctx = build_context(db, patch_event)
    prompt = _briefing_prompt(ctx)

    started = datetime.utcnow()
    try:
        result: OllamaResult = generate(prompt, system=SYSTEM_PROMPT, temperature=0.2)
    except OllamaError:
        raise

    record = AIAnalysis(
        patch_event_id=patch_event.id,
        analysis_type="BRIEFING",
        model_name=result.model,
        tokens_used=(result.prompt_tokens or 0) + (result.completion_tokens or 0),
        content=result.text,
        structured_data=json.dumps(
            {
                "counts": ctx["counts"],
                "effectiveness_pct": ctx["effectiveness_pct"],
                "kev_before": ctx["kev_before"],
                "kev_after": ctx["kev_after"],
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "duration_ms": result.total_duration_ms,
            }
        ),
        created_at=started,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def answer_question(
    db: Session,
    patch_event: PatchEvent,
    question: str,
    history: Optional[List[Dict[str, str]]] = None,
) -> str:
    """Chat with the AI about a specific patch event.

    ``history`` is an optional list of prior `{"role": ..., "content": ...}`
    messages. The patch context is always injected as a system preamble so the
    model stays grounded.
    """
    if not is_available():
        raise OllamaError(
            "Local Ollama daemon is not reachable. Install Ollama and run "
            "`ollama pull llama3.1:8b`, then try again."
        )

    ctx = build_context(db, patch_event)
    context_preamble = (
        "You are advising on this exact patch event. Stick to these numbers:\n"
        f"{json.dumps({k: ctx[k] for k in ('service', 'environment', 'ami_id', 'patch_date', 'current_state', 'counts', 'effectiveness_pct', 'kev_before', 'kev_after')}, indent=2)}\n\n"
        "Top remaining CVEs:\n"
        + _format_cve_list(ctx["top_remaining"])  # type: ignore[arg-type]
    )

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": context_preamble},
    ]
    if history:
        messages.extend(history[-8:])  # keep last 8 turns
    messages.append({"role": "user", "content": question})

    result = chat(messages, temperature=0.3)
    return result.text


# ---------------------------------------------------------------------------
# Fleet-wide briefing (the hero widget on the home page)
# ---------------------------------------------------------------------------


def _fleet_briefing_prompt(fleet) -> str:
    """Render a compact fleet-wide briefing prompt.

    ``fleet`` is a :class:`app.services.fleet_intel.FleetIntel` instance.
    Kept short for CPU inference; focuses on the numbers a viewer cares about
    when they first load the dashboard.
    """
    lines: List[str] = []
    lines.append(
        "Fleet vulnerability posture for enterprise security tools "
        "(Nessus Manager, Trend Micro, Grafana, Burp Suite, "
        "Tenable Security Center, ServiceNow MID Server)."
    )
    lines.append("")
    lines.append(f"Events: {fleet.total_patch_events} total, "
                 f"{fleet.events_with_evidence} with evidence.")
    lines.append(f"CVEs: {fleet.total_unique_cves} unique "
                 f"({fleet.enriched_cve_count} enriched).")
    lines.append(f"Vulnerabilities: {fleet.total_vulnerabilities} seen, "
                 f"{fleet.total_fixed} fixed, {fleet.total_remaining} remaining "
                 f"({fleet.overall_effectiveness_pct}% effective).")
    lines.append(f"CISA KEV actively-exploited: {fleet.kev_count}")
    lines.append(f"High EPSS (>= 70%): {fleet.high_epss_count}")
    lines.append(f"Critical CVSS (>= 9.0): {fleet.critical_cvss_count}")
    lines.append(f"Severity remaining: {fleet.severity_remaining}")
    lines.append("")

    # Service-level breakdown so the LLM can name specific tools
    if fleet.top_services_by_risk:
        lines.append("Risk by service (name | remaining CVEs | risk score | CISA KEV count):")
        for svc in fleet.top_services_by_risk[:8]:
            kev_note = f" | {svc['kev']} KEV" if svc.get("kev") else ""
            lines.append(
                f"  - {svc['service']}: {svc['remaining']} remaining "
                f"| risk {svc['risk']:.0f}{kev_note}"
            )
        lines.append("")

    lines.append("Top remaining CVEs (ranked by risk):")
    top = fleet.top_exploited or fleet.top_critical_remaining
    for c in top[:6]:
        extras = []
        if c.cvss is not None:
            extras.append(f"CVSS {c.cvss:.1f}")
        if c.epss is not None:
            extras.append(f"EPSS {c.epss * 100:.0f}%")
        if c.is_kev:
            extras.append("CISA KEV — actively exploited")
        head = " ".join(extras)
        desc = (c.description or "").strip()
        line = f"- {c.cve} ({c.severity}) {head}"
        if desc:
            line += f": {desc[:100]}"
        lines.append(line)
    lines.append("")
    lines.append(
        "Write a short fleet briefing in markdown. Use THESE sections, in order:\n"
        "**State of the fleet**: 2 sentences naming the specific services scanned "
        "and their overall CVE exposure.\n"
        "**What matters most right now**: 3 bullets each citing a specific CVE ID, "
        "the affected service, and its CVSS/EPSS score.\n"
        "**Recommended next actions**: 3 bullets each starting with a verb and "
        "naming the specific service or CVE to act on.\n"
        "**Posture verdict:** one of EXCELLENT / GOOD / ELEVATED / CRITICAL.\n"
        "Never say 'EC2 AMI'. Always refer to the service by name.\n"
    )
    return "\n".join(lines)


# Fleet briefings are aggregate (not tied to a specific patch event), so we
# cache them in-process rather than in the AIAnalysis table. Process-level
# cache keeps the dashboard snappy on repeat loads without needing a DB
# migration to make patch_event_id nullable.
_FLEET_BRIEFING_CACHE: Dict[str, object] = {}
_FLEET_BRIEFING_TTL = timedelta(minutes=10)


def generate_fleet_briefing(db: Session, *, force: bool = False) -> Dict[str, object]:
    """Generate a fleet-wide AI briefing for the dashboard hero.

    Cached in-process for 10 minutes so repeat dashboard loads are instant.
    Call with ``force=True`` to regenerate on demand.
    """
    from app.services.fleet_intel import compute_fleet_intel

    cached_at = _FLEET_BRIEFING_CACHE.get("created_at")
    if (
        not force
        and isinstance(cached_at, datetime)
        and datetime.utcnow() - cached_at < _FLEET_BRIEFING_TTL
    ):
        return {**_FLEET_BRIEFING_CACHE, "cached": True}

    if not is_available():
        raise OllamaError(
            "Local Ollama daemon is not reachable. Install Ollama and run "
            "`ollama pull llama3.1:8b`, then try again."
        )

    fleet = compute_fleet_intel(db)
    prompt = _fleet_briefing_prompt(fleet)
    result = generate(prompt, system=SYSTEM_PROMPT, temperature=0.25)

    payload: Dict[str, object] = {
        "content": result.text,
        "model_used": result.model,
        "created_at": datetime.utcnow(),
        "cached": False,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
    }
    _FLEET_BRIEFING_CACHE.update(payload)
    return payload


# ---------------------------------------------------------------------------
# Action-plan narrative
# ---------------------------------------------------------------------------


def generate_action_narrative(
    db: Session,
    patch_event: PatchEvent,
    recommendations,
) -> str:
    """Produce a short Markdown narrative explaining the recommended action plan.

    The action codes themselves come from the deterministic recommender in
    ``app.services.action_planner`` - the LLM only writes prose. Best-effort:
    if Ollama is unavailable, returns an empty string and the caller should
    skip the narrative section.
    """
    if not is_available() or not recommendations:
        return ""

    ctx = build_context(db, patch_event)
    primary = recommendations[0]
    others = recommendations[1:]

    bullet_others = ""
    if others:
        bullet_others = "\nOther available actions:\n" + "\n".join(
            f"- {r.label}: {r.rationale}" for r in others
        )

    prompt = (
        f"Patch event for service `{ctx['service']}` in `{ctx['environment']}`.\n"
        f"Current lifecycle state: `{ctx['current_state']}`.\n"
        f"Patch effectiveness: {ctx['effectiveness_pct']}%, "
        f"{ctx['counts']['fixed']} CVEs fixed, "
        f"{ctx['counts']['after']} remaining.\n"
        f"KEV before: {ctx['kev_before']} -> after: {ctx['kev_after']}.\n\n"
        f"Top remaining CVEs:\n{_format_cve_list(ctx['top_remaining'])}\n\n"
        f"Recommended NEXT action (deterministic, do NOT change it): "
        f"**{primary.label}** -- {primary.rationale}\n"
        f"{bullet_others}\n\n"
        "Write a SHORT, professional briefing in markdown with EXACTLY these "
        "three sections, each one or two sentences:\n"
        "**Where we are**: factual current status.\n"
        "**Why this next step**: why the recommended action is the right "
        "move right now.\n"
        "**What it will do**: what changes when the operator approves it.\n\n"
        "Do NOT recommend any other action. Do NOT invent CVE numbers."
    )

    try:
        result = generate(prompt, system=SYSTEM_PROMPT, temperature=0.2)
        return result.text.strip()
    except OllamaError as exc:
        logger.info("Action narrative skipped: %s", exc)
        return ""
