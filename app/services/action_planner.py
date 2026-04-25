"""Action planner for guided, AI-recommended patch lifecycle automation.

The dashboard's AI agent is *advisory only* - it can read the patch event,
explain the risk picture, and recommend a next step, but it cannot mutate
state on its own. Every action requires explicit user approval.

This module is the single source of truth for:

1. **What actions are possible** at all (the action catalog).
2. **What is recommended next** given the patch event's current state and
   evidence (a deterministic recommender driven by the existing state
   machine in ``app.state``).
3. **How to execute an approved action** (``execute_action``) which mutates
   the database in exactly the same way the corresponding manual route
   does, and records an :class:`AIAnalysis` audit row.

The LLM never picks action codes - those come from the deterministic
recommender. The LLM only writes the human-readable *narrative* explaining
why each step is recommended, so it cannot trigger a forbidden transition
even if it hallucinates.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import AIAnalysis, PatchEvent, ScanSnapshot, SnapshotType, Vulnerability
from app.services.cr_text import build_prod_cr_text, build_stage_cr_text
from app.services.cve_enrichment import compute_risk_score, get_intel_map
from app.services.diff import (
    compute_fixed_vulnerabilities,
    count_by_severity,
    extract_before_after_vulnerabilities,
)
from app.services.synthetic_data import (
    generate_after_snapshot,
    generate_before_snapshot,
)
from app.state import (
    CLOSED,
    DEV_EVIDENCE_CAPTURED,
    DEV_VERIFIED,
    PROD_CR_READY,
    PROD_PATCHED,
    STAGE_CR_READY,
    STAGE_PATCHED,
    get_state_for_event,
    transition_patch_event,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionDef:
    """Static description of an action the AI can recommend."""

    code: str
    label: str  # Short button text, e.g. "Generate STAGE CR"
    description: str  # Longer explanation of what it does
    risk: str  # 'safe' | 'standard' | 'high'  - drives UI styling
    requires_confirm: bool = False


# All canonical action codes. Anything outside this dict will be rejected
# by ``execute_action``, so a hallucinating LLM can only suggest known,
# safe operations.
ACTION_CATALOG: Dict[str, ActionDef] = {
    "GENERATE_BEFORE": ActionDef(
        code="GENERATE_BEFORE",
        label="Run BEFORE Scan",
        description="Generate the pre-patch synthetic vulnerability snapshot.",
        risk="safe",
    ),
    "GENERATE_AFTER": ActionDef(
        code="GENERATE_AFTER",
        label="Run AFTER Scan",
        description="Generate the post-patch synthetic vulnerability snapshot to "
                    "verify what was actually fixed.",
        risk="safe",
    ),
    "COMPUTE_EVIDENCE": ActionDef(
        code="COMPUTE_EVIDENCE",
        label="Compute DEV Evidence",
        description="Diff BEFORE vs AFTER scans and mark DEV evidence as captured.",
        risk="safe",
    ),
    "TRANSITION_DEV_VERIFIED": ActionDef(
        code="TRANSITION_DEV_VERIFIED",
        label="Mark DEV Verified",
        description="Acknowledge that the patch is verified in DEV and ready for "
                    "promotion to STAGE.",
        risk="standard",
    ),
    "GENERATE_STAGE_CR": ActionDef(
        code="GENERATE_STAGE_CR",
        label="Auto-Generate STAGE CR",
        description="Build the STAGE Change Request narrative from real evidence "
                    "(fixed CVEs, severity, affected services).",
        risk="standard",
    ),
    "TRANSITION_STAGE_PATCHED": ActionDef(
        code="TRANSITION_STAGE_PATCHED",
        label="Mark STAGE Patched",
        description="Record that the STAGE rollout completed successfully.",
        risk="standard",
    ),
    "GENERATE_PROD_CR": ActionDef(
        code="GENERATE_PROD_CR",
        label="Auto-Generate PROD CR",
        description="Build the PRODUCTION Change Request narrative referencing "
                    "the STAGE rollout and AFTER-scan evidence.",
        risk="standard",
    ),
    "TRANSITION_PROD_PATCHED": ActionDef(
        code="TRANSITION_PROD_PATCHED",
        label="Mark PROD Patched",
        description="Record that the production rollout completed successfully.",
        risk="high",
        requires_confirm=True,
    ),
    "TRANSITION_CLOSED": ActionDef(
        code="TRANSITION_CLOSED",
        label="Close Patch Event",
        description="Move the patch event to the terminal CLOSED state.",
        risk="standard",
    ),
}


# ---------------------------------------------------------------------------
# Recommender (deterministic, source of truth)
# ---------------------------------------------------------------------------


@dataclass
class RecommendedAction:
    code: str
    label: str
    description: str
    risk: str
    requires_confirm: bool
    rationale: str  # One-sentence explanation of *why* this is the next step
    is_primary: bool = False  # True for the single most-recommended action


def _has_snapshot(event: PatchEvent, kind: SnapshotType) -> bool:
    return any(s.snapshot_type == kind for s in event.snapshots)


def recommend_next_actions(event: PatchEvent) -> List[RecommendedAction]:
    """Return an ordered list of recommended actions for a patch event.

    The first item in the list is the "primary" recommendation - the single
    action a user should usually click. Additional items are reasonable
    alternatives the operator might want (e.g. re-running the AFTER scan).

    This is purely state-machine driven: no LLM involvement, so it can
    never recommend something the lifecycle disallows.
    """
    has_before = _has_snapshot(event, SnapshotType.BEFORE)
    has_after = _has_snapshot(event, SnapshotType.AFTER)
    has_evidence = bool(event.dev_evidence_available)
    state_code = event.current_state_code

    recs: List[RecommendedAction] = []

    def add(code: str, rationale: str, *, primary: bool = False) -> None:
        a = ACTION_CATALOG[code]
        recs.append(
            RecommendedAction(
                code=a.code,
                label=a.label,
                description=a.description,
                risk=a.risk,
                requires_confirm=a.requires_confirm,
                rationale=rationale,
                is_primary=primary,
            )
        )

    # Pre-flight: missing scans / evidence
    if not has_before:
        add(
            "GENERATE_BEFORE",
            "No BEFORE scan exists yet. We need it to know what was vulnerable "
            "before patching.",
            primary=True,
        )
        return recs
    if not has_after:
        add(
            "GENERATE_AFTER",
            "BEFORE scan exists but the patch hasn't been verified - run an "
            "AFTER scan to see what's actually fixed.",
            primary=True,
        )
        # Allow a manual evidence recompute as a secondary option.
        return recs
    if not has_evidence:
        add(
            "COMPUTE_EVIDENCE",
            "Both scans exist but evidence hasn't been computed. Run the diff "
            "to confirm what was fixed.",
            primary=True,
        )
        return recs

    # Lifecycle progression
    if state_code == DEV_EVIDENCE_CAPTURED:
        add(
            "TRANSITION_DEV_VERIFIED",
            "Evidence is captured. Acknowledge DEV verification so the patch "
            "can be promoted to STAGE.",
            primary=True,
        )
    elif state_code == DEV_VERIFIED:
        add(
            "GENERATE_STAGE_CR",
            "DEV is verified. Auto-build the STAGE CR using the real fixed-CVE "
            "evidence, then advance to STAGE_CR_READY automatically.",
            primary=True,
        )
    elif state_code == STAGE_CR_READY:
        add(
            "TRANSITION_STAGE_PATCHED",
            "STAGE CR is ready. After the STAGE rollout completes, mark STAGE "
            "as patched here.",
            primary=True,
        )
    elif state_code == STAGE_PATCHED:
        add(
            "GENERATE_PROD_CR",
            "STAGE is patched. Auto-build the PROD CR referencing the STAGE "
            "rollout and AFTER-scan evidence.",
            primary=True,
        )
        add(
            "GENERATE_AFTER",
            "Optionally re-run an AFTER scan to refresh post-patch evidence "
            "before PROD.",
        )
    elif state_code == PROD_CR_READY:
        add(
            "TRANSITION_PROD_PATCHED",
            "PROD CR is ready and approved. Once production rollout completes, "
            "mark PROD as patched.",
            primary=True,
        )
    elif state_code == PROD_PATCHED:
        add(
            "TRANSITION_CLOSED",
            "Production is patched. Close this patch event to lock the "
            "lifecycle.",
            primary=True,
        )
    elif state_code == CLOSED:
        # Terminal - no further actions.
        pass

    return recs


# ---------------------------------------------------------------------------
# Executors - one per action code
# ---------------------------------------------------------------------------


class ActionExecutionError(Exception):
    """Raised when an approved action cannot be executed."""


ExecutorResult = Dict[str, str]


def _exec_generate_before(db: Session, event: PatchEvent) -> ExecutorResult:
    if _has_snapshot(event, SnapshotType.BEFORE):
        raise ActionExecutionError("BEFORE snapshot already exists.")
    generate_before_snapshot(db, event)
    return {"message": "Synthetic BEFORE snapshot generated."}


def _exec_generate_after(db: Session, event: PatchEvent) -> ExecutorResult:
    if not _has_snapshot(event, SnapshotType.BEFORE):
        raise ActionExecutionError(
            "Cannot generate AFTER snapshot before BEFORE exists."
        )
    if _has_snapshot(event, SnapshotType.AFTER):
        raise ActionExecutionError("AFTER snapshot already exists.")
    generate_after_snapshot(db, event)
    return {"message": "Synthetic AFTER snapshot generated."}


def _split_before_after(event: PatchEvent):
    """Return (before_vulns, after_vulns) lists for a patch event."""
    grouped = extract_before_after_vulnerabilities(event.snapshots)
    return (
        grouped.get(SnapshotType.BEFORE, []),
        grouped.get(SnapshotType.AFTER, []),
    )


def _exec_compute_evidence(db: Session, event: PatchEvent) -> ExecutorResult:
    before, after = _split_before_after(event)
    if not before or not after:
        raise ActionExecutionError(
            "Both BEFORE and AFTER snapshots are required to compute evidence."
        )
    fixed = compute_fixed_vulnerabilities(before, after)
    event.dev_evidence_available = True
    db.commit()
    return {
        "message": f"DEV evidence captured ({len(fixed)} CVEs fixed).",
    }


def _exec_transition(target: str) -> Callable[[Session, PatchEvent], ExecutorResult]:
    """Build an executor that transitions the patch event to ``target``."""

    def _run(db: Session, event: PatchEvent) -> ExecutorResult:
        try:
            transition_patch_event(event, target)
        except ValueError as exc:
            raise ActionExecutionError(str(exc)) from exc
        db.commit()
        return {"message": f"State advanced to {target}."}

    return _run


def _build_cr_inputs(event: PatchEvent):
    """Compute (fixed_vulnerabilities, severity_counts) for CR generation."""
    before, after = _split_before_after(event)
    fixed = compute_fixed_vulnerabilities(before, after) if before and after else []
    counts = count_by_severity(fixed)
    return fixed, counts


def _exec_generate_stage_cr(db: Session, event: PatchEvent) -> ExecutorResult:
    if not event.dev_evidence_available:
        raise ActionExecutionError(
            "Cannot build STAGE CR without DEV evidence."
        )
    fixed, counts = _build_cr_inputs(event)
    text = build_stage_cr_text(event, fixed, counts)
    event.stage_cr_summary = text
    # Auto-advance lifecycle if currently DEV_VERIFIED -> STAGE_CR_READY.
    state = get_state_for_event(event)
    if STAGE_CR_READY in state.allowed_transitions(event):
        try:
            transition_patch_event(event, STAGE_CR_READY)
        except ValueError:
            logger.info("STAGE CR generated but state did not advance.")
    db.commit()
    return {"message": f"STAGE CR generated ({len(fixed)} fixed CVEs)."}


def _exec_generate_prod_cr(db: Session, event: PatchEvent) -> ExecutorResult:
    allowed = {STAGE_PATCHED, PROD_CR_READY, PROD_PATCHED, CLOSED}
    if event.current_state_code not in allowed:
        raise ActionExecutionError(
            "PROD CR can only be generated once STAGE has been patched."
        )
    fixed, counts = _build_cr_inputs(event)
    text = build_prod_cr_text(event, fixed, counts)
    event.prod_cr_summary = text
    state = get_state_for_event(event)
    if PROD_CR_READY in state.allowed_transitions(event):
        try:
            transition_patch_event(event, PROD_CR_READY)
        except ValueError:
            logger.info("PROD CR generated but state did not advance.")
    db.commit()
    return {"message": f"PROD CR generated ({len(fixed)} fixed CVEs)."}


# Dispatch table - the only way an action code becomes a side-effect.
EXECUTORS: Dict[str, Callable[[Session, PatchEvent], ExecutorResult]] = {
    "GENERATE_BEFORE": _exec_generate_before,
    "GENERATE_AFTER": _exec_generate_after,
    "COMPUTE_EVIDENCE": _exec_compute_evidence,
    "TRANSITION_DEV_VERIFIED": _exec_transition(DEV_VERIFIED),
    "GENERATE_STAGE_CR": _exec_generate_stage_cr,
    "TRANSITION_STAGE_PATCHED": _exec_transition(STAGE_PATCHED),
    "GENERATE_PROD_CR": _exec_generate_prod_cr,
    "TRANSITION_PROD_PATCHED": _exec_transition(PROD_PATCHED),
    "TRANSITION_CLOSED": _exec_transition(CLOSED),
}


def execute_action(
    db: Session,
    event: PatchEvent,
    action_code: str,
    *,
    approved_by: str = "user",
) -> ExecutorResult:
    """Run an approved action and write an audit log row.

    Raises :class:`ActionExecutionError` for unknown codes, disallowed
    transitions, or missing prerequisites. Callers should translate this
    into a 4xx response.
    """
    if action_code not in ACTION_CATALOG:
        raise ActionExecutionError(f"Unknown action code: {action_code}")
    if action_code not in EXECUTORS:
        raise ActionExecutionError(
            f"Action {action_code} has no executor wired up."
        )

    # Verify the action is currently a recommended option. Without this,
    # a malicious or stale UI could approve any action at any time.
    valid_codes = {r.code for r in recommend_next_actions(event)}
    if action_code not in valid_codes:
        raise ActionExecutionError(
            f"Action {action_code} is not currently recommended for this "
            f"patch event (state={event.current_state_code})."
        )

    state_before = event.current_state_code
    result = EXECUTORS[action_code](db, event)
    state_after = event.current_state_code
    result.setdefault("state_before", state_before)
    result.setdefault("state_after", state_after)

    # Audit log
    audit = AIAnalysis(
        patch_event_id=event.id,
        analysis_type="ACTION_APPROVED",
        model_name="action_planner",
        tokens_used=0,
        content=f"Approved by {approved_by}: {action_code}",
        structured_data=json.dumps(
            {
                "action_code": action_code,
                "approved_by": approved_by,
                "state_before": state_before,
                "state_after": state_after,
                "result": {k: v for k, v in result.items() if k != "state_before" and k != "state_after"},
            }
        ),
        created_at=datetime.utcnow(),
    )
    db.add(audit)
    db.commit()
    return result


# ---------------------------------------------------------------------------
# Convenience: full plan with optional LLM narrative
# ---------------------------------------------------------------------------


def build_action_plan(
    db: Session,
    event: PatchEvent,
    *,
    include_narrative: bool = False,
) -> Dict[str, object]:
    """Return the full plan payload for the UI.

    Always returns the deterministic recommendations. If ``include_narrative``
    is True, also asks the LLM for a short Markdown narrative explaining the
    overall situation. The LLM call is best-effort - if Ollama is down, the
    narrative is omitted but the plan still renders.
    """
    recommendations = recommend_next_actions(event)
    narrative: Optional[str] = None

    if include_narrative and recommendations:
        try:
            from app.services.ai_agent import generate_action_narrative
            narrative = generate_action_narrative(db, event, recommendations)
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to generate AI narrative; falling back.")
            narrative = None

    return {
        "current_state": event.current_state_code,
        "recommendations": [r.__dict__ for r in recommendations],
        "narrative": narrative,
        "is_terminal": event.current_state_code == CLOSED,
    }


# ---------------------------------------------------------------------------
# Per-action metrics (BEFORE/AFTER/FIXED + AMI + hosts + remaining priorities)
# ---------------------------------------------------------------------------


def _safe_severity(v: Vulnerability) -> str:
    try:
        return v.severity.value
    except AttributeError:
        return str(v.severity)


def _compute_metrics(db: Session, event: PatchEvent) -> Dict[str, object]:
    """Return a dict of human-readable metrics for one patch event.

    These power the rich pre-action ("can I proceed?") and post-action
    ("here's what happened") cards. Everything is derived from existing
    snapshots and the public CVE intel cache - no LLM in this function.
    """
    before, after = _split_before_after(event)
    fixed = compute_fixed_vulnerabilities(before, after) if before and after else []

    before_count = len(before)
    after_count = len(after)
    fixed_count = len(fixed)
    effectiveness = round((fixed_count / before_count) * 100, 1) if before_count else 0.0

    # Distinct hosts the scan touched. Falls back gracefully if either
    # snapshot is empty.
    hosts: set = set()
    for v in (before or []):
        if v.host:
            hosts.add(v.host)
    for v in (after or []):
        if v.host:
            hosts.add(v.host)

    # Top remaining vulnerabilities ranked by composite KEV+EPSS+CVSS.
    remaining_cves = sorted({v.cve for v in (after or []) if v.cve})
    intel_map = get_intel_map(db, remaining_cves) if remaining_cves else {}

    # Build (cve, intel, occurrences, max_severity, hosts_for_cve)
    occurrence: Dict[str, Dict[str, object]] = {}
    for v in (after or []):
        if not v.cve:
            continue
        slot = occurrence.setdefault(
            v.cve,
            {"hosts": set(), "severity": _safe_severity(v), "description": v.description or ""},
        )
        if v.host:
            slot["hosts"].add(v.host)

    ranked: List[Dict[str, object]] = []
    for cve, slot in occurrence.items():
        intel = intel_map.get(cve)
        ranked.append(
            {
                "cve": cve,
                "severity": slot["severity"],
                "description": (slot["description"] or "")[:160],
                "hosts": len(slot["hosts"]),
                "kev": bool(intel and intel.is_kev),
                "epss": float(intel.epss_score) if intel and intel.epss_score is not None else None,
                "cvss": float(intel.cvss_v3_score) if intel and intel.cvss_v3_score is not None else None,
                "risk": compute_risk_score(intel),
            }
        )
    ranked.sort(key=lambda r: r["risk"], reverse=True)

    # Severity tally on remaining for quick eyeball.
    severity_remaining = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in ranked:
        sev = r["severity"]
        if sev in severity_remaining:
            severity_remaining[sev] += 1

    return {
        "service": event.service.name if event.service else "(unknown)",
        "environment": (
            event.environment.value if hasattr(event.environment, "value") else str(event.environment)
        ),
        "ami_id": event.ami_id,
        "patch_date": event.patch_date.isoformat() if event.patch_date else None,
        "current_state": event.current_state_code,
        "host_count": len(hosts),
        "before_count": before_count,
        "after_count": after_count,
        "fixed_count": fixed_count,
        "effectiveness_pct": effectiveness,
        "severity_remaining": severity_remaining,
        "top_remaining": ranked[:5],
        "kev_remaining": sum(1 for r in ranked if r["kev"]),
    }


def _build_recommendations_for_remaining(metrics: Dict[str, object]) -> List[str]:
    """Plain-English bullet recommendations for the highest-risk remaining
    CVEs after a patch. Pure templating, no LLM."""
    bullets: List[str] = []
    top = metrics.get("top_remaining") or []
    if not top:
        bullets.append("No remaining CVEs detected on the scanned hosts. Consider closing the patch event.")
        return bullets

    if metrics.get("kev_remaining"):
        bullets.append(
            f"{metrics['kev_remaining']} CISA KEV CVE(s) still present - prioritise these before promoting further."
        )

    for r in top[:3]:
        flags = []
        if r.get("kev"):
            flags.append("KEV")
        if r.get("epss") is not None and r["epss"] >= 0.7:
            flags.append(f"EPSS {int(r['epss']*100)}%")
        if r.get("cvss") is not None and r["cvss"] >= 9.0:
            flags.append(f"CVSS {r['cvss']}")
        flag_text = (" [" + ", ".join(flags) + "]") if flags else ""
        bullets.append(
            f"{r['cve']}{flag_text}: still on {r['hosts']} host(s) - schedule a follow-up patch or mitigation."
        )
    return bullets


def build_action_preview(
    db: Session,
    event: PatchEvent,
    action_code: str,
) -> Dict[str, object]:
    """Build the rich pre-action approval payload.

    Used by the "Are you sure?" card the operator sees before clicking
    Confirm. Surfaces AMI, environment, hosts touched, current
    effectiveness, and which CVEs are still outstanding.
    """
    if action_code not in ACTION_CATALOG:
        raise ActionExecutionError(f"Unknown action code: {action_code}")

    valid = {r.code: r for r in recommend_next_actions(event)}
    if action_code not in valid:
        raise ActionExecutionError(
            f"Action {action_code} is not currently a recommended next step."
        )

    action_def = ACTION_CATALOG[action_code]
    rec = valid[action_code]
    metrics = _compute_metrics(db, event)

    question = (
        f"I'm about to **{action_def.label}** for service "
        f"`{metrics['service']}` running AMI `{metrics['ami_id']}` in the "
        f"`{metrics['environment']}` environment "
        f"({metrics['host_count']} host(s) scanned, "
        f"{metrics['effectiveness_pct']}% patch effectiveness so far). "
        f"Proceed?"
    )

    return {
        "action": {
            "code": action_def.code,
            "label": action_def.label,
            "description": action_def.description,
            "risk": action_def.risk,
            "requires_confirm": action_def.requires_confirm,
            "rationale": rec.rationale,
        },
        "metrics": metrics,
        "question": question,
    }


def build_action_result(
    db: Session,
    event: PatchEvent,
    action_code: str,
    executor_message: str,
    *,
    state_before: str,
    state_after: str,
) -> Dict[str, object]:
    """Build the rich post-action result payload.

    Shown after the operator confirms an action. Reports BEFORE / AFTER /
    FIXED counts, the lifecycle transition that just happened, and
    ranked recommendations for the highest-risk remaining CVEs.
    """
    metrics = _compute_metrics(db, event)
    action_def = ACTION_CATALOG.get(action_code)
    return {
        "action": {
            "code": action_code,
            "label": action_def.label if action_def else action_code,
        },
        "executor_message": executor_message,
        "state_before": state_before,
        "state_after": state_after,
        "state_changed": state_before != state_after,
        "metrics": metrics,
        "recommendations": _build_recommendations_for_remaining(metrics),
    }
