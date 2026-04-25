from datetime import date
from typing import Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Environment, PatchEvent, Service, SnapshotType
from app.services.ai_agent import (
    answer_question,
    generate_fleet_briefing,
    generate_patch_briefing,
)
from app.services.action_planner import (
    ACTION_CATALOG,
    ActionExecutionError,
    build_action_plan,
    build_action_preview,
    build_action_result,
    execute_action,
)
from app.services.fleet_intel import compute_fleet_intel
from app.services.cr_text import build_prod_cr_text, build_stage_cr_text
from app.services.cve_enrichment import (
    compute_risk_score,
    enrich_cves_bulk,
    get_intel_map,
)
from app.services.ollama_client import (
    OLLAMA_MODEL,
    OllamaError,
    is_available as ollama_available,
    list_models as ollama_list_models,
    warmup as ollama_warmup,
)
from app.services.diff import (
    compute_fixed_vulnerabilities,
    compute_remaining_vulnerabilities,
    count_by_severity,
    extract_before_after_vulnerabilities,
)
from app.services.synthetic_data import (
    generate_after_snapshot,
    generate_before_snapshot,
)
from app.state import get_state_for_event, transition_patch_event

router = APIRouter()

templates = Jinja2Templates(directory="templates")


def _build_intel_context(db: Session, *vuln_lists) -> Dict[str, object]:
    """Collect enrichment data for one or more vulnerability lists.

    Returns a dict with:
    - intel_map: {cve_id: CVEIntelligence}
    - risk_scores: {cve_id: float (0-100)}
    - kev_count: number of vulns that are on the CISA KEV list
    - high_epss_count: number of vulns with EPSS >= 0.5
    """
    all_cves: List[str] = []
    for vulns in vuln_lists:
        for v in vulns or []:
            if getattr(v, "cve", None):
                all_cves.append(v.cve)

    intel_map = get_intel_map(db, all_cves)
    risk_scores = {
        cve_id: compute_risk_score(intel)
        for cve_id, intel in intel_map.items()
    }

    kev_count = sum(1 for intel in intel_map.values() if intel.is_kev)
    high_epss_count = sum(
        1
        for intel in intel_map.values()
        if intel.epss_score is not None and intel.epss_score >= 0.5
    )

    return {
        "intel_map": intel_map,
        "risk_scores": risk_scores,
        "kev_count": kev_count,
        "high_epss_count": high_epss_count,
    }


def _run_full_dev_pipeline(db: Session, patch_event: PatchEvent) -> Dict[str, bool]:
    """Drive a brand-new patch event through the entire deterministic
    DEV pipeline in one shot, no human clicks required.

    Steps run, in order, each guarded so a partial failure still lets
    the page render:
      1. Generate synthetic BEFORE snapshot (if missing)
      2. Generate synthetic AFTER snapshot  (if missing)
      3. Diff -> mark ``dev_evidence_available = True``
      4. Build & persist STAGE CR text (idempotent)

    Anything genuinely needing human approval (state-machine transitions
    into STAGE_PATCHED / PROD_PATCHED) is intentionally left for the
    operator. Returns a small dict so callers / tests can see what ran.
    """
    result: Dict[str, bool] = {
        "before_generated": False,
        "after_generated": False,
        "evidence_marked": False,
        "stage_cr_built": False,
    }

    has_before = any(
        s.snapshot_type == SnapshotType.BEFORE for s in patch_event.snapshots
    )
    has_after = any(
        s.snapshot_type == SnapshotType.AFTER for s in patch_event.snapshots
    )

    if not has_before:
        generate_before_snapshot(db, patch_event)
        result["before_generated"] = True
    if not has_after:
        generate_after_snapshot(db, patch_event)
        result["after_generated"] = True

    # Refresh so the new snapshots are visible on the relationship.
    db.refresh(patch_event)
    snapshots = list(patch_event.snapshots)
    split = extract_before_after_vulnerabilities(snapshots)
    before_vulns = split[SnapshotType.BEFORE]
    after_vulns = split[SnapshotType.AFTER]

    if before_vulns and after_vulns:
        fixed_vulnerabilities = compute_fixed_vulnerabilities(
            before_vulns, after_vulns
        )
        if not patch_event.dev_evidence_available:
            patch_event.dev_evidence_available = True
            result["evidence_marked"] = True

        # Auto-build STAGE CR text the moment evidence is available so
        # the user never has to click "Generate STAGE CR" manually.
        if not patch_event.stage_cr_summary:
            severity_counts = count_by_severity(fixed_vulnerabilities)
            patch_event.stage_cr_summary = build_stage_cr_text(
                patch_event,
                fixed_vulnerabilities,
                severity_counts,
            )
            result["stage_cr_built"] = True

        db.add(patch_event)
        db.commit()

    return result


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    service_id: Optional[str] = None,
    environment: Optional[str] = None,
    state: Optional[str] = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    services = db.query(Service).order_by(Service.name).all()

    # Normalize empty strings -> None
    service_id = service_id or None
    environment = environment or None
    state = state or None

    # Convert service_id to int if present
    service_id_int: Optional[int] = None
    if service_id is not None:
        try:
            service_id_int = int(service_id)
        except ValueError:
            service_id_int = None  # ignore bad input rather than 422

    # Convert environment to Environment enum if present
    environment_enum: Optional[Environment] = None
    if environment is not None:
        try:
            environment_enum = Environment(environment)
        except ValueError:
            environment_enum = None  # ignore bad input rather than 422

    query = db.query(PatchEvent).join(Service)

    if service_id_int is not None:
        query = query.filter(PatchEvent.service_id == service_id_int)
    if environment_enum is not None:
        query = query.filter(PatchEvent.environment == environment_enum)
    if state is not None:
        query = query.filter(PatchEvent.current_state_code == state)

    patch_events = query.order_by(PatchEvent.patch_date.desc()).all()

    # Simple summary metrics for dashboard stats cards
    total_events = len(patch_events)
    dev_events = sum(
        1 for e in patch_events if e.environment == Environment.DEV
    )
    stage_events = sum(
        1 for e in patch_events if e.environment == Environment.STAGE
    )
    prod_events = sum(
        1 for e in patch_events if e.environment == Environment.PROD
    )

    dev_phase_events = sum(
        1 for e in patch_events if e.current_state_code.startswith("DEV")
    )
    stage_phase_events = sum(
        1 for e in patch_events if e.current_state_code.startswith("STAGE")
    )
    prod_phase_events = sum(
        1 for e in patch_events if e.current_state_code.startswith("PROD")
    )
    closed_events = sum(
        1 for e in patch_events
        if e.current_state_code == "CLOSED"
    )

    state_options = [
        "DEV_EVIDENCE_CAPTURED",
        "DEV_VERIFIED",
        "STAGE_CR_READY",
        "STAGE_PATCHED",
        "PROD_CR_READY",
        "PROD_PATCHED",
        "CLOSED",
    ]

    # Fleet-wide threat intelligence aggregation. This is the headline
    # content of the new dashboard: real CVSS / EPSS / KEV numbers rolled
    # up across every patch event so the first thing a viewer sees is the
    # overall vulnerability posture, not a list of transactional rows.
    fleet = compute_fleet_intel(db)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "services": services,
            "patch_events": patch_events,
            "selected_service_id": service_id_int,
            "selected_environment": (
                environment_enum.value if environment_enum else None
            ),
            "selected_state": state,
            "state_options": state_options,
            "environment_options": [env.value for env in Environment],
            # Summary metrics
            "total_events": total_events,
            "dev_events": dev_events,
            "stage_events": stage_events,
            "prod_events": prod_events,
            "dev_phase_events": dev_phase_events,
            "stage_phase_events": stage_phase_events,
            "prod_phase_events": prod_phase_events,
            "closed_events": closed_events,
            # Fleet-wide vulnerability intelligence
            "fleet": fleet,
        },
    )


@router.get("/patch-events/new", response_class=HTMLResponse)
def new_patch_event(
    request: Request,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    services = db.query(Service).order_by(Service.name).all()

    return templates.TemplateResponse(
        "patch_event_detail.html",
        {
            "request": request,
            "patch_event": None,
            "services": services,
            "environment_options": [env.value for env in Environment],
            "is_new": True,
        },
    )


@router.post("/patch-events")
def create_patch_event(
    request: Request,
    service_id: int = Form(...),
    environment: Environment = Form(...),
    ami_id: str = Form(...),
    patch_date: date = Form(...),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Create a patch event and auto-materialize the full evidence workflow.

    Previously the user had to click Generate BEFORE, Generate AFTER, and
    Compute sequentially. The new AI-powered workflow does this in one shot:
    - Generate BEFORE snapshot
    - Generate AFTER snapshot
    - Mark DEV evidence available
    - Kick off CVE threat-intel enrichment in the background

    By the time the detail page renders, the user sees a fully analyzed event
    with real NVD/EPSS/KEV data, ready for AI briefing generation. This is
    the "log in and see it work" experience the demo is built around.
    """
    import threading

    from app.database import SessionLocal

    service = db.query(Service).filter(Service.id == service_id).first()
    if service is None:
        raise HTTPException(status_code=400, detail="Invalid service selected")

    patch_event = PatchEvent(
        service_id=service_id,
        environment=environment,
        ami_id=ami_id,
        patch_date=patch_date,
        notes=notes,
    )
    db.add(patch_event)
    db.commit()
    db.refresh(patch_event)

    # Run the *entire* DEV pipeline up to STAGE-CR generation in one shot
    # so the user lands on a fully populated detail page. The previous
    # version stopped after AFTER, leaving the user to click Compute and
    # Generate STAGE CR manually.
    try:
        _run_full_dev_pipeline(db, patch_event)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Auto-pipeline failed for new patch event %s: %s",
            patch_event.id,
            exc,
        )

    # Fire-and-forget CVE enrichment so NVD/EPSS/KEV data is ready by the
    # time the detail page's async badges render. Uses a fresh DB session
    # because the request session closes when this handler returns.
    patch_event_id = patch_event.id

    def _enrich_in_bg() -> None:
        session = SessionLocal()
        try:
            pe = (
                session.query(PatchEvent)
                .filter(PatchEvent.id == patch_event_id)
                .first()
            )
            if not pe:
                return
            cves: List[str] = []
            for snap in pe.snapshots:
                for v in snap.vulnerabilities:
                    if v.cve:
                        cves.append(v.cve)
            if cves:
                enrich_cves_bulk(session, cves, force_refresh=False)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Background enrichment failed: %s", exc)
        finally:
            session.close()

    threading.Thread(target=_enrich_in_bg, daemon=True).start()

    url = request.url_for(
        "get_patch_event_detail",
        patch_event_id=patch_event.id,
    )
    return RedirectResponse(url=url, status_code=303)


@router.get(
    "/patch-events/{patch_event_id}",
    response_class=HTMLResponse,
    name="get_patch_event_detail",
)
def get_patch_event_detail(
    request: Request,
    patch_event_id: int,
    message: Optional[str] = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    services = db.query(Service).order_by(Service.name).all()

    snapshots = list(patch_event.snapshots)
    split = extract_before_after_vulnerabilities(snapshots)
    before_vulns = split[SnapshotType.BEFORE]
    after_vulns = split[SnapshotType.AFTER]

    before_count = len(before_vulns)
    after_count = len(after_vulns)

    fixed_vulnerabilities: List = []
    severity_counts: Dict = {}
    before_severity_counts: Dict = {}
    after_severity_counts: Dict = {}

    if before_vulns:
        before_severity_counts = count_by_severity(before_vulns)
    if after_vulns:
        after_severity_counts = count_by_severity(after_vulns)

    if patch_event.dev_evidence_available and before_vulns and after_vulns:
        fixed_vulnerabilities = compute_fixed_vulnerabilities(
            before_vulns,
            after_vulns,
        )
        severity_counts = count_by_severity(fixed_vulnerabilities)

    state_obj = get_state_for_event(patch_event)
    allowed_next_states = state_obj.allowed_transitions(patch_event)

    prod_cr_allowed_states = {
        "STAGE_PATCHED",
        "PROD_CR_READY",
        "PROD_PATCHED",
        "CLOSED",
    }
    prod_cr_allowed = patch_event.current_state_code in prod_cr_allowed_states

    intel_ctx = _build_intel_context(
        db, before_vulns, after_vulns, fixed_vulnerabilities
    )

    # ------------------------------------------------------------------
    # Chart-friendly data for the patch event detail analytics panel.
    # Computed here (not in the template) so Jinja stays simple and the
    # Python is testable. All structures are JSON-safe primitives.
    # ------------------------------------------------------------------
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def _sev_dict_to_list(counts: Dict) -> List[int]:
        # ``counts`` keys may be Severity enums; normalise to strings.
        as_str = {
            (k.value if hasattr(k, "value") else str(k)): v
            for k, v in (counts or {}).items()
        }
        return [int(as_str.get(sev, 0)) for sev in severity_order]

    # Aggregate after-vulnerabilities per CVE so each CVE appears once
    # in the top-remaining bar chart, with its host count and risk score.
    after_by_cve: Dict[str, Dict] = {}
    for v in after_vulns:
        if not v.cve:
            continue
        slot = after_by_cve.setdefault(
            v.cve,
            {
                "cve": v.cve,
                "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                "hosts": set(),
                "risk": float(intel_ctx["risk_scores"].get(v.cve, 0.0)),
            },
        )
        if v.host:
            slot["hosts"].add(v.host)

    top_remaining_chart = sorted(
        (
            {
                "cve": s["cve"],
                "severity": s["severity"],
                "hosts": len(s["hosts"]),
                "risk": round(s["risk"], 1),
            }
            for s in after_by_cve.values()
        ),
        key=lambda r: r["risk"],
        reverse=True,
    )[:8]

    chart_data = {
        "severity_order": severity_order,
        "before_severity": _sev_dict_to_list(before_severity_counts),
        "after_severity": _sev_dict_to_list(after_severity_counts),
        "fixed_severity": _sev_dict_to_list(severity_counts),
        "fixed_count": len(fixed_vulnerabilities),
        "remaining_count": after_count,
        "before_count": before_count,
        "effectiveness_pct": (
            round((len(fixed_vulnerabilities) / before_count) * 100, 1)
            if before_count else 0.0
        ),
        "top_remaining": top_remaining_chart,
    }

    # Lifecycle pipeline: ordered list of stages with status flags.
    lifecycle_stages_order = [
        ("DEV_EVIDENCE_CAPTURED", "Evidence"),
        ("DEV_VERIFIED", "DEV Verified"),
        ("STAGE_CR_READY", "STAGE CR"),
        ("STAGE_PATCHED", "STAGE Patched"),
        ("PROD_CR_READY", "PROD CR"),
        ("PROD_PATCHED", "PROD Patched"),
        ("CLOSED", "Closed"),
    ]
    current_idx = next(
        (i for i, (code, _) in enumerate(lifecycle_stages_order)
         if code == patch_event.current_state_code),
        0,
    )
    lifecycle_pipeline = [
        {
            "code": code,
            "label": label,
            "status": (
                "completed" if i < current_idx
                else "current" if i == current_idx
                else "upcoming"
            ),
        }
        for i, (code, label) in enumerate(lifecycle_stages_order)
    ]

    return templates.TemplateResponse(
        "patch_event_detail.html",
        {
            "request": request,
            "patch_event": patch_event,
            "services": services,
            "environment_options": [env.value for env in Environment],
            "is_new": False,
            # Evidence and diff outputs
            "before_count": before_count,
            "after_count": after_count,
            "before_vulnerabilities": before_vulns,
            "after_vulnerabilities": after_vulns,
            "before_severity_counts": before_severity_counts,
            "after_severity_counts": after_severity_counts,
            "fixed_vulnerabilities": fixed_vulnerabilities,
            "severity_counts": severity_counts,
            "dev_evidence_available": patch_event.dev_evidence_available,
            # Lifecycle
            "allowed_next_states": allowed_next_states,
            "lifecycle_pipeline": lifecycle_pipeline,
            # CR summaries
            "stage_cr_summary": patch_event.stage_cr_summary,
            "prod_cr_summary": patch_event.prod_cr_summary,
            "prod_cr_allowed": prod_cr_allowed,
            # CVE threat intel (NVD/EPSS/CISA KEV)
            "intel_map": intel_ctx["intel_map"],
            "risk_scores": intel_ctx["risk_scores"],
            "kev_count": intel_ctx["kev_count"],
            "high_epss_count": intel_ctx["high_epss_count"],
            # Chart-friendly aggregates
            "chart_data": chart_data,
            # Feedback message (optional)
            "message": message,
        },
    )


@router.post("/patch-events/{patch_event_id}/run-auto-pipeline")
def run_auto_pipeline(
    request: Request,
    patch_event_id: int,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """One-click "do everything" for legacy patch events that pre-date
    the auto-pilot creation flow. Idempotent: skips any step that has
    already produced output."""
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    try:
        ran = _run_full_dev_pipeline(db, patch_event)
        steps = [k for k, v in ran.items() if v] or ["nothing (already complete)"]
        message = "Auto-pipeline ran: " + ", ".join(steps) + "."
    except Exception as exc:  # noqa: BLE001
        logger.exception("Auto-pipeline failed for event %s", patch_event_id)
        message = f"Auto-pipeline error: {exc}"

    url = request.url_for(
        "get_patch_event_detail",
        patch_event_id=patch_event_id,
    )
    params = urlencode({"message": message})
    return RedirectResponse(url=f"{url}?{params}", status_code=303)


@router.post("/patch-events/{patch_event_id}/generate-before")
def generate_before(
    request: Request,
    patch_event_id: int,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    generate_before_snapshot(db, patch_event)

    url = request.url_for(
        "get_patch_event_detail",
        patch_event_id=patch_event_id,
    )
    params = urlencode(
        {
            "message": (
                "Synthetic BEFORE snapshot generated with "
                "vulnerabilities."
            ),
        }
    )
    return RedirectResponse(url=f"{url}?{params}", status_code=303)


@router.post("/patch-events/{patch_event_id}/generate-stage-cr")
def generate_stage_cr(
    request: Request,
    patch_event_id: int,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    if not patch_event.dev_evidence_available:
        message = (
            "DEV evidence must be computed before generating a "
            "STAGE CR summary."
        )
    else:
        snapshots = list(patch_event.snapshots)
        split = extract_before_after_vulnerabilities(snapshots)
        before_vulns = split[SnapshotType.BEFORE]
        after_vulns = split[SnapshotType.AFTER]

        if not before_vulns or not after_vulns:
            message = (
                "Synthetic BEFORE and AFTER snapshots are required to build a "
                "STAGE CR summary."
            )
        else:
            fixed_vulnerabilities = compute_fixed_vulnerabilities(
                before_vulns,
                after_vulns,
            )
            severity_counts = count_by_severity(fixed_vulnerabilities)
            text = build_stage_cr_text(
                patch_event,
                fixed_vulnerabilities,
                severity_counts,
            )
            patch_event.stage_cr_summary = text
            db.add(patch_event)
            db.commit()
            message = "STAGE CR summary generated from synthetic DEV evidence."

    url = (
        request.url_for(
            "get_patch_event_detail",
            patch_event_id=patch_event_id,
        )
    )
    params = urlencode({"message": message})
    return RedirectResponse(url=f"{url}?{params}", status_code=303)


@router.post("/patch-events/{patch_event_id}/generate-prod-cr")
def generate_prod_cr(
    request: Request,
    patch_event_id: int,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    allowed_states = {
        "STAGE_PATCHED",
        "PROD_CR_READY",
        "PROD_PATCHED",
        "CLOSED",
    }

    if patch_event.current_state_code not in allowed_states:
        message = (
            "Patch event must be at least in STAGE_PATCHED state before "
            "generating a PROD CR summary."
        )
    else:
        snapshots = list(patch_event.snapshots)
        split = extract_before_after_vulnerabilities(snapshots)
        before_vulns = split[SnapshotType.BEFORE]
        after_vulns = split[SnapshotType.AFTER]

        if not before_vulns or not after_vulns:
            message = (
                "Synthetic BEFORE and AFTER snapshots are required to build a "
                "PROD CR summary."
            )
        else:
            fixed_vulnerabilities = compute_fixed_vulnerabilities(
                before_vulns, after_vulns
            )
            severity_counts = count_by_severity(fixed_vulnerabilities)
            text = build_prod_cr_text(
                patch_event,
                fixed_vulnerabilities,
                severity_counts,
            )
            patch_event.prod_cr_summary = text
            db.add(patch_event)
            db.commit()
            message = "PROD CR summary generated from synthetic evidence."

    url = request.url_for(
        "get_patch_event_detail",
        patch_event_id=patch_event_id,
    )
    params = urlencode({"message": message})
    return RedirectResponse(url=f"{url}?{params}", status_code=303)


@router.post("/patch-events/{patch_event_id}/generate-after")
def generate_after(
    request: Request,
    patch_event_id: int,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    # Enforce DEV evidence ordering: BEFORE must exist before AFTER.
    has_before_snapshot = any(
        snapshot.snapshot_type == SnapshotType.BEFORE
        for snapshot in patch_event.snapshots
    )
    url = request.url_for(
        "get_patch_event_detail",
        patch_event_id=patch_event_id,
    )

    if not has_before_snapshot:
        params = urlencode(
            {
                "message": "Generate BEFORE snapshot first for this event.",
            }
        )
        return RedirectResponse(url=f"{url}?{params}", status_code=303)

    generate_after_snapshot(db, patch_event)

    params = urlencode(
        {
            "message": (
                "Synthetic AFTER snapshot generated with "
                "vulnerabilities."
            ),
        }
    )
    return RedirectResponse(url=f"{url}?{params}", status_code=303)


@router.post("/patch-events/{patch_event_id}/compute-evidence")
def compute_evidence(
    request: Request,
    patch_event_id: int,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    snapshots = list(patch_event.snapshots)
    split = extract_before_after_vulnerabilities(snapshots)
    before_vulns = split[SnapshotType.BEFORE]
    after_vulns = split[SnapshotType.AFTER]

    if not before_vulns or not after_vulns:
        message = (
            "Cannot compute fixed vulnerabilities: synthetic BEFORE and AFTER "
            "snapshots are required."
        )
    else:
        # We compute the diff here to validate data and then mark DEV evidence
        # available; results are recomputed on subsequent GET.
        compute_fixed_vulnerabilities(before_vulns, after_vulns)
        patch_event.dev_evidence_available = True
        db.add(patch_event)
        db.commit()
        message = "DEV evidence computed from synthetic snapshots."

    url = request.url_for(
        "get_patch_event_detail",
        patch_event_id=patch_event_id,
    )
    params = urlencode({"message": message})
    return RedirectResponse(url=f"{url}?{params}", status_code=303)


@router.post("/patch-events/{patch_event_id}/transition-state")
def transition_state(
    request: Request,
    patch_event_id: int,
    target_state: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    try:
        transition_patch_event(patch_event, target_state)
        db.add(patch_event)
        db.commit()
        message = f"State updated to {target_state}."
    except ValueError as exc:  # invalid transition
        db.rollback()
        message = str(exc)

    url = request.url_for(
        "get_patch_event_detail",
        patch_event_id=patch_event_id,
    )
    params = urlencode({"message": message})
    return RedirectResponse(url=f"{url}?{params}", status_code=303)


@router.get(
    "/patch-events/{patch_event_id}/analysis",
    response_class=HTMLResponse,
    name="vulnerability_analysis",
)
def vulnerability_analysis(
    request: Request,
    patch_event_id: int,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Third screen: Vulnerability Analysis with interactive charts."""
    from app.models import Severity

    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    snapshots = list(patch_event.snapshots)
    split = extract_before_after_vulnerabilities(snapshots)
    before_vulns = split[SnapshotType.BEFORE]
    after_vulns = split[SnapshotType.AFTER]

    before_count = len(before_vulns)
    after_count = len(after_vulns)

    # Compute fixed and remaining vulnerabilities
    fixed_vulns = compute_fixed_vulnerabilities(before_vulns, after_vulns)
    remaining_vulns = compute_remaining_vulnerabilities(after_vulns)

    fixed_count = len(fixed_vulns)
    remaining_count = len(remaining_vulns)

    # Calculate effectiveness percentage
    effectiveness_pct = (
        round((fixed_count / before_count) * 100)
        if before_count > 0
        else 0
    )

    # Severity counts for each category
    before_severity = count_by_severity(before_vulns)
    after_severity = count_by_severity(after_vulns)
    fixed_severity = count_by_severity(fixed_vulns)
    remaining_severity = count_by_severity(remaining_vulns)

    def severity_to_dict(counts):
        return {
            "CRITICAL": counts.get(Severity.CRITICAL, 0),
            "HIGH": counts.get(Severity.HIGH, 0),
            "MEDIUM": counts.get(Severity.MEDIUM, 0),
            "LOW": counts.get(Severity.LOW, 0),
        }

    intel_ctx = _build_intel_context(
        db, before_vulns, after_vulns, fixed_vulns, remaining_vulns
    )

    return templates.TemplateResponse(
        "vulnerability_analysis.html",
        {
            "request": request,
            "patch_event": patch_event,
            # Counts
            "before_count": before_count,
            "after_count": after_count,
            "fixed_count": fixed_count,
            "remaining_count": remaining_count,
            "effectiveness_pct": effectiveness_pct,
            # Vulnerability lists
            "before_vulnerabilities": before_vulns,
            "after_vulnerabilities": after_vulns,
            "fixed_vulnerabilities": fixed_vulns,
            "remaining_vulnerabilities": remaining_vulns,
            # Severity counts for charts (as dicts)
            "before_severity": severity_to_dict(before_severity),
            "after_severity": severity_to_dict(after_severity),
            "fixed_severity": severity_to_dict(fixed_severity),
            "remaining_severity": severity_to_dict(remaining_severity),
            # Severity counts with enum keys for template iteration
            "fixed_severity_counts": fixed_severity,
            # CVE threat intel (NVD/EPSS/CISA KEV)
            "intel_map": intel_ctx["intel_map"],
            "risk_scores": intel_ctx["risk_scores"],
            "kev_count": intel_ctx["kev_count"],
            "high_epss_count": intel_ctx["high_epss_count"],
        },
    )


@router.post("/patch-events/{patch_event_id}/refresh-intel")
def refresh_threat_intel(
    request: Request,
    patch_event_id: int,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Force-refresh the NVD/EPSS/CISA KEV enrichment for this event's CVEs.

    Useful if the cached data is stale or if enrichment failed during the
    initial snapshot generation (e.g., no internet connectivity at that time).
    """
    patch_event = (
        db.query(PatchEvent)
        .filter(PatchEvent.id == patch_event_id)
        .first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    snapshots = list(patch_event.snapshots)
    split = extract_before_after_vulnerabilities(snapshots)
    all_cves = []
    for vulns in (split[SnapshotType.BEFORE], split[SnapshotType.AFTER]):
        for v in vulns:
            if v.cve:
                all_cves.append(v.cve)

    if all_cves:
        enrich_cves_bulk(db, all_cves, force_refresh=True)
        message = (
            f"Refreshed threat intel for {len(set(all_cves))} unique CVEs "
            f"from NVD / EPSS / CISA KEV."
        )
    else:
        message = "No CVEs to enrich for this patch event."

    url = request.url_for(
        "get_patch_event_detail",
        patch_event_id=patch_event_id,
    )
    params = urlencode({"message": message})
    return RedirectResponse(url=f"{url}?{params}", status_code=303)


# ---------------------------------------------------------------------------
# AI agent endpoints (Ollama-backed, advisory-only)
# ---------------------------------------------------------------------------


@router.get("/ai-status")
def ai_status() -> Dict[str, object]:
    """Return whether the local Ollama daemon is reachable and which model
    is configured. Used by the UI to decide whether to show the AI panel.

    Side-effect: if Ollama is available and the model is installed, kick off
    a background warmup so the first real generation isn't slowed by model
    loading. Idempotent - cheap once the model is resident.
    """
    import threading

    available = ollama_available()
    installed = ollama_list_models() if available else []

    if available and OLLAMA_MODEL in installed:
        # Fire-and-forget warmup so the UI can proceed immediately
        threading.Thread(
            target=ollama_warmup, kwargs={"model": OLLAMA_MODEL}, daemon=True
        ).start()

    return {
        "available": available,
        "configured_model": OLLAMA_MODEL,
        "installed_models": installed,
    }


@router.get(
    "/patch-events/{patch_event_id}/ai-briefing",
    response_class=HTMLResponse,
)
def get_ai_briefing(
    request: Request,
    patch_event_id: int,
    refresh: bool = False,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Return an HTML partial with the AI briefing for a patch event.

    Loaded via fetch() from the detail page so the user can wait on the LLM
    without blocking the main render.
    """
    patch_event = (
        db.query(PatchEvent).filter(PatchEvent.id == patch_event_id).first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    try:
        briefing = generate_patch_briefing(db, patch_event, force=refresh)
        return templates.TemplateResponse(
            "_ai_briefing_partial.html",
            {
                "request": request,
                "briefing": briefing,
                "patch_event": patch_event,
            },
        )
    except OllamaError as exc:
        return HTMLResponse(
            f'<div class="p-4 rounded-lg bg-amber-900/30 border '
            f'border-amber-500/50 text-amber-200 text-sm">'
            f"<strong>AI unavailable:</strong> {exc}"
            f"</div>",
            status_code=200,
        )


@router.post(
    "/patch-events/{patch_event_id}/ai-chat",
    response_class=HTMLResponse,
)
def post_ai_chat(
    request: Request,
    patch_event_id: int,
    question: str = Form(...),
    history_json: str = Form(default="[]"),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Answer a free-form question grounded in the patch-event context.

    Returns an HTML fragment (the assistant message) so the chat widget can
    append it directly.
    """
    patch_event = (
        db.query(PatchEvent).filter(PatchEvent.id == patch_event_id).first()
    )
    if patch_event is None:
        raise HTTPException(status_code=404, detail="Patch event not found")

    import json as _json

    try:
        history = _json.loads(history_json) if history_json else []
        if not isinstance(history, list):
            history = []
    except _json.JSONDecodeError:
        history = []

    try:
        answer = answer_question(db, patch_event, question.strip(), history)
    except OllamaError as exc:
        answer = f"_AI unavailable: {exc}_"

    return templates.TemplateResponse(
        "_ai_chat_message.html",
        {
            "request": request,
            "role": "assistant",
            "content": answer,
        },
    )


@router.get(
    "/patch-events/{patch_event_id}/ai-action-plan",
    response_class=HTMLResponse,
)
def get_ai_action_plan(
    request: Request,
    patch_event_id: int,
    narrative: bool = True,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Return the deterministic action plan + optional AI narrative for a
    patch event as an HTML fragment. Action codes come from the state
    machine, NOT the LLM, so the plan is always safe even if the LLM is
    offline or hallucinates.
    """
    patch_event = db.query(PatchEvent).filter(PatchEvent.id == patch_event_id).first()
    if not patch_event:
        raise HTTPException(status_code=404, detail="Patch event not found")

    plan = build_action_plan(db, patch_event, include_narrative=narrative)
    return templates.TemplateResponse(
        "_ai_action_plan_partial.html",
        {
            "request": request,
            "patch_event": patch_event,
            "plan": plan,
        },
    )


@router.get(
    "/patch-events/{patch_event_id}/ai-action-preview",
    response_class=HTMLResponse,
)
def get_ai_action_preview(
    request: Request,
    patch_event_id: int,
    action_code: str,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Render the rich pre-action approval card.

    The card surfaces the AMI, service, environment, host count, current
    patch effectiveness, and an LLM-style question ("I'm about to do X
    on Y, proceed?") so the operator can confirm before any state
    mutation happens.
    """
    patch_event = db.query(PatchEvent).filter(PatchEvent.id == patch_event_id).first()
    if not patch_event:
        raise HTTPException(status_code=404, detail="Patch event not found")

    try:
        preview = build_action_preview(db, patch_event, action_code)
    except ActionExecutionError as exc:
        return templates.TemplateResponse(
            "_ai_action_error.html",
            {
                "request": request,
                "patch_event": patch_event,
                "error_message": str(exc),
            },
        )

    return templates.TemplateResponse(
        "_ai_action_preview.html",
        {
            "request": request,
            "patch_event": patch_event,
            "preview": preview,
        },
    )


@router.post(
    "/patch-events/{patch_event_id}/ai-approve",
    response_class=HTMLResponse,
)
def approve_ai_action(
    request: Request,
    patch_event_id: int,
    action_code: str = Form(...),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Execute an AI-recommended action after user approval.

    On success returns a rich result card showing BEFORE/AFTER/FIXED
    counts plus follow-up recommendations for the highest-risk remaining
    CVEs. On failure returns an inline error card; the caller can re-fetch
    the plan to refresh the recommendations list.
    """
    patch_event = db.query(PatchEvent).filter(PatchEvent.id == patch_event_id).first()
    if not patch_event:
        raise HTTPException(status_code=404, detail="Patch event not found")

    try:
        result = execute_action(db, patch_event, action_code)
    except ActionExecutionError as exc:
        return templates.TemplateResponse(
            "_ai_action_error.html",
            {
                "request": request,
                "patch_event": patch_event,
                "error_message": str(exc),
            },
        )

    db.refresh(patch_event)
    payload = build_action_result(
        db,
        patch_event,
        action_code,
        executor_message=result.get("message", "Action executed."),
        state_before=result.get("state_before", patch_event.current_state_code),
        state_after=result.get("state_after", patch_event.current_state_code),
    )

    return templates.TemplateResponse(
        "_ai_action_result.html",
        {
            "request": request,
            "patch_event": patch_event,
            "result": payload,
        },
    )


@router.get("/ai-fleet-briefing", response_class=HTMLResponse)
def get_ai_fleet_briefing(
    request: Request,
    refresh: bool = False,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Return an HTML fragment with the fleet-wide AI briefing for the home
    page hero. Cached for 10 minutes; call with ``?refresh=true`` to force
    regeneration. If Ollama isn't reachable we render a friendly fallback
    so the rest of the dashboard still looks complete.
    """
    try:
        briefing = generate_fleet_briefing(db, force=refresh)
    except OllamaError as exc:
        return HTMLResponse(
            f'<div class="p-3 rounded-lg bg-amber-900/25 border '
            f'border-amber-500/40 text-amber-200 text-xs">'
            f"<strong>AI unavailable:</strong> {exc}"
            f"</div>",
            status_code=200,
        )

    created = briefing.get("created_at")
    created_s = (
        created.strftime("%Y-%m-%d %H:%M UTC") if created else "just now"
    )
    cached_tag = (
        '<span class="text-[10px] text-slate-500 italic">cached</span>'
        if briefing.get("cached")
        else ""
    )

    # Raw markdown is rendered client-side by marked.js via data-raw-markdown.
    content = briefing.get("content") or ""
    escaped = (
        content.replace("&", "&amp;").replace('"', "&quot;")
        .replace("<", "&lt;").replace(">", "&gt;")
    )

    return HTMLResponse(
        f'''
<div class="ai-hero-content">
  <div class="flex items-center justify-between mb-2">
    <div class="text-[11px] text-indigo-400/80">
      Model <code class="text-indigo-200">{briefing.get("model_used", "")}</code>
      · {created_s} {cached_tag}
    </div>
  </div>
  <div data-raw-markdown="{escaped}"><pre class="whitespace-pre-wrap text-sm text-slate-200">{content}</pre></div>
</div>
'''.strip()
    )
