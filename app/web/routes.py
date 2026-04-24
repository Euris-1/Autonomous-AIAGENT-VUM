from datetime import date
from typing import Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Environment, PatchEvent, Service, SnapshotType
from app.services.cr_text import build_prod_cr_text, build_stage_cr_text
from app.services.cve_enrichment import (
    compute_risk_score,
    enrich_cves_bulk,
    get_intel_map,
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
            # CR summaries
            "stage_cr_summary": patch_event.stage_cr_summary,
            "prod_cr_summary": patch_event.prod_cr_summary,
            "prod_cr_allowed": prod_cr_allowed,
            # CVE threat intel (NVD/EPSS/CISA KEV)
            "intel_map": intel_ctx["intel_map"],
            "risk_scores": intel_ctx["risk_scores"],
            "kev_count": intel_ctx["kev_count"],
            "high_epss_count": intel_ctx["high_epss_count"],
            # Feedback message (optional)
            "message": message,
        },
    )


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
