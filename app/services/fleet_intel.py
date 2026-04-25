"""Fleet-wide vulnerability intelligence aggregation.

Rolls up vulnerability + threat-intel data across every patch event in the
system so the home page can render a single, authoritative "state of the
fleet" dashboard. This is the view a hiring manager sees first - it must
answer in 3 seconds: "how exposed are we, and what matters most right now?"

All values come from the existing `Vulnerability`, `CVEIntelligence`, and
`PatchEvent` tables. No outbound calls in this module; enrichment happens
elsewhere.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import (
    CVEIntelligence,
    PatchEvent,
    Severity,
    SnapshotType,
    Vulnerability,
)
from app.services.cve_enrichment import compute_risk_score

logger = logging.getLogger(__name__)


# Thresholds used across the UI for "high-risk" flags
HIGH_EPSS_THRESHOLD = 0.70  # 70th percentile
CRITICAL_CVSS_THRESHOLD = 9.0


@dataclass
class TopCVE:
    cve: str
    severity: str
    cvss: Optional[float]
    epss: Optional[float]
    is_kev: bool
    risk_score: int
    description: str
    host_count: int
    vendor: Optional[str] = None
    product: Optional[str] = None


@dataclass
class FleetIntel:
    """Flat snapshot of fleet-wide vulnerability posture."""

    # Headline counts
    total_patch_events: int = 0
    events_with_evidence: int = 0
    total_unique_cves: int = 0
    total_vulnerabilities: int = 0
    total_fixed: int = 0
    total_remaining: int = 0
    overall_effectiveness_pct: float = 0.0

    # Threat intel headline counts
    kev_count: int = 0
    high_epss_count: int = 0
    critical_cvss_count: int = 0
    enriched_cve_count: int = 0

    # Severity distribution across remaining vulns
    severity_remaining: Dict[str, int] = field(default_factory=dict)
    severity_fixed: Dict[str, int] = field(default_factory=dict)

    # Top N lists
    top_exploited: List[TopCVE] = field(default_factory=list)
    top_critical_remaining: List[TopCVE] = field(default_factory=list)
    top_fixed: List[TopCVE] = field(default_factory=list)

    # ---- Advanced analytics for dashboard charts ----
    # CVSS bucket histogram for remaining CVEs (0-3, 3-5, 5-7, 7-9, 9-10).
    cvss_distribution: Dict[str, int] = field(default_factory=dict)
    # EPSS bucket histogram for remaining CVEs (0-1%, 1-5%, 5-25%, 25-70%, 70-100%).
    epss_distribution: Dict[str, int] = field(default_factory=dict)
    # KEV vs non-KEV split among remaining unique CVEs.
    kev_split: Dict[str, int] = field(default_factory=dict)
    # Top services ranked by aggregate remaining risk score
    # (sum of compute_risk_score over remaining vulns on each service).
    top_services_by_risk: List[Dict[str, object]] = field(default_factory=list)
    # Patch effectiveness over the last N events (in chronological order)
    # for an effectiveness-trend line chart.
    effectiveness_trend: List[Dict[str, object]] = field(default_factory=list)

    # ---- KPI drill-down lists (top 10 each) ----
    # CVEs with EPSS >= HIGH_EPSS_THRESHOLD (drill-down for "High EPSS" KPI).
    high_epss_list: List[Dict[str, object]] = field(default_factory=list)
    # CVEs with CVSS >= CRITICAL_CVSS_THRESHOLD (drill-down for "CVSS >= 9.0" KPI).
    critical_cvss_list: List[Dict[str, object]] = field(default_factory=list)
    # CVEs flagged on the CISA KEV catalogue (drill-down for "CISA KEV" KPI).
    kev_list: List[Dict[str, object]] = field(default_factory=list)

    # Source attribution strings
    sources: List[str] = field(
        default_factory=lambda: [
            "NVD (nvd.nist.gov)",
            "FIRST.org EPSS",
            "CISA KEV",
        ]
    )


def _sev_dict(counts: Dict[Severity, int]) -> Dict[str, int]:
    return {s.value: counts.get(s, 0) for s in Severity}


def _rank_cves(
    vulns_by_cve: Dict[str, List[Vulnerability]],
    intel_map: Dict[str, CVEIntelligence],
    limit: int,
    filter_fn=None,
) -> List[TopCVE]:
    ranked: List[TopCVE] = []
    for cve_id, occurrences in vulns_by_cve.items():
        intel = intel_map.get(cve_id)
        if filter_fn and not filter_fn(intel, occurrences):
            continue
        first = occurrences[0]
        hosts = {v.host for v in occurrences if v.host}
        ranked.append(
            TopCVE(
                cve=cve_id,
                severity=first.severity.value,
                cvss=getattr(intel, "cvss_v3_score", None) if intel else None,
                epss=getattr(intel, "epss_score", None) if intel else None,
                is_kev=getattr(intel, "is_kev", False) if intel else False,
                risk_score=compute_risk_score(intel),
                description=(
                    (getattr(intel, "description", None) or "")[:200]
                    if intel
                    else ""
                ),
                host_count=len(hosts),
                vendor=getattr(intel, "vendor", None) if intel else None,
                product=getattr(intel, "product", None) if intel else None,
            )
        )
    ranked.sort(key=lambda c: (c.risk_score, c.cvss or 0), reverse=True)
    return ranked[:limit]


def compute_fleet_intel(db: Session) -> FleetIntel:
    """Scan every patch event + snapshot and build the aggregate view.

    Strategy:
    - Collect all BEFORE and AFTER vulns across all events
    - Group by CVE id (so the same CVE on 5 hosts counts once in "unique CVEs"
      but `host_count=5` in the top-exploited table)
    - Pull CVE intelligence in one bulk query
    - Compute severity distributions, effectiveness, KEV/EPSS/CVSS headlines
    """
    intel = FleetIntel()

    patch_events: List[PatchEvent] = (
        db.query(PatchEvent).order_by(PatchEvent.patch_date.desc()).all()
    )
    intel.total_patch_events = len(patch_events)
    intel.events_with_evidence = sum(
        1 for e in patch_events if e.dev_evidence_available
    )

    # Gather vulns per-event so we can correctly handle events that only have
    # a BEFORE snapshot (unpatched): those vulns are REMAINING, not fixed.
    all_before: List[Vulnerability] = []
    all_remaining: List[Vulnerability] = []  # AFTER vulns OR BEFORE-only vulns
    all_fixed: List[Vulnerability] = []

    for event in patch_events:
        before_vulns: List[Vulnerability] = []
        after_vulns: List[Vulnerability] = []
        has_after = False
        for snap in event.snapshots:
            if snap.snapshot_type == SnapshotType.BEFORE:
                before_vulns.extend(snap.vulnerabilities)
            elif snap.snapshot_type == SnapshotType.AFTER:
                after_vulns.extend(snap.vulnerabilities)
                has_after = True

        all_before.extend(before_vulns)

        if has_after:
            # Patched event: remaining = AFTER, fixed = BEFORE not in AFTER
            all_remaining.extend(after_vulns)
            after_keys_event = {(v.cve, v.host) for v in after_vulns}
            for v in before_vulns:
                if (v.cve, v.host) not in after_keys_event:
                    all_fixed.append(v)
        else:
            # Unpatched event (BEFORE snapshot only): everything is still remaining
            all_remaining.extend(before_vulns)

    intel.total_vulnerabilities = len(all_before)
    intel.total_remaining = len(all_remaining)
    intel.total_fixed = len(all_fixed)
    intel.overall_effectiveness_pct = (
        round(intel.total_fixed / len(all_before) * 100, 1)
        if all_before
        else 0.0
    )

    # Severity dicts
    sev_remaining: Dict[Severity, int] = {s: 0 for s in Severity}
    for v in all_remaining:
        sev_remaining[v.severity] = sev_remaining.get(v.severity, 0) + 1
    sev_fixed: Dict[Severity, int] = {s: 0 for s in Severity}
    for v in all_fixed:
        sev_fixed[v.severity] = sev_fixed.get(v.severity, 0) + 1
    intel.severity_remaining = _sev_dict(sev_remaining)
    intel.severity_fixed = _sev_dict(sev_fixed)

    # Group remaining vulns by CVE for ranking
    remaining_by_cve: Dict[str, List[Vulnerability]] = {}
    fixed_by_cve: Dict[str, List[Vulnerability]] = {}
    for v in all_remaining:
        if v.cve:
            remaining_by_cve.setdefault(v.cve, []).append(v)
    for v in all_fixed:
        if v.cve:
            fixed_by_cve.setdefault(v.cve, []).append(v)

    unique_cves = set(remaining_by_cve) | set(fixed_by_cve)
    intel.total_unique_cves = len(unique_cves)

    # Bulk-load intel
    intel_rows: List[CVEIntelligence] = (
        db.query(CVEIntelligence)
        .filter(CVEIntelligence.cve_id.in_(unique_cves) if unique_cves else False)
        .all()
        if unique_cves
        else []
    )
    intel_map: Dict[str, CVEIntelligence] = {r.cve_id: r for r in intel_rows}
    intel.enriched_cve_count = sum(
        1 for r in intel_rows if r.enrichment_status in {"SUCCESS", "PARTIAL"}
    )

    # Headline intel counts (remaining only - fixed is already handled)
    for cve_id in remaining_by_cve:
        r = intel_map.get(cve_id)
        if not r:
            continue
        if r.is_kev:
            intel.kev_count += 1
        if r.epss_score is not None and r.epss_score >= HIGH_EPSS_THRESHOLD:
            intel.high_epss_count += 1
        if (
            r.cvss_v3_score is not None
            and r.cvss_v3_score >= CRITICAL_CVSS_THRESHOLD
        ):
            intel.critical_cvss_count += 1

    # Top lists
    intel.top_exploited = _rank_cves(
        remaining_by_cve,
        intel_map,
        limit=10,
        filter_fn=lambda r, _: r is not None and r.is_kev,
    )
    # Fallback: if no KEV hits, just show highest risk remaining
    if not intel.top_exploited:
        intel.top_exploited = _rank_cves(remaining_by_cve, intel_map, limit=10)

    intel.top_critical_remaining = _rank_cves(
        remaining_by_cve,
        intel_map,
        limit=8,
    )
    intel.top_fixed = _rank_cves(fixed_by_cve, intel_map, limit=5)

    # ---- KPI drill-down lists (top 10, JSON-safe primitives) ----
    def _flatten(top_list):
        return [
            {
                "cve": c.cve,
                "severity": c.severity,
                "cvss": c.cvss,
                "epss": c.epss,
                "is_kev": c.is_kev,
                "risk": c.risk_score,
                "hosts": c.host_count,
                "description": (c.description or "")[:140],
            }
            for c in top_list
        ]

    intel.kev_list = _flatten(
        _rank_cves(
            remaining_by_cve, intel_map, limit=10,
            filter_fn=lambda r, _: r is not None and r.is_kev,
        )
    )
    intel.high_epss_list = _flatten(
        _rank_cves(
            remaining_by_cve, intel_map, limit=10,
            filter_fn=lambda r, _: (
                r is not None
                and r.epss_score is not None
                and r.epss_score >= HIGH_EPSS_THRESHOLD
            ),
        )
    )
    intel.critical_cvss_list = _flatten(
        _rank_cves(
            remaining_by_cve, intel_map, limit=10,
            filter_fn=lambda r, _: (
                r is not None
                and r.cvss_v3_score is not None
                and r.cvss_v3_score >= CRITICAL_CVSS_THRESHOLD
            ),
        )
    )

    # ------------------------------------------------------------------
    # Advanced analytics for the dashboard charts
    # ------------------------------------------------------------------

    # ---- CVSS bucket histogram (remaining unique CVEs) ----
    cvss_buckets = {"0-3": 0, "3-5": 0, "5-7": 0, "7-9": 0, "9-10": 0, "unknown": 0}
    for cve_id in remaining_by_cve:
        r = intel_map.get(cve_id)
        score = getattr(r, "cvss_v3_score", None) if r else None
        if score is None:
            cvss_buckets["unknown"] += 1
        elif score < 3:
            cvss_buckets["0-3"] += 1
        elif score < 5:
            cvss_buckets["3-5"] += 1
        elif score < 7:
            cvss_buckets["5-7"] += 1
        elif score < 9:
            cvss_buckets["7-9"] += 1
        else:
            cvss_buckets["9-10"] += 1
    intel.cvss_distribution = cvss_buckets

    # ---- EPSS bucket histogram (remaining unique CVEs) ----
    epss_buckets = {"<1%": 0, "1-5%": 0, "5-25%": 0, "25-70%": 0, "70-100%": 0, "unknown": 0}
    for cve_id in remaining_by_cve:
        r = intel_map.get(cve_id)
        score = getattr(r, "epss_score", None) if r else None
        if score is None:
            epss_buckets["unknown"] += 1
        elif score < 0.01:
            epss_buckets["<1%"] += 1
        elif score < 0.05:
            epss_buckets["1-5%"] += 1
        elif score < 0.25:
            epss_buckets["5-25%"] += 1
        elif score < 0.70:
            epss_buckets["25-70%"] += 1
        else:
            epss_buckets["70-100%"] += 1
    intel.epss_distribution = epss_buckets

    # ---- KEV vs non-KEV split among remaining unique CVEs ----
    kev_count_unique = sum(
        1 for cve_id in remaining_by_cve
        if intel_map.get(cve_id) and intel_map[cve_id].is_kev
    )
    intel.kev_split = {
        "kev": kev_count_unique,
        "non_kev": max(len(remaining_by_cve) - kev_count_unique, 0),
    }

    # ---- Top services by aggregate remaining risk ----
    # Per-event: remaining = AFTER vulns if patched, else BEFORE vulns.
    service_risk: Dict[str, Dict[str, object]] = {}
    for event in patch_events:
        svc_name = event.service.name if event.service else "(unknown)"
        slot = service_risk.setdefault(
            svc_name,
            {
                "service": svc_name,
                "risk": 0.0,
                "remaining": 0,
                "kev": 0,
                "events": 0,
            },
        )
        slot["events"] = int(slot["events"]) + 1
        before_v: List[Vulnerability] = []
        after_v: List[Vulnerability] = []
        has_after_snap = False
        for snap in event.snapshots:
            if snap.snapshot_type == SnapshotType.BEFORE:
                before_v.extend(snap.vulnerabilities)
            elif snap.snapshot_type == SnapshotType.AFTER:
                after_v.extend(snap.vulnerabilities)
                has_after_snap = True
        remaining_for_event = after_v if has_after_snap else before_v
        for v in remaining_for_event:
            slot["remaining"] = int(slot["remaining"]) + 1
            if not v.cve:
                continue
            r = intel_map.get(v.cve)
            slot["risk"] = float(slot["risk"]) + float(compute_risk_score(r))
            if r and r.is_kev:
                slot["kev"] = int(slot["kev"]) + 1
    intel.top_services_by_risk = sorted(
        (
            {
                "service": s["service"],
                "risk": round(float(s["risk"]), 1),
                "remaining": int(s["remaining"]),
                "kev": int(s["kev"]),
                "events": int(s["events"]),
            }
            for s in service_risk.values()
            if int(s["remaining"]) > 0
        ),
        key=lambda r: r["risk"],
        reverse=True,
    )[:8]

    # ---- Patch effectiveness trend (last 10 events with evidence) ----
    trend: List[Dict[str, object]] = []
    # patch_events is already ordered by patch_date desc; reverse for chronology.
    chronological = list(reversed(patch_events))
    for event in chronological:
        if not event.dev_evidence_available:
            continue
        before_total = 0
        after_total = 0
        for snap in event.snapshots:
            if snap.snapshot_type == SnapshotType.BEFORE:
                before_total += len(snap.vulnerabilities)
            elif snap.snapshot_type == SnapshotType.AFTER:
                after_total += len(snap.vulnerabilities)
        if before_total == 0:
            continue
        eff = round(((before_total - after_total) / before_total) * 100, 1)
        trend.append(
            {
                "event_id": event.id,
                "label": (event.service.name if event.service else "?")[:14],
                "date": event.patch_date.isoformat() if event.patch_date else "",
                "effectiveness": eff,
                "fixed": before_total - after_total,
                "before": before_total,
            }
        )
    intel.effectiveness_trend = trend[-12:]  # last 12 in chronological order

    return intel
