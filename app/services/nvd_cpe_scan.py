"""NVD keyword-based auto-scan for registered services.

Queries the NVD CVE API by product keyword for each Service row,
pre-populates CVEIntelligence from the search response (no per-CVE NVD
calls needed), then enriches with EPSS and CISA KEV in bulk.

API calls per full scan:
  - 1 NVD search per service (rate-limited at 6.1 s between calls)
  - 1 bulk EPSS call for all CVEs found
  - 1 CISA KEV catalog load (cached 24 h)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import date, datetime
from typing import Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.models import (
    CVEIntelligence,
    Environment,
    PatchEvent,
    ScanSnapshot,
    Service,
    Severity,
    SnapshotType,
    Vulnerability,
)
from app.services.cve_enrichment import enrich_epss_kev_only

logger = logging.getLogger(__name__)

NVD_SEARCH_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SEARCH_TIMEOUT = 30.0
# 6.1 s gap keeps us under the 5-req/30-s NVD rate limit without an API key.
NVD_BETWEEN_SEARCH_DELAY = 6.5

# Map each service name to the keyword(s) that best surface its CVEs on NVD.
SERVICE_KEYWORD_MAP: Dict[str, str] = {
    "Nessus Manager": "Tenable Nessus",
    "Trend Micro": "Trend Micro",
    "Tenable Security Center": "Tenable Security Center",
    "ServiceNow MID Server": "ServiceNow",
    "Grafana Enterprise": "Grafana",
    "Burp Suite": "Burp Suite",
}

_SEVERITY_MAP: Dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


@dataclass
class _CVEResult:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_severity: str
    cvss_vector: Optional[str]
    published: Optional[datetime]
    nvd_url: str


def _parse_nvd_response(vulnerabilities: list) -> List[_CVEResult]:
    seen: set[str] = set()
    results: List[_CVEResult] = []
    for item in vulnerabilities:
        cve_data = item.get("cve") or {}
        cve_id = (cve_data.get("id") or "").strip().upper()
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)

        description = ""
        for desc in cve_data.get("descriptions") or []:
            if desc.get("lang") == "en":
                description = (desc.get("value") or "")[:500]
                break

        cvss_score: Optional[float] = None
        cvss_severity = "UNKNOWN"
        cvss_vector: Optional[str] = None
        metrics = cve_data.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30"):
            for m in metrics.get(key) or []:
                d = m.get("cvssData") or {}
                cvss_score = d.get("baseScore")
                cvss_severity = (d.get("baseSeverity") or "UNKNOWN").upper()
                cvss_vector = d.get("vectorString")
                break
            if cvss_score is not None:
                break

        published: Optional[datetime] = None
        pub_str = cve_data.get("published") or ""
        if pub_str:
            try:
                published = datetime.fromisoformat(
                    pub_str.replace("Z", "+00:00")
                )
            except ValueError:
                pass

        results.append(
            _CVEResult(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                published=published,
                nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )
    return results


def search_nvd_for_service(
    service_name: str,
    limit: int = 25,
) -> List[_CVEResult]:
    """Search NVD for recent CVEs matching a service keyword. Returns parsed results."""
    keywords = SERVICE_KEYWORD_MAP.get(service_name, service_name)
    params = {
        "keywordSearch": keywords,
        "resultsPerPage": limit,
    }
    try:
        with httpx.Client(timeout=NVD_SEARCH_TIMEOUT) as client:
            resp = client.get(NVD_SEARCH_URL, params=params)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("NVD search failed for '%s': %s", service_name, exc)
        return []
    return _parse_nvd_response(resp.json().get("vulnerabilities") or [])


def _pre_populate_intel(db: Session, results: List[_CVEResult]) -> None:
    """Store NVD search results in CVEIntelligence marked SUCCESS.

    Marking as SUCCESS prevents enrich_cves_bulk from making redundant
    per-CVE NVD calls. EPSS and KEV are added separately by
    enrich_epss_kev_only() after all services are scanned.
    """
    if not results:
        return
    existing_ids = {
        row.cve_id
        for row in db.query(CVEIntelligence.cve_id)
        .filter(CVEIntelligence.cve_id.in_([r.cve_id for r in results]))
        .all()
    }
    now = datetime.utcnow()
    for r in results:
        if r.cve_id in existing_ids:
            continue
        db.add(
            CVEIntelligence(
                cve_id=r.cve_id,
                description=r.description or None,
                cvss_v3_score=r.cvss_score,
                cvss_v3_severity=(
                    r.cvss_severity if r.cvss_severity != "UNKNOWN" else None
                ),
                cvss_v3_vector=r.cvss_vector,
                published_date=r.published,
                nvd_url=r.nvd_url,
                enrichment_status="SUCCESS",
                last_enriched_at=now,
            )
        )
    db.commit()


def _create_patch_event(
    db: Session,
    service: Service,
    results: List[_CVEResult],
) -> Optional[PatchEvent]:
    if not results:
        return None

    slug = service.name.lower().replace(" ", "-")
    event = PatchEvent(
        service_id=service.id,
        environment=Environment.DEV,
        ami_id=f"{slug}-latest",
        patch_date=date.today(),
        notes=f"NVD auto-scan — {len(results)} CVEs found",
    )
    db.add(event)
    db.flush()

    snapshot = ScanSnapshot(
        patch_event_id=event.id,
        snapshot_type=SnapshotType.BEFORE,
    )
    db.add(snapshot)
    db.flush()

    for r in results:
        severity = _SEVERITY_MAP.get(r.cvss_severity, Severity.MEDIUM)
        db.add(
            Vulnerability(
                scan_snapshot_id=snapshot.id,
                synthetic_id=f"nvd-{event.id}-{r.cve_id}",
                cve=r.cve_id,
                severity=severity,
                host=f"{slug}-host",
                description=r.description or None,
            )
        )

    db.commit()
    return event


def run_auto_scan(db: Session, force: bool = False) -> int:
    """Scan all registered services for CVEs via NVD and create patch events.

    Skips services that already have events unless force=True.
    Returns the number of patch events created.
    """
    services = db.query(Service).order_by(Service.name).all()
    created = 0
    all_cve_ids: List[str] = []

    for idx, service in enumerate(services):
        if not force:
            has_event = (
                db.query(PatchEvent)
                .filter(PatchEvent.service_id == service.id)
                .first()
            ) is not None
            if has_event:
                logger.debug(
                    "Skipping '%s' — already has patch events", service.name
                )
                continue

        logger.info("Scanning NVD for '%s'…", service.name)
        results = search_nvd_for_service(service.name)
        if not results:
            logger.warning("No CVEs found for '%s'", service.name)
            # Still respect rate limit between services
            if idx < len(services) - 1:
                time.sleep(NVD_BETWEEN_SEARCH_DELAY)
            continue

        _pre_populate_intel(db, results)
        event = _create_patch_event(db, service, results)
        if event:
            created += 1
            all_cve_ids.extend(r.cve_id for r in results)

        if idx < len(services) - 1:
            time.sleep(NVD_BETWEEN_SEARCH_DELAY)

    if all_cve_ids:
        unique_ids = list(set(all_cve_ids))
        logger.info("Enriching %d CVEs with EPSS + CISA KEV…", len(unique_ids))
        enrich_epss_kev_only(db, unique_ids)

    logger.info("Auto-scan complete — %d patch event(s) created", created)
    return created
