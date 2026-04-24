"""CVE Enrichment Service.

Fetches real-world threat intelligence for CVEs from three free public sources:

- NVD (National Vulnerability Database) - CVSS scores, descriptions, metadata
- EPSS (Exploit Prediction Scoring System) - exploit probability scores
- CISA KEV (Known Exploited Vulnerabilities) - actively exploited CVEs

All data is cached locally in the CVEIntelligence table to avoid hammering
the public APIs. Only synthetic CVE identifiers from curated public lists
are submitted - no company data ever leaves this machine.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.models import CVEIntelligence

logger = logging.getLogger(__name__)

# Public, free APIs - no auth required
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Cache freshness: re-enrich a CVE if data is older than this
CACHE_TTL = timedelta(days=7)

# Module-level cache for the CISA KEV catalog (single HTTP call per process)
_KEV_CACHE: Dict[str, Dict[str, Any]] = {}
_KEV_CACHE_LOADED_AT: Optional[datetime] = None


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Best-effort parse of an ISO 8601 datetime string."""
    if not value:
        return None
    try:
        # Handle trailing 'Z' for UTC
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None


def _fetch_nvd(client: httpx.Client, cve_id: str) -> Optional[Dict[str, Any]]:
    """Fetch CVE details from the NVD API."""
    try:
        response = client.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            timeout=15.0,
        )
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return None

    vulnerabilities = data.get("vulnerabilities") or []
    if not vulnerabilities:
        return None

    cve_entry = vulnerabilities[0].get("cve", {})

    # Description (prefer English)
    description = None
    for desc in cve_entry.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value")
            break

    # CVSS v3.1 (preferred), fallback to v3.0
    cvss_score = None
    cvss_severity = None
    cvss_vector = None
    metrics = cve_entry.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
            break

    # Extract vendor/product from first configuration if present
    vendor = None
    product = None
    for config in cve_entry.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    break
            if vendor:
                break
        if vendor:
            break

    return {
        "description": description,
        "cvss_v3_score": cvss_score,
        "cvss_v3_severity": cvss_severity,
        "cvss_v3_vector": cvss_vector,
        "published_date": _parse_iso_datetime(cve_entry.get("published")),
        "last_modified_date": _parse_iso_datetime(cve_entry.get("lastModified")),
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "vendor": vendor,
        "product": product,
    }


def _fetch_epss(client: httpx.Client, cve_id: str) -> Optional[Dict[str, Any]]:
    """Fetch EPSS exploit probability score from FIRST.org."""
    try:
        response = client.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=10.0,
        )
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        logger.warning("EPSS fetch failed for %s: %s", cve_id, exc)
        return None

    results = data.get("data") or []
    if not results:
        return None

    entry = results[0]
    try:
        return {
            "epss_score": float(entry.get("epss")) if entry.get("epss") else None,
            "epss_percentile": (
                float(entry.get("percentile"))
                if entry.get("percentile")
                else None
            ),
        }
    except (ValueError, TypeError):
        return None


def _load_kev_catalog(client: httpx.Client) -> Dict[str, Dict[str, Any]]:
    """Load (and cache) the CISA Known Exploited Vulnerabilities catalog."""
    global _KEV_CACHE, _KEV_CACHE_LOADED_AT

    if _KEV_CACHE_LOADED_AT and (
        datetime.utcnow() - _KEV_CACHE_LOADED_AT < timedelta(hours=24)
    ):
        return _KEV_CACHE

    try:
        response = client.get(CISA_KEV_URL, timeout=30.0)
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return _KEV_CACHE  # Return stale cache if available

    kev_entries = data.get("vulnerabilities") or []
    new_cache: Dict[str, Dict[str, Any]] = {}
    for entry in kev_entries:
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        new_cache[cve_id.upper()] = {
            "kev_date_added": _parse_iso_datetime(entry.get("dateAdded")),
            "kev_due_date": _parse_iso_datetime(entry.get("dueDate")),
            "kev_required_action": entry.get("requiredAction"),
            "kev_ransomware_use": entry.get("knownRansomwareCampaignUse"),
        }

    _KEV_CACHE = new_cache
    _KEV_CACHE_LOADED_AT = datetime.utcnow()
    logger.info("Loaded %d CISA KEV entries", len(new_cache))
    return _KEV_CACHE


def _check_kev(client: httpx.Client, cve_id: str) -> Dict[str, Any]:
    """Check if a CVE appears in the CISA KEV catalog."""
    catalog = _load_kev_catalog(client)
    entry = catalog.get(cve_id.upper())
    if entry:
        return {"is_kev": True, **entry}
    return {"is_kev": False}


def _is_cache_fresh(intel: CVEIntelligence) -> bool:
    """Return True if the cached intel is still within the TTL."""
    if intel.enrichment_status != "SUCCESS":
        return False
    if not intel.last_enriched_at:
        return False
    return datetime.utcnow() - intel.last_enriched_at < CACHE_TTL


def enrich_cve(
    db: Session,
    cve_id: str,
    force_refresh: bool = False,
) -> CVEIntelligence:
    """Fetch and cache threat intelligence for a single CVE.

    Returns the CVEIntelligence row. Uses cached data when fresh unless
    ``force_refresh=True``.
    """
    cve_id = cve_id.strip().upper()

    intel = (
        db.query(CVEIntelligence)
        .filter(CVEIntelligence.cve_id == cve_id)
        .first()
    )

    if intel and not force_refresh and _is_cache_fresh(intel):
        return intel

    if intel is None:
        intel = CVEIntelligence(cve_id=cve_id, enrichment_status="PENDING")
        db.add(intel)
        db.flush()

    errors: List[str] = []

    with httpx.Client() as client:
        # NVD
        nvd_data = _fetch_nvd(client, cve_id)
        if nvd_data:
            for field, value in nvd_data.items():
                setattr(intel, field, value)
        else:
            errors.append("NVD lookup returned no data")

        # EPSS
        epss_data = _fetch_epss(client, cve_id)
        if epss_data:
            intel.epss_score = epss_data.get("epss_score")
            intel.epss_percentile = epss_data.get("epss_percentile")
        else:
            errors.append("EPSS lookup returned no data")

        # CISA KEV
        try:
            kev_data = _check_kev(client, cve_id)
            intel.is_kev = kev_data.get("is_kev", False)
            if kev_data.get("is_kev"):
                intel.kev_date_added = kev_data.get("kev_date_added")
                intel.kev_due_date = kev_data.get("kev_due_date")
                intel.kev_required_action = kev_data.get("kev_required_action")
                intel.kev_ransomware_use = kev_data.get("kev_ransomware_use")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"KEV check failed: {exc}")

    intel.last_enriched_at = datetime.utcnow()

    if nvd_data is None and epss_data is None:
        intel.enrichment_status = "NOT_FOUND"
        intel.enrichment_error = "; ".join(errors) or "All sources returned no data"
    elif errors:
        intel.enrichment_status = "PARTIAL"
        intel.enrichment_error = "; ".join(errors)
    else:
        intel.enrichment_status = "SUCCESS"
        intel.enrichment_error = None

    db.commit()
    db.refresh(intel)
    return intel


def enrich_cves_bulk(
    db: Session,
    cve_ids: List[str],
    force_refresh: bool = False,
) -> Dict[str, CVEIntelligence]:
    """Enrich multiple CVEs. Returns a mapping of cve_id -> CVEIntelligence.

    Designed to be called from background tasks after a scan snapshot is
    generated so the UI can render threat-intel badges without blocking.
    """
    results: Dict[str, CVEIntelligence] = {}
    unique_cves = {c.strip().upper() for c in cve_ids if c}
    for cve_id in unique_cves:
        try:
            results[cve_id] = enrich_cve(db, cve_id, force_refresh=force_refresh)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Enrichment failed for %s: %s", cve_id, exc)
    return results


def get_intel_map(db: Session, cve_ids: List[str]) -> Dict[str, CVEIntelligence]:
    """Return cached intel for the given CVEs without triggering enrichment."""
    unique_cves = {c.strip().upper() for c in cve_ids if c}
    if not unique_cves:
        return {}
    rows = (
        db.query(CVEIntelligence)
        .filter(CVEIntelligence.cve_id.in_(unique_cves))
        .all()
    )
    return {row.cve_id: row for row in rows}


def compute_risk_score(intel: Optional[CVEIntelligence]) -> float:
    """Compute a composite risk score (0-100) from intel data.

    Formula blends:
    - CVSS base score (0-10, scaled to 0-60)
    - EPSS score (0-1, scaled to 0-30)
    - CISA KEV boost (+10 if actively exploited)
    """
    if intel is None:
        return 0.0

    score = 0.0
    if intel.cvss_v3_score is not None:
        score += (intel.cvss_v3_score / 10.0) * 60.0
    if intel.epss_score is not None:
        score += intel.epss_score * 30.0
    if intel.is_kev:
        score += 10.0

    return round(min(score, 100.0), 1)
