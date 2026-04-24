from __future__ import annotations

import logging
import random
from typing import List

from sqlalchemy.orm import Session

from app.models import (
    Environment,
    PatchEvent,
    ScanSnapshot,
    Severity,
    SnapshotType,
    Vulnerability,
)
from app.services.real_cve_catalog import pick_cve_for_severity

logger = logging.getLogger(__name__)


def _generate_synthetic_cve(severity: Severity | None = None) -> str:
    """Return a real, public CVE identifier matched to the given severity.

    We use real CVEs from the curated public catalog so that the AI
    enrichment pipeline can demonstrate real NVD/EPSS/CISA KEV data.
    The hosts, plugin IDs, AMIs, and all other data remain synthetic.
    """
    if severity is None:
        severity = Severity.HIGH
    return pick_cve_for_severity(severity)


def _generate_synthetic_plugin_id() -> str:
    return f"PLUG-{random.randint(10000, 99999)}"


def _generate_synthetic_host(environment: Environment) -> str:
    env_prefix = environment.value.lower()
    index = random.randint(1, 9)
    return f"{env_prefix}-synthetic-{index:02d}"


def _choose_severity() -> Severity:
    # Biased distribution: more medium/low, fewer critical.
    choices: List[Severity] = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.LOW,
        Severity.LOW,
    ]
    return random.choice(choices)


def _build_vulnerability(
    snapshot: ScanSnapshot,
    index: int,
) -> Vulnerability:
    environment = snapshot.patch_event.environment
    severity = _choose_severity()

    synthetic_id = f"VULN-{snapshot.id:04d}-{index:04d}"
    return Vulnerability(
        scan_snapshot_id=snapshot.id,
        synthetic_id=synthetic_id,
        cve=_generate_synthetic_cve(severity),
        plugin_id=_generate_synthetic_plugin_id(),
        severity=severity,
        host=_generate_synthetic_host(environment),
        description="Synthetic vulnerability used for demonstration only.",
    )


def _enrich_snapshot_cves(db: Session, snapshot: ScanSnapshot) -> None:
    """Trigger CVE enrichment for all vulnerabilities in the snapshot.

    Runs synchronously after the snapshot is committed. Failures are logged
    but never block snapshot generation.
    """
    try:
        from app.services.cve_enrichment import enrich_cves_bulk

        cve_ids = [v.cve for v in snapshot.vulnerabilities if v.cve]
        if cve_ids:
            enrich_cves_bulk(db, cve_ids)
    except Exception as exc:  # noqa: BLE001
        logger.warning("CVE enrichment failed (non-fatal): %s", exc)


def _delete_existing_snapshots(
    db: Session,
    patch_event_id: int,
    snapshot_type: SnapshotType,
) -> None:
    existing = (
        db.query(ScanSnapshot)
        .filter(
            ScanSnapshot.patch_event_id == patch_event_id,
            ScanSnapshot.snapshot_type == snapshot_type,
        )
        .all()
    )
    for snapshot in existing:
        db.delete(snapshot)


def generate_before_snapshot(
    db: Session,
    patch_event: PatchEvent,
    vulnerability_count: int = 20,
) -> ScanSnapshot:
    """Create a synthetic BEFORE scan snapshot and associated vulnerabilities.

    Any existing BEFORE snapshots for this event are removed first.
    """

    _delete_existing_snapshots(db, patch_event.id, SnapshotType.BEFORE)

    snapshot = ScanSnapshot(
        patch_event_id=patch_event.id,
        snapshot_type=SnapshotType.BEFORE,
    )
    db.add(snapshot)
    db.flush()  # ensure snapshot.id is available

    for index in range(1, vulnerability_count + 1):
        vuln = _build_vulnerability(snapshot, index)
        db.add(vuln)

    db.commit()
    db.refresh(snapshot)
    _enrich_snapshot_cves(db, snapshot)
    return snapshot


def generate_after_snapshot(
    db: Session,
    patch_event: PatchEvent,
    min_remaining_ratio: float = 0.3,
    max_remaining_ratio: float = 0.7,
) -> ScanSnapshot:
    """Create a synthetic AFTER snapshot derived from the BEFORE snapshot.

    A random subset of BEFORE vulnerabilities is carried over to simulate
    remaining issues; the rest are implicitly treated as fixed.
    """

    _delete_existing_snapshots(db, patch_event.id, SnapshotType.AFTER)

    before_snapshot = (
        db.query(ScanSnapshot)
        .filter(
            ScanSnapshot.patch_event_id == patch_event.id,
            ScanSnapshot.snapshot_type == SnapshotType.BEFORE,
        )
        .first()
    )

    if before_snapshot is None or not before_snapshot.vulnerabilities:
        # If there is no BEFORE data, fall back to generating a fresh
        # synthetic set with fewer entries.
        fallback_count = 10
        snapshot = ScanSnapshot(
            patch_event_id=patch_event.id,
            snapshot_type=SnapshotType.AFTER,
        )
        db.add(snapshot)
        db.flush()

        for index in range(1, fallback_count + 1):
            vuln = _build_vulnerability(snapshot, index)
            db.add(vuln)

        db.commit()
        db.refresh(snapshot)
        _enrich_snapshot_cves(db, snapshot)
        return snapshot

    before_vulns = list(before_snapshot.vulnerabilities)
    total = len(before_vulns)

    min_remaining = max(1, int(total * min_remaining_ratio))
    max_remaining = max(min_remaining, int(total * max_remaining_ratio))
    remaining_count = random.randint(min_remaining, max_remaining)

    remaining_vulns = random.sample(before_vulns, remaining_count)

    snapshot = ScanSnapshot(
        patch_event_id=patch_event.id,
        snapshot_type=SnapshotType.AFTER,
    )
    db.add(snapshot)
    db.flush()

    for index, before_vuln in enumerate(remaining_vulns, start=1):
        vuln = Vulnerability(
            scan_snapshot_id=snapshot.id,
            synthetic_id=before_vuln.synthetic_id,
            cve=before_vuln.cve,
            plugin_id=before_vuln.plugin_id,
            severity=before_vuln.severity,
            host=before_vuln.host,
            description=before_vuln.description,
        )
        db.add(vuln)

    db.commit()
    db.refresh(snapshot)
    _enrich_snapshot_cves(db, snapshot)
    return snapshot
