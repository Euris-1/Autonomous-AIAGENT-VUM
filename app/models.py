from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, Column, Date, DateTime
from sqlalchemy import Enum as SAEnum
from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base


class Environment(str, Enum):
    DEV = "DEV"
    STAGE = "STAGE"
    PROD = "PROD"


class SnapshotType(str, Enum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)

    patch_events = relationship("PatchEvent", back_populates="service")


class PatchEvent(Base):
    __tablename__ = "patch_events"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(
        Integer,
        ForeignKey("services.id"),
        nullable=False,
        index=True,
    )
    environment = Column(SAEnum(Environment), nullable=False)
    ami_id = Column(String(64), nullable=False)
    patch_date = Column(Date, nullable=False)
    notes = Column(Text, nullable=True)
    dev_evidence_available = Column(Boolean, default=False, nullable=False)
    stage_cr_summary = Column(Text, nullable=True)
    prod_cr_summary = Column(Text, nullable=True)
    current_state_code = Column(
        String(50),
        nullable=False,
        default="DEV_EVIDENCE_CAPTURED",
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    service = relationship("Service", back_populates="patch_events")
    snapshots = relationship(
        "ScanSnapshot",
        back_populates="patch_event",
        cascade="all, delete-orphan",
    )


class ScanSnapshot(Base):
    __tablename__ = "scan_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    patch_event_id = Column(
        Integer,
        ForeignKey("patch_events.id"),
        nullable=False,
        index=True,
    )
    snapshot_type = Column(SAEnum(SnapshotType), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    patch_event = relationship("PatchEvent", back_populates="snapshots")
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan_snapshot",
        cascade="all, delete-orphan",
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_snapshot_id = Column(
        Integer,
        ForeignKey("scan_snapshots.id"),
        nullable=False,
        index=True,
    )
    synthetic_id = Column(String(50), nullable=False)
    cve = Column(String(20), nullable=True, index=True)
    plugin_id = Column(String(20), nullable=True)
    severity = Column(SAEnum(Severity), nullable=False)
    host = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)

    scan_snapshot = relationship(
        "ScanSnapshot",
        back_populates="vulnerabilities",
    )


class CVEIntelligence(Base):
    """Cached threat intelligence for a CVE, sourced from NVD/EPSS/CISA KEV.

    This is a local cache to avoid repeatedly hitting public APIs and to
    allow offline viewing/analysis. All data comes from free public sources.
    """

    __tablename__ = "cve_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), unique=True, nullable=False, index=True)

    # NVD data
    description = Column(Text, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_severity = Column(String(20), nullable=True)
    cvss_v3_vector = Column(String(100), nullable=True)
    published_date = Column(DateTime, nullable=True)
    last_modified_date = Column(DateTime, nullable=True)
    nvd_url = Column(String(255), nullable=True)

    # EPSS data (Exploit Prediction Scoring System)
    epss_score = Column(Float, nullable=True)  # 0.0 to 1.0
    epss_percentile = Column(Float, nullable=True)  # 0.0 to 1.0

    # CISA KEV (Known Exploited Vulnerabilities) data
    is_kev = Column(Boolean, default=False, nullable=False)
    kev_date_added = Column(DateTime, nullable=True)
    kev_due_date = Column(DateTime, nullable=True)
    kev_required_action = Column(Text, nullable=True)
    kev_ransomware_use = Column(String(50), nullable=True)

    # Vendor / product info
    vendor = Column(String(100), nullable=True)
    product = Column(String(100), nullable=True)

    # Metadata
    enrichment_status = Column(String(20), default="PENDING", nullable=False)
    # Values: PENDING, SUCCESS, PARTIAL, FAILED, NOT_FOUND
    enrichment_error = Column(Text, nullable=True)
    last_enriched_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AIAnalysis(Base):
    """AI-generated analysis artifacts tied to a patch event.

    Stores briefings, recommendations, and post-patch summaries produced
    by the AI agent. User approval is tracked for advisory mode.
    """

    __tablename__ = "ai_analysis"

    id = Column(Integer, primary_key=True, index=True)
    patch_event_id = Column(
        Integer,
        ForeignKey("patch_events.id"),
        nullable=False,
        index=True,
    )
    analysis_type = Column(String(50), nullable=False)
    # Values: pre_patch_briefing, post_patch_analysis, recommendation,
    # pattern_insight, cr_summary

    content = Column(Text, nullable=False)  # Natural language content
    structured_data = Column(Text, nullable=True)  # JSON-encoded extras

    model_name = Column(String(50), nullable=True)
    tokens_used = Column(Integer, nullable=True)

    # Advisory mode: user approval tracking
    user_approved = Column(Boolean, default=False, nullable=False)
    user_rejected = Column(Boolean, default=False, nullable=False)
    user_feedback = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
