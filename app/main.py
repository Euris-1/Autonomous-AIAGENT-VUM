import logging
import threading

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .database import Base, SessionLocal, engine
from .models import PatchEvent, Service
from .web.routes import router as web_router

logger = logging.getLogger(__name__)

app = FastAPI(title="AMI Patch Evidence Tracker (Synthetic Data)")

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(web_router)


def seed_default_services() -> None:
    """Ensure all default services exist; adds any that are missing."""
    default_services = [
        "Nessus Manager",
        "Trend Micro",
        "Tenable Security Center",
        "ServiceNow MID Server",
        "Grafana Enterprise",
        "Burp Suite",
    ]
    db = SessionLocal()
    try:
        for name in default_services:
            if not db.query(Service).filter(Service.name == name).first():
                db.add(Service(name=name))
        db.commit()
    finally:
        db.close()


def _background_auto_scan() -> None:
    """Run NVD auto-scan in a background thread on first launch."""
    import time
    time.sleep(1)  # Let the server finish binding before heavy I/O
    db = SessionLocal()
    try:
        from app.services.nvd_cpe_scan import run_auto_scan
        run_auto_scan(db, force=False)
    except Exception:
        logger.exception("Background NVD auto-scan failed")
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    seed_default_services()

    # Kick off NVD scan in background only when the DB has no patch events yet.
    db = SessionLocal()
    try:
        has_events = db.query(PatchEvent).first() is not None
    finally:
        db.close()

    if not has_events:
        t = threading.Thread(target=_background_auto_scan, daemon=True)
        t.start()
        logger.info("NVD auto-scan started in background")
