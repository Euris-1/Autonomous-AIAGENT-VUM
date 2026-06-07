# Vulnerability Intelligence Hub

> **An autonomous, AI-powered CVE tracking and patch lifecycle management system grounded in real public threat intelligence**

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136+-green.svg)
![Ollama](https://img.shields.io/badge/LLM-Ollama%20llama3.1%3A8b-purple.svg)
![NVD](https://img.shields.io/badge/Data-NVD%20%7C%20EPSS%20%7C%20CISA%20KEV-red.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## What This Is

The Vulnerability Intelligence Hub is a full-stack web application that autonomously scans enterprise security and IT-operations software for known CVEs, enriches them with real-world threat intelligence from official government and industry sources, and uses a locally-running large language model to generate actionable security briefings — with zero paid AI/API costs and no private vulnerability context sent to a hosted LLM.

The moment you launch it, it goes to work. No manual setup. No clicking through wizards. No paid subscriptions.

---

## The Problem It Solves

Security teams managing tools like Nessus Manager, Trend Micro, Grafana Enterprise, Burp Suite, Tenable Security Center, and ServiceNow MID Server face a common challenge: knowing *which CVEs affect their stack right now, how dangerous they actually are, and what to do first.* Traditional answers involve expensive commercial scanners, paid threat feeds, and manual analyst time.

This application replaces all of that with free official data, a local LLM, and a composite risk model that ranks vulnerabilities by real-world exploitability — not just theoretical severity.

| Challenge | Solution |
|-----------|----------|
| **No visibility into CVE exposure** | Auto-scans NVD on launch for every registered service |
| **Raw CVSS scores don't reflect real risk** | Composite scoring: CVSS + EPSS exploit probability + CISA KEV status |
| **AI tools leak sensitive data to the cloud** | 100% local LLM inference via Ollama — nothing leaves your machine |
| **Manual patch evidence collection** | Automated BEFORE/AFTER snapshot comparison |
| **Inconsistent CR documentation** | Auto-generated Change Request summaries for STAGE and PROD |
| **No audit trail** | Full lifecycle state machine with timestamped transitions |

---

## Deployment Status

This project is currently intended to run locally.

The previous Railway-hosted deployment is no longer active, so users should run the application on their own machine using the local setup instructions below.

Because the AI layer uses Ollama for local inference, Ollama must be installed and running before starting the application.

There is currently no live hosted demo; the project is intended to be reviewed and run locally.


## How It Works — End to End

### 1. Autonomous CVE Discovery

On startup, the application queries the **NIST National Vulnerability Database (NVD) API v2** for each registered service using keyword searches. It creates a BEFORE snapshot for each service — a real-time picture of its current CVE exposure — automatically, with no user interaction required.

A **"Scan All Services"** button on the dashboard lets you trigger a fresh scan at any time.

### 2. Three-Layer Threat Intelligence Enrichment

Every CVE discovered is enriched from three free official sources in a single pipeline pass:

| Source | Data Provided | Update Frequency |
|--------|--------------|-----------------|
| **NIST NVD** | CVSS v3.1 score, attack vector, description, vendor/product | Per-CVE, 7-day cache |
| **FIRST.org EPSS** | Exploit probability (0–100%) — likelihood of active exploitation within 30 days | Bulk lookup, 7-day cache |
| **CISA KEV** | Known Exploited Vulnerabilities — CVEs already weaponized in real attacks | Full catalog, 24-hour cache |

### 3. Composite Risk Scoring

A custom formula combines all three intelligence signals into a single 0–100 risk score:

```
Risk Score = (CVSS / 10 × 60) + (EPSS × 30) + (10 if on CISA KEV list)
```

This means a CVSS 9.8 vulnerability with no active exploitation scores lower than a CVSS 7.5 that's already on the CISA active exploitation list. **Risk is measured by real-world threat, not theoretical severity.**

### 4. Local LLM Intelligence (Ollama — 100% Private)

A locally-running **llama3.1:8b** model via Ollama reads the enriched CVE data and produces:

- **AI Fleet Briefing** — state of the entire fleet, top risks by CVE ID and service name, prioritized remediation steps with specific service references
- **Per-Event Patch Briefings** — before/after patch comparisons, what was fixed, what still matters, posture verdict (LOW / MEDIUM / HIGH / CRITICAL)
- **AI Action Plan Narratives** — professional Markdown explanations for each step in the patch lifecycle
- **Interactive AI Chat** — ask follow-up questions about any specific patch event; the model is grounded to exact numbers and cannot hallucinate CVE data

The LLM is architecturally grounded: every prompt contains exact CVSS scores, EPSS percentiles, and CVE IDs. The model is instructed to use only those numbers and name specific services — never generic references.

### 5. Patch Lifecycle State Machine

Every patch event progresses through a deterministic lifecycle with enforced transitions:

```
DEV_EVIDENCE_CAPTURED → DEV_VERIFIED → STAGE_CR_READY → STAGE_PATCHED → PROD_CR_READY → PROD_PATCHED → CLOSED
```

Invalid transitions are blocked. You cannot promote to STAGE without DEV evidence. You cannot close without reaching PROD_PATCHED. At each stage, the system auto-generates professional Change Request documents.

---

## Dashboard Features

### Intelligence KPI Cards
- **Unique CVEs** — total distinct CVEs across all services (with enrichment count)
- **CISA KEV** — CVEs that are actively exploited in real-world attacks
- **High EPSS** — CVEs with ≥ 70% probability of being exploited within 30 days
- **CVSS ≥ 9.0** — critical-severity CVEs by base score
- **Patch Effectiveness** — percentage of known CVEs addressed across patched events
- **Patch Events** — total events tracked with evidence count

Every card is clickable and opens a drill-down panel showing the underlying CVE list.

### Visualizations
- **Severity Distribution** — switchable Donut / Bar / Radar / Polar chart
- **Top Remaining CVEs by Real-World Risk** — ranked by composite score (CISA KEV × EPSS × CVSS)
- **Top Services by Risk** — service-level aggregate risk breakdown
- **Patch Effectiveness Trend** — chronological effectiveness line chart across events
- **CVSS and EPSS Histograms** — distribution of CVEs across score buckets

### AI Fleet Briefing
Lazy-loaded on each dashboard visit. Checks Ollama availability, generates a structured briefing with:
- State of the fleet (service-specific, not generic)
- Top 3 highest-risk CVEs with IDs and scores
- 3 prioritized remediation actions naming specific services
- Overall posture verdict
- 10-minute in-process cache; one-click regeneration

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy ORM |
| **Database** | SQLite (zero-config, portable) |
| **Templating** | Jinja2 (Starlette 1.0 compatible) |
| **Frontend** | Tailwind CSS, Chart.js 4, marked.js, tippy.js |
| **Local LLM** | Ollama (llama3.1:8b, local inference — no internet required for AI generation after the model is installed) |
| **CVE Intelligence** | NVD API v2, FIRST.org EPSS API, CISA KEV JSON feed |
| **Architecture** | Service layer + State Machine + async background scanning |

---

## Project Structure

```text
Autonomous-AIAGENT-VUM/
├── app/
│   ├── main.py                     # FastAPI entrypoint + background NVD auto-scan
│   ├── database.py                 # SQLite + SQLAlchemy configuration
│   ├── models.py                   # ORM models: Service, PatchEvent, Vulnerability,
│   │                               #   CVEIntelligence, AIAnalysis
│   ├── state.py                    # Patch lifecycle state machine
│   ├── services/
│   │   ├── nvd_cpe_scan.py         # NVD keyword search + auto patch event creation  ← NEW
│   │   ├── cve_enrichment.py       # NVD / EPSS / CISA KEV enrichment + caching
│   │   ├── fleet_intel.py          # Fleet-wide risk aggregation for dashboard
│   │   ├── ai_agent.py             # LLM briefing, chat, and action narrative generation
│   │   ├── ollama_client.py        # Local Ollama API wrapper
│   │   ├── action_planner.py       # Deterministic patch lifecycle recommender
│   │   ├── synthetic_data.py       # Synthetic BEFORE/AFTER snapshot generation
│   │   ├── diff.py                 # Fixed vulnerability diffing + severity counts
│   │   ├── cr_text.py              # Change Request document generation
│   │   └── real_cve_catalog.py     # Curated CVE pool for synthetic mode
│   └── web/
│       └── routes.py               # All HTTP route handlers
├── templates/
│   ├── base.html
│   ├── dashboard.html              # Intelligence hub with KPIs, charts, AI briefing
│   ├── patch_event_detail.html     # Event detail + AI chat + lifecycle controls
│   └── vulnerability_analysis.html # Full analysis view with charts and export
├── static/
├── requirements.txt
└── README.md
```

---

## Getting Started

### Prerequisites

- **Python 3.12+**
- **Ollama** — for local LLM inference

#### Install Ollama

Download from [ollama.com](https://ollama.com) and pull the model:

```bash
ollama pull llama3.1:8b
```

Verify it runs:

```bash
ollama serve
```

Ollama must be running at `http://localhost:11434` before starting the application. The dashboard shows a live Ollama status indicator.

---

### 1. Clone the Repository

```bash
git clone <https://github.com/Euris-1/Autonomous-AIAGENT-VUM.git>
cd Autonomous-AIAGENT-VUM
```

### 2. Create and Activate a Virtual Environment

**Windows:**
```bash
python -m venv env
env\Scripts\activate
```

**macOS / Linux:**
```bash
python -m venv env
source env/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python -m uvicorn app.main:app --reload --port 8080
```

> **Note for Windows users:** Port 8000 is frequently reserved by Hyper-V or WSL. Use `--port 8080` or any available port above 8000.

Open your browser at **http://127.0.0.1:8080/**

---

## First Launch Behavior

On first launch the application:

1. Creates the SQLite database (`patch_tracker.db`) automatically
2. Seeds all default services: Nessus Manager, Trend Micro, Tenable Security Center, ServiceNow MID Server, Grafana Enterprise, Burp Suite
3. **Immediately starts a background NVD scan** — querying the National Vulnerability Database for real CVEs affecting each service
4. Populates the dashboard with real CVE data, EPSS scores, and CISA KEV flags within ~60 seconds
5. The AI Fleet Briefing auto-loads once Ollama is available and CVE data is present

**No manual steps required.** Refresh the dashboard after ~60 seconds to see the full intelligence picture.

---

## Environment Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(none)* | Free NVD API key — raises rate limit from 5 req/30s to 50 req/30s. Get one at [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama daemon URL |
| `OLLAMA_MODEL` | `llama3.1:8b` | Model to use for inference |
| `OLLAMA_TIMEOUT_S` | `600` | Inference timeout in seconds |

---

## Workflow: From Scan to Closed

```text
1. AUTO-SCAN  →  Launch app; NVD scan runs automatically for all services
2. REVIEW     →  Dashboard shows real CVEs ranked by composite risk score
3. ANALYZE    →  AI Fleet Briefing names specific CVEs and services to address
4. PATCH      →  Apply fixes to your actual systems (outside this app)
5. GENERATE   →  Run AFTER snapshot to capture post-patch state
6. COMPUTE    →  System diffs BEFORE/AFTER; shows what's fixed vs remaining
7. BRIEF      →  AI generates per-event patch briefing with verdict
8. DOCUMENT   →  Auto-generate STAGE and PROD Change Request summaries
9. PROMOTE    →  Advance through DEV → STAGE → PROD → CLOSED lifecycle
```

### Manual Scan

At any time, click **"Scan All Services"** on the dashboard to run a fresh NVD scan. New patch events are created alongside existing ones, building a historical record of your CVE exposure over time.

---

## Data Privacy

| Data Type | Stays Local? |
|-----------|-------------|
| Public CVE/service keyword lookups | Sent only to official public threat intelligence sources such as NVD, EPSS, and CISA KEV |
| LLM prompts and responses | Yes — Ollama runs entirely on your machine |
| Vulnerability data | Yes — stored in local SQLite only |
| EPSS / KEV lookups | Public CVE IDs only; no company context sent |

No company names, hostnames, internal identifiers, or sensitive context ever leave your machine.

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `N` | New Patch Event |
| `D` | Go to Dashboard |
| `A` | Go to Analysis view |
| `?` | Show shortcuts help |
| `Esc` | Close modals |

---

## Business Value

| Benefit | Impact |
|---------|--------|
| **Real threat intelligence** | CVSS + EPSS + CISA KEV from official sources — same data government agencies use |
| **AI-powered prioritization** | Composite risk scoring surfaces what to fix first, not just what scores highest |
| **Zero cost** | Every data source is free; local LLM inference has no per-call cost |
| **Zero data exposure** | Full air-gap capability; sensitive environments can run with no internet after first CVE cache |
| **Audit trail** | Complete timestamped lifecycle with Change Request documentation |
| **Speed** | Full fleet CVE briefing in under 60 seconds from cold start |

---

## License

MIT License — See LICENSE file for details.

---

## Author

Built by Chayim Euris Garcia — combining real public threat intelligence, local LLM inference, and production-grade software architecture into a single autonomous security intelligence platform.
