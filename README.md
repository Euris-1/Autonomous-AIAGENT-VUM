# Vulnerability Intelligence Hub

> **An autonomous, AI-powered CVE tracking and patch lifecycle management system grounded in real public threat intelligence**

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136+-green.svg)
![LLM](https://img.shields.io/badge/LLM-Ollama%20%7C%20Groq-purple.svg)
![NVD](https://img.shields.io/badge/Data-NVD%20%7C%20EPSS%20%7C%20CISA%20KEV-red.svg)
![Deploy](https://img.shields.io/badge/Deployed-Railway-black.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**Live Demo:** https://autonomous-aiagent-vum-production.up.railway.app/

---

## What This Is

The **Vulnerability Intelligence Hub** is a full-stack web application that autonomously scans enterprise security and IT-operations software for known CVEs, enriches them with real-world threat intelligence from official government and industry sources, and uses a **large language model** to generate actionable security briefings.

The LLM backend is dual-mode:
- **Local mode (Ollama)** — inference runs entirely on your machine. Nothing leaves localhost. No API costs. Full air-gap capability.
- **Cloud fallback (Groq)** — when Ollama is not running, the app automatically switches to Groq's free API, which runs the same llama3.1 model family in the cloud. This makes the live demo accessible to anyone without any local setup.

The moment you launch it, it goes to work. No manual setup. No clicking through wizards. No paid subscriptions.

---

## The Problem It Solves

Security teams managing tools like Nessus Manager, Trend Micro, Grafana Enterprise, Burp Suite, Tenable Security Center, and ServiceNow MID Server face a common challenge: knowing *which CVEs affect their stack right now, how dangerous they actually are, and what to do first.* Traditional answers involve expensive commercial scanners, paid threat feeds, and manual analyst time.

This application replaces all of that with free official data, a composite risk model, and an LLM that ranks vulnerabilities by real-world exploitability — not just theoretical severity.

| Challenge | Solution |
|-----------|----------|
| **No visibility into CVE exposure** | Auto-scans NVD on launch for every registered service |
| **Raw CVSS scores don't reflect real risk** | Composite scoring: CVSS + EPSS exploit probability + CISA KEV status |
| **AI tools leak sensitive data** | Local Ollama inference option — nothing leaves your machine |
| **Sharing requires local LLM setup** | Groq cloud fallback — live demo works for anyone, zero install |
| **Manual patch evidence collection** | Automated BEFORE/AFTER snapshot comparison |
| **Inconsistent CR documentation** | Auto-generated Change Request summaries for STAGE and PROD |
| **No audit trail** | Full lifecycle state machine with timestamped transitions |

---

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

### 4. Dual-Mode LLM Intelligence

The AI layer uses a priority-based backend selection:

```
Is Ollama running locally?
  YES → use llama3.1:8b on your machine (private, free, air-gapped)
  NO  → is GROQ_API_KEY set?
          YES → use llama-3.1-8b-instant via Groq API (same model, cloud)
          NO  → AI features disabled, rest of app still works
```

Both backends produce identical outputs — the same prompts, the same structured responses, the same `OllamaResult` object returned to the app. The switch is invisible to the rest of the codebase.

The LLM generates:
- **AI Fleet Briefing** — state of the entire fleet, top risks by CVE ID and service name, prioritized remediation steps
- **Per-Event Patch Briefings** — before/after comparisons, what was fixed, what still matters, posture verdict (LOW / MEDIUM / HIGH / CRITICAL)
- **AI Action Plan Narratives** — professional Markdown explanations for each lifecycle step
- **Interactive AI Chat** — ask follow-up questions grounded in exact CVE numbers

The LLM is architecturally grounded: every prompt contains exact CVSS scores, EPSS percentiles, and CVE IDs. The model is instructed to use only those numbers — it cannot hallucinate CVE data.

### 5. Patch Lifecycle State Machine

Every patch event progresses through a deterministic lifecycle with enforced transitions:

```
DEV_EVIDENCE_CAPTURED → DEV_VERIFIED → STAGE_CR_READY → STAGE_PATCHED → PROD_CR_READY → PROD_PATCHED → CLOSED
```

Invalid transitions are blocked. You cannot promote to STAGE without DEV evidence. You cannot close without reaching PROD_PATCHED. At each stage, the system auto-generates professional Change Request documents.

---

## Dashboard Features

### Intelligence KPI Cards
- **Unique CVEs** — total distinct CVEs across all services
- **CISA KEV** — CVEs actively exploited in real-world attacks
- **High EPSS** — CVEs with ≥ 70% probability of exploitation within 30 days
- **CVSS ≥ 9.0** — critical-severity CVEs by base score
- **Patch Effectiveness** — percentage of known CVEs addressed
- **Patch Events** — total events tracked with evidence count

### Visualizations
- **Severity Distribution** — switchable Donut / Bar / Radar / Polar chart
- **Top Remaining CVEs by Real-World Risk** — ranked by composite score
- **Top Services by Risk** — service-level aggregate risk breakdown
- **Patch Effectiveness Trend** — chronological effectiveness line chart
- **CVSS and EPSS Histograms** — distribution across score buckets

### AI Fleet Briefing
Lazy-loaded on each dashboard visit. Checks LLM availability, generates a structured briefing with service-specific CVE analysis, prioritized remediation actions, and an overall posture verdict. 10-minute in-process cache with one-click regeneration.

---

## Tech Stack

| Layer | Technology | Why |
|-------|------------|-----|
| **Backend** | Python 3.12, FastAPI | Async, fast, automatic API docs |
| **Database** | SQLite + SQLAlchemy ORM | Zero-config, portable, abstracted |
| **Templating** | Jinja2 | Server-side HTML rendering |
| **Frontend** | Tailwind CSS, Chart.js 4, marked.js | No build step, fast charts, markdown rendering |
| **Local LLM** | Ollama (llama3.1:8b) | Private, no API cost, air-gap capable |
| **Cloud LLM** | Groq API (llama-3.1-8b-instant) | Free fallback, same model, live demo accessible |
| **CVE Intelligence** | NVD API v2, FIRST.org EPSS, CISA KEV | Official government/industry sources, all free |
| **Deployment** | Railway | GitHub-connected, env var management, free tier |

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
│   │   ├── nvd_cpe_scan.py         # NVD keyword search + auto patch event creation
│   │   ├── cve_enrichment.py       # NVD / EPSS / CISA KEV enrichment + caching
│   │   ├── fleet_intel.py          # Fleet-wide risk aggregation for dashboard
│   │   ├── ai_agent.py             # LLM briefing, chat, and action narrative generation
│   │   ├── ollama_client.py        # Dual-mode LLM client: Ollama (local) + Groq (cloud)
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
├── Procfile                        # Railway start command
├── requirements.txt
└── README.md
```

---

## Getting Started

### Option A — Live Demo (no setup required)

Visit: **https://autonomous-aiagent-vum-production.up.railway.app/**

The live demo uses Groq's free API for AI inference. No installation needed.

---

### Option B — Run Locally with Ollama (fully private)

#### Prerequisites
- Python 3.12+
- Ollama — download from [ollama.com](https://ollama.com)

```bash
ollama pull llama3.1:8b
ollama serve
```

#### 1. Clone and Set Up

```bash
git clone https://github.com/Euris-1/Autonomous-AIAGENT-VUM.git
cd Autonomous-AIAGENT-VUM
python -m venv env
```

**Windows:**
```bash
env\Scripts\activate
```

**macOS / Linux:**
```bash
source env/bin/activate
```

```bash
pip install -r requirements.txt
```

#### 2. Run

```bash
python -m uvicorn app.main:app --reload --port 8080
```

Open **http://127.0.0.1:8080/**

---

### Option C — Run Locally with Groq (no Ollama needed)

Get a free API key at [console.groq.com](https://console.groq.com), then:

```bash
# Create a .env file in the project root
echo GROQ_API_KEY=your_key_here > .env
python -m uvicorn app.main:app --reload --port 8080
```

The app detects Ollama is absent and automatically uses Groq.

---

## First Launch Behavior

On first launch the application:

1. Creates the SQLite database (`patch_tracker.db`) automatically
2. Seeds all default services: Nessus Manager, Trend Micro, Tenable Security Center, ServiceNow MID Server, Grafana Enterprise, Burp Suite
3. **Starts a background NVD scan** — querying the National Vulnerability Database for real CVEs affecting each service
4. Populates the dashboard with real CVE data, EPSS scores, and CISA KEV flags within ~60 seconds
5. The AI Fleet Briefing auto-loads once any LLM backend is available

**No manual steps required.** Refresh the dashboard after ~60 seconds to see the full intelligence picture.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | *(none)* | Groq cloud API key — enables AI when Ollama is absent. Free at [console.groq.com](https://console.groq.com) |
| `GROQ_MODEL` | `llama-3.1-8b-instant` | Groq model to use |
| `NVD_API_KEY` | *(none)* | Raises NVD rate limit from 5 to 50 req/30s. Free at [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama daemon URL |
| `OLLAMA_MODEL` | `llama3.1:8b` | Local Ollama model |
| `OLLAMA_TIMEOUT_S` | `600` | Local inference timeout in seconds |

---

## Deploying to Railway

1. Push the repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Select your repo — Railway detects the `Procfile` and sets the start command automatically
4. Go to **Variables** tab → add `GROQ_API_KEY` with your Groq key
5. Railway provides a public URL — share it anywhere

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

---

## Data Privacy

| Data Type | Local Mode | Cloud Demo |
|-----------|-----------|------------|
| LLM prompts (CVE data + scores) | Never leaves machine | Sent to Groq API |
| Vulnerability database | Local SQLite only | Local SQLite only |
| CVE IDs sent to NVD/EPSS/KEV | Public IDs only | Public IDs only |
| Company names or hostnames | Never stored | Never stored |

For sensitive environments, run in local Ollama mode — full air-gap capability after first CVE cache is populated.

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

## License

MIT License — See LICENSE file for details.

---

## Author

Built by Chayim Euris Garcia — combining real public threat intelligence, dual-mode LLM inference, and production-grade software architecture into a single autonomous security intelligence platform.
