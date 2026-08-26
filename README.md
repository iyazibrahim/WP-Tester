# DP Security Platform

Docker-first security assessment platform for web applications, CMS platforms, and APIs.

DP Security Platform, operated under Digital Penang, orchestrates recon and vulnerability tools into one workflow, normalizes findings, maps them to remediation guidance, and serves results in an interactive dashboard and portable report formats.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Quick Start (Docker)](#quick-start-docker)
- [Quick Start (Native Fallback)](#quick-start-native-fallback)
- [Authentication and Security Model](#authentication-and-security-model)
- [Usage](#usage)
- [Scan Profiles and Modes](#scan-profiles-and-modes)
- [Architecture](#architecture)
- [Reports](#reports)
- [Project Structure](#project-structure)
- [Configuration Reference](#configuration-reference)
- [Operations](#operations)
- [GitHub Publishing Checklist](#github-publishing-checklist)
- [Legal Notice](#legal-notice)

## Overview

Security assessments usually require many disconnected tools with different install methods and output formats. DP Security Platform provides a single control plane that:

- Selects a profile-aware toolchain.
- Runs passive and active phases.
- Correlates output from multiple tools.
- Produces consistent reports for engineering and security teams.

## Key Features

- Profile-aware targeting for WordPress, Joomla, Drupal, Web App, and Custom API.
- Unified pipeline across 18+ open-source tools.
- Environment-aware logic for localhost/internal targets.
- SPA dashboard for targets, scan launch, status tracking, and report browsing.
- Built-in monitoring for website uptime, TCP/host reachability, heartbeat-based office NUC visibility, and Telegram incident alerts.
- Report management in UI: open, download artifacts, rename, and delete.
- Configurable report profiles (executive/technical/full) and optional manual-assessment appendix.
- Built-in remediation database mapping findings to fix guidance.
- Docker-first deployment with native install as an optional developer fallback.
- First-run setup auth flow with no hardcoded default credentials.

## Quick Start (Docker)

Recommended for Linux VPS/NUC deployments.

The container image uses a slim Debian runtime with a curated scanner toolset so it stays portable across smaller VPS instances.

### Prerequisites

- Docker Engine
- Docker Compose plugin (`docker compose`)

### Run

```bash
git clone <repository_url> dp-security-platform
cd dp-security-platform
docker compose build
docker compose up -d
```

Open:

```text
http://<your-server-ip>:5000
```

On first launch, DP Security Platform redirects to `/setup` for one-time admin creation.

### Persistent Data

- `./config` for runtime config, tokens, auth, and targets.
- `./reports` for generated reports.
- `./logs` for runtime/container logs.

## Quick Start (Native Fallback)

### Prerequisites

- Python 3.10+

### Linux/macOS

```bash
git clone <repository_url> dp-security-platform
cd dp-security-platform
chmod +x omniscan.sh
./omniscan.sh --install
./omniscan.sh app
```

### Windows (PowerShell)

```powershell
git clone <repository_url> dp-security-platform
cd dp-security-platform
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scanner.py --install
python app.py
```

Open:

```text
http://localhost:5000
```

## Authentication and Security Model

DP Security Platform is GitHub-safe by default and avoids shipping static credentials.

- No fixed default email/password in source.
- First run requires one-time setup at `/setup`.
- Passwords are stored hashed in `config/auth.json`.
- After setup, `/setup` is locked and login is served at `/login`.
- Protected API routes require authenticated session.

Sensitive runtime files that should never be committed:

- `config/auth.json`
- `config/tokens.json`
- `config/email-config.json`

## Usage

### Web Dashboard

Start app:

```bash
./omniscan.sh app
```

Use dashboard to:

- Manage targets and profiles.
- Configure token-backed tools.
- Configure module visibility and monitoring settings.
- Launch/cancel scans.
- Manage monitored assets and heartbeat-backed uptime checks.
- Monitor scan progress and ETA.
- Open/download/rename/delete reports.

### CLI

```bash
# Interactive menu
./omniscan.sh

# Passive scan
./omniscan.sh --target https://example.com --mode passive --profile webapp --ci

# Active WordPress scan
./omniscan.sh --target https://example.com --mode active --profile wordpress --ci

# Full API scan + email notification
./omniscan.sh --target https://example.com --mode full --profile api --ci --email

# Demo report generation
./omniscan.sh --demo
```

## Scan Profiles and Modes

### Profiles

| Profile | Typical Tools | Purpose |
| --- | --- | --- |
| `wordpress` | WPScan, Nuclei WP tags | WordPress core/plugin/theme assessment |
| `joomla` | JoomScan, CMSMap | Joomla-specific checks and exposures |
| `drupal` | Droopescan, CMSMap | Drupal version/module exposure checks |
| `webapp` | ffuf, Nuclei CVE tags | Generic web app recon and vuln testing |
| `api` | Nuclei API tags | API-focused checks and misconfigurations |
| `auto` | Adaptive | Chooses flow based on detected stack |

### Modes

- `passive`: scan/recon only (passive tools only).
- `active`: active tools only, aggressive scanning and testing.
- `full`: passive + active combined for maximum coverage (longer runtime).

### Toolset Profiles

| Toolset | Purpose | Default Behavior |
| --- | --- | --- |
| `portable_core` | Slim Docker-friendly coverage for smaller VPS deployments | Enabled by default |
| `deep_scan` | Optional heavier tooling for CMS- and injection-heavy follow-up testing | Opt-in |

### Recommended Docker Defaults

The default Docker profile is tuned for predictable completion and lower storage/runtime overhead:

- `toolset_profile: portable_core`
- `strict_tool_coverage: false`
- `adaptive_tool_selection: true`
- `automation_scheduler: true`
- `max_parallel_tools: 2`
- `max_parallel_heavy_tools: 1`
- `scan_hard_timeout_seconds: 2700`

With this policy enabled, DP Security Platform adapts execution to the target surface and still records completed, partial, skipped, timeout, and no-output tool outcomes in generated reports.

## Architecture

High-level phases:

1. Target validation and profile selection.
2. Passive reconnaissance (tech stack, headers, TLS, CORS, discovery).
3. Profile-driven active tooling.
4. Normalization and severity mapping.
5. Remediation enrichment.
6. Report generation and dashboard indexing.
7. Lightweight uptime monitoring, heartbeat ingestion, and transition-based incident alerting.

Representative portable-core passive tooling:

- httpx, WhatWeb, SSLyze, Corsy, Subfinder, gau, and Katana when applicable.

Representative portable-core active tooling:

- Nuclei, ffuf, Feroxbuster, Arjun, Dalfox, and Wapiti, with deeper CMS or injection tooling reserved for `deep_scan`.

## Reports

Each scan creates a dedicated report folder:

```text
reports/<target>_<timestamp>/
```

Main artifacts:

- `report.html`: interactive view with severity filters and discovery cards.
- `report.md`: markdown summary for tickets/docs.
- `findings.json`: normalized machine-readable findings.
- Optional exports: SARIF (`.sarif`) and CSV (`.csv`) for platform and GRC ingestion.

Report behavior can be tuned in `config/scan-config.json`:

- `report_profile`: `executive`, `technical`, or `full`
- `include_manual_assessment`: include or suppress manual analytics/narrative sections
- `output_formats`: choose generated outputs (`html`, `markdown`, `json`, `sarif`, `csv`)

## Project Structure

```text
app.py                 # Flask app + API routes + auth/session
scanner.py             # CLI entry and orchestration
lib/                   # Pipeline, parsing, enrichment, reporting
config/                # Runtime JSON config (targets/tokens/auth/settings)
fixes/                 # Remediation mapping database
web/                   # Dashboard frontend (SPA)
docker-compose.yml     # Container orchestration
Dockerfile             # Container image definition
```

## Configuration Reference

| File | Purpose |
| --- | --- |
| `config/targets.json` | Saved targets and selected profile |
| `config/scan-config.json` | Timeouts, rate limits, threads, run parameters |
| `config/ai-policy.json` | AI action policy rules (scope/method/payload/rate limits) |
| `config/tokens.json` | API tokens for integrated tooling |
| `config/auth.json` | Generated admin auth record (hashed password) |
| `fixes/remediation-db.json` | Finding-to-remediation mapping |

## Operations

Common Docker commands:

```bash
# Logs
docker compose logs -f

# Stop stack
docker compose down

# Rebuild and restart
docker compose up -d --build

# Run one-off CLI scan in container
docker compose run --rm dp-security-platform scanner --target https://example.com --mode full --profile auto --ci
```

### 2 GB VPS notes

The compose file caps the container at `1536m` RAM, rotates Docker JSON logs (`10m` × 3), and probes health via `http://127.0.0.1:5000/health` every 60s. Gunicorn runs one `gthread` worker with `--max-requests` recycling so a dead worker cannot leave the container **Up** but Unhealthy for weeks.

Scanner CLIs are downloaded as pinned GitHub release binaries (not compiled with Go/Rust on the VPS), which keeps rebuilds much lighter on small hosts.

Free disk after rebuilds:

```bash
docker image prune -f
docker builder prune -f
df -h
```

If the site stops responding while `docker ps` still shows the container:

```bash
docker inspect dp-security-platform --format "{{json .State.Health}}"
docker compose logs --tail 200 dp-security-platform
free -h
df -h
dmesg -T | grep -iE "oom|killed process" | tail
```

Optional startup behavior:

```bash
# Nuclei templates are baked at image build and skipped on start by default.
# Set to 1 only when you intentionally want a runtime template refresh
UPDATE_NUCLEI_TEMPLATES=1 docker compose up -d
```

Docker tooling notes:

- **httpx**: ProjectDiscovery's Go `httpx` must win over the Python `httpx` CLI. Scanner packages live in `/opt/scanner-venv`; wrappers call those binaries without putting that venv first on `PATH`. Use `-websocket` (not `-ws`) with httpx v1.7.x.
- **Nikto**: Requires Perl `XML::Writer` (`libxml-writer-perl`) for `-Format json`.
- **Nuclei**: Templates are baked at image build (`nuclei -ut`). Runtime refresh is off by default (`UPDATE_NUCLEI_TEMPLATES=0`); set to `1` only when needed.
- **Wapiti / droopescan / sslyze / arjun**: Installed in an isolated `/opt/scanner-venv` so wapiti’s `mitmproxy→Flask<2.3` pin cannot conflict with the Flask 3 app. App deps are in `requirements.txt`; scanner deps are in `requirements-scanners.txt`. Wapiti remains `>=3.1.8,<3.2` on Debian’s Python 3.11 (3.2+ needs Python 3.12+).

Operational reliability knobs in `config/scan-config.json`:

- `scan_time_budget_*_seconds`: planner budget for adaptive low-priority tool skipping near deadline
- `scan_hard_timeout_seconds`: hard upper bound for stale running scans before auto-fail cleanup

AI operator controls in `config/scan-config.json`:

- `ai_operator_enabled`: apply stored AI verification verdicts into finding/report statuses
- `ai_require_approval_high_impact`: require manual approval for state-changing/high-impact actions
- `ai_allow_full_autonomous_testing`: allow approval bypass when a valid token is provided
- `ai_full_testing_bypass_token`: shared secret used to enable full autonomous execution bypass

AI action API endpoints:

- `POST /api/ai/plans`: submit JSON action plan for policy evaluation
- `GET /api/ai/plans/<plan_id>`: fetch evaluated plan and execution status
- `POST /api/ai/plans/<plan_id>/approve`: approve pending high-impact actions
- `POST /api/ai/plans/<plan_id>/execute`: run approved actions with deterministic runner

Execution artifacts:

- Plans are stored in `config/ai-plans.json`
- Target verdict history is stored in `config/ai-results.json`
- Per-scan execution evidence is written to `ai-evidence.jsonl` and `ai-actions.json` inside the scan folder when `scan_id` is provided

## GitHub Publishing Checklist

Before making your repository public:

1. Confirm sensitive runtime files are ignored (`config/auth.json`, tokens, email config).
2. Ensure no hardcoded credentials remain in code, docs, or commit history.
3. Keep `config/`, `reports/`, and `logs/` persisted outside ephemeral containers.
4. Run behind HTTPS (reverse proxy recommended) for internet exposure.
5. Rotate any previously used tokens or credentials before release.

## Legal Notice

Only scan systems that you own or are explicitly authorized to test. Unauthorized security testing may be illegal.
