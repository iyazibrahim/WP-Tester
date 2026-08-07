# WP Tester — Workflow

## Current status

Scanner tooling fixes for Nikto, httpx, Nuclei, WPScan, and gau are implemented in-repo. **Live scan validation is manual on the cloud server** (not run by the agent).

## Completed: scanner tool fixes (2026-08-03)

### Root causes addressed

| Tool | Issue | Fix |
|------|--------|-----|
| Nikto | Missing `XML::Writer` Perl module | Install `libxml-writer-perl` (+ SSL/LWP deps) in Dockerfile / installer |
| httpx | Python `httpx` CLI shadowed ProjectDiscovery binary | Prefer `/usr/local/bin/httpx`, remove venv shim, PATH puts `/usr/local/bin` first |
| Nuclei | No templates in image / `UPDATE_NUCLEI_TEMPLATES=0` | Bake `nuclei -ut` at build; default compose env to `1`; detect missing-template notes |
| WPScan | Exit code `5` (vulnerable) treated as partial | Accept `{0, 5}` as successful scans |
| gau | Providers limited to wayback+otx | Config `gau_providers` default `wayback,otx,commoncrawl`; timeout 240s |

### Files touched

- `Dockerfile`
- `docker-compose.yml`
- `lib/tools.py`
- `lib/installer.py`
- `lib/config.py`
- `config/scan-config.json`
- `README.md`
- `tests/test_tool_status.py`
- `workflow.md`

## Follow-up fixes (2026-08-03)

| Tool | Issue | Fix |
|------|--------|-----|
| httpx | Exit code 2 in ~0.06s with `/usr/local/bin/httpx` | Invalid short flag `-ws` on httpx v1.7.1 — replaced with `-websocket` |
| Wapiti | Crash at `gettext.translation(... codeset=...)` on Python 3.11 | Pin `wapiti3>=3.1.8,<3.2` (3.2+ needs Py3.12) + Dockerfile patch removing `codeset=` |

### Manual re-check after rebuild

```bash
docker compose build --no-cache
docker compose up -d

# httpx flags must include -websocket (not -ws)
docker compose exec dp-security-platform httpx -u https://example.com -silent -sc -title -td -websocket -fr -json -o /tmp/httpx.json

# Wapiti must import cleanly
docker compose exec dp-security-platform wapiti --help
```

## Manual validation checklist (cloud server)

After pulling these changes on the cloud host:

```bash
# Rebuild & restart
docker compose build
docker compose up -d

# Binary / dependency sanity (inside container)
docker compose exec dp-security-platform which httpx
docker compose exec dp-security-platform httpx -version   # must be ProjectDiscovery, not Python
docker compose exec dp-security-platform perl -MXML::Writer -e1
docker compose exec dp-security-platform nuclei -tl | head
```

Then re-run the WordPress scan profile against your target and confirm:

1. **Nikto** — no `XML::Writer` error; status `completed` / `completed_partial` with `nikto.json`
2. **httpx** — status `completed` with `httpx.json` (not failed in under ~1s)
3. **Nuclei** — longer runtime with templates present; empty findings OK only when templates exist
4. **WPScan** — vulns / exit `5` → `completed` (not `completed_partial` solely because vulns were found)
5. **gau** — may still be empty for some hosts; providers should include commoncrawl when configured

## Next steps

- [ ] Deploy/rebuild on cloud server
- [ ] Run manual checklist above
- [ ] Record any remaining tool anomalies in this file

## Completed: A4 report layout fix (2026-08-07)

### Problem
HTML security assessment reports used a wide web layout (`max-width: 1240px` / `1320px`), so on-screen viewing looked oversized and triggered horizontal scrolling. A4 rules existed only under `@media print`.

### Fix
- On-screen report is now an A4-width page preview (`210mm`, centered, shrinks on narrow viewports)
- Removed non-wrapping brand tagline; grids use `minmax(0, …)` so columns can shrink
- Wide tables wrapped in `.table-scroll` so overflow stays inside the page, not the whole window
- Print styles remain `@page { size: A4 }` and strip page chrome for clean PDF/print output
- Applied to `templates/report-template.html` and the dark fallback CSS in `lib/reports.py`

### Files touched
- `templates/report-template.html`
- `lib/reports.py`
- `workflow.md`

### Validation
- Template asserts: `210mm`, `table-scroll`, `size: A4`, no `1240px`
- `from lib.reports import generate_html_report` OK
- `pytest tests/` → 10 passed

### Note
Existing saved report HTML files are static; re-run a scan (or regenerate from JSON) to pick up the new layout.
