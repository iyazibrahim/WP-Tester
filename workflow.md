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
