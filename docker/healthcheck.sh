#!/usr/bin/env bash
# Docker/Compose health probe — IPv4 only so localhost never prefers ::1.
set -euo pipefail
curl -fsS --max-time 10 "http://127.0.0.1:5000/health" >/dev/null
