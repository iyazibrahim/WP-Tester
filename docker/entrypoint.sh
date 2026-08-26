#!/usr/bin/env bash
set -euo pipefail

cd /app

mkdir -p reports logs config

if [[ "${UPDATE_NUCLEI_TEMPLATES:-0}" == "1" ]] && command -v nuclei >/dev/null 2>&1; then
    echo "[*] Updating nuclei templates..."
    nuclei -ut || true
fi

if [[ $# -eq 0 || "$1" == "app" ]]; then
    shift || true
        echo "[+] Starting DP Security Platform via gunicorn on 0.0.0.0:5000"
        exec gunicorn \
            --workers 1 \
            --threads 4 \
            --worker-class gthread \
            --bind 0.0.0.0:5000 \
            --timeout 120 \
            --graceful-timeout 30 \
            --keep-alive 5 \
            --max-requests 200 \
            --max-requests-jitter 50 \
            --log-level info \
            --logger-class docker.gunicorn_logging.Logger \
            --access-logfile logs/access.log \
            --error-logfile logs/error.log \
            app:app "$@"
fi

if [[ "$1" == "scanner" ]]; then
    shift
    exec python3 scanner.py "$@"
fi

exec "$@"
