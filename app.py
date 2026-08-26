import logging
import os
import re
import json
import shutil
import subprocess
import threading
import uuid
import time
import functools
import ipaddress
import atexit
from datetime import datetime, timedelta, UTC
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse
from flask import Flask, jsonify, request, send_from_directory, session, redirect, Response, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import safe_join
from lib.assessments import get_catalog, get_workbook, save_workbook, summarize_workbook
from lib.ai_policy import load_policy, evaluate_plan
from lib.ai_runner import execute_actions, persist_evidence
from lib.branding import (
    LOG_FILE_NAME,
    PRODUCT_NAME,
    SERVICE_SLUG,
)
from lib.monitoring import (
    MonitoringService,
    get_modules,
    save_modules,
    get_monitoring_assets,
    get_monitoring_settings,
    get_monitoring_events,
    summarize_monitoring,
)
from lib.reports import apply_report_layout_overrides

# ── Logging setup ───────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            Path(__file__).resolve().parent / "logs" / LOG_FILE_NAME,
            encoding="utf-8",
            delay=True,
        ),
    ],
)
logger = logging.getLogger(SERVICE_SLUG)

app = Flask(__name__, static_folder='web')

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
REPORT_INDEX_FILE = REPORTS_DIR / "report-index.json"
CONFIG_DIR = BASE_DIR / "config"
TARGETS_FILE = CONFIG_DIR / "targets.json"
SCAN_CONFIG_FILE = CONFIG_DIR / "scan-config.json"
TOKENS_FILE = CONFIG_DIR / "tokens.json"
AUTH_FILE = CONFIG_DIR / "auth.json"
AI_POLICY_FILE = CONFIG_DIR / "ai-policy.json"
AI_PLANS_FILE = CONFIG_DIR / "ai-plans.json"
AI_RESULTS_FILE = CONFIG_DIR / "ai-results.json"
MONITORING_SERVICE = MonitoringService()

# ── Auth bootstrap ───────────────────────────────────────────────────────────────

def _load_auth_data():
    if not AUTH_FILE.exists():
        return None
    try:
        data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("email") or not data.get("password_hash"):
        return None
    return data


def _is_auth_initialized() -> bool:
    return _load_auth_data() is not None


_auth_data = _load_auth_data() or {}
_env_secret = os.environ.get("DP_SECURITY_PLATFORM_SECRET_KEY") or os.environ.get("OMNISCAN_SECRET_KEY")
app.secret_key = _auth_data.get("secret_key") or _env_secret or uuid.uuid4().hex
if not _auth_data.get("secret_key") and not _env_secret:
    logger.warning(
        "No persistent secret_key found. Sessions will be invalidated on restart. "
        "Set OMNISCAN_SECRET_KEY environment variable for stable sessions."
    )
app.permanent_session_lifetime = timedelta(hours=12)

# ── Rate limiting ────────────────────────────────────────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[],
        storage_uri="memory://",
    )
    _RATE_LIMIT_ENABLED = True
except ImportError:
    logger.warning("flask-limiter not installed. Rate limiting disabled. Run: pip install Flask-Limiter")
    _RATE_LIMIT_ENABLED = False
    class _NoopLimiter:
        def limit(self, *a, **kw):
            return lambda f: f
    limiter = _NoopLimiter()

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated
SCAN_JOBS: dict[str, dict] = {}
SCAN_JOBS_LOCK = threading.Lock()

# ── Persistent scan job store ────────────────────────────────────────────────────
SCAN_JOBS_FILE = CONFIG_DIR / "scan-jobs.json"
_scan_jobs_dirty = False
_scan_jobs_save_lock = threading.Lock()
_last_scan_jobs_flush_at = 0.0

def _load_scan_jobs_from_disk():
    """Restore scan jobs persisted from prior runs (read-only on startup)."""
    try:
        if SCAN_JOBS_FILE.exists():
            data = json.loads(SCAN_JOBS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                with SCAN_JOBS_LOCK:
                    SCAN_JOBS.update(data)
                logger.info("Loaded %d scan job(s) from disk.", len(data))
    except Exception as exc:
        logger.warning("Could not load scan jobs from disk: %s", exc)

def _flush_scan_jobs_to_disk():
    """Write current SCAN_JOBS to disk (called after status changes)."""
    global _scan_jobs_dirty, _last_scan_jobs_flush_at
    with _scan_jobs_save_lock:
        if not _scan_jobs_dirty:
            return
        try:
            with SCAN_JOBS_LOCK:
                snapshot = dict(SCAN_JOBS)
            SCAN_JOBS_FILE.parent.mkdir(parents=True, exist_ok=True)
            SCAN_JOBS_FILE.write_text(
                json.dumps(snapshot, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            _scan_jobs_dirty = False
            _last_scan_jobs_flush_at = time.time()
        except Exception as exc:
            logger.warning("Could not persist scan jobs: %s", exc)

_load_scan_jobs_from_disk()

DEFAULT_SCAN_ESTIMATES_SECONDS = {
    "passive": 8 * 60,
    "active": 15 * 60,
    "full": 23 * 60,
}


def _safe_scan_host_label(target: str) -> str:
    return str(target or "").replace("https://", "").replace("http://", "").replace("/", "_")


def _scan_dir_for_job(job: dict) -> Path | None:
    raw = job.get("scan_dir")
    if raw:
        return Path(raw)

    target = str(job.get("target", "")).strip()
    started_at = job.get("started_at")
    if not target or not started_at:
        return None

    try:
        ts = datetime.fromtimestamp(float(started_at)).strftime("%Y%m%d_%H%M%S")
    except (TypeError, ValueError, OSError):
        return None

    return REPORTS_DIR / f"{_safe_scan_host_label(target)}_{ts}"


def _scan_completion_patch(job: dict) -> dict | None:
    scan_dir = _scan_dir_for_job(job)
    if scan_dir is None or not scan_dir.exists():
        return None

    marker_path = scan_dir / "scan-complete.json"
    if marker_path.exists():
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            marker = None
        if isinstance(marker, dict):
            patch = {
                "status": "completed",
                "phase": "completed",
                "progress": 100,
                "current_tool": "Completed",
                "scan_dir": str(scan_dir),
            }
            finished_at = marker.get("finished_at")
            if finished_at:
                patch["finished_at"] = finished_at
            report_paths = marker.get("report_paths")
            if isinstance(report_paths, dict) and report_paths:
                patch["report_paths"] = report_paths
            return patch

    report_json = sorted(scan_dir.rglob("report_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not report_json:
        return None

    latest_json = report_json[0]
    stem = latest_json.stem
    report_dir = latest_json.parent
    report_paths = {}
    for key, suffix in {"json": ".json", "html": ".html", "md": ".md", "sarif": ".sarif", "csv": ".csv"}.items():
        candidate = report_dir / f"{stem}{suffix}"
        if candidate.exists():
            report_paths[key] = str(candidate)

    return {
        "status": "completed",
        "phase": "completed",
        "progress": 100,
        "current_tool": "Completed",
        "finished_at": latest_json.stat().st_mtime,
        "report_paths": report_paths,
        "scan_dir": str(scan_dir),
    }


def _scan_stall_patch(job: dict) -> dict | None:
    status = str(job.get("status", "unknown"))
    if status in ("completed", "failed", "cancelled"):
        return None

    now = time.time()
    updated_at = float(job.get("updated_at") or job.get("started_at") or 0)
    stale_for = now - updated_at
    phase = str(job.get("phase", "")).lower()

    # If post-tool phases go stale, fail fast so jobs do not remain in running.
    if phase in {"parsing", "enrichment", "reporting"} and stale_for >= 300:
        patch = {
            "status": "failed",
            "phase": "failed",
            "current_tool": "Failed",
            "finished_at": now,
            "message": "Scan stalled during result processing. Check parser/report logs.",
        }
        scan_dir = _scan_dir_for_job(job)
        if scan_dir is not None:
            patch["scan_dir"] = str(scan_dir)
        return patch

    total_tools = _safe_int(job.get("total_tools"), 0)
    completed_tools = _safe_int(job.get("completed_tools"), 0)
    # Legacy recovery path for jobs that completed tool execution but never
    # reached terminal state.
    if total_tools > 0 and completed_tools >= total_tools and stale_for >= 300:
        patch = {
            "status": "failed",
            "phase": "failed",
            "current_tool": "Failed",
            "finished_at": now,
            "message": "Scan stalled after tool execution. Check server logs for parser or report-generation failures.",
        }
        scan_dir = _scan_dir_for_job(job)
        if scan_dir is not None:
            patch["scan_dir"] = str(scan_dir)
        return patch

    # Additional stale-running recovery when a scan exceeds a hard timeout.
    started_at = float(job.get("started_at") or now)
    elapsed = max(0, now - started_at)
    estimated = max(1, _safe_int(job.get("estimated_seconds"), DEFAULT_SCAN_ESTIMATES_SECONDS["full"]))
    hard_timeout = max(1800, _safe_int(job.get("hard_timeout_seconds"), estimated * 4))
    if status in ("running", "cancelling") and elapsed >= hard_timeout and stale_for >= 180:
        patch = {
            "status": "failed",
            "phase": "failed",
            "current_tool": "Failed",
            "finished_at": now,
            "message": "Scan exceeded hard runtime limit and stopped due to stale progress.",
        }
        scan_dir = _scan_dir_for_job(job)
        if scan_dir is not None:
            patch["scan_dir"] = str(scan_dir)
        return patch

    return None


def _scan_cancel_recovery_patch(job: dict) -> dict | None:
    status = str(job.get("status", "unknown"))
    if status != "cancelling" or not job.get("cancel_requested"):
        return None

    updated_at = float(job.get("updated_at") or job.get("started_at") or 0)
    if (time.time() - updated_at) < 45:
        return None

    patch = {
        "status": "cancelled",
        "phase": "cancelled",
        "current_tool": "Cancelled",
        "finished_at": time.time(),
        "message": "Scan cancelled by user.",
    }
    scan_dir = _scan_dir_for_job(job)
    if scan_dir is not None:
        patch["scan_dir"] = str(scan_dir)
    return patch

# ── Static / SPA ────────────────────────────────────────────────────────────────

# ── Static / SPA ────────────────────────────────────────────────────────────────

# ── Health check ────────────────────────────────────────────────────────────────

@app.route('/health')
def health_check():
    """Docker/load-balancer health probe. Always returns 200 when app is up."""
    return jsonify({"status": "ok", "service": SERVICE_SLUG})


@app.route('/login')
def login_page():
    if not _is_auth_initialized():
        return redirect('/setup')
    if session.get("user"):
        return redirect('/')
    return send_from_directory(app.static_folder, 'login.html')


@app.route('/setup')
def setup_page():
    if _is_auth_initialized():
        return redirect('/login')
    return send_from_directory(app.static_folder, 'setup.html')

@app.route('/')
def index():
    if not _is_auth_initialized():
        return redirect('/setup')
    if not session.get("user"):
        return redirect('/login')
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    # Always allow static assets; protect the SPA entry point
    static_exts = {'.js', '.css', '.ico', '.png', '.jpg', '.svg', '.woff', '.woff2', '.ttf'}
    if any(path.endswith(ext) for ext in static_exts) or path in {'login.html', 'setup.html'}:
        return send_from_directory(app.static_folder, path)
    if not _is_auth_initialized():
        return redirect('/setup')
    if not session.get("user"):
        return redirect('/login')
    return send_from_directory(app.static_folder, path)

# ── Auth endpoints ───────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("15 per minute; 60 per hour")
def auth_login():
    auth = _load_auth_data()
    if not auth:
        return jsonify({"error": "Initial setup is required", "setup_required": True}), 409

    data = request.json or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))
    if email == auth.get('email', '').lower() and check_password_hash(auth['password_hash'], password):
        session['user'] = email
        session.permanent = True
        csrf_token = uuid.uuid4().hex
        session['csrf_token'] = csrf_token
        logger.info("Successful login for %s from %s", email, request.remote_addr)
        return jsonify({"message": "Login successful", "email": email, "csrf_token": csrf_token})
    logger.warning("Failed login attempt for email=%s from %s", email, request.remote_addr)
    return jsonify({"error": "Invalid email or password"}), 401


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    auth = _load_auth_data()
    return jsonify({
        "initialized": bool(auth),
        "authenticated": bool(session.get("user")),
    })


@app.route('/api/auth/setup', methods=['POST'])
@limiter.limit("5 per hour")
def auth_setup():
    if _is_auth_initialized():
        return jsonify({"error": "Initial setup has already been completed"}), 409

    data = request.json or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))
    confirm_password = str(data.get('confirm_password', ''))

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "A valid email is required"}), 400
    if len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    auth_payload = {
        "email": email,
        "password_hash": generate_password_hash(password),
        "secret_key": uuid.uuid4().hex + uuid.uuid4().hex,
    }
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps(auth_payload, indent=2), encoding="utf-8")

    app.secret_key = auth_payload["secret_key"]
    session['user'] = email
    session.permanent = True
    return jsonify({"message": "Setup completed", "email": email})

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({"email": user})

# ── Helpers ─────────────────────────────────────────────────────────────────────

def _load_json(path: Path):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        pass
    return None

def _save_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding='utf-8')


def _load_ai_plan_store() -> dict:
    data = _load_json(AI_PLANS_FILE)
    return data if isinstance(data, dict) else {}


def _save_ai_plan_store(store: dict):
    _save_json(AI_PLANS_FILE, store)


def _load_ai_results_store() -> dict:
    data = _load_json(AI_RESULTS_FILE)
    return data if isinstance(data, dict) else {}


def _save_ai_results_store(store: dict):
    _save_json(AI_RESULTS_FILE, store)


def _scan_dir_for_scan_id(scan_id: str | None) -> Path | None:
    if not scan_id:
        return None
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        raw = (job or {}).get("scan_dir")
    if not raw:
        return None
    return Path(str(raw))


def _is_full_testing_bypass_enabled(scan_cfg: dict, bypass_token: str) -> bool:
    if not bool(scan_cfg.get("ai_allow_full_autonomous_testing", False)):
        return False
    expected = str(scan_cfg.get("ai_full_testing_bypass_token", "")).strip()
    if not expected or not bypass_token:
        return False
    return bypass_token == expected


def _require_target_arg():
    target = (request.args.get("target") or "").strip().rstrip("/")
    if not target:
        return None
    return target


def _safe_int(value, fallback=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _format_eta(seconds: int) -> str:
    total = max(0, int(seconds))
    mins, secs = divmod(total, 60)
    if mins >= 60:
        hours, mins = divmod(mins, 60)
        return f"~{hours}h {mins}m"
    if mins > 0:
        return f"~{mins}m {secs:02d}s"
    return f"~{secs}s"


def _parse_iso_datetime(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except Exception:
        return None


def _severity_weight(sev: str) -> float:
    return {
        "critical": 9.5,
        "high": 7.2,
        "medium": 4.8,
        "low": 2.0,
        "info": 0.8,
    }.get(str(sev or "low").strip().lower(), 2.0)


def _extract_cvss(finding: dict) -> float:
    for key in ("cvss", "cvss_score", "cvss_v3", "cvss_v31"):
        value = finding.get(key)
        if value in (None, ""):
            continue
        try:
            score = float(value)
            if 0 <= score <= 10:
                return score
        except Exception:
            continue
    return 0.0


def _is_internet_facing(asset: str) -> bool:
    parsed = urlparse(str(asset or ""))
    host = parsed.hostname or str(asset or "")
    host = host.strip().strip("/")
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return False
    try:
        ip_obj = ipaddress.ip_address(host)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except Exception:
        pass
    lowered = host.lower()
    if lowered.endswith(".local") or lowered.endswith(".lan"):
        return False
    return True


def _infer_asset_type(asset: str) -> str:
    token = str(asset or "").lower()
    if any(x in token for x in ("api", "graphql", "swagger")):
        return "api"
    if any(x in token for x in ("db", "database", "sql", "postgres", "mysql")):
        return "internal"
    if any(x in token for x in ("iot", "camera", "sensor", "switch", "router", "firewall")):
        return "network"
    if any(x in token for x in ("aws", "azure", "gcp", "cloudfront", "s3")):
        return "cloud"
    if any(x in token for x in ("laptop", "desktop", "workstation", "endpoint", "client")):
        return "endpoint"
    return "internet" if _is_internet_facing(asset) else "internal"


def _load_dashboard_findings(limit_reports: int = 300) -> list[dict]:
    now = datetime.now(UTC)
    selected_reports: list[Path] = []
    seen_targets: set[str] = set()

    index_data = _load_json(REPORT_INDEX_FILE)
    if isinstance(index_data, dict) and isinstance(index_data.get("reports"), list):
        sorted_items = sorted(
            [item for item in index_data.get("reports", []) if isinstance(item, dict)],
            key=lambda item: float(item.get("modified", 0) or 0),
            reverse=True,
        )
        for item in sorted_items:
            target = str(item.get("target_url", "")).strip().lower() or str(item.get("folder", "")).strip().lower()
            if target and target in seen_targets:
                continue
            json_rel = str(item.get("json_path", "")).strip().replace("\\", "/")
            if not json_rel:
                continue
            report_path = REPORTS_DIR / json_rel
            if not report_path.exists():
                continue
            selected_reports.append(report_path)
            if target:
                seen_targets.add(target)
            if len(selected_reports) >= limit_reports:
                break

    if not selected_reports and REPORTS_DIR.exists():
        selected_reports = sorted(REPORTS_DIR.rglob("report_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit_reports]

    findings_rows: list[dict] = []
    for json_file in selected_reports:
        try:
            report_data = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(report_data, dict):
            continue
        findings = report_data.get("findings", [])
        if not isinstance(findings, list):
            continue
        scan_started = _parse_iso_datetime(report_data.get("scan_started_at")) or datetime.fromtimestamp(json_file.stat().st_mtime, UTC)
        target_url = str(report_data.get("target_url", "")).strip()
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            sev = str(finding.get("severity", "low")).strip().lower()
            status = str(finding.get("status", "open")).strip().lower() or "open"
            cvss = _extract_cvss(finding)
            exploitability = str(finding.get("exploitability", "")).strip().lower()
            exploit_available = bool(finding.get("exploit_available") or exploitability == "high")
            asset = str(finding.get("asset") or finding.get("url") or finding.get("endpoint") or target_url or "Unknown")
            asset_type = _infer_asset_type(asset)
            found_at = _parse_iso_datetime(finding.get("first_seen_at") or finding.get("detected_at") or finding.get("created_at")) or scan_started
            age_days = max(0, int((now - found_at).total_seconds() // 86400))
            base = cvss if cvss > 0 else _severity_weight(sev)
            criticality = 1.25 if asset_type in {"internet", "cloud", "network"} else 1.0
            exploit_factor = 1.2 if exploit_available else 1.0
            findings_rows.append(
                {
                    "asset": asset,
                    "asset_type": asset_type,
                    "target": target_url,
                    "cve": str(finding.get("cve", "")).strip(),
                    "cwe": str(finding.get("cwe", "")).strip(),
                    "severity": sev,
                    "cvss": cvss,
                    "status": status,
                    "exploit_available": exploit_available,
                    "title": str(finding.get("title", "")).strip(),
                    "age_days": age_days,
                    "fixed": status in {"fixed", "resolved", "closed", "mitigated"},
                    "risk_points": round(base * criticality * exploit_factor, 2),
                }
            )
    return findings_rows


def _dashboard_insights_payload() -> dict:
    rows = _load_dashboard_findings()
    now = datetime.now(UTC)
    open_rows = [r for r in rows if not r.get("fixed")]
    resolved_rows = [r for r in rows if r.get("fixed")]

    def _sla_days(sev: str) -> int:
        return {"critical": 7, "high": 14, "medium": 30, "low": 60, "info": 90}.get(sev, 30)

    open_count = len(open_rows)
    total_risk_points = sum(float(r.get("risk_points", 0)) for r in open_rows)
    risk_score = min(100, round((total_risk_points / max(1.0, open_count * 10.0)) * 100))

    critical_open = [r for r in open_rows if r.get("severity") == "critical"]
    critical_new = [r for r in critical_open if r.get("age_days", 0) <= 7]
    new_findings_7d = [r for r in open_rows if int(r.get("age_days", 0)) <= 7]
    sla_breached = [r for r in open_rows if int(r.get("age_days", 0)) > _sla_days(str(r.get("severity", "medium")))]
    critical_sla_breached = [r for r in sla_breached if r.get("severity") == "critical"]

    assets = {str(r.get("asset", "Unknown")) for r in open_rows}
    internet_assets = {str(r.get("asset", "Unknown")) for r in open_rows if _is_internet_facing(str(r.get("asset", "")))}
    exposure_pct = round((len(internet_assets) / max(1, len(assets))) * 100, 1)

    mttr_days = None
    if resolved_rows:
        mttr_days = round(sum(int(r.get("age_days", 0)) for r in resolved_rows) / max(1, len(resolved_rows)), 1)

    high_risk_assets = {
        str(r.get("asset", "Unknown"))
        for r in open_rows
        if float(r.get("risk_points", 0)) >= 8.5 or r.get("severity") in {"critical", "high"}
    }

    priority = sorted(
        open_rows,
        key=lambda r: (
            1 if r.get("exploit_available") else 0,
            float(r.get("cvss", 0) or 0),
            float(r.get("risk_points", 0) or 0),
            1 if _is_internet_facing(str(r.get("asset", ""))) else 0,
        ),
        reverse=True,
    )[:12]

    attention_now = []
    for item in priority:
        sev = str(item.get("severity", "medium"))
        due = _sla_days(sev)
        age = int(item.get("age_days", 0))
        sla_text = "Overdue" if age > due else f"{max(0, due - age)} days"
        attention_now.append(
            {
                "asset": item.get("asset"),
                "cve": item.get("cve") or "-",
                "severity": sev,
                "cvss": round(float(item.get("cvss", 0) or 0), 1),
                "exploit_available": bool(item.get("exploit_available")),
                "sla": sla_text,
                "action": "Patch now" if bool(item.get("exploit_available")) and sev in {"critical", "high"} else "Review",
            }
        )

    surface_order = ["internet", "internal", "cloud", "endpoint", "network", "api"]
    surface = {key: {"assets": set(), "vulns": 0} for key in surface_order}
    for row in open_rows:
        key = row.get("asset_type", "internal")
        if key not in surface:
            surface[key] = {"assets": set(), "vulns": 0}
        surface[key]["assets"].add(str(row.get("asset", "Unknown")))
        surface[key]["vulns"] += 1
    attack_surface = [
        {
            "category": key,
            "asset_count": len(surface[key]["assets"]),
            "vulnerability_count": surface[key]["vulns"],
            "density": round(surface[key]["vulns"] / max(1, len(surface[key]["assets"])), 2),
        }
        for key in surface_order
    ]

    cvss_hist = {"0-3": 0, "4-6": 0, "7-8.9": 0, "9-10": 0}
    cwe_counts: dict[str, int] = defaultdict(int)
    exploit_yes = 0
    exploit_no = 0
    for row in open_rows:
        cvss = float(row.get("cvss", 0) or 0)
        if cvss >= 9:
            cvss_hist["9-10"] += 1
        elif cvss >= 7:
            cvss_hist["7-8.9"] += 1
        elif cvss >= 4:
            cvss_hist["4-6"] += 1
        else:
            cvss_hist["0-3"] += 1
        cwe = str(row.get("cwe", "")).strip()
        if cwe:
            cwe_counts[cwe] += 1
        if row.get("exploit_available"):
            exploit_yes += 1
        else:
            exploit_no += 1

    aging = {
        "lt_7": sum(1 for r in open_rows if int(r.get("age_days", 0)) < 7),
        "d_7_30": sum(1 for r in open_rows if 7 <= int(r.get("age_days", 0)) <= 30),
        "gt_30": sum(1 for r in open_rows if int(r.get("age_days", 0)) > 30),
        "sla_breached": len(sla_breached),
        "sla_compliance_pct": round(((len(open_rows) - len(sla_breached)) / max(1, len(open_rows))) * 100, 1),
    }

    asset_rollup: dict[str, dict] = defaultdict(lambda: {"risk": 0.0, "critical": 0, "count": 0})
    for row in open_rows:
        asset = str(row.get("asset", "Unknown"))
        asset_rollup[asset]["risk"] += float(row.get("risk_points", 0))
        asset_rollup[asset]["count"] += 1
        if row.get("severity") == "critical":
            asset_rollup[asset]["critical"] += 1
    top_assets = [
        {
            "asset": asset,
            "risk_score": min(100, round((metrics["risk"] / max(1.0, metrics["count"] * 10.0)) * 100)),
            "critical_count": metrics["critical"],
            "open_findings": metrics["count"],
        }
        for asset, metrics in sorted(asset_rollup.items(), key=lambda item: (item[1]["risk"], item[1]["critical"]), reverse=True)[:10]
    ]

    payload = {
        "generated_at": now.isoformat(),
        "overview": {
            "risk_score": risk_score,
            "critical_open": len(critical_open),
            "critical_new": len(critical_new),
            "critical_sla_breached": len(critical_sla_breached),
            "high_risk_assets": len(high_risk_assets),
            "mttr_days": mttr_days,
            "exposure_pct": exposure_pct,
            "open_findings": open_count,
            "tracked_assets": len(assets),
            "internet_facing_assets": len(internet_assets),
            "new_findings_7d": len(new_findings_7d),
        },
        "attention_now": attention_now,
        "attack_surface": attack_surface,
        "vulnerability_breakdown": {
            "cvss_histogram": cvss_hist,
            "exploit_availability": {"yes": exploit_yes, "no": exploit_no},
            "top_cwe": [
                {"cwe": cwe, "count": count}
                for cwe, count in sorted(cwe_counts.items(), key=lambda item: item[1], reverse=True)[:10]
            ],
        },
        "aging_sla": aging,
        "top_assets": top_assets,
    }
    monitoring_summary = summarize_monitoring()
    payload["monitoring"] = monitoring_summary
    payload["overview"].update(
        {
            "monitoring_enabled_assets": monitoring_summary.get("overview", {}).get("enabled_assets", 0),
            "monitoring_active_incidents": monitoring_summary.get("overview", {}).get("active_incidents", 0),
            "monitoring_uptime_24h_pct": monitoring_summary.get("overview", {}).get("uptime_24h_pct", 0),
            "monitoring_healthy_assets": monitoring_summary.get("overview", {}).get("healthy_assets", 0),
        }
    )
    return payload


def _compute_scan_estimates() -> dict:
    durations: dict[str, list[int]] = {"passive": [], "active": [], "full": []}
    tool_durations: dict[str, list[int]] = defaultdict(list)

    if REPORTS_DIR.exists():
        for json_file in REPORTS_DIR.rglob("report_*.json"):
            try:
                report_data = json.loads(json_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(report_data, dict):
                continue

            mode_raw = str(report_data.get("scan_mode", "")).lower().strip()
            duration = _safe_int(report_data.get("scan_duration_seconds"), 0)
            if duration > 0:
                if mode_raw.startswith("passive"):
                    durations["passive"].append(duration)
                elif mode_raw.startswith("active"):
                    durations["active"].append(duration)
                elif mode_raw.startswith("full"):
                    durations["full"].append(duration)

            for run in (report_data.get("tool_runs") or []):
                if not isinstance(run, dict):
                    continue
                tool_name = run.get("name") or run.get("tool") or ""
                tool_dur = _safe_int(run.get("duration_seconds"), 0)
                if tool_name and tool_dur > 0:
                    tool_durations[tool_name].append(tool_dur)

    estimates: dict = {}
    for mode, fallback in DEFAULT_SCAN_ESTIMATES_SECONDS.items():
        values = sorted(durations.get(mode, []))
        if values:
            mid = len(values) // 2
            median = values[mid] if len(values) % 2 == 1 else (values[mid - 1] + values[mid]) // 2
            estimate_seconds = max(45, median)
            source = "historical"
        else:
            estimate_seconds = fallback
            source = "default"

        estimates[mode] = {
            "seconds": estimate_seconds,
            "label": _format_eta(estimate_seconds),
            "source": source,
        }

    tool_estimates: dict = {}
    for tool_name, durs in tool_durations.items():
        sorted_durs = sorted(durs)
        mid = len(sorted_durs) // 2
        median = sorted_durs[mid] if len(sorted_durs) % 2 == 1 else (sorted_durs[mid - 1] + sorted_durs[mid]) // 2
        tool_estimates[tool_name] = {
            "seconds": median,
            "label": _format_eta(median),
        }
    estimates["tool_estimates"] = tool_estimates

    return estimates


def _update_scan_job(scan_id: str, patch: dict):
    global _scan_jobs_dirty
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return
        job.update(patch)
        job["updated_at"] = time.time()
        # Mark dirty; flush on terminal state changes to avoid excessive I/O
        _scan_jobs_dirty = True

    should_flush = patch.get("status") in ("completed", "failed", "cancelled")
    if not should_flush and (time.time() - _last_scan_jobs_flush_at) >= 5:
        should_flush = True
    if should_flush:
        _flush_scan_jobs_to_disk()


def _append_scan_event(scan_id: str, message: str):
    if not message:
        return
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return
        events = job.setdefault("events", [])
        events.append({"at": time.time(), "message": message})
        if len(events) > 35:
            del events[:-35]
        # Keep disk snapshot reasonably fresh for live dashboard recovery.
        global _scan_jobs_dirty
        _scan_jobs_dirty = True


def _normalized_job_status(job: dict) -> str:
    """Reconcile persisted/stale states so completed jobs are not shown as active."""
    status = str(job.get("status", "unknown"))
    if status in ("completed", "failed", "cancelled"):
        return status

    if _scan_completion_patch(job):
        return "completed"

    progress = _safe_int(job.get("progress"), 0)
    has_finished_marker = bool(job.get("finished_at") or job.get("report_paths"))
    if progress >= 100 or has_finished_marker:
        return "completed"

    return status

# ── Targets CRUD ────────────────────────────────────────────────────────────────

@app.route('/api/targets', methods=['GET'])
@login_required
def get_targets():
    data = _load_json(TARGETS_FILE)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and not item.get("profile"):
                item["profile"] = "auto"
        return jsonify(data)
    return jsonify([])

@app.route('/api/targets', methods=['POST'])
@login_required
def add_target():
    body = request.json or {}
    url = body.get('url', '').strip().rstrip('/')
    label = body.get('label', '').strip()
    profile = body.get('profile', 'auto').strip().lower()

    if not url or not label:
        return jsonify({"error": "url and label are required"}), 400

    # Validate URL scheme to prevent SSRF / command injection via malformed targets
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "Only http and https URLs are accepted"}), 400
    if not parsed.netloc:
        return jsonify({"error": "Invalid URL: missing host"}), 400

    # Sanitize label — allow only printable text, strip HTML-dangerous chars
    label = re.sub(r'[<>"\']', '', label)[:128].strip()
    if not label:
        return jsonify({"error": "Label is required"}), 400

    valid_profiles = {"auto", "wordpress", "joomla", "drupal", "webapp", "api"}
    if profile not in valid_profiles:
        profile = "auto"

    data = _load_json(TARGETS_FILE)
    if not isinstance(data, list):
        data = []

    target = {
        "id": uuid.uuid4().hex,
        "url": url,
        "label": label,
        "profile": profile,
        "last_scanned": None,
    }
    data.append(target)
    _save_json(TARGETS_FILE, data)
    return jsonify(target), 201

@app.route('/api/targets/<target_id>', methods=['DELETE'])
@login_required
def delete_target(target_id):
    data = _load_json(TARGETS_FILE)
    if not isinstance(data, list):
        return jsonify({"error": "No targets found"}), 404

    # Support deletion by UUID id field (new) or fallback to numeric index (legacy)
    if target_id.isdigit():
        idx = int(target_id)
        if idx < 0 or idx >= len(data):
            return jsonify({"error": "Invalid index"}), 404
        removed = data.pop(idx)
    else:
        original_len = len(data)
        data = [t for t in data if t.get("id") != target_id]
        if len(data) == original_len:
            return jsonify({"error": "Target not found"}), 404
        removed = {"id": target_id}

    _save_json(TARGETS_FILE, data)
    return jsonify({"removed": removed})

# ── Scan Config ─────────────────────────────────────────────────────────────────

@app.route('/api/config', methods=['GET'])
@login_required
def get_config():
    data = _load_json(SCAN_CONFIG_FILE)
    if isinstance(data, dict):
        return jsonify(data)
    return jsonify({})

@app.route('/api/config', methods=['PUT'])
@login_required
def update_config():
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    _save_json(SCAN_CONFIG_FILE, body)
    return jsonify({"message": "Configuration saved", "config": body})

# ── Tokens ──────────────────────────────────────────────────────────────────────

@app.route('/api/tokens', methods=['GET'])
@login_required
def get_tokens():
    data = _load_json(TOKENS_FILE)
    if not isinstance(data, dict):
        data = {"wpscan_api_token": "", "zap_api_key": ""}
    # Mask values for security
    masked = {}
    for key, val in data.items():
        if key.startswith('_'):
            continue
        if val and len(str(val)) > 4:
            masked[key] = str(val)[:4] + '•' * (len(str(val)) - 4)
        elif val:
            masked[key] = '••••'
        else:
            masked[key] = ''
    return jsonify(masked)

@app.route('/api/tokens', methods=['PUT'])
@login_required
def update_tokens():
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400

    # Load existing tokens so we don't overwrite with masked values
    existing = _load_json(TOKENS_FILE)
    if not isinstance(existing, dict):
        existing = {"wpscan_api_token": "", "zap_api_key": ""}

    for key, val in body.items():
        # Only update if the value doesn't contain mask chars (user actually changed it)
        if '•' not in str(val):
            existing[key] = val

    _save_json(TOKENS_FILE, existing)
    return jsonify({"message": "Tokens saved"})


# Modules

@app.route('/api/modules', methods=['GET'])
@login_required
def get_modules_config():
    return jsonify(get_modules())


@app.route('/api/modules', methods=['PUT'])
@login_required
def update_modules_config():
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    return jsonify({"message": "Modules saved", "modules": save_modules(body)})


# Monitoring

@app.route('/api/monitoring/assets', methods=['GET'])
@login_required
def list_monitoring_assets():
    status_map = MONITORING_SERVICE.snapshot()
    state_by_asset = {}
    for item in status_map.get("assets", []):
        if isinstance(item, dict):
            state_by_asset[str(item.get("id"))] = item.get("state", {})
    assets = []
    for asset in get_monitoring_assets():
        asset_copy = dict(asset)
        asset_copy["state"] = state_by_asset.get(str(asset.get("id")), {})
        assets.append(asset_copy)
    return jsonify(assets)


@app.route('/api/monitoring/assets', methods=['POST'])
@login_required
def upsert_monitoring_asset():
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    try:
        asset = MONITORING_SERVICE.upsert_asset(body)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"message": "Monitoring asset saved", "asset": asset})


@app.route('/api/monitoring/assets/<asset_id>', methods=['DELETE'])
@login_required
def delete_monitoring_asset(asset_id):
    if MONITORING_SERVICE.delete_asset(asset_id):
        return jsonify({"message": "Monitoring asset removed"})
    return jsonify({"error": "Asset not found"}), 404


@app.route('/api/monitoring/settings', methods=['GET'])
@login_required
def get_monitoring_settings_route():
    return jsonify(get_monitoring_settings())


@app.route('/api/monitoring/settings', methods=['PUT'])
@login_required
def update_monitoring_settings_route():
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    return jsonify({"message": "Monitoring settings saved", "settings": MONITORING_SERVICE.update_settings(body)})


@app.route('/api/monitoring/status', methods=['GET'])
@login_required
def get_monitoring_status_route():
    return jsonify(MONITORING_SERVICE.snapshot())


@app.route('/api/monitoring/events', methods=['GET'])
@login_required
def get_monitoring_events_route():
    limit_raw = request.args.get("limit", "100")
    try:
        limit = max(1, min(int(limit_raw), 500))
    except ValueError:
        limit = 100
    events = sorted(get_monitoring_events(), key=lambda item: str(item.get("created_at", "")), reverse=True)
    return jsonify(events[:limit])


@app.route('/api/monitoring/heartbeat', methods=['POST'])
def post_monitoring_heartbeat():
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    try:
        heartbeat = MONITORING_SERVICE.receive_heartbeat(body)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"message": "Heartbeat accepted", "heartbeat": heartbeat})


@app.route('/api/monitoring/test-telegram', methods=['POST'])
@login_required
def test_monitoring_telegram():
    success, message = MONITORING_SERVICE.test_telegram()
    status = 200 if success else 400
    return jsonify({"success": success, "message": message}), status

# ── Tools Status & Management ───────────────────────────────────────────────────

@app.route('/api/tools/update-templates', methods=['POST'])
@login_required
def update_nuclei_templates():
    """Trigger a nuclei template update. Runs nuclei -ut in a subprocess."""
    try:
        result = subprocess.run(
            ["nuclei", "-ut"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = (result.stdout or "") + (result.stderr or "")
        success = result.returncode == 0
        if success:
            logger.info("Nuclei templates updated successfully.")
        else:
            logger.warning("Nuclei template update exited with code %d", result.returncode)
        return jsonify({"success": success, "output": output[-2000:]})
    except FileNotFoundError:
        return jsonify({"error": "nuclei is not installed or not on PATH"}), 404
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Template update timed out after 300 seconds"}), 504
    except Exception as exc:
        logger.exception("Nuclei template update failed")
        return jsonify({"error": str(exc)}), 500


@app.route('/api/tools-status', methods=['GET'])
@login_required
def tools_status():
    import shutil
    from lib.tools import TOOLS
    
    tools = [dict(t) for t in TOOLS]
    for t in tools:
        t["installed"] = shutil.which(t["name"]) is not None
    return jsonify(tools)


# ── Guided Assessments ──────────────────────────────────────────────────────────

@app.route('/api/assessments/catalog', methods=['GET'])
@login_required
def assessments_catalog():
    return jsonify(get_catalog())


@app.route('/api/assessments', methods=['GET'])
@login_required
def get_assessment():
    target = _require_target_arg()
    if not target:
        return jsonify({"error": "target query parameter is required"}), 400
    workbook = get_workbook(target)
    summary = summarize_workbook(workbook)
    return jsonify({"workbook": workbook, "summary": summary})


@app.route('/api/assessments', methods=['PUT'])
@login_required
def update_assessment():
    target = _require_target_arg()
    if not target:
        return jsonify({"error": "target query parameter is required"}), 400
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    workbook = save_workbook(target, body)
    summary = summarize_workbook(workbook)
    return jsonify({"message": "Assessment workbook saved", "workbook": workbook, "summary": summary})


# ── AI Action Plans ─────────────────────────────────────────────────────────────

@app.route('/api/ai/plans', methods=['POST'])
@login_required
def create_ai_plan():
    body = request.json or {}
    target = str(body.get("target", "")).strip().rstrip("/")
    actions = body.get("actions", [])
    scan_id = str(body.get("scan_id", "")).strip() or None
    bypass_token = str(body.get("bypass_token", "")).strip()

    if not target:
        return jsonify({"error": "target is required"}), 400
    if not isinstance(actions, list) or not actions:
        return jsonify({"error": "actions array is required"}), 400

    scan_cfg = _load_json(SCAN_CONFIG_FILE)
    if not isinstance(scan_cfg, dict):
        scan_cfg = {}

    require_approval = bool(scan_cfg.get("ai_require_approval_high_impact", True))
    allow_bypass = _is_full_testing_bypass_enabled(scan_cfg, bypass_token)
    policy = load_policy(AI_POLICY_FILE)
    evaluated = evaluate_plan(
        plan_actions=actions,
        target_url=target,
        policy=policy,
        require_approval_high_impact=require_approval,
        allow_full_testing_bypass=allow_bypass,
    )

    plan_id = uuid.uuid4().hex
    created_at = datetime.now(UTC).isoformat()
    status = "approved" if (evaluated.get("requires_approval_count", 0) == 0 or allow_bypass) else "pending_approval"

    plan = {
        "id": plan_id,
        "created_at": created_at,
        "created_by": session.get("user", ""),
        "target": target,
        "scan_id": scan_id,
        "status": status,
        "bypass_used": allow_bypass,
        "approved_actions": evaluated.get("approved_actions", []),
        "rejected_actions": evaluated.get("rejected_actions", []),
        "requires_approval_count": evaluated.get("requires_approval_count", 0),
        "execution": None,
    }

    store = _load_ai_plan_store()
    store[plan_id] = plan
    _save_ai_plan_store(store)

    return jsonify({"message": "AI action plan created", "plan": plan}), 201


@app.route('/api/ai/plans/<plan_id>', methods=['GET'])
@login_required
def get_ai_plan(plan_id):
    store = _load_ai_plan_store()
    plan = store.get(plan_id)
    if not isinstance(plan, dict):
        return jsonify({"error": "Plan not found"}), 404
    return jsonify(plan)


@app.route('/api/ai/plans/<plan_id>/approve', methods=['POST'])
@login_required
def approve_ai_plan(plan_id):
    store = _load_ai_plan_store()
    plan = store.get(plan_id)
    if not isinstance(plan, dict):
        return jsonify({"error": "Plan not found"}), 404

    approved_actions = plan.get("approved_actions", [])
    for action in approved_actions:
        if isinstance(action, dict) and action.get("requires_approval"):
            action["approved"] = True

    plan["approved_actions"] = approved_actions
    plan["status"] = "approved"
    plan["approved_at"] = datetime.now(UTC).isoformat()
    plan["approved_by"] = session.get("user", "")
    store[plan_id] = plan
    _save_ai_plan_store(store)

    return jsonify({"message": "Plan approved", "plan": plan})


@app.route('/api/ai/plans/<plan_id>/execute', methods=['POST'])
@login_required
def execute_ai_plan(plan_id):
    store = _load_ai_plan_store()
    plan = store.get(plan_id)
    if not isinstance(plan, dict):
        return jsonify({"error": "Plan not found"}), 404

    body = request.json or {}
    bypass_token = str(body.get("bypass_token", "")).strip()

    scan_cfg = _load_json(SCAN_CONFIG_FILE)
    if not isinstance(scan_cfg, dict):
        scan_cfg = {}
    allow_bypass = _is_full_testing_bypass_enabled(scan_cfg, bypass_token)

    if plan.get("status") not in {"approved", "executed"} and not allow_bypass:
        return jsonify({"error": "Plan requires approval before execution"}), 409

    approved_actions = plan.get("approved_actions", []) if isinstance(plan.get("approved_actions"), list) else []
    actions_to_run: list[dict] = []
    for action in approved_actions:
        if not isinstance(action, dict):
            continue
        if allow_bypass:
            action["approved"] = True
        if action.get("approved"):
            actions_to_run.append(action)

    if not actions_to_run:
        return jsonify({"error": "No approved actions to execute"}), 400

    policy = load_policy(AI_POLICY_FILE)
    rpm = int((policy.get("rate_limits") or {}).get("requests_per_minute", 30) or 30)
    execution = execute_actions(actions_to_run, requests_per_minute=rpm)

    scan_dir = _scan_dir_for_scan_id(plan.get("scan_id"))
    evidence_paths = persist_evidence(scan_dir, execution)

    target = str(plan.get("target", "")).strip()
    result_store = _load_ai_results_store()
    target_entry = result_store.get(target)
    if not isinstance(target_entry, dict):
        target_entry = {"updated_at": "", "results": []}
    target_results = target_entry.get("results", []) if isinstance(target_entry.get("results"), list) else []
    target_results.extend(execution.get("results", []))
    # Keep only recent results to limit unbounded growth.
    if len(target_results) > 500:
        target_results = target_results[-500:]
    target_entry["updated_at"] = datetime.now(UTC).isoformat()
    target_entry["results"] = target_results
    target_entry["last_execution"] = {
        "plan_id": plan_id,
        "executed_at": execution.get("executed_at"),
        "verdict_counts": execution.get("verdict_counts", {}),
        "evidence_file": evidence_paths.get("evidence_file", ""),
        "actions_file": evidence_paths.get("actions_file", ""),
    }
    result_store[target] = target_entry
    _save_ai_results_store(result_store)

    plan["status"] = "executed"
    plan["executed_at"] = execution.get("executed_at")
    plan["executed_by"] = session.get("user", "")
    plan["bypass_used"] = bool(plan.get("bypass_used") or allow_bypass)
    plan["execution"] = {
        "result_count": execution.get("result_count", 0),
        "verdict_counts": execution.get("verdict_counts", {}),
        "evidence_file": evidence_paths.get("evidence_file", ""),
        "actions_file": evidence_paths.get("actions_file", ""),
    }

    store[plan_id] = plan
    _save_ai_plan_store(store)

    return jsonify({
        "message": "AI plan executed",
        "plan": plan,
        "execution": execution,
        "evidence": evidence_paths,
    })

# ── Reports ─────────────────────────────────────────────────────────────────────

@app.route('/api/reports', methods=['GET'])
@login_required
def list_reports():
    def _scan_reports_from_disk() -> list[dict]:
        reports_list: list[dict] = []
        if not REPORTS_DIR.exists():
            return reports_list

        for html_file in sorted(REPORTS_DIR.rglob("*.html"), reverse=True):
            rel = html_file.relative_to(REPORTS_DIR)
            size_kb = html_file.stat().st_size / 1024
            mtime = html_file.stat().st_mtime

            json_companion = html_file.with_suffix('.json')
            if not json_companion.exists():
                parent = html_file.parent
                json_files = list(parent.glob("report_*.json"))
                json_companion = json_files[0] if json_files else None

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            target_url = ""
            effective_profile = ""
            assessment_summary = {}
            scan_started_at = ""
            if json_companion and json_companion.exists():
                try:
                    report_data = json.loads(json_companion.read_text(encoding='utf-8'))
                    if isinstance(report_data, dict):
                        findings = report_data.get("findings", [])
                        target_url = report_data.get("target_url", "")
                        effective_profile = report_data.get("overview", {}).get("effective_profile", "")
                        assessment_summary = report_data.get("assessment", {}).get("summary", {})
                        scan_started_at = report_data.get("scan_started_at", "")
                    else:
                        findings = report_data
                    if isinstance(findings, list):
                        for f in findings:
                            sev = f.get('severity', 'low').lower()
                            if sev in severity_counts:
                                severity_counts[sev] += 1
                except Exception:
                    pass

            md_file = html_file.with_suffix('.md')
            md_rel = md_file.relative_to(REPORTS_DIR) if md_file.exists() else None
            json_dl_rel = None
            csv_file = html_file.with_suffix('.csv')
            csv_rel = csv_file.relative_to(REPORTS_DIR) if csv_file.exists() else None
            sarif_file = html_file.with_suffix('.sarif')
            sarif_rel = sarif_file.relative_to(REPORTS_DIR) if sarif_file.exists() else None
            if json_companion and json_companion.exists():
                try:
                    json_dl_rel = json_companion.relative_to(REPORTS_DIR)
                except ValueError:
                    pass

            reports_list.append({
                "path": str(rel).replace('\\', '/'),
                "name": html_file.stem,
                "folder": str(rel.parent).replace('\\', '/'),
                "target_url": target_url,
                "profile": effective_profile,
                "assessment_summary": assessment_summary,
                "scan_started_at": scan_started_at,
                "size_kb": round(size_kb, 1),
                "modified": mtime,
                "severities": severity_counts,
                "md_path": str(md_rel).replace('\\', '/') if md_rel else None,
                "json_path": str(json_dl_rel).replace('\\', '/') if json_dl_rel else None,
                "csv_path": str(csv_rel).replace('\\', '/') if csv_rel else None,
                "sarif_path": str(sarif_rel).replace('\\', '/') if sarif_rel else None,
            })
        return reports_list

    reports: list[dict] = []
    index_data = _load_json(REPORT_INDEX_FILE)
    if isinstance(index_data, dict) and isinstance(index_data.get("reports"), list):
        for item in index_data.get("reports", []):
            if not isinstance(item, dict):
                continue
            rel_path = str(item.get("path", "")).strip().replace('\\', '/')
            if not rel_path:
                continue
            html_path = REPORTS_DIR / rel_path
            if not html_path.exists():
                continue
            reports.append(
                {
                    "path": rel_path,
                    "name": item.get("name") or html_path.stem,
                    "folder": item.get("folder") or str(Path(rel_path).parent).replace('\\', '/'),
                    "target_url": item.get("target_url", ""),
                    "profile": item.get("profile", ""),
                    "assessment_summary": item.get("assessment_summary", {}),
                    "scan_started_at": item.get("scan_started_at", ""),
                    "size_kb": round(float(item.get("size_kb", round(html_path.stat().st_size / 1024, 1)) or 0), 1),
                    "modified": float(item.get("modified", html_path.stat().st_mtime) or html_path.stat().st_mtime),
                    "severities": item.get("severities") if isinstance(item.get("severities"), dict) else {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "md_path": item.get("md_path"),
                    "json_path": item.get("json_path"),
                    "csv_path": item.get("csv_path"),
                    "sarif_path": item.get("sarif_path"),
                }
            )

    if not reports:
        reports = _scan_reports_from_disk()

    reports.sort(key=lambda item: float(item.get("modified", 0) or 0), reverse=True)

    # Server-side pagination
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
        offset = max(0, int(request.args.get("offset", 0)))
    except (TypeError, ValueError):
        limit, offset = 50, 0

    total = len(reports)
    page_reports = reports[offset: offset + limit]
    response = jsonify({"reports": page_reports, "total": total, "limit": limit, "offset": offset})
    return response

@app.route('/api/reports/<path:filepath>')
@login_required
def serve_report(filepath):
    as_attach = request.args.get('dl', '0') == '1'
    if as_attach or not str(filepath).lower().endswith('.html'):
        return send_from_directory(str(REPORTS_DIR), filepath, as_attachment=as_attach)

    safe_path = safe_join(str(REPORTS_DIR), filepath)
    if not safe_path:
        abort(404)
    report_file = Path(safe_path)
    try:
        report_file.resolve().relative_to(REPORTS_DIR.resolve())
    except ValueError:
        abort(404)
    if not report_file.is_file():
        abort(404)
    html = report_file.read_text(encoding='utf-8', errors='replace')
    return Response(apply_report_layout_overrides(html), mimetype='text/html; charset=utf-8')


@app.route('/api/reports/rename', methods=['PATCH'])
@login_required
def rename_report():
    data = request.json or {}
    folder = data.get('folder', '').strip()
    new_name = data.get('name', '').strip()
    if not folder or not new_name:
        return jsonify({"error": "folder and name required"}), 400
    if not re.match(r'^[\w\-. ]+$', new_name) or '..' in new_name:
        return jsonify({"error": "Invalid name: only letters, numbers, hyphens, underscores and spaces allowed"}), 400
    folder_path = REPORTS_DIR / folder
    if not folder_path.exists() or not folder_path.is_dir():
        return jsonify({"error": "Report folder not found"}), 404
    new_path = folder_path.parent / new_name
    if new_path.exists():
        return jsonify({"error": "A report with that name already exists"}), 409
    folder_path.rename(new_path)
    new_rel = str(new_path.relative_to(REPORTS_DIR)).replace('\\', '/')
    return jsonify({"message": "Renamed successfully", "new_folder": new_rel})

# ── Monthly Stats (for chart) ──────────────────────────────────────────────────

@app.route('/api/dashboard-insights', methods=['GET'])
@login_required
def dashboard_insights():
    return jsonify(_dashboard_insights_payload())

@app.route('/api/reports/delete', methods=['DELETE'])
@login_required
def delete_report():
    data = request.json or {}
    folder = data.get('folder', '').strip()
    if not folder or '..' in folder:
        return jsonify({"error": "folder required"}), 400
    folder_path = REPORTS_DIR / folder
    # Resolve to ensure it stays inside REPORTS_DIR
    try:
        folder_path.resolve().relative_to(REPORTS_DIR.resolve())
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if not folder_path.exists():
        return jsonify({"error": "Report not found"}), 404
    if folder_path.is_dir():
        shutil.rmtree(folder_path)
    else:
        folder_path.unlink()
    return jsonify({"message": "Report deleted"})

# ── Monthly Stats (for chart) ──────────────────────────────────────────────────

@app.route('/api/monthly-stats', methods=['GET'])
@login_required
def get_monthly_stats():
    stats = defaultdict(lambda: {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "cve_backed": 0,
        "confirmed": 0,
        "exploitable": 0,
        "total": 0,
        "risk_points": 0.0,
        "critical_incidents": 0,
        "new_vulns": 0,
    })

    if REPORTS_DIR.exists():
        for json_file in REPORTS_DIR.rglob("report_*.json"):
            parts = json_file.parts
            month_str = "Unknown"
            for part in parts:
                if len(part) == 7 and part[4] == '-' and part[:4].isdigit():
                    month_str = part
                    break
            if month_str == "Unknown":
                continue
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                    findings = report_data.get("findings", []) if isinstance(report_data, dict) else report_data
                    for finding in findings:
                        sev = finding.get('severity', 'low').lower()
                        if sev in stats[month_str]:
                            stats[month_str][sev] += 1
                        stats[month_str]["total"] += 1
                        stats[month_str]["new_vulns"] += 1

                        cvss = _extract_cvss(finding)
                        base_score = cvss if cvss > 0 else _severity_weight(sev)
                        exploitability = str(finding.get("exploitability", "")).strip().lower()
                        exploit_factor = 1.2 if bool(finding.get("exploit_available") or exploitability == "high") else 1.0
                        stats[month_str]["risk_points"] += base_score * exploit_factor

                        if sev == "critical":
                            stats[month_str]["critical_incidents"] += 1

                        if str(finding.get("cve", "")).strip():
                            stats[month_str]["cve_backed"] += 1

                        status = str(finding.get("status", "")).strip().lower()
                        if status in {"confirmed", "reproduced", "exploited"}:
                            stats[month_str]["confirmed"] += 1

                        exploitability = str(finding.get("exploitability", "")).strip().lower()
                        if exploitability == "high":
                            stats[month_str]["exploitable"] += 1
            except Exception:
                pass

    sorted_months = sorted(stats.keys())
    insights = {
        "summary": "No trend data yet. Run scans to build monthly risk insights.",
        "latest_month": "",
        "critical_high_delta": 0,
        "direction": "flat",
    }

    if sorted_months:
        latest_month = sorted_months[-1]
        latest = stats[latest_month]
        latest_critical_high = latest["critical"] + latest["high"]
        prev_critical_high = 0
        if len(sorted_months) > 1:
            prev = stats[sorted_months[-2]]
            prev_critical_high = prev["critical"] + prev["high"]
        delta = latest_critical_high - prev_critical_high
        direction = "flat"
        if delta > 0:
            direction = "up"
        elif delta < 0:
            direction = "down"
        insights = {
            "summary": f"{latest_month}: {latest['critical']} critical, {latest['high']} high, {latest['cve_backed']} CVE-backed, {latest['confirmed']} confirmed findings.",
            "latest_month": latest_month,
            "critical_high_delta": delta,
            "direction": direction,
        }

    result = {
        "labels": sorted_months,
        "datasets": {
            "critical": [stats[m]["critical"] for m in sorted_months],
            "high": [stats[m]["high"] for m in sorted_months],
            "medium": [stats[m]["medium"] for m in sorted_months],
            "low": [stats[m]["low"] for m in sorted_months],
            "cve_backed": [stats[m]["cve_backed"] for m in sorted_months],
            "confirmed": [stats[m]["confirmed"] for m in sorted_months],
            "exploitable": [stats[m]["exploitable"] for m in sorted_months],
            "total": [stats[m]["total"] for m in sorted_months],
            "risk_score": [
                min(100, round((stats[m]["risk_points"] / max(1.0, stats[m]["total"] * 10.0)) * 100, 1))
                for m in sorted_months
            ],
            "new_vulns": [stats[m]["new_vulns"] for m in sorted_months],
            "critical_incidents": [stats[m]["critical_incidents"] for m in sorted_months],
        },
        "insights": insights,
    }
    return jsonify(result)

# ── Scan ────────────────────────────────────────────────────────────────────────

@app.route('/api/scan', methods=['POST'])
@login_required
def start_scan():
    global _scan_jobs_dirty
    data = request.json or {}
    target = str(data.get('target', '')).strip().rstrip('/')
    mode = str(data.get('mode', 'passive')).strip().lower()
    profile = str(data.get('profile', 'auto')).strip().lower() or "auto"

    if not target:
        return jsonify({"error": "Target is required"}), 400
    if mode not in {"passive", "active", "full"}:
        return jsonify({"error": "Invalid mode"}), 400

    estimates = _compute_scan_estimates()
    estimated_seconds = estimates.get(mode, {}).get("seconds", DEFAULT_SCAN_ESTIMATES_SECONDS["full"])
    scan_config = _load_json(SCAN_CONFIG_FILE)
    if not isinstance(scan_config, dict):
        scan_config = {}
    hard_timeout_seconds = max(1800, _safe_int(scan_config.get("scan_hard_timeout_seconds"), estimated_seconds * 4))
    scan_id = uuid.uuid4().hex
    started_at = time.time()
    run_label = datetime.fromtimestamp(started_at).strftime("%Y%m%d_%H%M%S")
    scan_dir = REPORTS_DIR / f"{_safe_scan_host_label(target)}_{run_label}"

    with SCAN_JOBS_LOCK:
        SCAN_JOBS[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "mode": mode,
            "profile": profile,
            "status": "running",
            "started_at": started_at,
            "updated_at": started_at,
            "progress": 1,
            "phase": "initializing",
            "current_tool": "Preparing scan",
            "completed_tools": 0,
            "total_tools": 0,
            "tool_status": [],
            "scan_dir": str(scan_dir),
            "estimated_seconds": estimated_seconds,
            "hard_timeout_seconds": hard_timeout_seconds,
            "events": [{"at": started_at, "message": "Scan queued and initializing."}],
            "message": f"Scan started on {target} in {mode} mode.",
        }
        _scan_jobs_dirty = True
    _flush_scan_jobs_to_disk()

    def _progress_callback(event: dict):
        if not isinstance(event, dict):
            return

        patch = {}
        event_type = event.get("event")

        if isinstance(event.get("message"), str) and event.get("message"):
            _append_scan_event(scan_id, event["message"])

        if event_type == "plan_updated":
            patch["total_tools"] = _safe_int(event.get("total_tools"), 0)
            if isinstance(event.get("phase"), str):
                patch["phase"] = event["phase"]
            if isinstance(event.get("planned_tools"), list):
                patch["planned_tools"] = event["planned_tools"]
            if isinstance(event.get("missing_tools"), list):
                patch["missing_tools"] = event["missing_tools"]

        elif event_type == "tool_started":
            with SCAN_JOBS_LOCK:
                _job = SCAN_JOBS.get(scan_id)
                if _job and _job.get("cancel_requested"):
                    raise InterruptedError("Scan cancelled by user.")
            tool_name = event.get("tool_label") or event.get("tool") or "Tool"
            patch.update(
                {
                    "phase": event.get("phase", "tool_execution"),
                    "current_tool": tool_name,
                    "completed_tools": _safe_int(event.get("completed_tools"), 0),
                    "total_tools": _safe_int(event.get("total_tools"), 0),
                    "progress": max(2, min(96, _safe_int(event.get("progress"), 2))),
                }
            )
            _append_scan_event(scan_id, f"Running {tool_name}...")

        elif event_type == "tool_finished":
            tool_name = event.get("tool_label") or event.get("tool") or "Tool"
            status = event.get("status", "completed")
            note = str(event.get("note", "") or "").strip()
            patch.update(
                {
                    "completed_tools": _safe_int(event.get("completed_tools"), 0),
                    "total_tools": _safe_int(event.get("total_tools"), 0),
                    "progress": max(2, min(96, _safe_int(event.get("progress"), 2))),
                }
            )
            _append_scan_event(scan_id, f"{tool_name} finished with status: {status}.")
            if note and status in {"timeout", "skipped", "cancelled", "failed", "missing"}:
                _append_scan_event(scan_id, note)

            with SCAN_JOBS_LOCK:
                job = SCAN_JOBS.get(scan_id)
                if job is not None:
                    tool_status = job.setdefault("tool_status", [])
                    tool_status.append(
                        {
                            "name": event.get("tool") or tool_name,
                            "label": tool_name,
                            "phase": event.get("phase", ""),
                            "status": status,
                            "duration_seconds": event.get("duration_seconds", 0),
                            "note": note,
                        }
                    )
                    if len(tool_status) > 40:
                        del tool_status[:-40]

        elif event_type == "stage":
            patch["phase"] = event.get("stage", "processing")
            patch["progress"] = max(2, min(99, _safe_int(event.get("progress"), 2)))
            if event.get("current_tool"):
                patch["current_tool"] = event.get("current_tool")

        elif event_type == "complete":
            patch.update(
                {
                    "status": "completed",
                    "phase": "completed",
                    "progress": 100,
                    "current_tool": "Completed",
                    "finished_at": time.time(),
                    "message": event.get("message", "Scan completed."),
                }
            )
            if event.get("report_paths"):
                patch["report_paths"] = event.get("report_paths")
            _append_scan_event(scan_id, "Scan completed successfully.")

        elif event_type == "error":
            patch.update(
                {
                    "status": "failed",
                    "phase": "failed",
                    "current_tool": "Failed",
                    "finished_at": time.time(),
                    "message": event.get("message", "Scan failed."),
                }
            )
            _append_scan_event(scan_id, f"Scan failed: {event.get('message', 'Unknown error')}")

        if patch:
            _update_scan_job(scan_id, patch)

    def _run_scan_job():
        from scanner import run_scan

        def _is_cancel_requested() -> bool:
            global _scan_jobs_dirty
            timeout_triggered = False
            with SCAN_JOBS_LOCK:
                job = SCAN_JOBS.get(scan_id)
                if not job:
                    return True
                if bool(job.get("cancel_requested")):
                    return True

                hard_timeout_seconds = max(1, _safe_int(job.get("hard_timeout_seconds"), 0))
                started_at = float(job.get("started_at") or time.time())
                if hard_timeout_seconds > 0 and (time.time() - started_at) >= hard_timeout_seconds:
                    if not bool(job.get("timeout_reached")):
                        job["timeout_reached"] = True
                        job["timeout_triggered_at"] = time.time()
                        job["message"] = "Global scan timeout reached. Finalizing partial report from available outputs."
                        job["updated_at"] = time.time()
                        _scan_jobs_dirty = True
                        timeout_triggered = True
                    return True

            if timeout_triggered:
                _append_scan_event(scan_id, "Global scan timeout reached. Finalizing partial report from available outputs.")
                _flush_scan_jobs_to_disk()
            return False

        try:
            run_scan(
                target,
                mode,
                True,
                False,
                None,
                profile,
                progress_callback=_progress_callback,
                ci_fail_on_findings=False,
                run_label=run_label,
                should_cancel=_is_cancel_requested,
            )
            with SCAN_JOBS_LOCK:
                job = SCAN_JOBS.get(scan_id)
            if job and (job.get("cancel_requested") or job.get("status") == "cancelling"):
                _update_scan_job(scan_id, {
                    "status": "cancelled",
                    "phase": "cancelled",
                    "current_tool": "Cancelled",
                    "finished_at": time.time(),
                    "message": "Scan cancelled by user.",
                })
                _append_scan_event(scan_id, "Scan cancelled by user.")
            elif job and job.get("status") == "running":
                _progress_callback({"event": "complete", "message": "Scan completed."})
        except InterruptedError:
            _update_scan_job(scan_id, {
                "status": "cancelled",
                "phase": "cancelled",
                "current_tool": "Cancelled",
                "finished_at": time.time(),
                "message": "Scan cancelled by user.",
            })
            _append_scan_event(scan_id, "Scan cancelled by user.")
        except SystemExit as exc:
            _progress_callback({"event": "error", "message": f"Scan aborted (exit {exc.code})."})
        except Exception as exc:
            _progress_callback({"event": "error", "message": str(exc)})

    thread = threading.Thread(target=_run_scan_job, daemon=True)
    thread.start()

    return jsonify(
        {
            "scan_id": scan_id,
            "message": f"Scan started successfully on {target} in {mode} mode.",
            "status": "running",
            "estimated_seconds": estimated_seconds,
            "estimated_label": _format_eta(estimated_seconds),
        }
    )


@app.route('/api/scan-status/<scan_id>', methods=['GET'])
@login_required
def get_scan_status(scan_id):
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        payload = dict(job)

    recovery_patch = _scan_completion_patch(payload) or _scan_cancel_recovery_patch(payload) or _scan_stall_patch(payload)
    if recovery_patch and payload.get("status") not in ("completed", "failed", "cancelled"):
        _update_scan_job(scan_id, recovery_patch)
        payload.update(recovery_patch)

    elapsed = max(0, int(time.time() - payload.get("started_at", time.time())))
    payload["status"] = _normalized_job_status(payload)
    if payload["status"] == "completed" and not payload.get("finished_at"):
        payload["finished_at"] = payload.get("updated_at") or time.time()
    estimate = max(1, _safe_int(payload.get("estimated_seconds"), DEFAULT_SCAN_ESTIMATES_SECONDS["full"]))
    payload["elapsed_seconds"] = elapsed
    payload["elapsed_label"] = _format_eta(elapsed)
    payload["estimated_label"] = _format_eta(estimate)
    payload["eta_seconds"] = max(0, estimate - elapsed) if payload.get("status") == "running" else 0
    payload["eta_label"] = _format_eta(payload["eta_seconds"]) if payload.get("status") == "running" else "~0s"

    return jsonify(payload)


@app.route('/api/scan-estimates', methods=['GET'])
@login_required
def get_scan_estimates():
    return jsonify(_compute_scan_estimates())


@app.route('/api/scan/<scan_id>/cancel', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    global _scan_jobs_dirty
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        if job.get("status") not in ("running", "cancelling"):
            return jsonify({"error": "Scan is not running"}), 400
        job["cancel_requested"] = True
        job["status"] = "cancelling"
        job["updated_at"] = time.time()
        job["message"] = "Cancellation requested. Stopping current tool..."
        _scan_jobs_dirty = True
    _flush_scan_jobs_to_disk()
    return jsonify({"message": "Cancel requested."})


@app.route('/api/scan-jobs', methods=['GET'])
@login_required
def list_scan_jobs():
    with SCAN_JOBS_LOCK:
        jobs = list(SCAN_JOBS.values())
    now = time.time()
    result = []
    for job in sorted(jobs, key=lambda x: x.get("started_at", 0), reverse=True)[:10]:
        recovery_patch = _scan_completion_patch(job) or _scan_cancel_recovery_patch(job) or _scan_stall_patch(job)
        if recovery_patch and job.get("status") not in ("completed", "failed", "cancelled"):
            _update_scan_job(job.get("scan_id"), recovery_patch)
            job = {**job, **recovery_patch}
        elapsed = max(0, int(now - job.get("started_at", now)))
        estimate = max(1, _safe_int(job.get("estimated_seconds"), DEFAULT_SCAN_ESTIMATES_SECONDS["full"]))
        status = _normalized_job_status(job)
        result.append({
            "scan_id": job.get("scan_id"),
            "target": job.get("target"),
            "mode": job.get("mode"),
            "profile": job.get("profile"),
            "status": status,
            "progress": job.get("progress", 0),
            "started_at": job.get("started_at"),
            "elapsed_label": _format_eta(elapsed),
            "eta_label": _format_eta(max(0, estimate - elapsed)) if status == "running" else None,
            "current_tool": job.get("current_tool"),
        })
    return jsonify(result)


if os.environ.get("DP_DISABLE_MONITORING_THREAD") != "1":
    MONITORING_SERVICE.start()
    atexit.register(MONITORING_SERVICE.stop)


if __name__ == '__main__':
    # Development only — production deployments use gunicorn via docker/entrypoint.sh
    logger.info("Starting %s in development mode on http://0.0.0.0:5000", PRODUCT_NAME)
    app.run(host='0.0.0.0', port=5000, debug=False)
