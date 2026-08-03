"""Tool execution wrappers and orchestration for DP Security Platform."""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from lib import ui

TOOLS = [
    {"name": "httpx", "label": "httpx", "phase": "passive", "category": "fingerprint"},
    {"name": "whatweb", "label": "WhatWeb", "phase": "passive", "category": "fingerprint"},
    {"name": "nuclei", "label": "Nuclei", "phase": "passive", "category": "broad"},
    {"name": "nikto", "label": "Nikto", "phase": "passive", "category": "broad"},
    {"name": "sslyze", "label": "SSLyze", "phase": "passive", "category": "tls"},
    {"name": "subfinder", "label": "Subfinder", "phase": "passive", "category": "discovery"},
    {"name": "corsy", "label": "Corsy", "phase": "passive", "category": "headers"},
    {"name": "gau", "label": "gau", "phase": "passive", "category": "discovery"},
    {"name": "katana", "label": "Katana", "phase": "passive", "category": "discovery"},
    {"name": "wpscan", "label": "WPScan", "phase": "passive", "category": "cms"},
    {"name": "joomscan", "label": "JoomScan", "phase": "passive", "category": "cms"},
    {"name": "droopescan", "label": "Droopescan", "phase": "passive", "category": "cms"},
    {"name": "cmsmap", "label": "CMSMap", "phase": "active", "category": "cms"},
    {"name": "sqlmap", "label": "SQLMap", "phase": "active", "category": "validation"},
    {"name": "ffuf", "label": "ffuf", "phase": "active", "category": "content"},
    {"name": "feroxbuster", "label": "Feroxbuster", "phase": "active", "category": "content"},
    {"name": "arjun", "label": "Arjun", "phase": "active", "category": "parameters"},
    {"name": "dalfox", "label": "Dalfox", "phase": "active", "category": "validation"},
    {"name": "commix", "label": "Commix", "phase": "active", "category": "validation"},
    {"name": "wapiti", "label": "Wapiti", "phase": "active", "category": "validation"},
]

WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
]

PORTABLE_CORE_TOOLS = {
    "httpx",
    "whatweb",
    "nuclei",
    "sslyze",
    "subfinder",
    "corsy",
    "gau",
    "katana",
    "ffuf",
    "feroxbuster",
    "arjun",
    "dalfox",
    "wapiti",
}

DEEP_SCAN_ONLY_TOOLS = {
    "wpscan",
    "cmsmap",
    "nikto",
    "sqlmap",
    "commix",
    "joomscan",
    "droopescan",
}

TOOLSET_PROFILES = {
    "portable_core": PORTABLE_CORE_TOOLS,
    "deep_scan": PORTABLE_CORE_TOOLS | DEEP_SCAN_ONLY_TOOLS,
}


def is_tool_installed(name: str) -> bool:
    """Check if a CLI tool is available on PATH."""
    return shutil.which(name) is not None


def get_installed_tools() -> dict[str, bool]:
    """Return dict of tool_name -> is_installed."""
    return {t["name"]: is_tool_installed(t["name"]) for t in TOOLS}


def get_allowed_tools_for_profile(profile_name: str) -> set[str]:
    return set(TOOLSET_PROFILES.get(str(profile_name or "").strip().lower(), TOOLSET_PROFILES["portable_core"]))


def show_tool_status():
    """Print tool availability to the terminal."""
    installed = get_installed_tools()
    total = sum(1 for v in installed.values() if v)

    ui.section("Tool Status")
    for t in TOOLS:
        if installed[t["name"]]:
            ui.ok(f"{t['label']}")
        else:
            print(f"  {ui.Fore.RED}[-]{ui.Style.RESET_ALL} {t['label']} (not found: {t['name']})")

    print(f"\n  {total} / {len(TOOLS)} tools available.\n")
    return installed


def is_local(url: str) -> bool:
    hostname = urlparse(url).hostname or ""
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private
    except ValueError:
        return hostname.endswith(".local")


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _safe_read_head(path: Path, max_bytes: int = 200_000) -> str:
    """Read only the first chunk of a potentially large file for fast heuristics."""
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return ""


def _path_has_content(path: Path) -> bool:
    try:
        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and child.stat().st_size > 0:
                    return True
            return False
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def _is_projectdiscovery_httpx(binary: str) -> bool:
    """Return True when binary looks like ProjectDiscovery httpx (not Python httpx CLI)."""
    try:
        help_proc = subprocess.run(
            [binary, "-h"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        help_text = f"{help_proc.stdout or ''}{help_proc.stderr or ''}".lower()
        if "tech-detect" in help_text or "-td" in help_text:
            return True
        if "projectdiscovery" in help_text:
            return True
        # Python encode/httpx CLI exposes HTTP methods, not probe flags.
        if "httpx [options] url" in help_text or "encode" in help_text:
            return False
        version_proc = subprocess.run(
            [binary, "-version"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        version_text = f"{version_proc.stdout or ''}{version_proc.stderr or ''}".lower()
        return "projectdiscovery" in version_text or "current version" in version_text
    except Exception:
        return False


def _resolve_httpx_binary() -> str | None:
    """Prefer ProjectDiscovery httpx over a Python httpx CLI shadowed on PATH."""
    candidates: list[str] = []
    preferred = Path("/usr/local/bin/httpx")
    if preferred.is_file() and os.access(preferred, os.X_OK):
        candidates.append(str(preferred))
    which = shutil.which("httpx")
    if which and which not in candidates:
        candidates.append(which)

    for candidate in candidates:
        if _is_projectdiscovery_httpx(candidate):
            return candidate
    return None


def _nuclei_missing_templates_signal(result: dict) -> bool:
    """Detect stderr/note patterns that indicate Nuclei has no usable templates."""
    chunks: list[str] = [str(result.get("note", "") or "")]
    for key in ("stderr_log", "stdout_log"):
        log_path = str(result.get(key, "") or "").strip()
        if log_path and Path(log_path).exists():
            chunks.append(_safe_read_head(Path(log_path), max_bytes=8000))
    combined = " ".join(chunks).lower()
    markers = (
        "no templates found",
        "could not find template",
        "no template",
        "0 templates",
        "templates not found",
        "failed to get templates",
        "template does not exist",
    )
    if any(m in combined for m in markers):
        return True
    if "nuclei-templates" in combined and any(
        token in combined for token in ("error", "failed", "missing", "not found", "unable")
    ):
        return True
    return False


def _result_template(
    tool_name: str,
    tool_label: str,
    phase: str,
    command: list[str],
    status: str,
    note: str = "",
) -> dict:
    return {
        "name": tool_name,
        "label": tool_label,
        "phase": phase,
        "command": command,
        "status": status,
        "returncode": None,
        "duration_seconds": 0.0,
        "stdout_log": "",
        "stderr_log": "",
        "output_files": [],
        "primary_output": "",
        "note": note,
        "coverage_applicable": True,
        "coverage_reason": "",
        "coverage_bucket": "",
    }


def _missing_tool_result(tool_name: str, tool_label: str, phase: str) -> dict:
    return _result_template(tool_name, tool_label, phase, [], "missing", "Tool not found on PATH.")


def _annotate_coverage(result: dict) -> dict:
    status = str(result.get("status", "") or "").strip().lower()
    note = str(result.get("note", "") or "").strip()

    if status in {"completed", "completed_no_output", "completed_partial"}:
        coverage_bucket = "completed"
        coverage_applicable = True
        if status == "completed_no_output":
            coverage_reason = note or "Completed successfully but did not return actionable output for this target."
        elif status == "completed_partial":
            coverage_reason = note or "Completed with partial evidence; review telemetry before dismissing the result."
        else:
            coverage_reason = note or "Completed successfully."
    elif status == "missing":
        coverage_bucket = "unavailable"
        coverage_applicable = True
        coverage_reason = note or "Required tool was unavailable on PATH."
    elif status == "timeout":
        coverage_bucket = "timeout"
        coverage_applicable = True
        coverage_reason = note or "Timed out before completing this applicable coverage check."
    elif status == "skipped":
        coverage_bucket = "not_applicable"
        coverage_applicable = False
        coverage_reason = note or "Skipped as intentionally non-applicable for the current profile or planner decision."
    elif status == "cancelled":
        coverage_bucket = "failed"
        coverage_applicable = True
        coverage_reason = note or "Cancelled before this applicable coverage check could complete."
    else:
        coverage_bucket = "failed"
        coverage_applicable = True
        coverage_reason = note or "Failed before this applicable coverage check could complete."

    result["coverage_applicable"] = coverage_applicable
    result["coverage_reason"] = coverage_reason
    result["coverage_bucket"] = coverage_bucket
    if status in {"completed_no_output", "completed_partial"} and not note:
        result["note"] = coverage_reason
    return result


def _write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="ignore")


def _spawn_tool_process(cmd: list[str], extra_env: dict | None = None) -> subprocess.Popen:
    kwargs: dict = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "env": extra_env,
    }
    # Isolate each tool in its own process group/session so cancellation and
    # timeout cleanup can terminate spawned children as well.
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(cmd, **kwargs)


def _terminate_process_tree(proc: subprocess.Popen, grace_seconds: float = 8.0):
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return

        os.killpg(proc.pid, signal.SIGTERM)
        deadline = time.perf_counter() + max(0.1, grace_seconds)
        while time.perf_counter() < deadline:
            if proc.poll() is not None:
                return
            time.sleep(0.1)
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_tool(
    cmd: list[str],
    tool_name: str,
    tool_label: str,
    phase: str,
    scan_dir: Path,
    output_files: list[Path] | None = None,
    stdout_file: Path | None = None,
    timeout: int = 600,
    extra_env: dict | None = None,
    acceptable_returncodes: set | None = None,
    cancel_check=None,
) -> dict:
    """Run a tool command and capture telemetry and logs."""
    result = _result_template(tool_name, tool_label, phase, cmd, "failed")
    start = time.perf_counter()

    stdout_log = scan_dir / f"{tool_name}.stdout.log"
    stderr_log = scan_dir / f"{tool_name}.stderr.log"

    try:
        proc = _spawn_tool_process(cmd, extra_env=extra_env)
        deadline = start + timeout
        stdout = ""
        stderr = ""
        returncode = None

        while True:
            if cancel_check and cancel_check():
                _terminate_process_tree(proc, grace_seconds=6.0)
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    _terminate_process_tree(proc, grace_seconds=1.0)
                    stdout, stderr = proc.communicate(timeout=2)
                duration = time.perf_counter() - start
                _write_text(stdout_log, stdout or "")
                _write_text(stderr_log, (stderr or "").strip() or f"{tool_label} cancelled by operator.")
                if stdout_file is not None and stdout:
                    _write_text(stdout_file, stdout)
                outputs = [str(p) for p in (output_files or []) if p.exists()]
                if stdout_file is not None and stdout_file.exists():
                    outputs.append(str(stdout_file))
                result.update(
                    {
                        "status": "cancelled",
                        "returncode": proc.returncode,
                        "duration_seconds": round(duration, 2),
                        "stdout_log": str(stdout_log),
                        "stderr_log": str(stderr_log),
                        "output_files": outputs,
                        "primary_output": outputs[0] if outputs else "",
                        "note": "Cancelled by operator.",
                    }
                )
                return result

            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                _terminate_process_tree(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    stdout, stderr = "", ""
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout, output=stdout, stderr=stderr)

            try:
                stdout, stderr = proc.communicate(timeout=min(1.0, max(0.1, remaining)))
                returncode = proc.returncode
                break
            except subprocess.TimeoutExpired:
                continue

        duration = time.perf_counter() - start
        _write_text(stdout_log, stdout or "")
        _write_text(stderr_log, stderr or "")
        if stdout_file is not None and stdout:
            _write_text(stdout_file, stdout)

        existing_output_paths = [p for p in (output_files or []) if p.exists()]
        outputs = [str(p) for p in existing_output_paths]
        if stdout_file is not None and stdout_file.exists():
            outputs.append(str(stdout_file))

        ok_codes = acceptable_returncodes if acceptable_returncodes is not None else {0}
        has_output = bool(outputs)
        has_meaningful_output = bool((stdout or "").strip()) or any(_path_has_content(path) for path in existing_output_paths)
        if stdout_file is not None and stdout_file.exists():
            has_meaningful_output = has_meaningful_output or _path_has_content(stdout_file)

        status = "completed" if (returncode in ok_codes or has_output) else "failed"
        if returncode == 0 and not has_meaningful_output:
            status = "completed_no_output"
        elif returncode not in ok_codes and has_output:
            status = "completed_partial"

        note = ""
        if status == "completed_no_output":
            note = "Completed successfully but did not return actionable output for this target."
        elif status == "completed_partial":
            note = stderr.strip()[:400] if stderr else "Completed with partial evidence; review captured output."
        elif returncode not in ok_codes and stderr:
            note = stderr.strip()[:400]
        elif returncode not in ok_codes:
            note = f"Exited with code {returncode} (no stderr)."

        result.update(
            {
                "status": status,
                "returncode": returncode,
                "duration_seconds": round(duration, 2),
                "stdout_log": str(stdout_log),
                "stderr_log": str(stderr_log),
                "output_files": outputs,
                "primary_output": outputs[0] if outputs else "",
                "note": note,
            }
        )
        return _annotate_coverage(result)
    except FileNotFoundError:
        return _annotate_coverage(_missing_tool_result(tool_name, tool_label, phase))
    except subprocess.TimeoutExpired:
        duration = time.perf_counter() - start
        _write_text(stderr_log, f"{tool_label} timed out after {timeout} seconds.")
        existing_output_paths = [p for p in (output_files or []) if p.exists()]
        outputs = [str(p) for p in existing_output_paths]
        if stdout_file is not None and stdout_file.exists():
            outputs.append(str(stdout_file))
        has_meaningful_output = any(_path_has_content(path) for path in existing_output_paths)
        if stdout_file is not None and stdout_file.exists():
            has_meaningful_output = has_meaningful_output or _path_has_content(stdout_file)
        result.update(
            {
                "status": "completed_partial" if has_meaningful_output else "timeout",
                "duration_seconds": round(duration, 2),
                "stdout_log": str(stdout_log),
                "stderr_log": str(stderr_log),
                "output_files": outputs,
                "primary_output": outputs[0] if outputs else "",
                "note": (
                    f"Timed out after {timeout} seconds. Partial output was captured before termination."
                    if has_meaningful_output
                    else f"Timed out after {timeout} seconds."
                ),
            }
        )
        return _annotate_coverage(result)
    except Exception as exc:
        duration = time.perf_counter() - start
        _write_text(stderr_log, str(exc))
        result.update(
            {
                "status": "failed",
                "duration_seconds": round(duration, 2),
                "stdout_log": str(stdout_log),
                "stderr_log": str(stderr_log),
                "note": str(exc)[:400],
            }
        )
        return _annotate_coverage(result)


def _resolve_wordlist(config: dict) -> str | None:
    configured = config.get("content_wordlist")
    if configured and Path(configured).exists():
        return configured
    for candidate in WORDLIST_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def _extract_detect_text(*paths: Path) -> str:
    # Heuristics do not need full files; cap reads to avoid stalling on large outputs.
    return "\n".join(_safe_read_head(path).lower() for path in paths if path.exists())


def _extract_urls_from_file(path: Path, max_lines: int = 25_000, max_urls: int = 5_000) -> set[str]:
    urls: set[str] = set()
    if not path.exists():
        return urls

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for idx, raw_line in enumerate(f):
                if idx >= max_lines or len(urls) >= max_urls:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("http://") or line.startswith("https://"):
                    urls.add(line)
                    continue
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    candidates = [
                        obj.get("url"),
                        obj.get("endpoint"),
                        obj.get("matched"),
                        (obj.get("request") or {}).get("url") if isinstance(obj.get("request"), dict) else None,
                    ]
                    for candidate in candidates:
                        if isinstance(candidate, str) and candidate.startswith(("http://", "https://")):
                            urls.add(candidate)
                            if len(urls) >= max_urls:
                                break
    except OSError:
        return urls
    return urls


def _collect_surface_signals(scan_dir: Path, target_url: str) -> dict:
    """Collect lightweight per-target signals used for adaptive tool planning."""
    urls = set([target_url])
    urls.update(_extract_urls_from_file(scan_dir / "gau.txt", max_lines=8_000, max_urls=1_500))
    katana_urls = _extract_urls_from_file(scan_dir / "katana.jsonl", max_lines=30_000, max_urls=5_000)
    urls.update(katana_urls)

    params: set[str] = set()
    api_like = 0
    html_like = 0
    auth_like = 0
    wp_paths = 0
    joomla_paths = 0
    drupal_paths = 0
    for u in urls:
        try:
            parsed = urlparse(u)
        except Exception:
            continue
        path_l = (parsed.path or "").lower()
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for k, _ in query_pairs:
            if k:
                params.add(k.lower())

        if any(marker in path_l for marker in ("/api", "/graphql", "/swagger", "/openapi", ".json")):
            api_like += 1
        if any(marker in path_l for marker in (".php", ".aspx", ".jsp", ".html", "/admin", "/login", "/signin", "/register", "/wp-")):
            html_like += 1
        if any(marker in path_l for marker in ("/login", "/signin", "/auth", "/token", "/oauth", "/session")):
            auth_like += 1
        if "/wp-" in path_l or "xmlrpc.php" in path_l or "wp-json" in path_l:
            wp_paths += 1
        if "/administrator" in path_l or "com_" in path_l:
            joomla_paths += 1
        if "/sites/default" in path_l or "/node/" in path_l:
            drupal_paths += 1

    detect_text = _extract_detect_text(
        scan_dir / "httpx.json",
        scan_dir / "whatweb.json",
        scan_dir / "whatweb.stdout.log",
        scan_dir / "nuclei.jsonl",
    )
    if "text/html" in detect_text or "<form" in detect_text:
        html_like += 2
    if "application/json" in detect_text or "openapi" in detect_text or "graphql" in detect_text:
        api_like += 2

    return {
        "url_count": len(urls),
        "param_count": len(params),
        "api_like_count": api_like,
        "html_like_count": html_like,
        "auth_like_count": auth_like,
        "wordpress_path_count": wp_paths,
        "joomla_path_count": joomla_paths,
        "drupal_path_count": drupal_paths,
        "parameters": sorted(params)[:40],
    }


def detect_profile_from_artifacts(scan_dir: Path, url: str, requested_profile: str) -> dict:
    """Infer the target profile when the user selects auto mode."""
    if requested_profile and requested_profile != "auto":
        return {
            "requested_profile": requested_profile,
            "effective_profile": requested_profile,
            "confidence": "user-selected",
            "scores": {requested_profile: 10},
            "reasons": ["Profile provided explicitly by the operator."],
        }

    scores = {"wordpress": 0, "joomla": 0, "drupal": 0, "api": 0, "webapp": 0}
    reasons: list[str] = []
    detect_text = _extract_detect_text(
        scan_dir / "httpx.json",
        scan_dir / "whatweb.json",
        scan_dir / "whatweb.stdout.log",
        scan_dir / "nuclei.jsonl",
    )
    parsed = urlparse(url)
    path_hint = (parsed.path or "").lower()
    surface_signals = _collect_surface_signals(scan_dir, url)

    patterns = {
        "wordpress": ["wordpress", "wp-content", "wp-json", "wp-includes", "xmlrpc.php"],
        "joomla": ["joomla", "com_content", "/administrator", "joomscan"],
        "drupal": ["drupal", "/sites/default", "/misc/", "droopescan"],
        "api": ["application/json", "openapi", "swagger", "graphql", "/api/", "rest api"],
    }

    for profile, markers in patterns.items():
        for marker in markers:
            if marker in detect_text or marker in path_hint:
                scores[profile] += 2
                reasons.append(f"Matched {profile} indicator: {marker}")

    wp_paths = surface_signals.get("wordpress_path_count", 0)
    joomla_paths = surface_signals.get("joomla_path_count", 0)
    drupal_paths = surface_signals.get("drupal_path_count", 0)
    if wp_paths >= 2:
        scores["wordpress"] += 3
        reasons.append("Detected multiple WordPress path indicators from crawl output.")
    if joomla_paths >= 2:
        scores["joomla"] += 3
        reasons.append("Detected multiple Joomla path indicators from crawl output.")
    if drupal_paths >= 2:
        scores["drupal"] += 3
        reasons.append("Detected multiple Drupal path indicators from crawl output.")

    if surface_signals["api_like_count"] >= 3:
        scores["api"] += 3
        reasons.append("Detected API-like routes and/or response hints.")
    if surface_signals["param_count"] >= 3 and surface_signals["api_like_count"] >= 2:
        scores["api"] += 2
        reasons.append("Detected parameterized API surface.")
    if surface_signals["html_like_count"] >= 3:
        scores["webapp"] += 3
        reasons.append("Detected HTML/web-login/admin-like routes.")

    if "x-powered-by" in detect_text or "server" in detect_text:
        scores["webapp"] += 1
    if path_hint.startswith("/api") or path_hint.endswith(".json"):
        scores["api"] += 2

    best_profile = max(scores, key=scores.get)
    if scores[best_profile] <= 0:
        best_profile = "api" if path_hint.startswith("/api") else "webapp"
        reasons.append("No strong CMS markers detected; defaulted to generic coverage.")

    confidence = "high" if scores[best_profile] >= 4 else "medium" if scores[best_profile] >= 2 else "low"
    return {
        "requested_profile": "auto",
        "effective_profile": best_profile,
        "confidence": confidence,
        "scores": scores,
        "surface_signals": surface_signals,
        "reasons": reasons[:8],
    }


def run_httpx(url: str, config: dict, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running httpx probe...")
    output_file = scan_dir / "httpx.json"
    httpx_bin = _resolve_httpx_binary()
    if not httpx_bin:
        result = _result_template(
            "httpx",
            "httpx",
            "passive",
            ["httpx"],
            "failed",
            "ProjectDiscovery httpx not found (Python httpx CLI may be shadowing PATH). Install Go httpx or remove /opt/venv/bin/httpx.",
        )
        return _annotate_coverage(result)
    rate = str(config.get("httpx_rate_limit", 25))
    cmd = [
        httpx_bin,
        "-u",
        url,
        "-json",
        "-o",
        str(output_file),
        "-rate-limit",
        rate,
        "-silent",
        "-sc",
        "-title",
        "-td",
        "-ws",
        "-fr",
    ]
    result = _run_tool(cmd, "httpx", "httpx", "passive", scan_dir, output_files=[output_file], acceptable_returncodes={0, 1}, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("httpx complete.")
    return result


def run_whatweb(url: str, config: dict, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running WhatWeb fingerprinting...")
    output_file = scan_dir / "whatweb.json"
    threads = str(config.get("whatweb_max_threads", 10))
    cmd = ["whatweb", url, f"--log-json={output_file}", "--max-threads", threads, "-q"]
    result = _run_tool(cmd, "whatweb", "WhatWeb", "passive", scan_dir, output_files=[output_file], cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("WhatWeb complete.")
    return result


def run_nuclei(url: str, config: dict, scan_dir: Path, profile: str, scan_mode: str = "passive", cancel_check=None) -> dict:
    ui.status("Running Nuclei...")
    output_file = scan_dir / "nuclei.jsonl"
    if profile == "wordpress":
        tags = config.get("nuclei_tags_wordpress", config.get("nuclei_tags", "wordpress,wp-plugin,wp-theme,cve,misconfig,exposure"))
    elif profile == "joomla":
        tags = config.get("nuclei_tags_joomla", "joomla,cve,misconfig,exposure")
    elif profile == "drupal":
        tags = config.get("nuclei_tags_drupal", "drupal,cve,misconfig,exposure")
    elif profile == "api":
        tags = config.get("nuclei_tags_api", "api,graphql,cve,exposure,misconfig,default-login")
    else:
        tags = config.get(
            "nuclei_tags_broad",
            "cve,rce,lfi,sqli,xss,ssrf,exposure,misconfig,default-login,redirect,takeover,token,credentials",
        )

    severities = config.get("nuclei_severity", "critical,high,medium,low,info")
    rate = str(config.get("nuclei_rate_limit", 25))
    cmd = [
        "nuclei",
        "-u",
        url,
        "-tags",
        tags,
        "-severity",
        severities,
        "-rate-limit",
        rate,
        "-jsonl",
        "-o",
        str(output_file),
        "-silent",
    ]
    timeout = int(config.get("nuclei_timeout_seconds", 900) or 900)
    result = _run_tool(cmd, "nuclei", "Nuclei", "passive", scan_dir, output_files=[output_file], timeout=timeout, cancel_check=cancel_check)

    retry_on_empty = bool(config.get("nuclei_retry_auto_scan_on_empty", True))
    full_only_auto_fallback = bool(config.get("nuclei_retry_auto_scan_on_empty_full_only", True))
    run_auto_fallback = retry_on_empty and (scan_mode == "full" or not full_only_auto_fallback)
    fallback_notes: list[str] = []
    if result.get("status") == "completed_no_output" and run_auto_fallback:
        ui.status("Nuclei returned no tagged matches; retrying with auto-scan templates...")
        auto_cmd = [
            "nuclei",
            "-u",
            url,
            "-as",
            "-severity",
            severities,
            "-rate-limit",
            rate,
            "-jsonl",
            "-o",
            str(output_file),
            "-silent",
        ]
        auto_timeout = int(config.get("nuclei_auto_fallback_timeout_seconds", max(timeout, 1200)) or max(timeout, 1200))
        auto_concurrency = int(config.get("nuclei_auto_scan_concurrency", 10) or 10)
        auto_bulk_size = int(config.get("nuclei_auto_scan_bulk_size", 10) or 10)
        req_timeout = int(config.get("nuclei_request_timeout", 10) or 10)
        auto_cmd += [
            "-concurrency", str(auto_concurrency),
            "-bulk-size", str(auto_bulk_size),
            "-timeout", str(req_timeout),
            "-retries", "0",
        ]
        auto_result = _run_tool(
            auto_cmd,
            "nuclei",
            "Nuclei",
            "passive",
            scan_dir,
            output_files=[output_file],
            timeout=auto_timeout,
            cancel_check=cancel_check,
        )
        if auto_result.get("status") in {"completed", "completed_partial"}:
            fallback_notes.append("Primary tagged scan returned no output; fallback auto-scan run produced findings or artifacts.")
            result = auto_result
        elif auto_result.get("status") == "timeout":
            fallback_notes.append("Primary tagged scan returned no output; auto-scan fallback timed out before producing results.")
            result = auto_result
        else:
            result = auto_result

    if result.get("status") == "completed_no_output" and retry_on_empty and scan_mode != "full" and full_only_auto_fallback:
        fallback_notes.append("Auto-scan fallback is limited to full scans; passive run completed with no Nuclei matches.")

    run_full_fallback = bool(config.get("nuclei_retry_full_template_on_empty_full", True)) and scan_mode == "full"
    if result.get("status") == "completed_no_output" and run_full_fallback:
        ui.status("Nuclei auto-scan returned no matches; retrying with broad full-template pass...")
        full_timeout = int(config.get("nuclei_full_fallback_timeout_seconds", max(timeout, 1500)) or max(timeout, 1500))
        full_concurrency = int(config.get("nuclei_auto_scan_concurrency", 10) or 10)
        full_bulk_size = int(config.get("nuclei_auto_scan_bulk_size", 10) or 10)
        req_timeout = int(config.get("nuclei_request_timeout", 10) or 10)
        full_cmd = [
            "nuclei",
            "-u",
            url,
            "-severity",
            severities,
            "-rate-limit",
            rate,
            "-jsonl",
            "-o",
            str(output_file),
            "-silent",
            "-concurrency", str(full_concurrency),
            "-bulk-size", str(full_bulk_size),
            "-timeout", str(req_timeout),
            "-retries", "0",
        ]
        full_result = _run_tool(
            full_cmd,
            "nuclei",
            "Nuclei",
            "passive",
            scan_dir,
            output_files=[output_file],
            timeout=full_timeout,
            cancel_check=cancel_check,
        )
        if full_result.get("status") != "completed_no_output":
            fallback_notes.append("Auto-scan fallback was empty; broad full-template pass was used.")
            result = full_result
        else:
            result = full_result
            fallback_notes.append("Tagged, auto-scan, and broad full-template Nuclei passes all returned no matches.")

    if result.get("status") == "completed_no_output":
        if _nuclei_missing_templates_signal(result):
            fallback_notes.append(
                "Nuclei templates appear missing or unusable. Update templates with `nuclei -ut` "
                "or set UPDATE_NUCLEI_TEMPLATES=1 and rebuild/restart the container."
            )
        else:
            fallback_notes.append(
                "Nuclei executed successfully but reported no findings. This can be normal for low-exposure targets; update templates and widen scope if needed."
            )

    if fallback_notes:
        existing = str(result.get("note", "") or "").strip()
        result["note"] = " ".join([part for part in [existing, *fallback_notes] if part]).strip()
        result = _annotate_coverage(result)

    if result["status"].startswith("completed"):
        ui.ok("Nuclei complete.")
    return result


def run_nikto(url: str, config: dict, scan_dir: Path, profile: str = "webapp", cancel_check=None) -> dict:
    ui.status("Running Nikto scan...")
    output_file = scan_dir / "nikto.json"
    pause = str(config.get("nikto_pause_seconds", 0))
    if profile == "wordpress":
        max_time = int(config.get("nikto_maxtime_wordpress_seconds", 180))
        hard_timeout = int(config.get("nikto_timeout_wordpress_seconds", max_time + 90))
        tuning = str(config.get("nikto_tuning_wordpress", config.get("nikto_tuning", "123bde")))
    else:
        max_time = int(config.get("nikto_maxtime_seconds", 180))
        hard_timeout = int(config.get("nikto_timeout_seconds", max_time + 90))
        tuning = str(config.get("nikto_tuning", "123456789"))
    # -maxtime limits nikto's own internal runtime so it exits gracefully before the hard timeout
    cmd = ["nikto", "-h", url, "-Format", "json", "-output", str(output_file),
        "-Pause", pause, "-nointeractive", "-maxtime", f"{max_time}s", "-Tuning", tuning]
    result = _run_tool(cmd, "nikto", "Nikto", "passive", scan_dir, output_files=[output_file], timeout=hard_timeout, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Nikto complete.")
    return result


def run_sslyze(hostname: str, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running SSLyze TLS audit...")
    output_file = scan_dir / "sslyze.json"
    import os as _os
    # Suppress ALL Python warnings (including CryptographyDeprecationWarning)
    _env = _os.environ.copy()
    _env["PYTHONWARNINGS"] = "ignore"
    # Also run sslyze via python -W ignore to guarantee warning suppression
    cmd = ["python", "-W", "ignore", "-m", "sslyze", hostname, f"--json_out={output_file}"]
    result = _run_tool(cmd, "sslyze", "SSLyze", "passive", scan_dir, output_files=[output_file], timeout=180, extra_env=_env, acceptable_returncodes={0, 1}, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("SSLyze complete.")
    return result


def run_subfinder(hostname: str, scan_dir: Path, config: dict, cancel_check=None) -> dict:
    ui.status("Running Subfinder...")
    output_file = scan_dir / "subfinder.json"
    cmd = ["subfinder", "-d", hostname, "-oJ", "-o", str(output_file), "-silent"]
    timeout = int(config.get("subfinder_timeout_seconds", 300))
    result = _run_tool(cmd, "subfinder", "Subfinder", "passive", scan_dir, output_files=[output_file], timeout=timeout, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Subfinder complete.")
    return result


def run_corsy(url: str, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running Corsy...")
    output_file = scan_dir / "corsy.txt"
    cmd = ["corsy", "-u", url]
    result = _run_tool(cmd, "corsy", "Corsy", "passive", scan_dir, output_files=[output_file], stdout_file=output_file, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Corsy complete.")
    return result


def run_gau(hostname: str, scan_dir: Path, config: dict, cancel_check=None) -> dict:
    ui.status("Running gau...")
    output_file = scan_dir / "gau.txt"
    providers = str(config.get("gau_providers", "wayback,otx,commoncrawl") or "wayback,otx,commoncrawl").strip()
    cmd = ["gau", hostname, "--retries", "2", "--providers", providers]
    timeout = int(config.get("gau_timeout_seconds", 240))
    result = _run_tool(cmd, "gau", "gau", "passive", scan_dir, output_files=[output_file], stdout_file=output_file, timeout=timeout, cancel_check=cancel_check)
    if result.get("status") == "completed_no_output":
        result["note"] = (
            f"gau finished successfully but did not return any archived URLs from providers: {providers}."
        )
        result = _annotate_coverage(result)
    if result["status"].startswith("completed"):
        ui.ok("gau complete.")
    return result


def run_katana(url: str, scan_dir: Path, config: dict, cancel_check=None) -> dict:
    ui.status("Running Katana crawler...")
    output_file = scan_dir / "katana.jsonl"
    cmd = ["katana", "-u", url, "-jsonl", "-o", str(output_file), "-silent"]
    timeout = int(config.get("katana_timeout_seconds", 480))
    result = _run_tool(cmd, "katana", "Katana", "passive", scan_dir, output_files=[output_file], timeout=timeout, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Katana complete.")
    return result


def run_wpscan(url: str, config: dict, tokens: dict, scan_dir: Path, is_local_target: bool, cancel_check=None) -> dict:
    ui.status("Running WPScan...")
    if int(config.get("wpscan_max_threads", 1) or 0) <= 0:
        return _result_template("wpscan", "WPScan", "passive", [], "skipped", "Skipped by automation rule: WPScan disabled in current profile preset.")
    output_file = scan_dir / "wpscan.json"
    enum = config.get("wpscan_enumerate", "vp,vt,u")
    threads = str(config.get("wpscan_max_threads", 1))
    cmd = ["wpscan", "--url", url, "--enumerate", enum, "--max-threads", threads, "--format", "json", "--output", str(output_file), "--no-banner"]
    if is_local_target:
        cmd.append("--disable-tls-checks")
    token = tokens.get("wpscan_api_token", "")
    if token:
        cmd.extend(["--api-token", token])
    result = _run_tool(
        cmd,
        "wpscan",
        "WPScan",
        "passive",
        scan_dir,
        output_files=[output_file],
        timeout=900,
        # 0 = OK (no vulns), 5 = VULNERABLE (findings present) — both are successful scans
        acceptable_returncodes={0, 5},
        cancel_check=cancel_check,
    )
    if result["status"].startswith("completed"):
        ui.ok("WPScan complete.")
    return result


def run_joomscan(url: str, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running JoomScan...")
    output_file = scan_dir / "joomscan.txt"
    cmd = ["joomscan", "--url", url]
    result = _run_tool(cmd, "joomscan", "JoomScan", "passive", scan_dir, output_files=[output_file], stdout_file=output_file, timeout=900, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("JoomScan complete.")
    return result


def run_droopescan(url: str, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running Droopescan...")
    output_file = scan_dir / "droopescan.json"
    cmd = ["droopescan", "scan", "drupal", "-u", url, "-o", "json"]
    result = _run_tool(cmd, "droopescan", "Droopescan", "passive", scan_dir, output_files=[output_file], stdout_file=output_file, timeout=900, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Droopescan complete.")
    return result


def run_cmsmap(url: str, scan_dir: Path, profile: str = "webapp", cancel_check=None) -> dict:
    ui.status("Running CMSMap...")
    output_file = scan_dir / "cmsmap.json"
    cmd = ["cmsmap", "-t", url, "-o", str(output_file), "-f", "J"]
    import os as _os
    _env = _os.environ.copy()
    _env["PYTHONWARNINGS"] = "ignore"
    cmsmap_timeout = 600 if profile == "wordpress" else 480
    result = _run_tool(
        cmd,
        "cmsmap",
        "CMSMap",
        "active",
        scan_dir,
        output_files=[output_file],
        timeout=cmsmap_timeout,
        extra_env=_env,
        acceptable_returncodes={0, 1},
        cancel_check=cancel_check,
    )
    if result["status"].startswith("completed"):
        ui.ok("CMSMap complete.")
    return result


def run_sqlmap(url: str, scan_dir: Path, profile: str, config: dict, cancel_check=None) -> dict:
    ui.status("Running SQLMap...")
    output_dir = scan_dir / "sqlmap-out"
    output_dir.mkdir(parents=True, exist_ok=True)
    # level=1 risk=1 is sufficient for automated pipeline; time-sec limits blind-injection waits
    cmd = ["sqlmap", "--batch", "--output-dir", str(output_dir),
        "--level=1", "--risk=1", "--time-sec=8", "--timeout=20", "--retries=1", "--no-cast"]
    if profile == "wordpress":
        cmd.extend(["-u", f"{url.rstrip('/')}/wp-login.php", "--forms"])
    elif profile == "joomla":
        cmd.extend(["-u", f"{url.rstrip('/')}/administrator/index.php", "--forms"])
    else:
        # crawl=1 instead of 2 to halve crawler depth for generic targets
        cmd.extend(["-u", url, "--crawl=1", "--forms"])
    timeout = int(config.get("sqlmap_timeout_api_seconds", 240)) if profile == "api" else int(config.get("sqlmap_timeout_seconds", 420))
    result = _run_tool(cmd, "sqlmap", "SQLMap", "active", scan_dir, output_files=[output_dir], timeout=timeout, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("SQLMap complete.")
    return result


def run_ffuf(url: str, config: dict, scan_dir: Path, profile: str = "webapp", cancel_check=None) -> dict:
    ui.status("Running ffuf...")
    output_file = scan_dir / "ffuf.json"
    ffuf_threads = str(config.get("ffuf_threads", 35))
    ffuf_timeout = int(config.get("ffuf_timeout_seconds", 900))
    ffuf_maxtime = str(config.get("ffuf_maxtime_seconds", 420))
    status_match = str(config.get("ffuf_match_codes", "200,204,301,302,307,401,403"))
    status_filter = str(config.get("ffuf_filter_codes", "400,404,405,500,501,502,503"))

    if profile == "wordpress":
        wp_wordlist_file = scan_dir / "ffuf-wp-wordlist.txt"
        wp_entries = [
            "wp-login.php",
            "xmlrpc.php",
            "wp-admin/",
            "wp-content/",
            "wp-content/plugins/",
            "wp-content/themes/",
            "wp-content/uploads/",
            "wp-json/",
            "wp-cron.php",
            "readme.html",
            "license.txt",
            ".htaccess",
            "debug.log",
            "backup.zip",
            "database.sql",
        ]
        _write_text(wp_wordlist_file, "\n".join(wp_entries) + "\n")
        cmd = [
            "ffuf",
            "-u",
            f"{url.rstrip('/')}/FUZZ",
            "-w",
            str(wp_wordlist_file),
            "-o",
            str(output_file),
            "-of",
            "json",
            "-s",
            "-ac",
            "-mc",
            status_match,
            "-fc",
            status_filter,
            "-t",
            ffuf_threads,
            "-maxtime",
            ffuf_maxtime,
        ]
    else:
        wordlist = _resolve_wordlist(config)
        if not wordlist:
            return _result_template("ffuf", "ffuf", "active", [], "skipped", "No compatible content-discovery wordlist found.")
        cmd = [
            "ffuf",
            "-u",
            f"{url.rstrip('/')}/FUZZ",
            "-w",
            wordlist,
            "-o",
            str(output_file),
            "-of",
            "json",
            "-s",
            "-ac",
            "-mc",
            status_match,
            "-fc",
            status_filter,
            "-t",
            ffuf_threads,
            "-maxtime",
            ffuf_maxtime,
        ]

    result = _run_tool(cmd, "ffuf", "ffuf", "active", scan_dir, output_files=[output_file], timeout=ffuf_timeout, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("ffuf complete.")
    return result


def run_feroxbuster(url: str, config: dict, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running Feroxbuster...")
    wordlist = _resolve_wordlist(config)
    if not wordlist:
        return _result_template("feroxbuster", "Feroxbuster", "active", [], "skipped", "No compatible content-discovery wordlist found.")
    output_file = scan_dir / "feroxbuster.json"
    cmd = ["feroxbuster", "-u", url, "-w", wordlist, "--json", "-o", str(output_file), "-q"]
    timeout = int(config.get("feroxbuster_timeout_seconds", 600) or 600)
    result = _run_tool(cmd, "feroxbuster", "Feroxbuster", "active", scan_dir, output_files=[output_file], timeout=timeout, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Feroxbuster complete.")
    return result


def run_arjun(url: str, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running Arjun parameter discovery...")
    output_file = scan_dir / "arjun.txt"
    cmd = ["arjun", "-u", url, "-oT", str(output_file)]
    result = _run_tool(cmd, "arjun", "Arjun", "active", scan_dir, output_files=[output_file], timeout=900, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Arjun complete.")
    return result


def run_dalfox(url: str, scan_dir: Path, cancel_check=None) -> dict:
    ui.status("Running Dalfox...")
    output_file = scan_dir / "dalfox.json"
    cmd = ["dalfox", "url", url, "--format", "json", "-o", str(output_file), "--no-color"]
    result = _run_tool(cmd, "dalfox", "Dalfox", "active", scan_dir, output_files=[output_file], timeout=1200, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Dalfox complete.")
    return result


def run_commix(url: str, scan_dir: Path, config: dict, profile: str, cancel_check=None) -> dict:
    ui.status("Running Commix...")
    output_file = scan_dir / "commix.txt"
    cmd = ["commix", "--url", url, "--batch", "--crawl=2"]
    timeout = int(config.get("commix_timeout_api_seconds", 420)) if profile == "api" else int(config.get("commix_timeout_seconds", 900))
    result = _run_tool(cmd, "commix", "Commix", "active", scan_dir, output_files=[output_file], stdout_file=output_file, timeout=timeout, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Commix complete.")
    return result


def run_wapiti(url: str, scan_dir: Path, config: dict, profile: str, cancel_check=None) -> dict:
    ui.status("Running Wapiti...")
    output_file = scan_dir / "wapiti.json"
    cmd = ["wapiti", "-u", url, "-f", "json", "-o", str(output_file)]
    timeout = int(config.get("wapiti_timeout_api_seconds", 360)) if profile == "api" else int(config.get("wapiti_timeout_seconds", 600))
    result = _run_tool(cmd, "wapiti", "Wapiti", "active", scan_dir, output_files=[output_file], timeout=timeout, cancel_check=cancel_check)
    if result["status"].startswith("completed"):
        ui.ok("Wapiti complete.")
    return result


def _run_registered_tool(
    tool_name: str,
    phase: str,
    installed: dict[str, bool],
    runner,
) -> dict:
    tool_meta = next((t for t in TOOLS if t["name"] == tool_name), {"label": tool_name})
    if not installed.get(tool_name):
        ui.warn(f"Skipping {tool_name} (not installed or missing from PATH).")
        return _annotate_coverage(_missing_tool_result(tool_name, tool_meta["label"], phase))
    return _annotate_coverage(runner())


def run_all_tools(
    url: str,
    scan_dir: Path,
    config: dict,
    tokens: dict,
    mode: str,
    profile: str = "auto",
    progress_callback=None,
    should_cancel=None,
) -> dict:
    """Run the scan plan and return rich execution metadata."""
    installed = get_installed_tools()
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or url
    local_target = is_local(url)
    scan_dir.mkdir(parents=True, exist_ok=True)

    tool_runs: list[dict] = []
    completed_count = 0
    parallel_enabled = bool(config.get("parallel_scans", False))
    max_parallel_tools = max(1, int(config.get("max_parallel_tools", 3)))
    max_parallel_heavy_tools = max(1, int(config.get("max_parallel_heavy_tools", 2)))
    automation_scheduler = bool(config.get("automation_scheduler", True))
    strict_tool_coverage = bool(config.get("strict_tool_coverage", False))
    toolset_profile = str(config.get("toolset_profile", "portable_core")).strip().lower() or "portable_core"
    allowed_tools = get_allowed_tools_for_profile(toolset_profile)
    fast_profile_tools = set(config.get("fast_profile_tools", ["httpx", "whatweb", "corsy", "gau", "sslyze", "subfinder"]))
    deferred_passive_tools = set(config.get("deferred_passive_tools", ["katana"]))
    deferred_profile_tools = set(config.get("deferred_profile_tools", ["wpscan"]))
    low_priority_tools = set(config.get("low_priority_tools", ["katana", "wpscan", "cmsmap", "commix"]))
    budget_key = f"scan_time_budget_{mode}_seconds"
    scan_time_budget_seconds = max(0, int(config.get(budget_key, 0) or 0))
    deadline_skip_grace_seconds = max(0, int(config.get("deadline_skip_grace_seconds", 180)))
    run_started = time.monotonic()

    def _emit(event: dict):
        if progress_callback:
            progress_callback(event)

    def _finalize_execution(
        effective_profile: str,
        profile_info: dict,
        interrupted: bool = False,
        interrupt_reason: str = "",
    ) -> dict:
        completed = [item["name"] for item in tool_runs if item["status"] in ("completed", "completed_no_output", "completed_partial")]
        profile_info = profile_info or {
            "requested_profile": profile,
            "effective_profile": effective_profile,
            "confidence": "unknown",
            "scores": {effective_profile: 1},
            "reasons": [],
        }
        if interrupted:
            profile_info = dict(profile_info)
            reasons = list(profile_info.get("reasons", []))
            if interrupt_reason:
                reasons.append(interrupt_reason)
            profile_info["reasons"] = reasons[-8:]
            profile_info["interrupted"] = True
            profile_info["interrupt_reason"] = interrupt_reason
        profile_info["tools_completed"] = completed
        profile_info["tools_attempted"] = [item["name"] for item in tool_runs]
        return {
            "requested_profile": profile,
            "effective_profile": effective_profile,
            "profile_detection": profile_info,
            "tools": tool_runs,
            "tools_used": completed,
            "interrupted": interrupted,
            "interrupt_reason": interrupt_reason,
        }

    def _tool_meta(tool_name: str) -> dict:
        return next((t for t in TOOLS if t["name"] == tool_name), {"name": tool_name, "label": tool_name, "phase": "active"})

    def _tool_progress(total_tools: int) -> int:
        return round((completed_count / max(1, total_tools)) * 80) + 4

    def _emit_tool_started(total_tools: int, tool_name: str, phase: str):
        tool_meta = _tool_meta(tool_name)
        _emit(
            {
                "event": "tool_started",
                "tool": tool_name,
                "tool_label": tool_meta.get("label", tool_name),
                "phase": phase,
                "completed_tools": completed_count,
                "total_tools": total_tools,
                "progress": _tool_progress(total_tools),
                "message": f"Running {tool_meta.get('label', tool_name)}.",
            }
        )

    def _emit_tool_finished(total_tools: int, tool_name: str, phase: str, result: dict):
        tool_meta = _tool_meta(tool_name)
        status = result.get("status", "unknown")
        note = str(result.get("note", "") or "").strip()
        if status == "timeout":
            message = f"{tool_meta.get('label', tool_name)} timed out."
        elif status == "skipped" and note:
            message = note
        elif status == "cancelled":
            message = f"{tool_meta.get('label', tool_name)} cancelled."
        elif status == "missing":
            message = f"{tool_meta.get('label', tool_name)} is missing from PATH."
        else:
            message = f"{tool_meta.get('label', tool_name)} completed with status {status}."
        _emit(
            {
                "event": "tool_finished",
                "tool": tool_name,
                "tool_label": tool_meta.get("label", tool_name),
                "phase": phase,
                "status": status,
                "duration_seconds": result.get("duration_seconds", 0),
                "completed_tools": completed_count,
                "total_tools": total_tools,
                "progress": _tool_progress(total_tools),
                "message": message,
                "note": note,
            }
        )

    def _skip_tool_result(tool_name: str, phase: str, reason: str) -> dict:
        tool_meta = _tool_meta(tool_name)
        return _annotate_coverage(_result_template(tool_name, tool_meta.get("label", tool_name), phase, [], "skipped", reason))

    def _profile_skip(tool_name: str, phase: str) -> dict | None:
        if tool_name in allowed_tools:
            return None
        return _skip_tool_result(
            tool_name,
            phase,
            f"Skipped by toolset profile: {toolset_profile} keeps {tool_name} disabled for lighter container runs.",
        )

    def _budget_skip(tool_name: str, phase: str) -> dict | None:
        if strict_tool_coverage:
            return None
        if scan_time_budget_seconds <= 0 or tool_name not in low_priority_tools:
            return None
        if (time.monotonic() - run_started) < max(0, scan_time_budget_seconds - deadline_skip_grace_seconds):
            return None
        minutes = max(1, scan_time_budget_seconds // 60)
        return _skip_tool_result(
            tool_name,
            phase,
            f"Skipped by automation rule: preserving report completion budget near the {minutes} minute target.",
        )

    def _with_progress(total_tools: int, tool_name: str, phase: str, runner):
        nonlocal completed_count

        if should_cancel and should_cancel():
            cancel_result = _skip_tool_result(tool_name, phase, "Execution interrupted by timeout/cancellation before this tool started.")
            cancel_result["status"] = "cancelled"
            cancel_result = _annotate_coverage(cancel_result)
            completed_count += 1
            _emit_tool_finished(total_tools, tool_name, phase, cancel_result)
            return cancel_result
        profile_skip = _profile_skip(tool_name, phase)
        if profile_skip is not None:
            completed_count += 1
            _emit_tool_finished(total_tools, tool_name, phase, profile_skip)
            return profile_skip
        skip_result = _budget_skip(tool_name, phase)
        if skip_result is not None:
            completed_count += 1
            _emit_tool_finished(total_tools, tool_name, phase, skip_result)
            return skip_result

        _emit_tool_started(total_tools, tool_name, phase)
        result = _run_registered_tool(tool_name, phase, installed, runner)
        completed_count += 1
        _emit_tool_finished(total_tools, tool_name, phase, result)
        return result

    def _execute_plan(plan: list[tuple[str, str, callable]], total_tools: int, max_workers: int) -> list[dict]:
        nonlocal completed_count

        if not plan:
            return []

        worker_count = 1 if (not parallel_enabled or max_workers <= 1 or len(plan) == 1) else min(len(plan), max_workers)
        if worker_count == 1:
            return [_with_progress(total_tools, tool_name, phase, runner) for tool_name, phase, runner in plan]

        results: list[dict | None] = [None] * len(plan)
        pending = list(enumerate(plan))
        running: dict = {}

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            def _submit_ready():
                nonlocal completed_count
                while pending and len(running) < worker_count:
                    index, (tool_name, phase, runner) = pending.pop(0)
                    if should_cancel and should_cancel():
                        break
                    profile_skip = _profile_skip(tool_name, phase)
                    if profile_skip is not None:
                        results[index] = profile_skip
                        completed_count += 1
                        _emit_tool_finished(total_tools, tool_name, phase, profile_skip)
                        continue
                    skip_result = _budget_skip(tool_name, phase)
                    if skip_result is not None:
                        results[index] = skip_result
                        completed_count += 1
                        _emit_tool_finished(total_tools, tool_name, phase, skip_result)
                        continue
                    _emit_tool_started(total_tools, tool_name, phase)
                    future = executor.submit(_run_registered_tool, tool_name, phase, installed, runner)
                    running[future] = (index, tool_name, phase)

            _submit_ready()

            while running:
                done, _ = wait(list(running.keys()), return_when=FIRST_COMPLETED)
                for future in done:
                    index, tool_name, phase = running.pop(future)
                    result = future.result()
                    results[index] = result
                    completed_count += 1
                    _emit_tool_finished(total_tools, tool_name, phase, result)
                _submit_ready()

        return [result for result in results if result is not None]

    static_plan: list[tuple[str, str, callable]] = []
    if mode in ("passive", "full"):
        static_plan.extend(
            [
                ("httpx", "passive", lambda: run_httpx(url, config, scan_dir, cancel_check=should_cancel)),
                ("whatweb", "passive", lambda: run_whatweb(url, config, scan_dir, cancel_check=should_cancel)),
                ("corsy", "passive", lambda: run_corsy(url, scan_dir, cancel_check=should_cancel)),
                ("gau", "passive", lambda: run_gau(hostname, scan_dir, config, cancel_check=should_cancel)),
                ("katana", "passive", lambda: run_katana(url, scan_dir, config, cancel_check=should_cancel)),
            ]
        )
        if not local_target and parsed_url.scheme == "https":
            static_plan.append(("sslyze", "passive", lambda: run_sslyze(hostname, scan_dir, cancel_check=should_cancel)))

        try:
            is_private_ip = ipaddress.ip_address(hostname).is_private
        except ValueError:
            is_private_ip = False
        if not local_target and not is_private_ip:
            static_plan.append(("subfinder", "passive", lambda: run_subfinder(hostname, scan_dir, config, cancel_check=should_cancel)))

    _emit({"event": "plan_updated", "phase": "tool_execution", "total_tools": len(static_plan), "message": "Initial scan plan prepared."})
    static_fast_plan = static_plan
    static_deferred_plan: list[tuple[str, str, callable]] = []
    if automation_scheduler:
        static_fast_plan = [item for item in static_plan if item[0] in fast_profile_tools or item[0] not in deferred_passive_tools]
        static_deferred_plan = [item for item in static_plan if item[0] in deferred_passive_tools and item not in static_fast_plan]

    tool_runs.extend(_execute_plan(static_fast_plan, len(static_plan), max_parallel_tools))
    if should_cancel and should_cancel():
        fallback_profile = profile if profile in {"wordpress", "joomla", "drupal", "api", "webapp"} else "webapp"
        partial_profile = {
            "requested_profile": profile,
            "effective_profile": fallback_profile,
            "confidence": "interrupted",
            "scores": {fallback_profile: 1},
            "surface_signals": {},
            "reasons": [],
        }
        return _finalize_execution(
            fallback_profile,
            partial_profile,
            interrupted=True,
            interrupt_reason="Execution interrupted during initial scan phase.",
        )

    _emit(
        {
            "event": "stage",
            "stage": "profile_analysis",
            "progress": 85,
            "current_tool": "Adaptive profile analysis",
            "message": "Analyzing discovered surface and selecting optimal profile/tool plan.",
        }
    )
    try:
        profile_info = detect_profile_from_artifacts(scan_dir, url, profile)
        effective_profile = profile_info["effective_profile"]
    except Exception as exc:
        fallback_profile = profile if profile in {"wordpress", "joomla", "drupal", "api", "webapp"} else "webapp"
        profile_info = {
            "requested_profile": profile,
            "effective_profile": fallback_profile,
            "confidence": "fallback",
            "scores": {fallback_profile: 1},
            "surface_signals": {},
            "reasons": [f"Adaptive profile detection fallback due to error: {str(exc)[:120]}"],
        }
        effective_profile = fallback_profile
        _emit(
            {
                "event": "stage",
                "stage": "profile_analysis",
                "progress": 86,
                "current_tool": "Adaptive profile analysis",
                "message": f"Adaptive detection fallback to {fallback_profile} profile.",
            }
        )
    surface = profile_info.get("surface_signals", _collect_surface_signals(scan_dir, url))

    if bool(config.get("adaptive_parallelism", True)):
        if effective_profile == "api":
            max_parallel_tools = max(max_parallel_tools, int(config.get("max_parallel_tools_api", 4)))
            max_parallel_heavy_tools = max(max_parallel_heavy_tools, int(config.get("max_parallel_heavy_tools_api", 3)))
        if surface.get("url_count", 0) >= int(config.get("parallelism_boost_min_urls", 80)):
            max_parallel_tools = min(max_parallel_tools + 1, int(config.get("max_parallel_tools_cap", 6)))
            max_parallel_heavy_tools = min(max_parallel_heavy_tools + 1, int(config.get("max_parallel_heavy_tools_cap", 4)))

    dynamic_plan: list[tuple[str, str, callable]] = []
    if mode in ("passive", "full"):
        nikto_enabled = bool(config.get("run_nikto", True))
        nikto_wordpress_enabled = bool(config.get("run_nikto_wordpress", False))
        dynamic_plan.append(("nuclei", "passive", lambda: run_nuclei(url, config, scan_dir, effective_profile, mode, cancel_check=should_cancel)))
        if nikto_enabled and (effective_profile != "wordpress" or nikto_wordpress_enabled):
            dynamic_plan.append(("nikto", "passive", lambda: run_nikto(url, config, scan_dir, effective_profile, cancel_check=should_cancel)))
        if effective_profile == "wordpress":
            if (
                profile == "auto"
                and not strict_tool_coverage
                and bool(config.get("adaptive_skip_wpscan_low_confidence", True))
                and profile_info.get("confidence") == "low"
            ):
                dynamic_plan.append(("wpscan", "passive", lambda: _skip_tool_result("wpscan", "passive", "Skipped by automation rule: WordPress confidence is too low for a full WPScan pass.")))
            else:
                dynamic_plan.append(("wpscan", "passive", lambda: run_wpscan(url, config, tokens, scan_dir, local_target, cancel_check=should_cancel)))
        elif effective_profile == "joomla":
            dynamic_plan.append(("joomscan", "passive", lambda: run_joomscan(url, scan_dir, cancel_check=should_cancel)))
        elif effective_profile == "drupal":
            dynamic_plan.append(("droopescan", "passive", lambda: run_droopescan(url, scan_dir, cancel_check=should_cancel)))

    if mode in ("active", "full"):
        run_content_wordpress = bool(config.get("run_content_discovery_wordpress", False))
        run_sqlmap_api = bool(config.get("run_sqlmap_api", False))
        run_wapiti_api = bool(config.get("run_wapiti_api", False))
        adaptive_tools = bool(config.get("adaptive_tool_selection", True))

        min_sqlmap_params = int(config.get("adaptive_sqlmap_min_params", 3))
        min_sqlmap_urls = int(config.get("adaptive_sqlmap_min_urls", 8))
        min_wapiti_html = int(config.get("adaptive_wapiti_min_html", 2))
        min_commix_params = int(config.get("adaptive_commix_min_params", 2))

        detect_text = _extract_detect_text(scan_dir / "nuclei.jsonl", scan_dir / "whatweb.stdout.log", scan_dir / "httpx.json")
        sql_error_hints = any(hint in detect_text for hint in ("sql syntax", "mysql", "postgres", "odbc", "sqlite", "sqlstate"))

        def _should_run_sqlmap() -> tuple[bool, str]:
            if strict_tool_coverage:
                return True, "Forced by strict coverage mode."
            if run_sqlmap_api and effective_profile == "api":
                return True, "Forced by run_sqlmap_api override."
            if not adaptive_tools:
                return (effective_profile != "api"), "Adaptive tool selection disabled."
            if sql_error_hints:
                return True, "Detected SQL error fingerprints from passive telemetry."
            param_count = int(surface.get("param_count", 0) or 0)
            url_count = int(surface.get("url_count", 0) or 0)
            sqlmap_logic = str(config.get("adaptive_sqlmap_logic", "any")).strip().lower()
            meets_param_threshold = param_count >= min_sqlmap_params
            meets_url_threshold = url_count >= min_sqlmap_urls
            if sqlmap_logic == "all":
                if meets_param_threshold and meets_url_threshold:
                    return True, f"Parameterized surface matched both SQLMap thresholds ({param_count}/{min_sqlmap_params} params, {url_count}/{min_sqlmap_urls} URLs)."
            else:
                if meets_param_threshold or meets_url_threshold:
                    matched_signal = "parameterized inputs" if meets_param_threshold else "crawlable URLs"
                    return True, f"Detected enough {matched_signal} for SQLMap ({param_count}/{min_sqlmap_params} params, {url_count}/{min_sqlmap_urls} URLs)."
            return False, (
                "Skipped by adaptive planner: low SQL-injection signal "
                f"({param_count}/{min_sqlmap_params} params, {url_count}/{min_sqlmap_urls} URLs, logic={sqlmap_logic})."
            )

        def _should_run_wapiti() -> tuple[bool, str]:
            if strict_tool_coverage:
                return True, "Forced by strict coverage mode."
            if run_wapiti_api and effective_profile == "api":
                return True, "Forced by run_wapiti_api override."
            if not adaptive_tools:
                return (effective_profile != "api"), "Adaptive tool selection disabled."
            if surface.get("html_like_count", 0) >= min_wapiti_html:
                return True, "Detected sufficient crawlable HTML/web surface for Wapiti."
            return False, "Skipped by adaptive planner: target appears API-first with limited crawlable HTML surface."

        def _should_run_commix() -> tuple[bool, str]:
            if strict_tool_coverage:
                return True, "Forced by strict coverage mode."
            if not adaptive_tools:
                return True, "Adaptive tool selection disabled."
            if surface.get("param_count", 0) >= min_commix_params:
                return True, "Detected parameterized surface for command-injection checks."
            return False, "Skipped by adaptive planner: too few parameter signals for Commix."

        if effective_profile in ("joomla", "drupal"):
            dynamic_plan.append(("cmsmap", "active", lambda: run_cmsmap(url, scan_dir, cancel_check=should_cancel)))
        elif effective_profile == "wordpress" and bool(config.get("run_cmsmap_wordpress", False)):
            dynamic_plan.append(("cmsmap", "active", lambda: run_cmsmap(url, scan_dir, effective_profile, cancel_check=should_cancel)))

        include_content_tools = effective_profile != "wordpress" or run_content_wordpress
        sqlmap_enabled, reason_sqlmap = _should_run_sqlmap()
        if sqlmap_enabled:
            dynamic_plan.append(("sqlmap", "active", lambda: run_sqlmap(url, scan_dir, effective_profile, config, cancel_check=should_cancel)))
        else:
            dynamic_plan.append(("sqlmap", "active", lambda: _skip_tool_result("sqlmap", "active", reason_sqlmap)))
        dynamic_plan.extend(
            [
                ("arjun", "active", lambda: run_arjun(url, scan_dir, cancel_check=should_cancel)),
                ("dalfox", "active", lambda: run_dalfox(url, scan_dir, cancel_check=should_cancel)),
            ]
        )
        wapiti_enabled, reason_wapiti = _should_run_wapiti()
        if wapiti_enabled:
            dynamic_plan.append(("wapiti", "active", lambda: run_wapiti(url, scan_dir, config, effective_profile, cancel_check=should_cancel)))
        else:
            dynamic_plan.append(("wapiti", "active", lambda: _skip_tool_result("wapiti", "active", reason_wapiti)))
        if include_content_tools:
            dynamic_plan.extend(
                [
                    ("ffuf", "active", lambda: run_ffuf(url, config, scan_dir, effective_profile, cancel_check=should_cancel)),
                    ("feroxbuster", "active", lambda: run_feroxbuster(url, config, scan_dir, cancel_check=should_cancel)),
                ]
            )
        if effective_profile in ("webapp", "api"):
            run_commix_ok, reason_commix = _should_run_commix()
            if run_commix_ok:
                dynamic_plan.append(("commix", "active", lambda: run_commix(url, scan_dir, config, effective_profile, cancel_check=should_cancel)))
            else:
                dynamic_plan.append(("commix", "active", lambda: _skip_tool_result("commix", "active", reason_commix)))

    prepared_static_deferred: list[tuple[str, str, callable]] = []
    for tool_name, phase, runner in static_deferred_plan:
        if tool_name == "katana":
            skip_api = bool(config.get("skip_katana_for_api", True)) and effective_profile == "api"
            skip_threshold = int(config.get("skip_katana_when_gau_count_gte", 600) or 0)
            skip_large = skip_threshold > 0 and surface.get("url_count", 0) >= skip_threshold
            if skip_api and not strict_tool_coverage:
                prepared_static_deferred.append((tool_name, phase, lambda: _skip_tool_result("katana", "passive", "Skipped by automation rule: Katana is deferred for API-first targets.")))
                continue
            if skip_large and not strict_tool_coverage:
                prepared_static_deferred.append((tool_name, phase, lambda threshold=skip_threshold: _skip_tool_result("katana", "passive", f"Skipped by automation rule: gau already exposed a large surface ({surface.get('url_count', 0)} URLs >= {threshold}).")))
                continue
        prepared_static_deferred.append((tool_name, phase, runner))

    total_tools = len(static_plan) + len(dynamic_plan)
    planned_tools = [
        {
            "name": tool_name,
            "label": _tool_meta(tool_name).get("label", tool_name),
            "phase": phase,
            "installed": bool(installed.get(tool_name)),
        }
        for tool_name, phase, _runner in (static_plan + dynamic_plan)
    ]
    missing_tools = [item["label"] for item in planned_tools if not item["installed"]]
    availability_message = f"Planned {total_tools} tools under {toolset_profile}; {len(planned_tools) - len(missing_tools)} available, {len(missing_tools)} missing from PATH."
    if missing_tools:
        availability_message += f" Missing: {', '.join(missing_tools[:5])}{'...' if len(missing_tools) > 5 else ''}."
    _emit(
        {
            "event": "plan_updated",
            "phase": "tool_execution",
            "total_tools": total_tools,
            "planned_tools": planned_tools,
            "missing_tools": missing_tools,
            "message": f"Profile resolved as {effective_profile}; {availability_message}",
        }
    )

    passive_dynamic = [item for item in dynamic_plan if item[1] == "passive"]
    active_dynamic = [item for item in dynamic_plan if item[1] == "active"]
    deferred_profile_plan = [item for item in passive_dynamic if item[0] in deferred_profile_tools]
    priority_passive_plan = [item for item in passive_dynamic if item[0] not in deferred_profile_tools]

    if automation_scheduler:
        remaining_plan = priority_passive_plan + active_dynamic + prepared_static_deferred + deferred_profile_plan
        remaining_workers = max(max_parallel_tools, max_parallel_heavy_tools)
        tool_runs.extend(_execute_plan(remaining_plan, total_tools, remaining_workers))
    else:
        tool_runs.extend(_execute_plan(priority_passive_plan + deferred_profile_plan + prepared_static_deferred, total_tools, max_parallel_tools))
        if should_cancel and should_cancel():
            return _finalize_execution(
                effective_profile,
                profile_info,
                interrupted=True,
                interrupt_reason="Execution interrupted before active testing phase.",
            )
        tool_runs.extend(_execute_plan(active_dynamic, total_tools, max_parallel_heavy_tools))

    if should_cancel and should_cancel():
        return _finalize_execution(
            effective_profile,
            profile_info,
            interrupted=True,
            interrupt_reason="Execution interrupted near completion due to timeout/cancellation.",
        )

    return _finalize_execution(effective_profile, profile_info)
