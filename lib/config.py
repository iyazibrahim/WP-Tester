"""Target, token, and scan configuration management."""

import json
import os
from pathlib import Path
import threading

_FILE_WRITE_LOCK = threading.Lock()

# ── Paths ───────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
FIXES_DIR = BASE_DIR / "fixes"
TEMPLATES_DIR = BASE_DIR / "templates"
REPORTS_DIR = BASE_DIR / "reports"

TARGETS_FILE = CONFIG_DIR / "targets.json"
TOKENS_FILE = CONFIG_DIR / "tokens.json"
SCAN_CONFIG_FILE = CONFIG_DIR / "scan-config.json"
REMEDIATION_DB_FILE = FIXES_DIR / "remediation-db.json"
HTML_TEMPLATE_FILE = TEMPLATES_DIR / "report-template.html"


def _ensure_dirs():
    """Create required directories if they don't exist."""
    for d in (CONFIG_DIR, FIXES_DIR, TEMPLATES_DIR, REPORTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> dict | list | None:
    """Load a JSON file, return None if not found or invalid."""
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        pass
    return None


def save_json(path: Path, obj):
    """Save an object as pretty-printed JSON with a write lock to prevent
    concurrent corruption from multiple threads/requests writing the same file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, indent=2, ensure_ascii=False)
    with _FILE_WRITE_LOCK:
        # Write to a temp file then rename for atomic replacement
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(path)
        except Exception:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
            raise


# ── Targets ─────────────────────────────────────────────────────────────────────

def get_targets() -> list[dict]:
    data = load_json(TARGETS_FILE)
    if isinstance(data, list):
        return data
    return []


def save_targets(targets: list[dict]):
    save_json(TARGETS_FILE, targets)


def add_target(url: str, label: str) -> dict:
    targets = get_targets()
    target = {"url": url.strip().rstrip("/"), "label": label.strip(), "profile": "auto", "last_scanned": None}
    targets.append(target)
    save_targets(targets)
    return target


def remove_target(index: int) -> bool:
    targets = get_targets()
    if 0 <= index < len(targets):
        targets.pop(index)
        save_targets(targets)
        return True
    return False


def select_target(targets: list[dict]) -> list[dict] | None:
    """Interactive target selector. Returns list of selected target(s) or None."""
    from lib import ui
    from colorama import Fore, Style

    if not targets:
        ui.warn("No targets saved. Add one first.")
        return None

    if len(targets) == 1:
        ui.status(f"Auto-selected: {targets[0]['label']}")
        return [targets[0]]

    # Show available targets
    ui.section("Saved Targets")
    for i, t in enumerate(targets):
        scanned = t.get("last_scanned") or "Never"
        print(f"  {Fore.CYAN}[{i+1}]{Style.RESET_ALL} {t['label']} - {t['url']} (Last scan: {scanned})")

    print(f"  {Fore.YELLOW}[A]{Style.RESET_ALL} Scan ALL targets")
    print()

    choice = input(f"  {Fore.CYAN}Select target number (or A for all): {Style.RESET_ALL}").strip()
    if choice.upper() == "A":
        return targets

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(targets):
            return [targets[idx]]
    except ValueError:
        pass

    ui.warn("Invalid selection.")
    return None


# ── Tokens ──────────────────────────────────────────────────────────────────────

def get_tokens() -> dict:
    """Load API tokens from tokens.json, with env var fallback for CI/cron."""
    data = load_json(TOKENS_FILE)
    if not isinstance(data, dict):
        data = {"wpscan_api_token": "", "zap_api_key": ""}

    # Environment variables override empty values (useful for CI/cron)
    if not data.get("wpscan_api_token"):
        data["wpscan_api_token"] = os.environ.get("WPSCAN_API_TOKEN", "")
    if not data.get("zap_api_key"):
        data["zap_api_key"] = os.environ.get("ZAP_API_KEY", "")

    return data


def save_tokens(tokens: dict):
    save_json(TOKENS_FILE, tokens)


def configure_tokens():
    """Interactive token configuration."""
    from lib import ui

    tokens = get_tokens()
    ui.section("API Token Configuration")
    current_wp = "[SET]" if tokens.get("wpscan_api_token") else "[EMPTY]"
    current_zap = "[SET]" if tokens.get("zap_api_key") else "[EMPTY]"
    print(f"  Current WPScan token: {current_wp}")
    print(f"  Current ZAP API key:  {current_zap}")
    print()
    print(f"  Press Enter to keep current value, or type new value.")
    print()

    wp_input = input(f"  WPScan API token: ").strip()
    if wp_input:
        tokens["wpscan_api_token"] = wp_input

    zap_input = input(f"  ZAP API key: ").strip()
    if zap_input:
        tokens["zap_api_key"] = zap_input

    save_tokens(tokens)
    ui.ok("Tokens saved.")


# ── Scan Config ─────────────────────────────────────────────────────────────────

def get_scan_config() -> dict:
    data = load_json(SCAN_CONFIG_FILE)
    if isinstance(data, dict):
        return data
    return {
        "toolset_profile": "portable_core",
        "default_scan_mode": "full",
        "nuclei_tags": "wordpress,wp-plugin,wp-theme,cve,exposure,misconfiguration",
        "nuclei_tags_wordpress": "wordpress,wp-plugin,wp-theme,cve,xss,sqli,lfi,ssrf,exposure,misconfig",
        "nuclei_tags_joomla": "joomla,cve,exposure,misconfig,default-login",
        "nuclei_tags_drupal": "drupal,cve,exposure,misconfig,default-login",
        "nuclei_tags_api": "api,graphql,cve,exposure,misconfig,default-login",
        "nuclei_tags_broad": "cve,rce,lfi,sqli,xss,ssrf,exposure,misconfig,default-login,redirect,takeover,credentials",
        "nuclei_severity": "critical,high,medium,low,info",
        "nuclei_rate_limit": 25,
        "nuclei_timeout_seconds": 2700,
        "nuclei_retry_auto_scan_on_empty": True,
        "nuclei_retry_auto_scan_on_empty_full_only": True,
        "nuclei_auto_fallback_timeout_seconds": 2700,
        "nuclei_auto_scan_concurrency": 5,
        "nuclei_auto_scan_bulk_size": 5,
        "nuclei_request_timeout": 15,
        "nuclei_retry_full_template_on_empty_full": True,
        "nuclei_full_fallback_timeout_seconds": 3000,
        "wpscan_enumerate": "vp,vt,u",
        "wpscan_max_threads": 1,
        "whatweb_max_threads": 8,
        "httpx_rate_limit": 25,
        "gau_providers": "wayback,otx,commoncrawl",
        "gau_timeout_seconds": 240,
        "nikto_tuning": "123456789",
        "nikto_tuning_wordpress": "123bde",
        "nikto_pause_seconds": 1,
        "nikto_maxtime_seconds": 780,
        "nikto_timeout_seconds": 900,
        "nikto_maxtime_wordpress_seconds": 840,
        "nikto_timeout_wordpress_seconds": 900,
        "ffuf_timeout_seconds": 900,
        "ffuf_maxtime_seconds": 420,
        "feroxbuster_timeout_seconds": 600,
        "ffuf_threads": 35,
        "ffuf_match_codes": "200,204,301,302,307,401,403",
        "ffuf_filter_codes": "400,404,405,500,501,502,503",
        "run_nikto": True,
        "run_nikto_wordpress": True,
        "adaptive_tool_selection": True,
        "strict_tool_coverage": False,
        "adaptive_sqlmap_min_params": 2,
        "adaptive_sqlmap_min_urls": 8,
        "adaptive_sqlmap_logic": "any",
        "adaptive_wapiti_min_html": 2,
        "adaptive_commix_min_params": 2,
        "adaptive_parallelism": True,
        "automation_scheduler": True,
        "fast_profile_tools": ["httpx", "whatweb", "corsy", "gau", "sslyze", "subfinder"],
        "deferred_passive_tools": ["katana"],
        "deferred_profile_tools": ["wpscan"],
        "low_priority_tools": ["katana", "wpscan", "cmsmap", "commix", "feroxbuster"],
        "scan_time_budget_passive_seconds": 2700,
        "scan_time_budget_active_seconds": 2400,
        "scan_time_budget_full_seconds": 2700,
        "deadline_skip_grace_seconds": 180,
        "run_content_discovery_wordpress": True,
        "run_cmsmap_wordpress": True,
        "ai_operator_enabled": False,
        "ai_require_approval_high_impact": True,
        "ai_allow_full_autonomous_testing": False,
        "ai_full_testing_bypass_token": "",
        "scan_hard_timeout_seconds": 2700,
        "parallel_scans": True,
        "max_parallel_tools": 2,
        "max_parallel_heavy_tools": 1,
        "max_parallel_tools_api": 2,
        "max_parallel_heavy_tools_api": 1,
        "parallelism_boost_min_urls": 120,
        "max_parallel_tools_cap": 3,
        "max_parallel_heavy_tools_cap": 2,
        "skip_katana_for_api": True,
        "skip_katana_when_gau_count_gte": 600,
        "report_profile": "technical",
        "include_manual_assessment": False,
        "output_formats": ["html", "markdown", "json", "sarif", "csv"],
        "content_wordlist": "",
    }


def save_scan_config(config: dict):
    save_json(SCAN_CONFIG_FILE, config)


def configure_performance_profile():
    """Interactive performance profile configuration."""
    from lib import ui
    from colorama import Fore, Style
    
    ui.section("Performance / Network Profile")
    print(f"  {Fore.CYAN}[1]{Style.RESET_ALL} Best Performance (Fast, but heavy on routers/network)")
    print(f"  {Fore.CYAN}[2]{Style.RESET_ALL} Stable (Safe for consumer modems/routers - Default)")
    print(f"  {Fore.CYAN}[3]{Style.RESET_ALL} Lightweight (Extremely slow, for weak connections)")
    print(f"  {Fore.CYAN}[4]{Style.RESET_ALL} Manual (Keep current settings or edit scan-config.json directly)")
    print()
    
    choice = input(f"  {Fore.CYAN}Select profile [1/2/3/4]: {Style.RESET_ALL}").strip()
    
    if choice == "4":
        ui.info("Manual mode selected. Edit config/scan-config.json directly for custom values.")
        return
        
    config = get_scan_config()
    
    if choice == "1":
        # Best Performance
        config.update({
            "nuclei_rate_limit": 150,
            "wpscan_max_threads": 5,
            "nikto_pause_seconds": 0,
            "whatweb_max_threads": 25,
            "httpx_rate_limit": 150
        })
        profile = "Best Performance"
    elif choice == "3":
        # Lightweight
        config.update({
            "nuclei_rate_limit": 5,
            "wpscan_max_threads": 1,
            "nikto_pause_seconds": 3,
            "whatweb_max_threads": 1,
            "httpx_rate_limit": 2
        })
        profile = "Lightweight"
    else:
        # 2 or Default (Stable)
        config.update({
            "nuclei_rate_limit": 20,
            "wpscan_max_threads": 1,
            "nikto_pause_seconds": 1,
            "whatweb_max_threads": 5,
            "httpx_rate_limit": 10
        })
        profile = "Stable"
        
    save_scan_config(config)
    ui.ok(f"Applied '{profile}' performance profile to scan-config.json")


# Ensure directories exist on import
_ensure_dirs()
