"""Cross-platform tool installer for Windows and Linux (Kali/Debian/Ubuntu)."""

import os
import platform
import shutil
import subprocess
import sys
import zipfile
import tarfile
import tempfile
from pathlib import Path

from lib import ui


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _run(cmd: list[str] | str, shell: bool = False, check: bool = True) -> bool:
    """Run a command and return True if successful."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0 and result.stderr:
            ui.warn(f"  stderr: {result.stderr.strip()[:200]}")
        return result.returncode == 0
    except Exception as e:
        ui.err(f"  Command failed: {e}")
        return False


def _pip_install(package: str) -> bool:
    """Install a Python package via pip."""
    ui.status(f"Installing {package} via pip...")
    return _run([sys.executable, "-m", "pip", "install", package])


def _apt_install(packages: list[str] | str) -> bool:
    """Install packages via apt (Linux only)."""
    if isinstance(packages, str):
        packages = [packages]
    ui.status(f"Installing {', '.join(packages)} via apt...")
    return _run(["sudo", "apt-get", "install", "-y"] + packages)


def _go_available() -> bool:
    return shutil.which("go") is not None


def _git_available() -> bool:
    return shutil.which("git") is not None


def _ruby_available() -> bool:
    return shutil.which("ruby") is not None


def _gem_available() -> bool:
    return shutil.which("gem") is not None


def _download_file(url: str, dest: Path) -> bool:
    """Download a file using Python urllib."""
    import urllib.request
    try:
        ui.status(f"Downloading {url}...")
        urllib.request.urlretrieve(url, str(dest))
        return dest.exists()
    except Exception as e:
        ui.err(f"Download failed: {e}")
        return False


def _get_go_bin_dir() -> Path:
    """Get the Go binary directory."""
    gopath = os.environ.get("GOPATH", str(Path.home() / "go"))
    return Path(gopath) / "bin"


# ── Per-tool installers ─────────────────────────────────────────────────────────

def install_nuclei() -> bool:
    """Install Nuclei (Go binary from ProjectDiscovery)."""
    ui.section("Installing Nuclei")

    if _is_linux():
        # Try go install first
        if _go_available():
            ui.status("Installing via go install...")
            ok = _run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"])
            if ok:
                ui.ok("Nuclei installed via go install.")
                return True

        # Fallback: download binary
        ui.status("Downloading Nuclei binary...")
        import urllib.request
        import json
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest",
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                release = json.loads(resp.read())
                for asset in release.get("assets", []):
                    name = asset["name"]
                    if "linux" in name and "amd64" in name and name.endswith(".zip"):
                        dl_path = Path(tempfile.mktemp(suffix=".zip"))
                        _download_file(asset["browser_download_url"], dl_path)
                        with zipfile.ZipFile(dl_path) as zf:
                            zf.extractall("/usr/local/bin/")
                        dl_path.unlink(missing_ok=True)
                        _run(["chmod", "+x", "/usr/local/bin/nuclei"])
                        ui.ok("Nuclei installed to /usr/local/bin/")
                        return True
        except Exception as e:
            ui.err(f"Failed to download Nuclei: {e}")

    elif _is_windows():
        if _go_available():
            ui.status("Installing via go install...")
            ok = _run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"])
            if ok:
                go_bin = _get_go_bin_dir()
                ui.ok(f"Nuclei installed to {go_bin}")
                ui.info(f"Ensure {go_bin} is in your PATH.")
                return True

        ui.warn("Go is not installed. Please install Go from https://go.dev/dl/ first,")
        ui.warn("then run: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    return False


def install_wpscan() -> bool:
    """Install WPScan (Ruby gem)."""
    ui.section("Installing WPScan")

    if _is_linux():
        # On Kali/Debian, try apt first (wpscan is in Kali repos)
        if _run(["which", "apt-get"], check=False):
            if _apt_install("wpscan"):
                ui.ok("WPScan installed via apt.")
                return True

        # Fallback to gem
        if _gem_available():
            ui.status("Installing via gem...")
            ok = _run(["sudo", "gem", "install", "wpscan"])
            if ok:
                ui.ok("WPScan installed via gem.")
                return True

        ui.warn("Install Ruby first: sudo apt install ruby ruby-dev build-essential")
        ui.warn("Then run: sudo gem install wpscan")

    elif _is_windows():
        if _gem_available():
            ui.status("Installing via gem...")
            ok = _run(["gem", "install", "wpscan"])
            if ok:
                ui.ok("WPScan installed via gem.")
                return True

        ui.warn("WPScan requires Ruby. Install Ruby from https://rubyinstaller.org/")
        ui.warn("Then run: gem install wpscan")

    return False


def install_nikto() -> bool:
    """Install Nikto (Perl-based web scanner)."""
    ui.section("Installing Nikto")

    nikto_perl_deps = [
        "libxml-writer-perl",
        "libnet-ssleay-perl",
        "libio-socket-ssl-perl",
        "libwww-perl",
    ]

    if _is_linux():
        # JSON/HTTPS Nikto formats need these Perl modules even with apt nikto.
        _apt_install(nikto_perl_deps)
        if _apt_install("nikto"):
            ui.ok("Nikto installed via apt.")
            return True

        if _git_available():
            install_dir = Path.home() / "tools" / "nikto"
            if not install_dir.exists():
                ui.status("Cloning Nikto from GitHub...")
                ok = _run(["git", "clone", "https://github.com/sullo/nikto.git", str(install_dir)])
                if not ok:
                    return False
            ui.ok(f"Nikto available at {install_dir}")
            ui.info(f"Run: perl {install_dir / 'program' / 'nikto.pl'} -h <target>")
            return True

    elif _is_windows():
        if _git_available():
            install_dir = Path.home() / "tools" / "nikto"
            if not install_dir.exists():
                ui.status("Cloning Nikto from GitHub...")
                ok = _run(["git", "clone", "https://github.com/sullo/nikto.git", str(install_dir)])
                if ok:
                    ui.ok(f"Nikto cloned to {install_dir}")
                    ui.info(f"Add {install_dir / 'program'} to your PATH,")
                    ui.info("or run directly: perl nikto.pl -h <target>")
                    ui.warn("Ensure Strawberry Perl includes XML::Writer (cpan XML::Writer) for JSON output.")
                    return True
            else:
                ui.ok(f"Nikto already exists at {install_dir}")
                return True

        ui.warn("Nikto requires Perl and Git.")
        ui.warn("Install Git from https://git-scm.com/ and Perl from https://strawberryperl.com/")

    return False


def install_zap() -> bool:
    """Install OWASP ZAP CLI."""
    ui.section("Installing OWASP ZAP")

    if _is_linux():
        # Try apt first (available in Kali repos)
        if _apt_install("zaproxy"):
            ui.ok("OWASP ZAP installed via apt.")
            # Also install the Python CLI wrapper
            _pip_install("python-owasp-zap-v2.4")
            return True

    elif _is_windows():
        ui.info("OWASP ZAP is a GUI application with an installer.")
        ui.info("Download from: https://www.zaproxy.org/download/")
        ui.info("After installing, add ZAP to your PATH and install the CLI:")
        ui.info("  pip install python-owasp-zap-v2.4")

    # Install Python CLI wrapper either way
    if _pip_install("python-owasp-zap-v2.4"):
        ui.ok("ZAP Python client installed.")

    return False


def install_sqlmap() -> bool:
    """Install SQLMap (Python-based SQL injection tool)."""
    ui.section("Installing SQLMap")

    if _is_linux():
        # Try apt first
        if _apt_install("sqlmap"):
            ui.ok("SQLMap installed via apt.")
            return True

    # Fallback: pip install works on both platforms
    if _pip_install("sqlmap"):
        ui.ok("SQLMap installed via pip.")
        return True

    return False


def install_sslyze() -> bool:
    """Install SSLyze (Python-based TLS scanner)."""
    ui.section("Installing SSLyze")

    if _pip_install("sslyze"):
        ui.ok("SSLyze installed via pip.")
        return True

    return False


def install_whatweb() -> bool:
    """Install WhatWeb (Ruby-based web fingerprinter)."""
    ui.section("Installing WhatWeb")

    if _is_linux():
        if _apt_install("whatweb"):
            ui.ok("WhatWeb installed via apt.")
            return True

    elif _is_windows():
        if _git_available():
            install_dir = Path.home() / "tools" / "whatweb"
            if not install_dir.exists():
                ui.status("Cloning WhatWeb from GitHub...")
                ok = _run(["git", "clone", "https://github.com/urbanadventurer/WhatWeb.git", str(install_dir)])
                if ok:
                    ui.ok(f"WhatWeb cloned to {install_dir}")
                    ui.info(f"Add {install_dir} to your PATH.")
                    ui.info("Requires Ruby: https://rubyinstaller.org/")
                    return True
            else:
                ui.ok(f"WhatWeb already exists at {install_dir}")
                return True

        ui.warn("WhatWeb requires Git and Ruby.")
        ui.warn("Install Git from https://git-scm.com/ and Ruby from https://rubyinstaller.org/")

    return False


def install_httpx() -> bool:
    """Install httpx (Go-based HTTP probe by ProjectDiscovery)."""
    ui.section("Installing httpx")

    if _go_available():
        ui.status("Installing via go install...")
        ok = _run(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"])
        if ok:
            go_bin = _get_go_bin_dir()
            ui.ok(f"httpx installed to {go_bin}")
            if _is_windows():
                ui.info(f"Ensure {go_bin} is in your PATH.")
            return True

    if _is_linux():
        # Try downloading binary
        import urllib.request
        import json
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/projectdiscovery/httpx/releases/latest",
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                release = json.loads(resp.read())
                for asset in release.get("assets", []):
                    name = asset["name"]
                    if "linux" in name and "amd64" in name and name.endswith(".zip"):
                        dl_path = Path(tempfile.mktemp(suffix=".zip"))
                        _download_file(asset["browser_download_url"], dl_path)
                        with zipfile.ZipFile(dl_path) as zf:
                            zf.extractall("/usr/local/bin/")
                        dl_path.unlink(missing_ok=True)
                        _run(["chmod", "+x", "/usr/local/bin/httpx"])
                        ui.ok("httpx installed to /usr/local/bin/")
                        return True
        except Exception as e:
            ui.err(f"Failed to download httpx: {e}")

    ui.warn("Go is required. Install from https://go.dev/dl/")
    ui.warn("Then run: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
    return False


def install_cmsmap() -> bool:
    """Install CMSMap (Python-based CMS scanner)."""
    ui.section("Installing CMSMap")

    if _git_available():
        install_dir = Path.home() / "tools" / "cmsmap"
        if not install_dir.exists():
            ui.status("Cloning CMSMap from GitHub...")
            ok = _run(["git", "clone", "https://github.com/dionach/CMSmap.git", str(install_dir)])
            if ok:
                # Install dependencies
                req_file = install_dir / "requirements.txt"
                if req_file.exists():
                    _run([sys.executable, "-m", "pip", "install", "-r", str(req_file)])
                ui.ok(f"CMSMap installed to {install_dir}")
                ui.info(f"Add {install_dir} to your PATH,")
                ui.info(f"or run: python {install_dir / 'cmsmap.py'}")
                return True
        else:
            ui.ok(f"CMSMap already exists at {install_dir}")
            return True

    ui.warn("CMSMap requires Git. Install from https://git-scm.com/")
    return False


def _git_clone_tool(name: str, repo: str, pip_reqs: bool = False) -> bool:
    if _git_available():
        install_dir = Path.home() / "tools" / name.lower()
        if not install_dir.exists():
            ui.status(f"Cloning {name} from GitHub...")
            ok = _run(["git", "clone", repo, str(install_dir)])
            if ok:
                if pip_reqs:
                    req_file = install_dir / "requirements.txt"
                    if req_file.exists():
                        ui.status(f"Installing {name} pip requirements...")
                        _run([sys.executable, "-m", "pip", "install", "-r", str(req_file)])
                ui.ok(f"{name} cloned to {install_dir}")
                ui.info(f"Please ensure {install_dir} or its executable script is in your PATH.")
                return True
        else:
            ui.ok(f"{name} already exists at {install_dir}")
            return True
    ui.warn(f"{name} requires Git. Install from https://git-scm.com/")
    return False

def install_ffuf() -> bool:
    ui.section("Installing ffuf")
    if _go_available():
        ok = _run(["go", "install", "-v", "github.com/ffuf/ffuf/v2@latest"])
        if ok:
            ui.ok("ffuf installed via go install.")
            return True
    ui.warn("Go is required. Install from https://go.dev/dl/")
    return False

def install_dalfox() -> bool:
    ui.section("Installing Dalfox")
    if _go_available():
        ok = _run(["go", "install", "-v", "github.com/hahwul/dalfox/v2@latest"])
        if ok:
            ui.ok("Dalfox installed via go install.")
            return True
    ui.warn("Go is required.")
    return False

def install_subfinder() -> bool:
    ui.section("Installing Subfinder")
    if _go_available():
        ok = _run(["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"])
        if ok:
            ui.ok("Subfinder installed via go install.")
            return True
    ui.warn("Go is required.")
    return False

def install_gitleaks() -> bool:
    ui.section("Installing Gitleaks")
    if _go_available():
        ok = _run(["go", "install", "-v", "github.com/zricethezav/gitleaks/v8@latest"])
        if ok:
            ui.ok("Gitleaks installed via go install.")
            return True
    ui.warn("Go is required.")
    return False

def install_wapiti() -> bool:
    ui.section("Installing Wapiti")
    if _pip_install("wapiti3"):
        ui.ok("Wapiti installed via pip.")
        return True
    return False

def install_droopescan() -> bool:
    ui.section("Installing Droopescan")
    if _pip_install("droopescan"):
        ui.ok("Droopescan installed via pip.")
        return True
    return False

def install_corsy() -> bool:
    ui.section("Installing Corsy")
    return _git_clone_tool("Corsy", "https://github.com/s0md3v/Corsy.git", pip_reqs=True)

def install_commix() -> bool:
    ui.section("Installing Commix")
    return _git_clone_tool("Commix", "https://github.com/commixproject/commix.git", pip_reqs=False)

def install_joomscan() -> bool:
    ui.section("Installing JoomScan")
    return _git_clone_tool("JoomScan", "https://github.com/OWASP/joomscan.git", pip_reqs=False)


# ── Install registry ───────────────────────────────────────────────────────────

INSTALLERS = {
    "nuclei":    {"fn": install_nuclei,  "label": "Nuclei",    "method_win": "go install / binary download",  "method_linux": "go install / binary download"},
    "wpscan":    {"fn": install_wpscan,  "label": "WPScan",    "method_win": "gem install",                    "method_linux": "apt / gem install"},
    "nikto":     {"fn": install_nikto,   "label": "Nikto",     "method_win": "git clone + perl",               "method_linux": "apt install"},
    "zap-cli":   {"fn": install_zap,     "label": "OWASP ZAP", "method_win": "manual download + pip",          "method_linux": "apt install"},
    "sqlmap":    {"fn": install_sqlmap,  "label": "SQLMap",    "method_win": "pip install",                    "method_linux": "apt / pip install"},
    "sslyze":    {"fn": install_sslyze,  "label": "SSLyze",    "method_win": "pip install",                    "method_linux": "pip install"},
    "whatweb":   {"fn": install_whatweb, "label": "WhatWeb",   "method_win": "git clone + ruby",               "method_linux": "apt install"},
    "httpx":     {"fn": install_httpx,   "label": "httpx",     "method_win": "go install",                     "method_linux": "go install / binary download"},
    "cmsmap":    {"fn": install_cmsmap,  "label": "CMSMap",    "method_win": "git clone + pip",                "method_linux": "git clone + pip"},
    "ffuf":      {"fn": install_ffuf,    "label": "ffuf",      "method_win": "go install",                     "method_linux": "go install"},
    "dalfox":    {"fn": install_dalfox,  "label": "Dalfox",    "method_win": "go install",                     "method_linux": "go install"},
    "subfinder": {"fn": install_subfinder,"label": "Subfinder", "method_win": "go install",                     "method_linux": "go install"},
    "gitleaks":  {"fn": install_gitleaks, "label": "Gitleaks",  "method_win": "go install",                     "method_linux": "go install"},
    "wapiti":    {"fn": install_wapiti,  "label": "Wapiti",    "method_win": "pip install",                    "method_linux": "pip install"},
    "droopescan":{"fn": install_droopescan,"label":"Droopescan","method_win": "pip install",                    "method_linux": "pip install"},
    "corsy":     {"fn": install_corsy,   "label": "Corsy",     "method_win": "git clone + pip",                "method_linux": "git clone + pip"},
    "commix":    {"fn": install_commix,  "label": "Commix",    "method_win": "git clone",                      "method_linux": "git clone"},
    "joomscan":  {"fn": install_joomscan,"label": "JoomScan",  "method_win": "git clone",                      "method_linux": "git clone"},
}


def install_tool(tool_name: str) -> bool:
    """Install a specific tool by name."""
    installer = INSTALLERS.get(tool_name)
    if not installer:
        ui.err(f"Unknown tool: {tool_name}")
        return False
    return installer["fn"]()


def install_missing_tools(installed: dict[str, bool]) -> int:
    """Offer to install all missing tools. Returns count of newly installed."""
    os_name = "Windows" if _is_windows() else "Linux"
    missing = {k: v for k, v in installed.items() if not v}

    if not missing:
        ui.ok("All tools are already installed!")
        return 0

    ui.section(f"Missing Tools ({len(missing)} on {os_name})")
    print()
    for i, (tool_name, _) in enumerate(missing.items(), 1):
        info = INSTALLERS.get(tool_name, {})
        method = info.get(f"method_{'win' if _is_windows() else 'linux'}", "manual")
        print(f"  [{i}] {info.get('label', tool_name):12s} - via {method}")

    print(f"\n  [A] Install ALL missing tools")
    print(f"  [B] Back")
    print()

    choice = input(f"  Select tool number, A for all, or B to go back: ").strip()

    if choice.upper() == "B":
        return 0

    ui.section("Checking and Installing System Dependencies")
    if _is_linux():
        ui.info("Linux detected. Installing build tools, Ruby, Git, Go, Python pip, Java...")
        if _run(["which", "apt-get"], check=False):
            _run(["sudo", "apt-get", "update"])
            deps = ["git", "ruby", "ruby-dev", "build-essential", "perl", "golang-go", "python3-pip", "default-jre"]
            _apt_install(deps)
            ui.ok("System dependencies checked/installed.")
        else:
            ui.warn("apt-get not found. Please manually install: git, ruby, go, perl, python3-pip, java")
    elif _is_windows():
        ui.info("Windows detected. Some tools require Git, Go, Ruby, or Perl.")
        ui.info("Please ensure they are installed, or install them via winget:")
        ui.info("  winget install Git.Git GoLang.Go RubyInstallerTeam.RubyWithDevKit")

    count = 0
    if choice.upper() == "A":
        for tool_name in missing:
            ok = install_tool(tool_name)
            if ok:
                count += 1
            print()
    else:
        try:
            idx = int(choice) - 1
            tool_name = list(missing.keys())[idx]
            ok = install_tool(tool_name)
            if ok:
                count += 1
        except (ValueError, IndexError):
            ui.warn("Invalid selection.")

    if count > 0:
        ui.ok(f"{count} tool(s) installed successfully.")
        ui.info("Run --check-tools again to verify.")
    return count
