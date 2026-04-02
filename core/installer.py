"""Auto-installer for missing CLI tools.

Downloads pre-built binaries to a local ./bin directory when a tool
is not found in PATH.  Called automatically before scanning so the
user never has to run a separate install step.
"""

import logging
import os
import platform
import shutil
import stat
import subprocess
import urllib.request

logger = logging.getLogger(__name__)

# ── versions to install ──────────────────────────────────────────
GITLEAKS_VERSION = "8.18.2"
TITUS_VERSION = "1.1.14"
# trufflehog uses its own install script, no pinned version needed
# detect-secrets is a pip package, handled via requirements.txt
# ─────────────────────────────────────────────────────────────────


def _detect_platform():
    """Return (os_name, arch) normalised for GitHub release filenames."""
    system = platform.system().lower()          # darwin / linux
    machine = platform.machine().lower()        # x86_64 / arm64 / aarch64
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine
    return system, arch


def _download(url, dest):
    logger.info(f"Downloading {url}")
    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        logger.error(f"Download failed: {e}")
        return False


def _make_executable(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _install_gitleaks(bin_dir):
    os_name, arch = _detect_platform()
    # Gitleaks uses "x64" instead of "amd64"
    gl_arch = "x64" if arch == "amd64" else arch
    url = (
        f"https://github.com/gitleaks/gitleaks/releases/download/"
        f"v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_{os_name}_{gl_arch}.tar.gz"
    )
    tarball = os.path.join(bin_dir, "gitleaks.tar.gz")
    if not _download(url, tarball):
        return False
    try:
        import tarfile
        with tarfile.open(tarball) as tf:
            tf.extract("gitleaks", bin_dir)
        _make_executable(os.path.join(bin_dir, "gitleaks"))
        return True
    except Exception as e:
        logger.error(f"Failed to extract gitleaks: {e}")
        return False
    finally:
        if os.path.exists(tarball):
            os.remove(tarball)


def _install_trufflehog(bin_dir):
    """Use the official install script (same approach as install_deps.sh)."""
    try:
        result = subprocess.run(
            ["bash", "-c",
             f"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b {bin_dir}"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if result.returncode == 0:
            return True
        logger.error(f"Trufflehog install script failed: {result.stderr}")
        return False
    except Exception as e:
        logger.error(f"Failed to install trufflehog: {e}")
        return False


def _install_detect_secrets():
    """pip-install detect-secrets into the current environment."""
    try:
        result = subprocess.run(
            [shutil.which("pip3") or shutil.which("pip") or "pip",
             "install", "detect-secrets"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if result.returncode == 0:
            return True
        logger.error(f"pip install detect-secrets failed: {result.stderr}")
        return False
    except Exception as e:
        logger.error(f"Failed to install detect-secrets: {e}")
        return False


def _install_titus(bin_dir):
    os_name, arch = _detect_platform()
    url = (
        f"https://github.com/praetorian-inc/titus/releases/download/"
        f"v{TITUS_VERSION}/titus-{os_name}-{arch}"
    )
    dest = os.path.join(bin_dir, "titus")
    if not _download(url, dest):
        return False
    _make_executable(dest)
    return True


# Map tool CLI name → installer function
# detect-secrets installer doesn't need bin_dir
_INSTALLERS = {
    "gitleaks":       lambda bd: _install_gitleaks(bd),
    "trufflehog":     lambda bd: _install_trufflehog(bd),
    "detect-secrets": lambda bd: _install_detect_secrets(),
    "titus":          lambda bd: _install_titus(bd),
}


def ensure_tools(tool_names, bin_dir):
    """Check each requested tool; auto-install missing ones.
    
    After install, *bin_dir* is added to PATH so subsequent
    shutil.which() calls in scanners will find the binary.
    """
    os.makedirs(bin_dir, exist_ok=True)

    # Make sure bin_dir is on PATH first
    current_path = os.environ.get("PATH", "")
    if bin_dir not in current_path:
        os.environ["PATH"] = bin_dir + os.pathsep + current_path

    for name in tool_names:
        cli_cmd = name  # CLI name matches registry key for all tools
        if shutil.which(cli_cmd):
            logger.info(f"[installer] {name} found at {shutil.which(cli_cmd)}")
            continue

        installer = _INSTALLERS.get(name)
        if installer is None:
            logger.warning(f"[installer] No auto-installer for '{name}'. Skipping.")
            continue

        logger.warning(f"[installer] {name} not found. Attempting auto-install...")
        success = installer(bin_dir)
        if success and shutil.which(cli_cmd):
            logger.info(f"[installer] {name} installed successfully at {shutil.which(cli_cmd)}")
        else:
            logger.error(f"[installer] Failed to install {name}. It will be skipped during scan.")
