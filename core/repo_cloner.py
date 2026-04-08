"""Clone repositories listed in a text file.

Reads a plain-text file where each non-empty, non-comment line is a Git
repository URL.  Repositories are cloned via SSH
(``git clone git@<host>:<org>/<repo>.git``) into a caller-specified
directory.

Both HTTPS and SSH URLs are accepted as input — HTTPS URLs are
automatically converted to SSH format before cloning.
"""

import logging
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Matches  https://github.com/org/repo  or  https://github.com/org/repo.git
_HTTPS_RE = re.compile(
    r"^https?://(?P<host>[^/]+)/(?P<path>.+?)(?:\.git)?$"
)

# Already SSH: git@host:org/repo.git
_SSH_RE = re.compile(
    r"^git@(?P<host>[^:]+):(?P<path>.+?)(?:\.git)?$"
)


def _to_ssh_url(url: str) -> str:
    """Convert *url* to SSH clone format (``git@host:path.git``).

    If the URL is already in SSH format it is returned as-is (with a
    ``.git`` suffix ensured).
    """
    m = _HTTPS_RE.match(url.strip())
    if m:
        return f"git@{m.group('host')}:{m.group('path')}.git"

    m = _SSH_RE.match(url.strip())
    if m:
        return f"git@{m.group('host')}:{m.group('path')}.git"

    # Unknown format — return unchanged, let git fail with a clear message
    return url.strip()


def _repo_name_from_url(url: str) -> str:
    """Extract a directory name from a repository URL.

    >>> _repo_name_from_url("https://github.com/octocat/hello-world.git")
    'hello-world'
    >>> _repo_name_from_url("git@github.com:octocat/hello-world.git")
    'hello-world'
    """
    # Strip trailing .git and slashes, then take basename
    cleaned = url.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    return os.path.basename(cleaned)


def read_repo_list(filepath: str) -> list[str]:
    """Read repository URLs from a text file.

    Blank lines and lines starting with ``#`` are skipped.
    Duplicates are removed and the result is sorted alphabetically.
    """
    seen: set[str] = set()
    urls: list[str] = []
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped not in seen:
                seen.add(stripped)
                urls.append(stripped)
    return sorted(urls)


def _clone_single(url: str, dest_dir: str) -> str | None:
    """Clone a single repository. Returns the local path on success, else None."""
    ssh_url = _to_ssh_url(url)
    name = _repo_name_from_url(url)
    target = os.path.join(dest_dir, name)

    if os.path.isdir(os.path.join(target, ".git")):
        logger.info(f"[cloner] {name} already cloned at {target}, skipping.")
        return target

    logger.info(f"[cloner] Cloning {ssh_url} → {target}")
    try:
        result = subprocess.run(
            ["git", "clone", ssh_url, target],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if result.returncode == 0:
            logger.info(f"[cloner] Successfully cloned {name}")
            return target
        else:
            logger.error(
                f"[cloner] Failed to clone {ssh_url}: {result.stderr.strip()}"
            )
    except subprocess.TimeoutExpired:
        logger.error(f"[cloner] Timed out cloning {ssh_url}")
    except Exception as exc:
        logger.error(f"[cloner] Error cloning {ssh_url}: {exc}")
    return None


def clone_repos(urls: list[str], dest_dir: str, threads: int = 1) -> list[str]:
    """Clone each repository in *urls* into *dest_dir* via SSH.

    *threads* controls how many clones run in parallel (mirrors the
    ``--threads`` CLI flag so cloning scales together with scanning).

    Returns the list of local paths that were successfully cloned.
    Already-cloned repos (directory exists and contains ``.git``) are
    skipped with a log message rather than re-cloned.
    """
    os.makedirs(dest_dir, exist_ok=True)
    cloned_paths: list[str] = []

    with ThreadPoolExecutor(max_workers=max(threads, 1)) as executor:
        futures = {
            executor.submit(_clone_single, url, dest_dir): url
            for url in urls
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                path = future.result()
                if path is not None:
                    cloned_paths.append(path)
            except Exception as exc:
                logger.error(f"[cloner] Unexpected error cloning {url}: {exc}")

    return cloned_paths
