"""Record the latest commit of a repository before a scan begins.

Creates a ``<repo_name>_latest_commit.txt`` file in the scan output
directory so that subsequent scans can tell exactly which revision was
last analysed.
"""

import logging
import os
import subprocess

logger = logging.getLogger(__name__)


def get_latest_commit(repo_path: str) -> dict:
    """Return a dict with the latest commit metadata for *repo_path*.

    Keys: ``hash``, ``short_hash``, ``author``, ``date``, ``subject``.
    Returns an empty dict when the info cannot be determined.
    """
    fmt = "%H%n%h%n%an%n%aI%n%s"
    try:
        result = subprocess.run(
            ["git", "log", "-1", f"--format={fmt}"],
            capture_output=True,
            text=True,
            cwd=os.path.abspath(repo_path),
            timeout=10,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            logger.warning(
                f"[commit-tracker] Could not read HEAD for {repo_path}: "
                f"{result.stderr.strip()}"
            )
            return {}

        lines = result.stdout.strip().splitlines()
        return {
            "hash": lines[0],
            "short_hash": lines[1],
            "author": lines[2],
            "date": lines[3],
            "subject": lines[4] if len(lines) > 4 else "",
        }
    except Exception as exc:
        logger.warning(f"[commit-tracker] Error reading HEAD for {repo_path}: {exc}")
        return {}


def save_commit_info(repo_path: str, output_dir: str) -> str | None:
    """Persist the latest-commit metadata to a text file.

    Returns the path to the written file, or ``None`` on failure.
    """
    info = get_latest_commit(repo_path)
    if not info:
        return None

    repo_name = os.path.basename(os.path.abspath(repo_path).rstrip("/"))
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"{repo_name}_latest_commit.txt")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(f"repository: {repo_name}\n")
        fh.write(f"commit:     {info['hash']}\n")
        fh.write(f"short:      {info['short_hash']}\n")
        fh.write(f"author:     {info['author']}\n")
        fh.write(f"date:       {info['date']}\n")
        fh.write(f"subject:    {info['subject']}\n")

    logger.info(f"[commit-tracker] Saved latest commit info → {out_path}")
    return out_path
