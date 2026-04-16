"""Manifest CRUD for resumable iterative multi-repo triage.

Tracks per-repo status so the triage pipeline can resume from where
it left off after interruption.  Every state change persists to disk
BEFORE moving to the next repo.

Usage::

    from core.ai.manifest import create_manifest, load_manifest, update_repo, next_pending

    manifest = create_manifest(prefilter_results, output_dir="/tmp/results")
    save_manifest(manifest)

    repo = next_pending(manifest)
    update_repo(manifest["path"], repo["name"], status="in_progress")
    ...
    update_repo(manifest["path"], repo["name"], status="done", risk_score=42)

Or from the CLI::

    python3 -m core.ai.manifest --status <manifest.json>
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Tier thresholds (after pre-filter)
_TIER_THRESHOLDS = [
    (0, "skip"),
    (20, "lightweight"),
    (200, "standard"),
]


def _assign_tier(needs_triage_count):
    """Assign dispatch tier based on finding count after pre-filter."""
    if needs_triage_count == 0:
        return "skip"
    if needs_triage_count <= 20:
        return "lightweight"
    if needs_triage_count <= 200:
        return "standard"
    return "large"


def _compute_priority(tier, needs_triage_count):
    """Higher priority = processed first. Skip tier is lowest."""
    tier_weight = {"skip": 0, "lightweight": 1, "standard": 2, "large": 3}
    return tier_weight.get(tier, 0) * 1000 + needs_triage_count


def create_manifest(prefilter_results, output_dir):
    """Build a manifest from pre-filter batch output.

    Parameters
    ----------
    prefilter_results : list[dict]
        Output from ``prefilter_batch()`` — one entry per repo with
        ``repo``, ``input``, ``output``, ``summary`` keys.
    output_dir : str
        Directory to write manifest.json.

    Returns
    -------
    dict
        The manifest dict (also written to disk).
    """
    repos = []
    for entry in prefilter_results:
        s = entry["summary"]
        needs = s["needs_triage"]
        tier = _assign_tier(needs)
        repos.append({
            "name": entry["repo"],
            "aggregated_json": entry["input"],
            "prefiltered_json": entry["output"],
            "raw_findings": s["total"],
            "pre_filtered": s["auto_fp"],
            "tier": tier,
            "priority": _compute_priority(tier, needs),
            "status": "pending",
            "started_at": None,
            "completed_at": None,
            "risk_score": None,
            "tps": None,
            "fps": None,
            "dups": None,
            "duration_s": None,
            "triage_json": None,
            "validated": None,
            "error": None,
        })

    # Sort by priority descending (highest priority first)
    repos.sort(key=lambda r: r["priority"], reverse=True)

    manifest_path = os.path.join(output_dir, "manifest.json")
    manifest = {
        "path": manifest_path,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_repos": len(repos),
        "total_findings": sum(r["raw_findings"] for r in repos),
        "completed": 0,
        "failed": 0,
        "repos": repos,
    }

    save_manifest(manifest)
    logger.info("Created manifest: %s (%d repos)", manifest_path, len(repos))
    return manifest


def save_manifest(manifest):
    """Persist manifest to disk."""
    path = manifest["path"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def load_manifest(path):
    """Load manifest from disk.

    Parameters
    ----------
    path : str
        Path to manifest.json.

    Returns
    -------
    dict
        The manifest dict.
    """
    with open(path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["path"] = path  # ensure path is always current
    return manifest


def update_repo(manifest_path, repo_name, **fields):
    """Update a single repo entry in the manifest and recompute totals.

    Parameters
    ----------
    manifest_path : str
        Path to manifest.json.
    repo_name : str
        Name of the repo to update.
    **fields
        Fields to update (e.g. ``status="done"``, ``risk_score=42``).

    Returns
    -------
    dict
        The updated manifest.
    """
    manifest = load_manifest(manifest_path)

    for repo in manifest["repos"]:
        if repo["name"] == repo_name:
            repo.update(fields)
            break
    else:
        raise ValueError(f"Repo '{repo_name}' not found in manifest")

    # Recompute totals
    manifest["completed"] = sum(1 for r in manifest["repos"] if r["status"] == "done")
    manifest["failed"] = sum(1 for r in manifest["repos"] if r["status"] == "failed")

    save_manifest(manifest)
    return manifest


def next_pending(manifest):
    """Return the next repo to process (first with status=pending).

    Parameters
    ----------
    manifest : dict
        The manifest dict (repos are already sorted by priority).

    Returns
    -------
    dict or None
        The next pending repo entry, or None if all done.
    """
    for repo in manifest["repos"]:
        if repo["status"] == "pending":
            return repo
    return None


def recover_stale(manifest_path, stale_minutes=10):
    """Reset in_progress repos stuck longer than *stale_minutes* back to pending.

    Parameters
    ----------
    manifest_path : str
        Path to manifest.json.
    stale_minutes : int
        Threshold in minutes.

    Returns
    -------
    list[str]
        Names of recovered repos.
    """
    manifest = load_manifest(manifest_path)
    now = time.time()
    recovered = []

    for repo in manifest["repos"]:
        if repo["status"] != "in_progress":
            continue
        started = repo.get("started_at")
        if not started:
            continue
        try:
            started_ts = datetime.fromisoformat(started).timestamp()
        except (ValueError, TypeError):
            continue
        if (now - started_ts) > stale_minutes * 60:
            repo["status"] = "pending"
            repo["started_at"] = None
            repo["error"] = f"recovered: stale after {stale_minutes}min"
            recovered.append(repo["name"])

    if recovered:
        manifest["completed"] = sum(1 for r in manifest["repos"] if r["status"] == "done")
        manifest["failed"] = sum(1 for r in manifest["repos"] if r["status"] == "failed")
        save_manifest(manifest)
        logger.info("Recovered %d stale repo(s): %s", len(recovered), recovered)

    return recovered


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] != "--status":
        print("Usage: python3 -m core.ai.manifest --status <manifest.json>")
        sys.exit(1)

    path = sys.argv[2]
    if not os.path.isfile(path):
        print(f"Error: {path} not found")
        sys.exit(1)

    m = load_manifest(path)
    total = m["total_repos"]
    done = m["completed"]
    failed = m["failed"]
    pending = sum(1 for r in m["repos"] if r["status"] == "pending")
    in_prog = sum(1 for r in m["repos"] if r["status"] == "in_progress")

    print(f"Manifest: {path}")
    print(f"  Total repos:  {total}")
    print(f"  Completed:    {done}")
    print(f"  Failed:       {failed}")
    print(f"  In progress:  {in_prog}")
    print(f"  Pending:      {pending}")

    if failed > 0:
        print("\nFailed repos:")
        for r in m["repos"]:
            if r["status"] == "failed":
                print(f"  - {r['name']}: {r.get('error', 'unknown')}")
