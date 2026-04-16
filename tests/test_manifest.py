import json
import os
from datetime import datetime, timezone, timedelta

import pytest

from core.ai.manifest import (
    create_manifest,
    load_manifest,
    update_repo,
    next_pending,
    recover_stale,
)


def _prefilter_results(repos=None):
    """Build mock prefilter_batch output."""
    if repos is None:
        repos = [
            ("repo-a", 50, 10),  # 50 total, 10 auto-FP → 40 need triage
            ("repo-b", 5, 2),    # 5 total, 2 auto-FP → 3 need triage
            ("repo-c", 10, 10),  # 10 total, 10 auto-FP → 0 need triage (skip)
        ]
    results = []
    for name, total, auto_fp in repos:
        needs = total - auto_fp
        results.append({
            "repo": name,
            "input": f"/tmp/{name}/{name}_aggregated_secrets.json",
            "output": f"/tmp/{name}/prefiltered.json",
            "summary": {
                "total": total,
                "needs_triage": needs,
                "auto_fp": auto_fp,
                "fp_categories": {},
            },
        })
    return results


class TestCreateManifest:
    def test_creates_file(self, tmp_path):
        results = _prefilter_results()
        manifest = create_manifest(results, str(tmp_path))
        assert os.path.isfile(manifest["path"])

    def test_repo_count(self, tmp_path):
        results = _prefilter_results()
        manifest = create_manifest(results, str(tmp_path))
        assert manifest["total_repos"] == 3
        assert len(manifest["repos"]) == 3

    def test_tier_assignment(self, tmp_path):
        results = _prefilter_results()
        manifest = create_manifest(results, str(tmp_path))
        tiers = {r["name"]: r["tier"] for r in manifest["repos"]}
        assert tiers["repo-a"] == "standard"   # 40 need triage
        assert tiers["repo-b"] == "lightweight" # 3 need triage
        assert tiers["repo-c"] == "skip"        # 0 need triage

    def test_sorted_by_priority(self, tmp_path):
        results = _prefilter_results()
        manifest = create_manifest(results, str(tmp_path))
        priorities = [r["priority"] for r in manifest["repos"]]
        assert priorities == sorted(priorities, reverse=True)

    def test_all_pending(self, tmp_path):
        results = _prefilter_results()
        manifest = create_manifest(results, str(tmp_path))
        assert all(r["status"] == "pending" for r in manifest["repos"])

    def test_total_findings(self, tmp_path):
        results = _prefilter_results()
        manifest = create_manifest(results, str(tmp_path))
        assert manifest["total_findings"] == 65  # 50 + 5 + 10

    def test_large_tier(self, tmp_path):
        results = _prefilter_results([("big-repo", 500, 100)])
        manifest = create_manifest(results, str(tmp_path))
        assert manifest["repos"][0]["tier"] == "large"


class TestLoadManifest:
    def test_roundtrip(self, tmp_path):
        results = _prefilter_results()
        original = create_manifest(results, str(tmp_path))
        loaded = load_manifest(original["path"])
        assert loaded["total_repos"] == original["total_repos"]
        assert len(loaded["repos"]) == len(original["repos"])


class TestUpdateRepo:
    def test_update_status(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        updated = update_repo(manifest["path"], "repo-a", status="in_progress")
        repo_a = next(r for r in updated["repos"] if r["name"] == "repo-a")
        assert repo_a["status"] == "in_progress"

    def test_update_persists(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        update_repo(manifest["path"], "repo-a", status="done", risk_score=42)
        reloaded = load_manifest(manifest["path"])
        repo_a = next(r for r in reloaded["repos"] if r["name"] == "repo-a")
        assert repo_a["status"] == "done"
        assert repo_a["risk_score"] == 42

    def test_recomputes_totals(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        update_repo(manifest["path"], "repo-a", status="done")
        update_repo(manifest["path"], "repo-b", status="failed", error="timeout")
        reloaded = load_manifest(manifest["path"])
        assert reloaded["completed"] == 1
        assert reloaded["failed"] == 1

    def test_unknown_repo_raises(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        with pytest.raises(ValueError, match="not found"):
            update_repo(manifest["path"], "nonexistent", status="done")


class TestNextPending:
    def test_returns_highest_priority(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        repo = next_pending(manifest)
        assert repo is not None
        assert repo["name"] == "repo-a"  # highest priority (standard tier)

    def test_skips_non_pending(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        update_repo(manifest["path"], "repo-a", status="done")
        reloaded = load_manifest(manifest["path"])
        repo = next_pending(reloaded)
        assert repo["name"] == "repo-b"

    def test_returns_none_when_all_done(self, tmp_path):
        results = _prefilter_results([("only-repo", 5, 0)])
        manifest = create_manifest(results, str(tmp_path))
        update_repo(manifest["path"], "only-repo", status="done")
        reloaded = load_manifest(manifest["path"])
        assert next_pending(reloaded) is None


class TestRecoverStale:
    def test_recovers_stale_repo(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        # Set repo-a to in_progress with a timestamp 20 minutes ago
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
        update_repo(manifest["path"], "repo-a",
                    status="in_progress", started_at=old_time)

        recovered = recover_stale(manifest["path"], stale_minutes=10)
        assert "repo-a" in recovered

        reloaded = load_manifest(manifest["path"])
        repo_a = next(r for r in reloaded["repos"] if r["name"] == "repo-a")
        assert repo_a["status"] == "pending"

    def test_does_not_recover_recent(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        recent = datetime.now(timezone.utc).isoformat()
        update_repo(manifest["path"], "repo-a",
                    status="in_progress", started_at=recent)

        recovered = recover_stale(manifest["path"], stale_minutes=10)
        assert recovered == []

    def test_ignores_done_repos(self, tmp_path):
        manifest = create_manifest(_prefilter_results(), str(tmp_path))
        update_repo(manifest["path"], "repo-a", status="done")
        recovered = recover_stale(manifest["path"], stale_minutes=0)
        assert "repo-a" not in recovered
