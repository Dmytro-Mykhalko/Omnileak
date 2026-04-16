import json
import os

import pytest

from core.ai.triage_writer import assemble
from core.ai.constants import compute_risk_score


def _raw_finding(id_="r1", file_path="config/app.yml", secret_type="API_KEY"):
    return {
        "id": id_,
        "repository": "test-repo",
        "file_path": file_path,
        "line_number": 10,
        "secret_type": secret_type,
        "secret_value": "FAKE_KEY_000",
        "commit_hash": "aaa1111",
        "repo_url": "",
        "found_by": ["gitleaks"],
    }


def _classifications(findings=None, composites=None):
    return {
        "findings": findings or [],
        "composite_vulnerabilities": composites or [],
    }


def _write_files(tmp_path, raw, classifications, prefilter=None):
    raw_path = str(tmp_path / "aggregated.json")
    cls_path = str(tmp_path / "classifications.json")
    with open(raw_path, "w") as f:
        json.dump(raw, f)
    with open(cls_path, "w") as f:
        json.dump(classifications, f)
    pf_path = None
    if prefilter is not None:
        pf_path = str(tmp_path / "prefiltered.json")
        with open(pf_path, "w") as f:
            json.dump(prefilter, f)
    return raw_path, cls_path, pf_path


class TestAssemble:
    def test_basic_assembly(self, tmp_path):
        raw = [_raw_finding("r1")]
        cls = _classifications([{
            "omnileak_ids": ["r1"],
            "classification": "TRUE_POSITIVE",
            "severity": "HIGH",
            "category": "API Key",
            "confidence": "high",
            "environment": "production",
            "remediation": "ROTATE_IMMEDIATELY",
            "effort": "quick",
            "on_disk": True,
            "fp_reason": None,
            "duplicate_of": None,
        }])
        raw_path, cls_path, _ = _write_files(tmp_path, raw, cls)
        out_dir = str(tmp_path / "out")

        path = assemble(raw_path, cls_path, "test-repo", out_dir)
        assert os.path.isfile(path)
        assert "test-repo" in os.path.basename(path)

        with open(path) as f:
            data = json.load(f)
        assert data["meta"]["repo"] == "test-repo"
        assert data["meta"]["true_positives"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["classification"] == "TRUE_POSITIVE"

    def test_unmapped_raw_ids_become_duplicates(self, tmp_path):
        raw = [_raw_finding("r1"), _raw_finding("r2")]
        cls = _classifications([{
            "omnileak_ids": ["r1"],
            "classification": "TRUE_POSITIVE",
            "severity": "MEDIUM",
            "category": "key",
        }])
        raw_path, cls_path, _ = _write_files(tmp_path, raw, cls)

        path = assemble(raw_path, cls_path, "repo", str(tmp_path / "out"))
        with open(path) as f:
            data = json.load(f)
        assert len(data["findings"]) == 2
        classifications = {f["classification"] for f in data["findings"]}
        assert "DUPLICATE" in classifications

    def test_prefilter_auto_fps_included(self, tmp_path):
        raw = [_raw_finding("r1"), _raw_finding("r2")]
        cls = _classifications([{
            "omnileak_ids": ["r1"],
            "classification": "TRUE_POSITIVE",
            "severity": "LOW",
            "category": "key",
        }])
        pf = {
            "needs_triage": [_raw_finding("r1")],
            "auto_fp": [{**_raw_finding("r2"), "fp_category": "vendor_code"}],
            "summary": {"total": 2, "needs_triage": 1, "auto_fp": 1, "fp_categories": {}},
        }
        raw_path, cls_path, pf_path = _write_files(tmp_path, raw, cls, pf)

        path = assemble(raw_path, cls_path, "repo", str(tmp_path / "out"), prefilter_path=pf_path)
        with open(path) as f:
            data = json.load(f)
        fps = [f for f in data["findings"] if f["classification"] == "FALSE_POSITIVE"]
        assert len(fps) == 1
        assert "Auto-filtered" in fps[0]["fp_reason"]

    def test_file_naming_includes_score(self, tmp_path):
        raw = [_raw_finding("r1")]
        cls = _classifications([{
            "omnileak_ids": ["r1"],
            "classification": "TRUE_POSITIVE",
            "severity": "CRITICAL",
            "category": "key",
            "on_disk": True,
        }])
        raw_path, cls_path, _ = _write_files(tmp_path, raw, cls)

        path = assemble(raw_path, cls_path, "myapp", str(tmp_path / "out"))
        basename = os.path.basename(path)
        assert basename.startswith("myapp_triage-results_")
        assert basename.endswith(".json")

    def test_empty_raw_and_classifications(self, tmp_path):
        raw_path, cls_path, _ = _write_files(tmp_path, [], _classifications())
        path = assemble(raw_path, cls_path, "repo", str(tmp_path / "out"))
        with open(path) as f:
            data = json.load(f)
        assert data["findings"] == []
        assert data["meta"]["risk_score"] == 0

    def test_duplicates_in_meta(self, tmp_path):
        raw = [_raw_finding("r1"), _raw_finding("r2")]
        cls = _classifications([{
            "omnileak_ids": ["r1"],
            "classification": "TRUE_POSITIVE",
            "severity": "MEDIUM",
            "category": "key",
        }])
        raw_path, cls_path, _ = _write_files(tmp_path, raw, cls)

        path = assemble(raw_path, cls_path, "repo", str(tmp_path / "out"))
        with open(path) as f:
            data = json.load(f)
        assert data["meta"]["duplicates"] == 1  # r2 becomes a DUPLICATE

    def test_meta_fields_present(self, tmp_path):
        raw = [_raw_finding("r1")]
        cls = _classifications([{
            "omnileak_ids": ["r1"],
            "classification": "FALSE_POSITIVE",
            "category": "noise",
            "fp_reason": "not real",
        }])
        raw_path, cls_path, _ = _write_files(tmp_path, raw, cls)

        path = assemble(
            raw_path, cls_path, "myrepo", str(tmp_path / "out"),
            repo_url="https://github.com/org/myrepo",
            last_commit="abc123",
        )
        with open(path) as f:
            data = json.load(f)
        meta = data["meta"]
        assert meta["repo"] == "myrepo"
        assert meta["repo_url"] == "https://github.com/org/myrepo"
        assert meta["last_commit"] == "abc123"
        assert meta["total_raw_findings"] == 1


class TestComputeRiskScore:
    def test_zero_for_no_tps(self):
        assert compute_risk_score([{"classification": "FALSE_POSITIVE"}]) == 0

    def test_critical_scores_10(self):
        findings = [{"classification": "TRUE_POSITIVE", "severity": "CRITICAL"}]
        assert compute_risk_score(findings) == 10

    def test_composite_multiplier(self):
        findings = [{"classification": "TRUE_POSITIVE", "severity": "CRITICAL"}]
        assert compute_risk_score(findings, [{"id": 1}]) == 15  # 10 * 1.5

    def test_on_disk_multiplier(self):
        findings = [{"classification": "TRUE_POSITIVE", "severity": "CRITICAL", "on_disk": True}]
        assert compute_risk_score(findings) == 13  # 10 * 1.3

    def test_both_multipliers(self):
        findings = [{"classification": "TRUE_POSITIVE", "severity": "CRITICAL", "on_disk": True}]
        # 10 * 1.5 * 1.3 = 19.5 → ceil = 20
        assert compute_risk_score(findings, [{"id": 1}]) == 20

    def test_capped_at_100(self):
        findings = [{"classification": "TRUE_POSITIVE", "severity": "CRITICAL", "on_disk": True}] * 20
        score = compute_risk_score(findings, [{"id": 1}])
        assert score == 100

    def test_mixed_severities(self):
        findings = [
            {"classification": "TRUE_POSITIVE", "severity": "CRITICAL"},
            {"classification": "TRUE_POSITIVE", "severity": "HIGH"},
            {"classification": "TRUE_POSITIVE", "severity": "MEDIUM"},
            {"classification": "TRUE_POSITIVE", "severity": "LOW"},
            {"classification": "FALSE_POSITIVE"},
        ]
        # 10 + 5 + 2 + 1 = 18
        assert compute_risk_score(findings) == 18
