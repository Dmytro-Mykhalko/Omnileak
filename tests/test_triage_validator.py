import json
import os

import pytest

from core.ai.triage_validator import validate


def _valid_triage(findings=None, composites=None, meta_overrides=None):
    """Build a minimal valid triage-results structure."""
    if findings is None:
        findings = [{
            "id": 1,
            "omnileak_ids": ["r1"],
            "classification": "TRUE_POSITIVE",
            "severity": "HIGH",
            "category": "API Key",
            "secret_value": "FAKE_KEY_000",
            "file_path": "config/app.yml",
            "line_number": 10,
            "commit": "aaa1111",
            "on_disk": True,
            "confidence": "high",
            "environment": "production",
            "remediation": "ROTATE_IMMEDIATELY",
            "effort": "quick",
            "detected_by": ["gitleaks"],
            "fp_reason": None,
            "duplicate_of": None,
        }]
    tp_count = sum(1 for f in findings if f["classification"] == "TRUE_POSITIVE")
    fp_count = sum(1 for f in findings if f["classification"] == "FALSE_POSITIVE")

    dup_count = sum(1 for f in findings if f["classification"] == "DUPLICATE")

    meta = {
        "repo": "test-repo",
        "scan_date": "2026-04-16T00:00:00Z",
        "mode": "full_scan",
        "risk_score": 7,  # HIGH=5, on_disk=True → 5*1.3=6.5 → ceil=7
        "total_raw_findings": 1,
        "true_positives": tp_count,
        "false_positives_filtered": fp_count,
        "duplicates": dup_count,
        "assembled_by": "triage_writer/v1",
    }
    if meta_overrides:
        meta.update(meta_overrides)

    return {
        "meta": meta,
        "findings": findings,
        "composite_vulnerabilities": composites or [],
    }


def _write(tmp_path, data, name=None):
    if name is None:
        # Default to a name that matches the validator's file naming check
        repo = data.get("meta", {}).get("repo", "test-repo")
        score = data.get("meta", {}).get("risk_score", 0)
        name = f"{repo}_triage-results_{score}.json"
    path = str(tmp_path / name)
    with open(path, "w") as f:
        json.dump(data, f)
    return path


class TestValidStructure:
    def test_valid_triage_passes(self, tmp_path):
        path = _write(tmp_path, _valid_triage())
        errors = validate(path)
        assert errors == []

    def test_missing_meta_field(self, tmp_path):
        data = _valid_triage()
        del data["meta"]["repo"]
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("repo" in e for e in errors)

    def test_wrong_meta_type(self, tmp_path):
        data = _valid_triage(meta_overrides={"risk_score": "high"})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("risk_score" in e for e in errors)

    def test_invalid_classification(self, tmp_path):
        data = _valid_triage()
        data["findings"][0]["classification"] = "MAYBE"
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("classification" in e for e in errors)

    def test_tp_without_severity(self, tmp_path):
        data = _valid_triage()
        data["findings"][0]["severity"] = None
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("severity" in e for e in errors)

    def test_missing_finding_field(self, tmp_path):
        data = _valid_triage()
        del data["findings"][0]["detected_by"]
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("detected_by" in e for e in errors)

    def test_omnileak_ids_must_be_list(self, tmp_path):
        data = _valid_triage()
        data["findings"][0]["omnileak_ids"] = "r1"
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("omnileak_ids" in e for e in errors)

    def test_fp_classification_valid(self, tmp_path):
        fp = {
            "id": 1, "omnileak_ids": ["r1"], "classification": "FALSE_POSITIVE",
            "severity": None, "category": "noise", "secret_value": "x",
            "file_path": "f", "line_number": 1, "commit": "a",
            "on_disk": True, "detected_by": ["gitleaks"],
            "fp_reason": "not real", "duplicate_of": None,
        }
        data = _valid_triage(findings=[fp], meta_overrides={
            "risk_score": 0, "true_positives": 0, "false_positives_filtered": 1,
            "duplicates": 0,
        })
        path = _write(tmp_path, data)
        errors = validate(path)
        assert errors == []


class TestCountConsistency:
    def test_tp_count_mismatch(self, tmp_path):
        data = _valid_triage(meta_overrides={"true_positives": 99})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("true_positives" in e for e in errors)

    def test_fp_count_mismatch(self, tmp_path):
        data = _valid_triage(meta_overrides={"false_positives_filtered": 5})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("false_positives_filtered" in e for e in errors)


class TestRiskScore:
    def test_correct_score_passes(self, tmp_path):
        data = _valid_triage(meta_overrides={"risk_score": 7})  # HIGH=5, on_disk → ceil(5*1.3)=7
        path = _write(tmp_path, data)
        assert validate(path) == []

    def test_wrong_score_flagged(self, tmp_path):
        data = _valid_triage(meta_overrides={"risk_score": 99})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("risk_score" in e for e in errors)


class TestIdCoverage:
    def test_all_ids_covered(self, tmp_path):
        raw = [{"id": "r1", "file_path": "f", "secret_value": "x"}]
        data = _valid_triage()
        triage_path = _write(tmp_path, data)
        raw_path = _write(tmp_path, raw, "raw.json")
        errors = validate(triage_path, raw_path=raw_path)
        assert errors == []

    def test_missing_id_flagged(self, tmp_path):
        raw = [
            {"id": "r1", "file_path": "f", "secret_value": "x"},
            {"id": "r2", "file_path": "g", "secret_value": "y"},
        ]
        data = _valid_triage()  # only covers r1
        triage_path = _write(tmp_path, data, "triage.json")
        raw_path = _write(tmp_path, raw, "raw.json")
        errors = validate(triage_path, raw_path=raw_path)
        assert any("r2" in str(e) for e in errors)

    def test_duplicate_id_flagged(self, tmp_path):
        data = _valid_triage(findings=[
            {
                "id": 1, "omnileak_ids": ["r1"], "classification": "TRUE_POSITIVE",
                "severity": "HIGH", "category": "k", "secret_value": "x",
                "file_path": "f", "line_number": 1, "commit": "a",
                "on_disk": True, "detected_by": ["gitleaks"],
            },
            {
                "id": 2, "omnileak_ids": ["r1"], "classification": "DUPLICATE",
                "severity": "HIGH", "category": "k", "secret_value": "x",
                "file_path": "f", "line_number": 1, "commit": "a",
                "on_disk": True, "detected_by": ["gitleaks"],
            },
        ], meta_overrides={"risk_score": 5, "true_positives": 1, "false_positives_filtered": 0,
                           "duplicates": 1, "total_raw_findings": 2})
        raw = [{"id": "r1"}]
        triage_path = _write(tmp_path, data, "triage.json")
        raw_path = _write(tmp_path, raw, "raw.json")
        errors = validate(triage_path, raw_path=raw_path)
        assert any("multiple" in e for e in errors)


class TestEdgeCases:
    def test_invalid_json_file(self, tmp_path):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as f:
            f.write("not json")
        errors = validate(path)
        assert len(errors) == 1
        assert "cannot read" in errors[0]

    def test_empty_findings(self, tmp_path):
        data = _valid_triage(findings=[], meta_overrides={
            "risk_score": 0, "true_positives": 0, "false_positives_filtered": 0,
            "duplicates": 0, "total_raw_findings": 0,
        })
        path = _write(tmp_path, data)
        assert validate(path) == []


class TestTotalCoverage:
    def test_coverage_gap_flagged(self, tmp_path):
        data = _valid_triage(meta_overrides={"total_raw_findings": 100})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("total coverage gap" in e for e in errors)

    def test_more_findings_than_raw_is_ok(self, tmp_path):
        """Extra findings (e.g. AI-only) are acceptable."""
        data = _valid_triage(meta_overrides={"total_raw_findings": 0})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert not any("total coverage gap" in e for e in errors)


class TestSequentialIds:
    def test_valid_sequential_passes(self, tmp_path):
        data = _valid_triage()  # default finding has id=1
        path = _write(tmp_path, data)
        errors = validate(path)
        assert not any("sequential" in e for e in errors)

    def test_non_sequential_flagged(self, tmp_path):
        data = _valid_triage()
        data["findings"][0]["id"] = 5  # should be 1
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("sequential" in e for e in errors)

    def test_string_id_flagged(self, tmp_path):
        data = _valid_triage()
        data["findings"][0]["id"] = "TP-001"
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("integer" in e for e in errors)


class TestDuplicateCount:
    def test_matching_dup_count_passes(self, tmp_path):
        data = _valid_triage(meta_overrides={"duplicates": 0})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert not any("meta.duplicates" in e for e in errors)

    def test_mismatched_dup_count_flagged(self, tmp_path):
        data = _valid_triage(meta_overrides={"duplicates": 5})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("meta.duplicates" in e for e in errors)


class TestFileNaming:
    def test_correct_naming_passes(self, tmp_path):
        data = _valid_triage()
        path = _write(tmp_path, data)  # auto-generates correct name
        errors = validate(path)
        assert not any("file naming" in e for e in errors)

    def test_wrong_naming_flagged(self, tmp_path):
        data = _valid_triage()
        path = _write(tmp_path, data, "wrong_name.json")
        errors = validate(path)
        assert any("file naming" in e for e in errors)


class TestAssembledByMarker:
    def test_correct_marker_passes(self, tmp_path):
        data = _valid_triage()
        path = _write(tmp_path, data)
        errors = validate(path)
        assert not any("assembled_by" in e for e in errors)

    def test_missing_marker_flagged(self, tmp_path):
        data = _valid_triage()
        del data["meta"]["assembled_by"]
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("assembled_by" in e and "missing" in e for e in errors)

    def test_wrong_marker_flagged(self, tmp_path):
        data = _valid_triage(meta_overrides={"assembled_by": "my_custom_script"})
        path = _write(tmp_path, data)
        errors = validate(path)
        assert any("my_custom_script" in e for e in errors)
