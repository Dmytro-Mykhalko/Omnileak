import json
import os

import pytest

from core.ai.prefilter import prefilter, prefilter_file


def _finding(file_path="src/app.py", id_="f1"):
    return {
        "id": id_,
        "repository": "test-repo",
        "file_path": file_path,
        "line_number": 1,
        "secret_type": "generic",
        "secret_value": "FAKE_VALUE_000",
        "commit_hash": "aaa1111",
        "found_by": ["gitleaks"],
    }


class TestPrefilter:
    def test_normal_file_passes_through(self):
        result = prefilter([_finding("src/config.yml")])
        assert len(result["needs_triage"]) == 1
        assert len(result["auto_fp"]) == 0

    def test_node_modules_filtered(self):
        result = prefilter([_finding("node_modules/pkg/index.js")])
        assert len(result["needs_triage"]) == 0
        assert len(result["auto_fp"]) == 1
        assert result["auto_fp"][0]["fp_category"] == "vendor_code"

    def test_vendor_filtered(self):
        result = prefilter([_finding("vendor/lib/translations/hu.php")])
        assert result["auto_fp"][0]["fp_category"] == "vendor_code"

    def test_lock_files_filtered(self):
        for name in ["pnpm-lock.yaml", "yarn.lock", "package-lock.json",
                      "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock"]:
            result = prefilter([_finding(name)])
            assert len(result["auto_fp"]) == 1, f"{name} should be filtered"
            assert result["auto_fp"][0]["fp_category"] == "lock_file"

    def test_minified_js_filtered(self):
        result = prefilter([_finding("public/assets/app.min.js")])
        assert result["auto_fp"][0]["fp_category"] == "minified_code"

    def test_bundle_js_filtered(self):
        result = prefilter([_finding("assets/main.bundle.js")])
        assert result["auto_fp"][0]["fp_category"] == "minified_code"

    def test_dist_directory_filtered(self):
        result = prefilter([_finding("dist/index.js")])
        assert result["auto_fp"][0]["fp_category"] == "bundled_frontend"

    def test_source_map_filtered(self):
        result = prefilter([_finding("assets/app.js.map")])
        assert result["auto_fp"][0]["fp_category"] == "source_map"

    def test_snapshot_filtered(self):
        result = prefilter([_finding("tests/__snapshots__/App.test.js.snap")])
        assert result["auto_fp"][0]["fp_category"] == "test_snapshot"

    def test_mixed_findings(self):
        findings = [
            _finding("src/config.yml", "f1"),
            _finding("node_modules/pkg/i.js", "f2"),
            _finding("vendor/lib/x.php", "f3"),
            _finding(".env", "f4"),
        ]
        result = prefilter(findings)
        assert len(result["needs_triage"]) == 2
        assert len(result["auto_fp"]) == 2
        assert result["summary"]["total"] == 4

    def test_summary_counts(self):
        findings = [
            _finding("node_modules/a.js", "f1"),
            _finding("node_modules/b.js", "f2"),
            _finding("vendor/c.php", "f3"),
            _finding("src/d.py", "f4"),
        ]
        result = prefilter(findings)
        s = result["summary"]
        assert s["total"] == 4
        assert s["needs_triage"] == 1
        assert s["auto_fp"] == 3
        assert s["fp_categories"]["vendor_code"] == 3

    def test_empty_input(self):
        result = prefilter([])
        assert result["needs_triage"] == []
        assert result["auto_fp"] == []
        assert result["summary"]["total"] == 0

    def test_original_finding_fields_preserved(self):
        f = _finding("node_modules/pkg/i.js")
        result = prefilter([f])
        fp = result["auto_fp"][0]
        assert fp["id"] == f["id"]
        assert fp["secret_value"] == f["secret_value"]
        assert "fp_category" in fp


class TestPrefilterFile:
    def test_writes_output(self, tmp_path):
        findings = [_finding("src/app.py"), _finding("node_modules/x.js")]
        input_path = str(tmp_path / "aggregated.json")
        with open(input_path, "w") as f:
            json.dump(findings, f)

        output_path = prefilter_file(input_path)
        assert os.path.isfile(output_path)

        with open(output_path) as f:
            data = json.load(f)
        assert len(data["needs_triage"]) == 1
        assert len(data["auto_fp"]) == 1

    def test_custom_output_path(self, tmp_path):
        input_path = str(tmp_path / "in.json")
        output_path = str(tmp_path / "custom_out.json")
        with open(input_path, "w") as f:
            json.dump([], f)

        result = prefilter_file(input_path, output_path)
        assert result == output_path
        assert os.path.isfile(output_path)
