import os
import json
import pytest
from scanners import GitleaksScanner, TrufflehogScanner, DetectSecretsScanner, TitusScanner


# ------------------------------------------------------------------
# Gitleaks
# ------------------------------------------------------------------
class TestGitleaksParser:
    def test_basic_parsing(self, tmp_path):
        scanner = GitleaksScanner("fake/repo", str(tmp_path))
        raw_data = [
            {
                "Description": "AWS Access Key",
                "StartLine": 12,
                "File": "config.yaml",
                "Commit": "abc123def",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "RuleID": "aws-access-token",
            }
        ]
        with open(scanner.raw_output, "w") as f:
            json.dump(raw_data, f)

        res = scanner.parse_results()
        assert len(res) == 1
        assert res[0]["secret_value"] == "AKIAIOSFODNN7EXAMPLE"
        assert res[0]["commit_hash"] == "abc123def"
        assert res[0]["secret_type"] == "aws-access-token"
        assert res[0]["line_number"] == 12
        assert "gitleaks" in res[0]["found_by"]
        assert res[0]["id"]  # should have a hash

    def test_empty_file(self, tmp_path):
        scanner = GitleaksScanner("fake/repo", str(tmp_path))
        with open(scanner.raw_output, "w") as f:
            json.dump([], f)
        assert scanner.parse_results() == []

    def test_missing_file(self, tmp_path):
        scanner = GitleaksScanner("fake/repo", str(tmp_path))
        assert scanner.parse_results() == []

    def test_corrupt_json(self, tmp_path):
        scanner = GitleaksScanner("fake/repo", str(tmp_path))
        with open(scanner.raw_output, "w") as f:
            f.write("{corrupt")
        assert scanner.parse_results() == []

    def test_multiple_findings(self, tmp_path):
        scanner = GitleaksScanner("fake/repo", str(tmp_path))
        raw_data = [
            {"File": "a.py", "Secret": "sec1", "StartLine": 1, "Commit": "c1", "RuleID": "r1"},
            {"File": "b.py", "Secret": "sec2", "StartLine": 2, "Commit": "c2", "RuleID": "r2"},
            {"File": "c.py", "Secret": "sec3", "StartLine": 3, "Commit": "c3", "RuleID": "r3"},
        ]
        with open(scanner.raw_output, "w") as f:
            json.dump(raw_data, f)
        assert len(scanner.parse_results()) == 3


# ------------------------------------------------------------------
# Trufflehog
# ------------------------------------------------------------------
class TestTrufflehogParser:
    def test_basic_ndjson(self, tmp_path):
        scanner = TrufflehogScanner("fake/repo", str(tmp_path))
        lines = [
            json.dumps({
                "SourceMetadata": {"Data": {"Git": {"file": "settings.py", "commit": "xyz789", "line": 5}}},
                "Raw": "my_secret_key",
                "DetectorName": "Generic Password",
            }),
            json.dumps({
                "SourceMetadata": {"Data": {"Git": {"file": "app.js", "commit": "def456", "line": 10}}},
                "Raw": "AKIAEXAMPLE123",
                "DetectorName": "AWS",
            }),
        ]
        with open(scanner.raw_output, "w") as f:
            f.write("\n".join(lines) + "\n")

        res = scanner.parse_results()
        assert len(res) == 2
        assert res[0]["secret_value"] == "my_secret_key"
        assert res[0]["file_path"] == "settings.py"
        assert res[1]["secret_value"] == "AKIAEXAMPLE123"

    def test_malformed_lines_skipped(self, tmp_path):
        scanner = TrufflehogScanner("fake/repo", str(tmp_path))
        with open(scanner.raw_output, "w") as f:
            f.write('{"bad json\n')
            f.write("\n")  # empty line
            f.write(json.dumps({
                "SourceMetadata": {"Data": {"Git": {"file": "ok.py", "commit": "a", "line": 1}}},
                "Raw": "valid_secret",
                "DetectorName": "Test",
            }) + "\n")
        res = scanner.parse_results()
        assert len(res) == 1
        assert res[0]["secret_value"] == "valid_secret"

    def test_missing_file(self, tmp_path):
        scanner = TrufflehogScanner("fake/repo", str(tmp_path))
        assert scanner.parse_results() == []

    def test_skips_empty_secret(self, tmp_path):
        scanner = TrufflehogScanner("fake/repo", str(tmp_path))
        with open(scanner.raw_output, "w") as f:
            f.write(json.dumps({
                "SourceMetadata": {"Data": {"Git": {"file": "x.py"}}},
                "Raw": "",
                "DetectorName": "Test",
            }) + "\n")
        assert scanner.parse_results() == []


# ------------------------------------------------------------------
# Detect Secrets
# ------------------------------------------------------------------
class TestDetectSecretsParser:
    def test_basic_parsing(self, tmp_path):
        scanner = DetectSecretsScanner("fake/repo", str(tmp_path))
        raw_data = {
            "results": {
                "main.py": [
                    {
                        "type": "Basic Auth Credentials",
                        "hashed_secret": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c",
                        "line_number": 42,
                    }
                ]
            }
        }
        with open(scanner.raw_output, "w") as f:
            json.dump(raw_data, f)

        res = scanner.parse_results()
        assert len(res) == 1
        assert res[0]["secret_value"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c"
        assert res[0]["file_path"] == "main.py"
        assert res[0]["line_number"] == 42
        assert "detect-secrets" in res[0]["found_by"]

    def test_empty_results(self, tmp_path):
        scanner = DetectSecretsScanner("fake/repo", str(tmp_path))
        with open(scanner.raw_output, "w") as f:
            json.dump({"results": {}}, f)
        assert scanner.parse_results() == []

    def test_missing_file(self, tmp_path):
        scanner = DetectSecretsScanner("fake/repo", str(tmp_path))
        assert scanner.parse_results() == []

    def test_multiple_files(self, tmp_path):
        scanner = DetectSecretsScanner("fake/repo", str(tmp_path))
        raw_data = {
            "results": {
                "a.py": [{"type": "T1", "hashed_secret": "h1", "line_number": 1}],
                "b.py": [
                    {"type": "T2", "hashed_secret": "h2", "line_number": 2},
                    {"type": "T3", "hashed_secret": "h3", "line_number": 3},
                ],
            }
        }
        with open(scanner.raw_output, "w") as f:
            json.dump(raw_data, f)
        assert len(scanner.parse_results()) == 3


# ------------------------------------------------------------------
# Titus
# ------------------------------------------------------------------
import base64 as _b64

def _b64e(text):
    """Helper: encode a plain string to base64 for Titus mock data."""
    return _b64.b64encode(text.encode()).decode()


class TestTitusParser:
    def test_basic_parsing(self, tmp_path):
        """Titus JSON: Snippet fields are base64-encoded, no FilePath on match."""
        scanner = TitusScanner("fake/repo", str(tmp_path))
        raw_data = [
            {
                "ID": "finding1",
                "RuleID": "np.aws.6",
                "RuleName": "AWS API Credentials",
                "Groups": [_b64e("AKIAIOSFODNN7EXAMPLE")],
                "Matches": [
                    {
                        "BlobID": "deadbeef1234",
                        "StructuralID": "match1",
                        "RuleID": "np.aws.6",
                        "RuleName": "AWS API Credentials",
                        "Snippet": {
                            "Before": _b64e("KEY="),
                            "Matching": _b64e("AKIAIOSFODNN7EXAMPLE"),
                            "After": _b64e("\n"),
                        },
                        "Location": {
                            "Offset": {"Start": 10, "End": 30},
                            "Source": {
                                "Start": {"Line": 5, "Column": 4},
                                "End": {"Line": 5, "Column": 24},
                            },
                        },
                    }
                ],
            }
        ]
        with open(scanner.raw_output, "w") as f:
            json.dump(raw_data, f)

        res = scanner.parse_results()
        assert len(res) == 1
        assert res[0]["secret_value"] == "AKIAIOSFODNN7EXAMPLE"
        assert res[0]["secret_type"] == "AWS API Credentials"
        assert res[0]["line_number"] == 5
        assert "titus" in res[0]["found_by"]

    def test_multiple_matches(self, tmp_path):
        scanner = TitusScanner("fake/repo", str(tmp_path))
        raw_data = [
            {
                "ID": "f1",
                "RuleID": "np.generic.6",
                "RuleName": "Generic Password",
                "Groups": [],
                "Matches": [
                    {
                        "BlobID": "blob1",
                        "Snippet": {"Before": "", "Matching": _b64e("password=abc123"), "After": ""},
                        "Location": {"Source": {"Start": {"Line": 1}}},
                    },
                    {
                        "BlobID": "blob2",
                        "Snippet": {"Before": "", "Matching": _b64e("password=xyz789"), "After": ""},
                        "Location": {"Source": {"Start": {"Line": 10}}},
                    },
                ],
            }
        ]
        with open(scanner.raw_output, "w") as f:
            json.dump(raw_data, f)

        res = scanner.parse_results()
        assert len(res) == 2
        assert res[0]["secret_value"] == "password=abc123"
        assert res[1]["secret_value"] == "password=xyz789"

    def test_finding_without_matches(self, tmp_path):
        """Finding with Groups but no Matches should still produce a result."""
        scanner = TitusScanner("fake/repo", str(tmp_path))
        raw_data = [
            {
                "ID": "f1",
                "RuleID": "np.aws.1",
                "RuleName": "AWS Key",
                "Groups": [_b64e("AKIATEST")],
                "Matches": [],
            }
        ]
        with open(scanner.raw_output, "w") as f:
            json.dump(raw_data, f)

        res = scanner.parse_results()
        assert len(res) == 1
        assert res[0]["secret_value"] == "AKIATEST"
        assert res[0]["file_path"] == ""
        assert "titus" in res[0]["found_by"]

    def test_missing_file(self, tmp_path):
        scanner = TitusScanner("fake/repo", str(tmp_path))
        assert scanner.parse_results() == []

    def test_corrupt_json(self, tmp_path):
        scanner = TitusScanner("fake/repo", str(tmp_path))
        with open(scanner.raw_output, "w") as f:
            f.write("{bad")
        assert scanner.parse_results() == []

    def test_empty_results(self, tmp_path):
        scanner = TitusScanner("fake/repo", str(tmp_path))
        with open(scanner.raw_output, "w") as f:
            json.dump([], f)
        assert scanner.parse_results() == []
