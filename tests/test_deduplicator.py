import pytest
from core.deduplicator import Deduplicator


class TestDeduplicator:
    def test_merges_found_by(self):
        dedup = Deduplicator()
        dedup.load([
            {
                "id": "aaa",
                "repository": "repo",
                "file_path": "config.yml",
                "line_number": "10",
                "secret_type": "AWS",
                "secret_value": "AKIA123",
                "commit_hash": "abc",
                "found_by": ["gitleaks"],
            },
            {
                "id": "aaa",
                "repository": "repo",
                "file_path": "config.yml",
                "line_number": "10",
                "secret_type": "AWS_Key",
                "secret_value": "AKIA123",
                "commit_hash": "",
                "found_by": ["trufflehog"],
            },
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        assert "gitleaks" in result[0]["found_by"]
        assert "trufflehog" in result[0]["found_by"]
        assert result[0]["commit_hash"] == "abc"

    def test_keeps_distinct(self):
        dedup = Deduplicator()
        dedup.load([
            {
                "id": "aaa",
                "repository": "repo",
                "file_path": "config.yml",
                "line_number": "10",
                "secret_type": "AWS",
                "secret_value": "AKIA123",
                "commit_hash": "abc",
                "found_by": ["gitleaks"],
            },
            {
                "id": "bbb",
                "repository": "repo",
                "file_path": "env.sh",
                "line_number": "2",
                "secret_type": "DB_PASS",
                "secret_value": "COMPLETELY_DIFFERENT",
                "commit_hash": "def",
                "found_by": ["detect-secrets"],
            },
        ])
        result = dedup.deduplicate()
        assert len(result) == 2

    def test_merges_missing_fields(self):
        """If one tool has a commit hash and the other doesn't, the merge should keep it."""
        dedup = Deduplicator()
        dedup.load([
            {
                "id": "ccc",
                "repository": "repo",
                "file_path": "f.py",
                "line_number": "",
                "secret_type": "T",
                "secret_value": "s",
                "commit_hash": "",
                "found_by": ["detect-secrets"],
            },
            {
                "id": "ccc",
                "repository": "repo",
                "file_path": "f.py",
                "line_number": "42",
                "secret_type": "T",
                "secret_value": "s",
                "commit_hash": "deadbeef",
                "found_by": ["gitleaks"],
            },
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        assert result[0]["commit_hash"] == "deadbeef"
        assert result[0]["line_number"] == "42"

    def test_empty_input(self):
        dedup = Deduplicator()
        assert dedup.deduplicate() == []

    def test_found_by_sorted(self):
        dedup = Deduplicator()
        dedup.load([
            {"id": "x", "repository": "r", "file_path": "f", "line_number": "", "secret_type": "T", "secret_value": "s", "commit_hash": "", "found_by": ["trufflehog"]},
            {"id": "x", "repository": "r", "file_path": "f", "line_number": "", "secret_type": "T", "secret_value": "s", "commit_hash": "", "found_by": ["gitleaks"]},
            {"id": "x", "repository": "r", "file_path": "f", "line_number": "", "secret_type": "T", "secret_value": "s", "commit_hash": "", "found_by": ["detect-secrets"]},
        ])
        result = dedup.deduplicate()
        assert result[0]["found_by"] == ["detect-secrets", "gitleaks", "trufflehog"]

    def test_cross_tool_whitespace_dedup(self):
        """Same secret reported with different whitespace by different tools
        but same file — should merge via same ID (whitespace-normalized)."""
        dedup = Deduplicator()
        dedup.load([
            {
                "id": "same_because_normalized",
                "repository": "repo",
                "file_path": "key.pem",
                "line_number": "1",
                "secret_type": "private-key",
                "secret_value": "-----BEGIN KEY-----\n    MHcCAQ",
                "commit_hash": "aaa",
                "found_by": ["gitleaks"],
            },
            {
                "id": "same_because_normalized",
                "repository": "repo",
                "file_path": "key.pem",
                "line_number": "1",
                "secret_type": "PrivateKey",
                "secret_value": "-----BEGIN KEY-----\nMHcCAQ",
                "commit_hash": "aaa",
                "found_by": ["trufflehog"],
            },
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        assert "gitleaks" in result[0]["found_by"]
        assert "trufflehog" in result[0]["found_by"]

    def test_cross_tool_different_paths_same_secret(self):
        """Same secret found with different file paths (e.g. noseyparker has
        empty path) — Pass 2 merges them by secret-only key."""
        dedup = Deduplicator()
        dedup.load([
            {
                "id": "id_with_path",
                "repository": "repo",
                "file_path": "src/config.py",
                "line_number": "10",
                "secret_type": "aws-key",
                "secret_value": "AKIAEXAMPLE",
                "commit_hash": "abc",
                "found_by": ["gitleaks"],
            },
            {
                "id": "id_without_path",
                "repository": "repo",
                "file_path": "",
                "line_number": "",
                "secret_type": "AWS",
                "secret_value": "AKIAEXAMPLE",
                "commit_hash": "",
                "found_by": ["noseyparker"],
            },
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        assert result[0]["file_path"] == "src/config.py"
        assert result[0]["commit_hash"] == "abc"
        assert "gitleaks" in result[0]["found_by"]
        assert "noseyparker" in result[0]["found_by"]
