import pytest
from core.deduplicator import Deduplicator, _normalize, _extract_core, _is_overlap


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
        """Same secret found with different file paths (e.g. titus has
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
                "found_by": ["titus"],
            },
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        assert result[0]["file_path"] == "src/config.py"
        assert result[0]["commit_hash"] == "abc"
        assert "gitleaks" in result[0]["found_by"]
        assert "titus" in result[0]["found_by"]


def _make_finding(secret_value, found_by, fid="x", repo="repo",
                  file_path=".env", line_number="10", commit_hash="abc",
                  secret_type="generic"):
    """Helper to build a finding dict for tests."""
    return {
        "id": fid,
        "repository": repo,
        "file_path": file_path,
        "line_number": line_number,
        "secret_type": secret_type,
        "secret_value": secret_value,
        "commit_hash": commit_hash,
        "found_by": found_by if isinstance(found_by, list) else [found_by],
    }


class TestNormalize:
    def test_collapses_whitespace(self):
        assert _normalize("hello  world") == "helloworld"

    def test_collapses_real_newlines(self):
        assert _normalize("line1\nline2") == "line1line2"

    def test_collapses_escaped_newlines(self):
        assert _normalize("line1\\nline2") == "line1line2"

    def test_mixed(self):
        assert _normalize("BEGIN\\n  MII\nABC") == "BEGINMIIABC"


class TestExtractCore:
    def test_strips_var_assignment(self):
        assert _extract_core("SECRET=Xk9mPqRsT4vW") == "Xk9mPqRsT4vW"

    def test_strips_compound_var(self):
        assert _extract_core("S3_CREDENTIALS_KEY=AKIA123") == "AKIA123"

    def test_strips_surrounding_quotes(self):
        assert _extract_core("'mysecret'") == "mysecret"

    def test_leaves_plain_secret(self):
        assert _extract_core("AKIAIOSFODNN7EXAMPLE") == "AKIAIOSFODNN7EXAMPLE"

    def test_strips_code_context(self):
        core = _extract_core("$variable = 'testvalue';")
        assert "testvalue" in core


class TestIsOverlap:
    """Test the _is_overlap helper that checks if finding a should be
    absorbed into finding b."""

    def test_exact_match(self):
        a = _make_finding("AKIA123", "gitleaks")
        b = _make_finding("AKIA123", "trufflehog")
        assert _is_overlap(a, b)

    def test_raw_substring(self):
        a = _make_finding("AKIA123", "gitleaks")
        b = _make_finding("KEY=AKIA123\\nSECRET=xyz", "titus")
        assert _is_overlap(a, b)

    def test_core_substring(self):
        a = _make_finding("SECRET=Xk9mPqRsT4vW", "titus")
        b = _make_finding("Xk9mPqRsT4vWzYn/8+Ab2", "gitleaks")
        assert _is_overlap(a, b)

    def test_no_overlap(self):
        a = _make_finding("mysql://user:pass@db:3306/myapp", "titus")
        b = _make_finding("mysql://user:pass@db:3306/otherapp", "titus")
        assert not _is_overlap(a, b)
        assert not _is_overlap(b, a)

    def test_different_tokens(self):
        a = _make_finding("token_AAA_111", "gitleaks")
        b = _make_finding("token_BBB_222", "titus")
        assert not _is_overlap(a, b)


class TestProximityDedup:
    """Pass 3 — merge findings at the same (file, line, commit) when one
    secret contains the other."""

    def test_raw_substring_merged(self):
        dedup = Deduplicator()
        dedup.load([
            _make_finding("ghp_FAKE01234TOKEN56", ["gitleaks", "trufflehog"],
                          fid="a"),
            _make_finding('"github.com": "ghp_FAKE01234TOKEN56"', ["detect-secrets"],
                          fid="b"),
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        assert "gitleaks" in result[0]["found_by"]
        assert "detect-secrets" in result[0]["found_by"]
        # Keeps the longer value
        assert "github.com" in result[0]["secret_value"]

    def test_core_substring_merged(self):
        """SECRET=value vs value/more  — neither raw is a substring of the
        other, but core(a) ⊆ normalized(b)."""
        dedup = Deduplicator()
        dedup.load([
            _make_finding("SECRET=Xk9mPqRsT4vWzYnN7GC6Vr", ["titus"],
                          fid="a"),
            _make_finding("Xk9mPqRsT4vWzYnN7GC6VrHxz6Lg29/9+R5l", ["gitleaks"],
                          fid="b"),
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        assert "titus" in result[0]["found_by"]
        assert "gitleaks" in result[0]["found_by"]

    def test_different_secrets_same_line_kept(self):
        """Two genuinely different secrets on the same line stay separate."""
        dedup = Deduplicator()
        dedup.load([
            _make_finding("mysql://user:pass@db:3306/myapp", ["detect-secrets"],
                          fid="a"),
            _make_finding("mysql://user:pass@db:3306/otherapp", ["titus"],
                          fid="b"),
        ])
        result = dedup.deduplicate()
        assert len(result) == 2

    def test_different_tokens_same_line_kept(self):
        """Different API tokens on the same line are not merged."""
        dedup = Deduplicator()
        dedup.load([
            _make_finding("API_TOKEN=aaa111bbb222ccc333ddd444", ["titus"],
                          fid="a"),
            _make_finding("API_TOKEN=eee555fff666ggg777hhh888", ["titus"],
                          fid="b"),
        ])
        result = dedup.deduplicate()
        assert len(result) == 2

    def test_multiple_jwt_same_line(self):
        """Multiple different JWTs on the same line — only duplicates merged."""
        jwt_a = "eyJ0ZXN0IjoiYSJ9.eyJzdWIiOiJ0ZXN0MSIsIm5hbWUiOiJGYWtlIn0.abc"
        jwt_b = "eyJ0ZXN0IjoiYSJ9.eyJzdWIiOiJ0ZXN0MiIsInByb2QiOiJ4eHgifQ.xyz"
        dedup = Deduplicator()
        dedup.load([
            _make_finding(jwt_a, ["gitleaks"], fid="a"),
            _make_finding(f"'signedPayload' => '{jwt_a}'", ["detect-secrets"], fid="b"),
            _make_finding(jwt_a, ["titus"], fid="c"),
            _make_finding(jwt_b, ["gitleaks"], fid="d"),
        ])
        result = dedup.deduplicate()
        # jwt_a group (3 findings) -> 1 survivor, jwt_b -> 1 survivor
        assert len(result) == 2
        # The jwt_a survivor should have all three tools
        jwt_a_result = [r for r in result if "signedPayload" in r["secret_value"]
                        or r["secret_value"] == jwt_a]
        assert len(jwt_a_result) == 1
        assert set(jwt_a_result[0]["found_by"]) == {"gitleaks", "detect-secrets", "titus"}

    def test_no_grouping_without_location(self):
        """Findings missing file_path / line / commit are not proximity-grouped."""
        dedup = Deduplicator()
        dedup.load([
            _make_finding("secret_A", ["gitleaks"], fid="a",
                          file_path="", line_number="", commit_hash=""),
            _make_finding("secret_A_longer", ["titus"], fid="b",
                          file_path="", line_number="", commit_hash=""),
        ])
        result = dedup.deduplicate()
        # Without location info they stay separate (no proximity grouping)
        assert len(result) == 2

    def test_private_key_newline_variants(self):
        """Same private key with \\\\n vs \\n — merged after normalization."""
        dedup = Deduplicator()
        dedup.load([
            _make_finding(
                "-----BEGIN PRIVATE KEY-----\\nMIIBogIBAAJBAKx",
                ["gitleaks"], fid="a"),
            _make_finding(
                "-----BEGIN PRIVATE KEY-----\nMIIBogIBAAJBAKxExtra",
                ["trufflehog"], fid="b"),
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        assert "gitleaks" in result[0]["found_by"]
        assert "trufflehog" in result[0]["found_by"]

    def test_keeps_longest_secret(self):
        """The survivor should retain the longest secret_value."""
        dedup = Deduplicator()
        dedup.load([
            _make_finding("AKIAIOSFODNN7EXAMPLE", ["gitleaks"], fid="a"),
            _make_finding("S3_KEY=AKIAIOSFODNN7EXAMPLE", ["detect-secrets"], fid="b"),
            _make_finding(
                "AKIAIOSFODNN7EXAMPLE\\nS3_SECRET=wJalrXUtnFEMI/bPx",
                ["titus"], fid="c"),
        ])
        result = dedup.deduplicate()
        assert len(result) == 1
        # Titus value is longest
        assert "wJalrXUtnFEMI" in result[0]["secret_value"]
        assert set(result[0]["found_by"]) == {"gitleaks", "detect-secrets", "titus"}
