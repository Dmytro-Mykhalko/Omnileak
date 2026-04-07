import subprocess
import pytest
from unittest.mock import patch, MagicMock
from scanners import GitleaksScanner, TrufflehogScanner, DetectSecretsScanner, TitusScanner


class TestPreflightCheck:
    """Test the is_available() pre-flight check for each scanner."""

    @patch("shutil.which", return_value="/usr/local/bin/gitleaks")
    def test_gitleaks_available(self, mock_which, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path))
        assert scanner.is_available() is True

    @patch("shutil.which", return_value=None)
    def test_gitleaks_missing(self, mock_which, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path))
        assert scanner.is_available() is False

    @patch("shutil.which", return_value=None)
    def test_trufflehog_missing(self, mock_which, tmp_path):
        scanner = TrufflehogScanner("repo", str(tmp_path))
        assert scanner.is_available() is False

    @patch("shutil.which", return_value=None)
    def test_detect_secrets_missing(self, mock_which, tmp_path):
        scanner = DetectSecretsScanner("repo", str(tmp_path))
        assert scanner.is_available() is False

    @patch("shutil.which", return_value=None)
    def test_titus_missing(self, mock_which, tmp_path):
        scanner = TitusScanner("repo", str(tmp_path))
        assert scanner.is_available() is False


class TestSubprocessHandling:
    """Test that subprocess errors are handled gracefully."""

    @patch("subprocess.run")
    def test_gitleaks_successful_run(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        scanner = GitleaksScanner("repo", str(tmp_path))
        assert scanner.run_scan() is True
        assert mock_run.called

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="gitleaks", timeout=10))
    def test_gitleaks_timeout(self, mock_run, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path), timeout=10)
        assert scanner.run_scan() is False

    @patch("subprocess.run", side_effect=FileNotFoundError("gitleaks not found"))
    def test_gitleaks_not_found(self, mock_run, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path))
        assert scanner.run_scan() is False


class TestExecuteLifecycle:
    """Test the full execute() lifecycle with mocked availability and scan."""

    @patch("shutil.which", return_value=None)
    def test_execute_skips_when_missing(self, mock_which, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path))
        result = scanner.execute()
        assert result == []


class TestCommitRange:
    """Test commit-range related helpers and filtering."""

    def test_has_commit_range_false_by_default(self, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path))
        assert scanner.has_commit_range is False

    def test_has_commit_range_with_from(self, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path), commit_from="abc")
        assert scanner.has_commit_range is True

    def test_has_commit_range_with_to(self, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path), commit_to="def")
        assert scanner.has_commit_range is True

    def test_git_log_range_both(self, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path),
                                  commit_from="aaa", commit_to="bbb")
        assert scanner._git_log_range() == "aaa..bbb"

    def test_git_log_range_from_only(self, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path), commit_from="aaa")
        assert scanner._git_log_range() == "aaa..HEAD"

    def test_git_log_range_to_only(self, tmp_path):
        scanner = GitleaksScanner("repo", str(tmp_path), commit_to="bbb")
        assert scanner._git_log_range() == "bbb"

    def test_filter_by_commit_range(self, tmp_path):
        """Findings outside the allowed commit set are dropped."""
        scanner = GitleaksScanner("repo", str(tmp_path),
                                  commit_from="aaa", commit_to="bbb")
        # Simulate cached commit set
        scanner._commits_in_range = {"c1", "c2", "c3"}

        findings = [
            {"commit_hash": "c1", "secret_value": "s1"},
            {"commit_hash": "c2", "secret_value": "s2"},
            {"commit_hash": "outside", "secret_value": "s3"},
            {"commit_hash": "", "secret_value": "s4"},
        ]
        result = scanner._filter_by_commit_range(findings)
        assert len(result) == 2
        assert result[0]["commit_hash"] == "c1"
        assert result[1]["commit_hash"] == "c2"

    def test_filter_noop_when_no_commits_resolved(self, tmp_path):
        """If git rev-list returned nothing, keep all findings (don't drop everything)."""
        scanner = GitleaksScanner("repo", str(tmp_path),
                                  commit_from="aaa", commit_to="bbb")
        scanner._commits_in_range = set()

        findings = [{"commit_hash": "c1", "secret_value": "s1"}]
        result = scanner._filter_by_commit_range(findings)
        assert len(result) == 1

    @patch("subprocess.run")
    def test_gitleaks_adds_log_opts(self, mock_run, tmp_path):
        """Gitleaks should pass --log-opts with the commit range."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        scanner = GitleaksScanner("repo", str(tmp_path),
                                  commit_from="aaa", commit_to="bbb")
        scanner.run_scan()
        cmd = mock_run.call_args[0][0]
        assert "--log-opts" in cmd
        idx = cmd.index("--log-opts")
        assert cmd[idx + 1] == "aaa..bbb"

    @patch("subprocess.run")
    def test_trufflehog_adds_since_commit(self, mock_run, tmp_path):
        """Trufflehog should pass --since-commit when commit_from is set."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        scanner = TrufflehogScanner("repo", str(tmp_path), commit_from="aaa")
        scanner.run_scan()
        call_args = mock_run.call_args
        # run_command_to_file opens a file, so check via the cmd list
        cmd = call_args[0][0]
        assert "--since-commit" in cmd
        idx = cmd.index("--since-commit")
        assert cmd[idx + 1] == "aaa"

    @patch("subprocess.run")
    def test_gitleaks_no_log_opts_without_range(self, mock_run, tmp_path):
        """Without commit range, gitleaks should NOT have --log-opts."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        scanner = GitleaksScanner("repo", str(tmp_path))
        scanner.run_scan()
        cmd = mock_run.call_args[0][0]
        assert "--log-opts" not in cmd
