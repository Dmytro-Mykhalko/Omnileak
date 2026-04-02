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
