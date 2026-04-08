import os
import shutil
import subprocess
import pytest
from unittest.mock import patch, MagicMock

from core.commit_tracker import get_latest_commit, save_commit_info


# ------------------------------------------------------------------
# Unit tests with mocked subprocess
# ------------------------------------------------------------------
class TestGetLatestCommit:
    @patch("core.commit_tracker.subprocess.run")
    def test_returns_commit_info(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="abc123def456789012345678901234567890abcd\nabc123d\nJane Doe\n2025-01-15T10:30:00+00:00\nfix: patch config leak\n",
            stderr="",
        )
        info = get_latest_commit(str(tmp_path))
        assert info["hash"] == "abc123def456789012345678901234567890abcd"
        assert info["short_hash"] == "abc123d"
        assert info["author"] == "Jane Doe"
        assert info["date"] == "2025-01-15T10:30:00+00:00"
        assert info["subject"] == "fix: patch config leak"

    @patch("core.commit_tracker.subprocess.run")
    def test_returns_empty_on_failure(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=128,
            stdout="",
            stderr="fatal: not a git repository",
        )
        assert get_latest_commit(str(tmp_path)) == {}

    @patch("core.commit_tracker.subprocess.run", side_effect=Exception("boom"))
    def test_returns_empty_on_exception(self, mock_run, tmp_path):
        assert get_latest_commit(str(tmp_path)) == {}


class TestSaveCommitInfo:
    @patch("core.commit_tracker.get_latest_commit")
    def test_writes_file(self, mock_get, tmp_path):
        mock_get.return_value = {
            "hash": "abc123def456789012345678901234567890abcd",
            "short_hash": "abc123d",
            "author": "Jane Doe",
            "date": "2025-01-15T10:30:00+00:00",
            "subject": "fix: patch config leak",
        }
        repo_path = str(tmp_path / "my-repo")
        os.makedirs(repo_path)
        out_dir = str(tmp_path / "output")

        result = save_commit_info(repo_path, out_dir)

        assert result is not None
        assert os.path.exists(result)
        assert os.path.basename(result) == "my-repo_latest_commit.txt"

        content = open(result).read()
        assert "abc123def456789012345678901234567890abcd" in content
        assert "Jane Doe" in content
        assert "fix: patch config leak" in content

    @patch("core.commit_tracker.get_latest_commit", return_value={})
    def test_returns_none_on_failure(self, mock_get, tmp_path):
        result = save_commit_info(str(tmp_path), str(tmp_path / "out"))
        assert result is None

    @patch("core.commit_tracker.get_latest_commit")
    def test_file_content_format(self, mock_get, tmp_path):
        """Verify each line of the output file has the expected label."""
        mock_get.return_value = {
            "hash": "f" * 40,
            "short_hash": "f" * 7,
            "author": "Test Author",
            "date": "2025-06-01T00:00:00+00:00",
            "subject": "initial commit",
        }
        repo_path = str(tmp_path / "test-repo")
        os.makedirs(repo_path)
        out_dir = str(tmp_path / "output")

        path = save_commit_info(repo_path, out_dir)
        lines = open(path).read().splitlines()

        assert lines[0].startswith("repository:")
        assert lines[1].startswith("commit:")
        assert lines[2].startswith("short:")
        assert lines[3].startswith("author:")
        assert lines[4].startswith("date:")
        assert lines[5].startswith("subject:")


# ------------------------------------------------------------------
# Integration test — real git repo
# ------------------------------------------------------------------
class TestCommitTrackerIntegration:
    """Uses a real (tiny) git repo created in tmp_path."""

    @pytest.fixture
    def git_repo(self, tmp_path):
        repo = tmp_path / "sample-repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=str(repo), capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=str(repo), capture_output=True, check=True,
        )
        (repo / "README.md").write_text("# hello\n")
        subprocess.run(["git", "add", "."], cwd=str(repo), capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", "initial commit"],
            cwd=str(repo), capture_output=True, check=True,
        )
        yield str(repo)
        shutil.rmtree(str(repo), ignore_errors=True)

    def test_get_latest_commit_real(self, git_repo):
        info = get_latest_commit(git_repo)
        assert len(info["hash"]) == 40
        assert info["author"] == "Test User"
        assert info["subject"] == "initial commit"

    def test_save_commit_info_real(self, git_repo, tmp_path):
        out_dir = str(tmp_path / "results")
        path = save_commit_info(git_repo, out_dir)

        assert path is not None
        content = open(path).read()
        assert "sample-repo" in content
        assert "Test User" in content
        assert "initial commit" in content
        assert len(content.splitlines()) == 6
