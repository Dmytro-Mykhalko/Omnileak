import os
import shutil
import subprocess
import pytest
from unittest.mock import patch, MagicMock

from core.repo_cloner import (
    _to_ssh_url,
    _repo_name_from_url,
    read_repo_list,
    clone_repos,
)


# ------------------------------------------------------------------
# URL conversion helpers
# ------------------------------------------------------------------
class TestToSshUrl:
    def test_https_github(self):
        assert (
            _to_ssh_url("https://github.com/octocat/hello-world")
            == "git@github.com:octocat/hello-world.git"
        )

    def test_https_with_dotgit(self):
        assert (
            _to_ssh_url("https://github.com/octocat/hello-world.git")
            == "git@github.com:octocat/hello-world.git"
        )

    def test_ssh_passthrough(self):
        assert (
            _to_ssh_url("git@github.com:octocat/hello-world.git")
            == "git@github.com:octocat/hello-world.git"
        )

    def test_ssh_without_dotgit(self):
        assert (
            _to_ssh_url("git@github.com:octocat/hello-world")
            == "git@github.com:octocat/hello-world.git"
        )

    def test_gitlab_https(self):
        assert (
            _to_ssh_url("https://gitlab.example.com/team/project")
            == "git@gitlab.example.com:team/project.git"
        )

    def test_unknown_format_returned_unchanged(self):
        assert _to_ssh_url("ftp://weird/url") == "ftp://weird/url"

    def test_whitespace_stripped(self):
        assert (
            _to_ssh_url("  https://github.com/octocat/hello-world  ")
            == "git@github.com:octocat/hello-world.git"
        )


class TestRepoNameFromUrl:
    def test_https(self):
        assert _repo_name_from_url("https://github.com/octocat/hello-world") == "hello-world"

    def test_https_dotgit(self):
        assert _repo_name_from_url("https://github.com/octocat/hello-world.git") == "hello-world"

    def test_ssh(self):
        assert _repo_name_from_url("git@github.com:octocat/hello-world.git") == "hello-world"

    def test_trailing_slash(self):
        assert _repo_name_from_url("https://github.com/octocat/hello-world/") == "hello-world"


# ------------------------------------------------------------------
# Reading the repo list file
# ------------------------------------------------------------------
class TestReadRepoList:
    def test_reads_urls(self, tmp_path):
        f = tmp_path / "repos.txt"
        f.write_text(
            "https://github.com/octocat/hello-world\n"
            "git@github.com:octocat/Spoon-Knife.git\n"
        )
        result = read_repo_list(str(f))
        assert result == [
            "git@github.com:octocat/Spoon-Knife.git",
            "https://github.com/octocat/hello-world",
        ]

    def test_skips_blanks_and_comments(self, tmp_path):
        f = tmp_path / "repos.txt"
        f.write_text(
            "# This is a comment\n"
            "\n"
            "https://github.com/octocat/hello-world\n"
            "   \n"
            "# Another comment\n"
            "https://github.com/octocat/Spoon-Knife\n"
        )
        result = read_repo_list(str(f))
        assert len(result) == 2

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        assert read_repo_list(str(f)) == []

    def test_deduplicates_urls(self, tmp_path):
        f = tmp_path / "repos.txt"
        f.write_text(
            "https://github.com/octocat/hello-world\n"
            "https://github.com/octocat/Spoon-Knife\n"
            "https://github.com/octocat/hello-world\n"
            "https://github.com/octocat/Spoon-Knife\n"
            "https://github.com/octocat/hello-world\n"
        )
        result = read_repo_list(str(f))
        assert result == [
            "https://github.com/octocat/Spoon-Knife",
            "https://github.com/octocat/hello-world",
        ]

    def test_sorted_output(self, tmp_path):
        f = tmp_path / "repos.txt"
        f.write_text(
            "https://github.com/octocat/linguist\n"
            "https://github.com/octocat/hello-world\n"
            "https://github.com/octocat/Spoon-Knife\n"
        )
        result = read_repo_list(str(f))
        assert result == [
            "https://github.com/octocat/Spoon-Knife",
            "https://github.com/octocat/hello-world",
            "https://github.com/octocat/linguist",
        ]


# ------------------------------------------------------------------
# Cloning with mocked subprocess
# ------------------------------------------------------------------
class TestCloneReposMocked:
    @patch("core.repo_cloner.subprocess.run")
    def test_clones_via_ssh(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        urls = ["https://github.com/octocat/hello-world"]
        dest = str(tmp_path / "cloned")

        result = clone_repos(urls, dest)

        assert len(result) == 1
        assert result[0] == os.path.join(dest, "hello-world")
        # Verify it used the SSH URL
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "git"
        assert call_args[1] == "clone"
        assert call_args[2] == "git@github.com:octocat/hello-world.git"

    @patch("core.repo_cloner.subprocess.run")
    def test_skips_already_cloned(self, mock_run, tmp_path):
        dest = str(tmp_path / "cloned")
        repo_dir = os.path.join(dest, "hello-world")
        os.makedirs(os.path.join(repo_dir, ".git"))

        result = clone_repos(["https://github.com/octocat/hello-world"], dest)

        assert len(result) == 1
        assert result[0] == repo_dir
        mock_run.assert_not_called()

    @patch("core.repo_cloner.subprocess.run")
    def test_failed_clone_excluded(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=128, stdout="", stderr="fatal: repo not found")
        urls = ["https://github.com/octocat/nonexistent-repo"]
        dest = str(tmp_path / "cloned")

        result = clone_repos(urls, dest)
        assert result == []

    @patch("core.repo_cloner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=300))
    def test_timeout_excluded(self, mock_run, tmp_path):
        urls = ["https://github.com/octocat/hello-world"]
        dest = str(tmp_path / "cloned")

        result = clone_repos(urls, dest)
        assert result == []

    @patch("core.repo_cloner.subprocess.run")
    def test_parallel_cloning(self, mock_run, tmp_path):
        """Multiple URLs with threads > 1 should all be cloned."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        urls = [
            "https://github.com/octocat/hello-world",
            "https://github.com/octocat/Spoon-Knife",
            "https://github.com/octocat/linguist",
        ]
        dest = str(tmp_path / "cloned")

        result = clone_repos(urls, dest, threads=3)

        assert len(result) == 3
        assert mock_run.call_count == 3
        cloned_names = sorted(os.path.basename(p) for p in result)
        assert cloned_names == ["Spoon-Knife", "hello-world", "linguist"]

    @patch("core.repo_cloner.subprocess.run")
    def test_threads_default_is_sequential(self, mock_run, tmp_path):
        """Default threads=1 should still clone all repos."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        urls = [
            "https://github.com/octocat/hello-world",
            "https://github.com/octocat/Spoon-Knife",
        ]
        dest = str(tmp_path / "cloned")

        result = clone_repos(urls, dest)

        assert len(result) == 2
        assert mock_run.call_count == 2


# ------------------------------------------------------------------
# Integration test — actually clones from GitHub (public repo)
# ------------------------------------------------------------------
class TestCloneReposIntegration:
    """Clones a real public repo and cleans up afterwards.

    This test requires network + SSH access to github.com.
    Skip with: pytest -k 'not Integration'
    """

    @pytest.fixture
    def clone_dir(self, tmp_path):
        d = tmp_path / "integration_clones"
        d.mkdir()
        yield str(d)
        # Cleanup: remove everything that was cloned
        shutil.rmtree(str(d), ignore_errors=True)

    @pytest.mark.integration
    def test_clone_real_repo(self, clone_dir):
        urls = ["https://github.com/octocat/hello-world"]
        cloned = clone_repos(urls, clone_dir)

        assert len(cloned) == 1
        repo_path = cloned[0]
        assert os.path.isdir(os.path.join(repo_path, ".git"))

        # Verify it's a valid git repo
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H"],
            capture_output=True, text=True,
            cwd=repo_path, check=False,
        )
        assert result.returncode == 0
        assert len(result.stdout.strip()) == 40  # full SHA

        # Cleanup verification: the fixture will remove clone_dir
        assert os.path.basename(repo_path) == "hello-world"
