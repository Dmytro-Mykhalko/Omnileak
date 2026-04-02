import os
import json
import pytest
import pandas as pd
from core.reporter import Reporter


SAMPLE_DATA = [
    {
        "id": "aaa",
        "repository": "repo",
        "file_path": "config.yml",
        "line_number": 10,
        "secret_type": "AWS_KEY",
        "secret_value": "AKIA123",
        "commit_hash": "abc",
        "found_by": ["gitleaks", "trufflehog"],
    },
    {
        "id": "bbb",
        "repository": "repo",
        "file_path": "env.sh",
        "line_number": 2,
        "secret_type": "DB_PASS",
        "secret_value": "s3cr3t",
        "commit_hash": "def",
        "found_by": ["detect-secrets"],
    },
]


class TestJsonReport:
    def test_generates_json(self, tmp_path):
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_json(SAMPLE_DATA)
        assert os.path.exists(path)
        assert os.path.basename(path) == "myrepo_aggregated_secrets.json"
        with open(path) as f:
            data = json.load(f)
        assert len(data) == 2
        assert data[0]["id"] == "aaa"

    def test_empty_json(self, tmp_path):
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_json([])
        with open(path) as f:
            data = json.load(f)
        assert data == []

    def test_json_without_repo_name(self, tmp_path):
        reporter = Reporter(str(tmp_path))
        path = reporter.generate_json(SAMPLE_DATA)
        assert os.path.basename(path) == "aggregated_secrets.json"


class TestExcelReport:
    def test_generates_excel_with_tabs(self, tmp_path):
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_excel(SAMPLE_DATA)
        assert os.path.exists(path)
        assert os.path.basename(path) == "myrepo_secrets_report.xlsx"

        xl = pd.ExcelFile(path)
        sheet_names = xl.sheet_names
        assert "General" in sheet_names
        assert "Gitleaks" in sheet_names
        assert "Trufflehog" in sheet_names
        assert "Detect-secrets" in sheet_names

    def test_general_tab_has_all_rows(self, tmp_path):
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_excel(SAMPLE_DATA)
        df = pd.read_excel(path, sheet_name="General")
        assert len(df) == 2

    def test_found_by_is_string_in_excel(self, tmp_path):
        """found_by should be a comma-separated string, not a Python list."""
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_excel(SAMPLE_DATA)
        df = pd.read_excel(path, sheet_name="General")
        assert df.iloc[0]["found_by"] == "gitleaks, trufflehog"
        assert df.iloc[1]["found_by"] == "detect-secrets"

    def test_empty_data(self, tmp_path):
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_excel([])
        assert os.path.exists(path)
        assert os.path.basename(path) == "myrepo_secrets_report.xlsx"
        df = pd.read_excel(path, sheet_name="General")
        assert len(df) == 0

    def test_tool_tab_content(self, tmp_path):
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_excel(SAMPLE_DATA)
        df_gl = pd.read_excel(path, sheet_name="Gitleaks")
        assert len(df_gl) == 1
        assert df_gl.iloc[0]["secret_value"] == "AKIA123"

    def test_auto_filters_applied(self, tmp_path):
        """Each sheet should have auto-filters enabled on all columns."""
        from openpyxl import load_workbook
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_excel(SAMPLE_DATA)
        wb = load_workbook(path)
        for ws in wb.worksheets:
            assert ws.auto_filter.ref == ws.dimensions, (
                f"Sheet '{ws.title}' missing auto-filter"
            )

    def test_auto_filters_on_empty(self, tmp_path):
        """Auto-filters should be present even on an empty report."""
        from openpyxl import load_workbook
        reporter = Reporter(str(tmp_path), repo_name="myrepo")
        path = reporter.generate_excel([])
        wb = load_workbook(path)
        ws = wb["General"]
        assert ws.auto_filter.ref == ws.dimensions
