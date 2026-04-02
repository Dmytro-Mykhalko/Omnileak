import os
import json
import logging
import copy
import pandas as pd

logger = logging.getLogger(__name__)

COLUMNS = [
    "id", "repository", "file_path", "line_number",
    "secret_type", "secret_value", "commit_hash", "found_by",
]


class Reporter:
    def __init__(self, output_dir, repo_name=""):
        self.output_dir = output_dir
        self.repo_name = repo_name

    def _prefixed(self, filename):
        """Prepend repo_name_ to filename when a repo name is set."""
        if self.repo_name:
            return f"{self.repo_name}_{filename}"
        return filename

    def generate_json(self, data):
        json_path = os.path.join(self.output_dir, self._prefixed("aggregated_secrets.json"))
        logger.info(f"Generating aggregated JSON report at {json_path}")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Wrote {len(data)} findings to {json_path}")
        return json_path

    def _prepare_excel_data(self, data):
        """Convert found_by lists to comma-separated strings for Excel/Google Sheets readability."""
        excel_data = []
        for item in data:
            row = copy.deepcopy(item)
            if isinstance(row.get("found_by"), list):
                row["found_by"] = ", ".join(row["found_by"])
            excel_data.append(row)
        return excel_data

    def generate_excel(self, data):
        excel_path = os.path.join(self.output_dir, self._prefixed("secrets_report.xlsx"))
        logger.info(f"Generating Excel report at {excel_path}")

        if not data:
            logger.warning("No data to write to Excel.")
            df = pd.DataFrame(columns=COLUMNS)
            with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name="General", index=False)
                ws = writer.sheets["General"]
                ws.auto_filter.ref = ws.dimensions
            return excel_path

        excel_data = self._prepare_excel_data(data)
        df_all = pd.DataFrame(excel_data)

        # Determine all unique tools
        tools = set()
        for item in data:
            tools.update(item["found_by"])

        with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
            # General tab — all deduplicated findings
            df_all.to_excel(writer, sheet_name="General", index=False)

            # Per-tool tabs
            for tool in sorted(tools):
                df_tool = pd.DataFrame(
                    self._prepare_excel_data(
                        [item for item in data if tool in item["found_by"]]
                    )
                )
                if not df_tool.empty:
                    sheet_name = str(tool).capitalize()[:31]
                    df_tool.to_excel(writer, sheet_name=sheet_name, index=False)

            # Add auto-filters to every sheet
            for ws in writer.sheets.values():
                ws.auto_filter.ref = ws.dimensions

        logger.info(f"Wrote Excel report with {len(tools)} tool tabs to {excel_path}")
        return excel_path
