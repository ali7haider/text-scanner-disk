"""
report.py
=============================================================================
Responsible for ONE thing only: turning a list of scan result dicts into a
well-structured, human-readable CSV file.

It has zero knowledge of the GUI, file extraction, or regex patterns.
This makes it easy to test independently and reuse in future CLI tools or
automated pipelines.

Public API
----------
  generate_filename()               → str        timestamped default filename
  save_csv(results, output_path)    → str        write CSV, return abs path

CSV columns (in order)
----------------------
  #              – row number (1-based) for easy reference
  Severity       – Critical / High
  Data Type      – e.g. Email Address, SSN
  Matched Value  – the exact string that triggered the match
  File Name      – just the filename (e.g. records.csv)
  File Type      – uppercase extension without dot (e.g. CSV)
  File Path      – full absolute path to the source file
  Location       – position within the file (Line 4, Row 2 | Col B, etc.)
  Context        – surrounding text snippet for quick human review
=============================================================================
"""

import csv
import os
from datetime import datetime
from pathlib import Path


# Column order in the output CSV.
# Changing this list is the only thing needed to add/remove/reorder columns.
CSV_COLUMNS = [
    "#",
    "Severity",
    "Data Type",
    "Matched Value",
    "File Name",
    "File Type",
    "File Path",
    "Location",
    "Context",
]

# Maps result dict keys → CSV column names.
# If a new column is added to CSV_COLUMNS, add its mapping here.
_KEY_MAP = {
    "#":             "#",           # filled in by save_csv()
    "Severity":      "severity",
    "Data Type":     "data_type",
    "Matched Value": "match",
    "File Name":     "file_name",
    "File Type":     "file_ext",
    "File Path":     "file_path",
    "Location":      "location",
    "Context":       "context",
}


def generate_filename() -> str:
    """
    Build a timestamped default filename so successive reports never
    overwrite each other.

    Example return value:  "pii_report_20260518_143022.csv"
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"pii_report_{ts}.csv"


def save_csv(results: list[dict], output_path: str | Path) -> str:
    """
    Write scan results to a CSV file.

    File encoding: UTF-8 with BOM (utf-8-sig) so that Microsoft Excel
    opens the file correctly on Windows without a manual encoding step.

    Args:
      results      – list of result dicts from scanner.scan_file() or
                     scanner.scan_folder()
      output_path  – destination file path (str or Path)

    Returns:
      The absolute path to the written file as a string.

    Raises:
      OSError / PermissionError if the destination cannot be written.
    """
    output_path = Path(output_path)

    # Ensure the destination directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for row_num, result in enumerate(results, start=1):
            # Build one CSV row from the result dict
            row = {}
            for col in CSV_COLUMNS:
                if col == "#":
                    row[col] = row_num
                else:
                    # Look up the result dict key for this column;
                    # default to empty string if the key is somehow missing
                    dict_key = _KEY_MAP.get(col, col.lower())
                    row[col] = result.get(dict_key, "")
            writer.writerow(row)

    return str(output_path.resolve())


def summary_stats(results: list[dict]) -> dict:
    """
    Compute a quick summary of scan results for display in the GUI
    status bar and stat cards.

    Returns a dict with keys:
      total          – total number of matches
      critical       – count of Critical-severity matches
      high           – count of High-severity matches
      files_scanned  – number of unique source files in the results
      ext_counts     – dict mapping extension → count  (e.g. {"CSV": 5, "PDF": 2})
    """
    critical     = sum(1 for r in results if r.get("severity") == "Critical")
    high         = sum(1 for r in results if r.get("severity") == "High")
    files        = {r.get("file_path", "") for r in results}
    ext_counts: dict[str, int] = {}
    for r in results:
        ext = r.get("file_ext", "Unknown")
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

    return {
        "total":         len(results),
        "critical":      critical,
        "high":          high,
        "files_scanned": len(files),
        "ext_counts":    ext_counts,
    }
