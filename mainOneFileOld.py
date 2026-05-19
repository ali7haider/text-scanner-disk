"""
=============================================================================
PII Scanner  –  Multi-Format Edition
=============================================================================
Supported file types:
    .txt  .csv  .docx  .pdf  .xlsx

Detects (with severity):
    • Full Name            [High]
    • Date of Birth        [High]
    • Social Security No.  [Critical]
    • Email Address        [High]
    • Phone Number         [High]

How to run:
    python pii_scanner.py          ← launches the GUI

Requirements:
    pip install python-docx pdfplumber openpyxl
    (all other packages are part of the Python standard library)
=============================================================================
"""

# ─── Standard library ────────────────────────────────────────────────────────
import re
import os
import csv
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
from pathlib import Path

# ─── Third-party (optional – graceful degradation if missing) ─────────────
try:
    import docx as _docx          # python-docx  →  .docx support
    DOCX_OK = True
except ImportError:
    DOCX_OK = False

try:
    import pdfplumber             # pdfplumber   →  .pdf  support
    PDF_OK = True
except ImportError:
    PDF_OK = False

try:
    import openpyxl               # openpyxl     →  .xlsx support
    XLSX_OK = True
except ImportError:
    XLSX_OK = False


# =============================================================================
# SECTION 1 – SUPPORTED EXTENSIONS
# =============================================================================
# Which file extensions this tool will scan.
# Adding a new type here + a handler in Section 3 is all that is needed.
SUPPORTED_EXTENSIONS = {".txt", ".csv", ".docx", ".pdf", ".xlsx"}


# =============================================================================
# SECTION 2 – PATTERN DEFINITIONS
# Multiple regex variants per data type to maximise recall while minimising
# false negatives.  Patterns within a group are deduplicated per line/cell
# so the same value is never reported twice.
# =============================================================================

# ── Full Name ─────────────────────────────────────────────────────────────────
# Catches:  "John Smith",  "Mary-Jane Watson",  "O'Brien Connor",
#           "Juan Carlos Lopez",  "Anne-Marie De Silva"
FULL_NAME_PATTERNS = [
    # Simple "First Last"
    r"\b[A-Z][a-z]+ [A-Z][a-z]+\b",
    # 2-to-4 capitalised words  (middle names, compound surnames)
    r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b",
    # Hyphenated names  (Mary-Jane Watson, Jean-Paul Gaultier)
    r"\b[A-Z][a-z]+(?:-[A-Z][a-z]+)?\s+[A-Z][a-z]+(?:-[A-Z][a-z]+)?\b",
    # Apostrophe names  (O'Brien, D'Angelo)
    r"\b[A-Z][A-Za-z]+(?:'[A-Z][A-Za-z]+)?\s+[A-Z][A-Za-z]+(?:'[A-Z][A-Za-z]+)?\b",
]

# ── Date of Birth ─────────────────────────────────────────────────────────────
# Catches:  01/15/1985,  1-15-85,  DOB: 01.15.1985,  January 15, 1985
DOB_PATTERNS = [
    # MM/DD/YYYY  (separator: / - .)  strict 19xx/20xx year
    r"\b(?:0?[1-9]|1[0-2])[\/\-\.](?:0?[1-9]|[12]\d|3[01])[\/\-\.](?:19|20)\d{2}\b",
    # Same but also allows 2-digit year
    r"\b(?:0?[1-9]|1[0-2])[\/\-\.](?:0?[1-9]|[12]\d|3[01])[\/\-\.](?:\d{2}|(?:19|20)\d{2})\b",
    # Keyword-labelled  (DOB: 01/15/1985,  Date of Birth - 01.15.1985)
    r"\b(?:DOB|D\.O\.B\.|Date of Birth|Birth Date|Birthdate)[:\s\-]*"
    r"(?:0?[1-9]|1[0-2])[\/\-\.](?:0?[1-9]|[12]\d|3[01])[\/\-\.](?:19|20)\d{2}\b",
    # Written month  (January 15, 1985  /  March 3 2001)
    r"\b(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+(?:0?[1-9]|[12]\d|3[01]),?\s+(?:19|20)\d{2}\b",
]

# ── Social Security Number ────────────────────────────────────────────────────
# Catches:  123-45-6789,  123 45 6789,  SSN: 123-45-6789,  ***-**-6789
# Excludes: invalid SSA blocks (000, 666, 900-999 area codes; 00 group; 0000 serial)
SSN_PATTERNS = [
    # Basic 9-digit  (dashes/spaces optional)
    r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",
    # Validated: excludes illegal SSA prefixes
    r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b",
    # Keyword-labelled  (SSN: 123-45-6789)
    r"\b(?:SSN|Social Security Number|Social Security No\.?|Soc\.?\s*Sec\.?\s*No\.?)"
    r"[:\s#\-]*(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b",
    # Masked/redacted  (***-**-1234  or  XXX-XX-6789)
    r"\b(?:XXX|xxx|\*{3})[- ]?(?:XX|xx|\*{2})[- ]?\d{4}\b",
]

# ── Email Address ─────────────────────────────────────────────────────────────
# Catches:  john@example.com,  Email: j.doe@corp.co.uk
EMAIL_PATTERNS = [
    # Standard RFC-ish
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    # Keyword-labelled  (Email: ...,  Work Email: ...)
    r"\b(?:Email|E\-mail|Email Address|Contact Email|Work Email|Personal Email)"
    r"[:\s\-]*[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    # Strict local-part max 64 chars (RFC 5321)
    r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+\-]{0,62}[A-Za-z0-9])?@"
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+\b",
    # Multi-level TLD  (.co.uk, .com.au)
    r"\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}\b",
]

# ── Phone Number ──────────────────────────────────────────────────────────────
# Catches:  (212) 555-0199,  212.555.0199,  +1-212-555-0199,  Phone: 2125550199
PHONE_PATTERNS = [
    # NXX-NXX-XXXX  (dash, dot, or space separator)
    r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b",
    # Optional parentheses around area code
    r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    # Optional +1 country code
    r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    # Keyword-labelled  (Phone: ...,  Mobile: ...,  Tel: ...)
    r"\b(?:Phone|Phone Number|Mobile|Cell(?:\s+Phone)?|Home Phone|Work Phone|"
    r"Telephone|Tel\.?|Fax)[:\s#\-]*(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
]


# =============================================================================
# SECTION 3 – PATTERN REGISTRY
# One entry per data type.  To add a new type:
#   1. Define its pattern list above.
#   2. Add an entry here.  Done.
# =============================================================================
PATTERN_GROUPS = [
    {
        "label":    "Full Name",
        "severity": "High",
        # No IGNORECASE – names must be capitalised to reduce false positives
        "patterns": [re.compile(p) for p in FULL_NAME_PATTERNS],
    },
    {
        "label":    "Date of Birth",
        "severity": "High",
        "patterns": [re.compile(p, re.IGNORECASE) for p in DOB_PATTERNS],
    },
    {
        "label":    "Social Security Number",
        "severity": "Critical",
        "patterns": [re.compile(p, re.IGNORECASE) for p in SSN_PATTERNS],
    },
    {
        "label":    "Email Address",
        "severity": "High",
        "patterns": [re.compile(p, re.IGNORECASE) for p in EMAIL_PATTERNS],
    },
    {
        "label":    "Phone Number",
        "severity": "High",
        "patterns": [re.compile(p, re.IGNORECASE) for p in PHONE_PATTERNS],
    },
]


# =============================================================================
# SECTION 4 – TEXT EXTRACTION LAYER
# One function per file type.  Every function returns a list of
# (location_label, text_string) tuples so the scanner always gets plain text.
#
#   location_label – human-readable position hint, e.g. "Line 12" or "Sheet: Sales | Row 4"
#   text_string    – the raw text of that unit (line / cell / paragraph)
#
# Edge cases handled per format are documented inside each function.
# =============================================================================

def _read_encoding(path: Path) -> str:
    """
    Try UTF-8 first (most modern files), fall back to latin-1.
    latin-1 decodes every byte 0x00-0xFF without error, covering
    most legacy Windows-created files.
    """
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def extract_txt(path: Path) -> list[tuple[str, str]]:
    """
    Plain text files.
    Edge cases:
      • Mixed line endings (\\r\\n, \\n, \\r) – splitlines() handles all.
      • BOM (byte-order mark) at file start – stripped automatically by
        Python when encoding='utf-8-sig'; we handle it via try/except chain.
      • Empty files – returns an empty list (no crash).
    """
    try:
        text = path.read_text(encoding="utf-8-sig")   # utf-8-sig strips BOM
    except UnicodeDecodeError:
        text = path.read_text(encoding="latin-1")

    return [(f"Line {i+1}", line) for i, line in enumerate(text.splitlines())]


def extract_csv(path: Path) -> list[tuple[str, str]]:
    """
    CSV files.  Each cell is scanned individually so PII that spans no
    delimiter boundary is still caught.
    Edge cases:
      • Quoted fields with embedded commas / newlines – csv.reader handles.
      • Different delimiters (, ; \\t) – csv.Sniffer auto-detects.
      • Completely empty cells – skipped silently.
      • Header row – treated like data (could contain PII column names in values).
      • Encoding fallback same as .txt.
    """
    units = []
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raw = path.read_text(encoding="latin-1")

    try:
        # Sniffer detects delimiter on first 2 KB
        dialect = csv.Sniffer().sniff(raw[:2048], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel   # safe default

    import io
    reader = csv.reader(io.StringIO(raw), dialect)
    for row_idx, row in enumerate(reader, start=1):
        for col_idx, cell in enumerate(row):
            cell = cell.strip()
            if cell:
                # Label: "Row 1 | Col A"  (Excel-style column letter)
                col_letter = _col_letter(col_idx)
                units.append((f"Row {row_idx} | Col {col_letter}", cell))
    return units


def extract_docx(path: Path) -> list[tuple[str, str]]:
    """
    Word documents (.docx).
    Scans:
      • Body paragraphs (normal text)
      • Tables (each cell individually)
      • Headers and footers (often contain names/dates)
    Edge cases:
      • Password-protected files – caught, skipped with error note.
      • Corrupt/truncated zip – caught, skipped.
      • Empty paragraphs – skipped.
    """
    if not DOCX_OK:
        return [("ERROR", "python-docx not installed – cannot read .docx files")]
    units = []
    try:
        doc = _docx.Document(str(path))

        # Body paragraphs
        for i, para in enumerate(doc.paragraphs, start=1):
            text = para.text.strip()
            if text:
                units.append((f"Paragraph {i}", text))

        # Tables → iterate every cell
        for t_idx, table in enumerate(doc.tables, start=1):
            for r_idx, row in enumerate(table.rows, start=1):
                for c_idx, cell in enumerate(row.cells, start=1):
                    text = cell.text.strip()
                    if text:
                        units.append((f"Table {t_idx} | Row {r_idx} | Col {c_idx}", text))

        # Headers and footers
        for sec_idx, section in enumerate(doc.sections, start=1):
            for part_name, part in [
                ("Header", section.header),
                ("Footer", section.footer),
            ]:
                if part:
                    for para in part.paragraphs:
                        text = para.text.strip()
                        if text:
                            units.append((f"Section {sec_idx} {part_name}", text))

    except Exception as e:
        units.append(("ERROR", f"Could not read .docx: {e}"))
    return units


def extract_pdf(path: Path) -> list[tuple[str, str]]:
    """
    PDF files via pdfplumber.
    Scans text line-by-line from every page.
    Edge cases:
      • Scanned / image-only PDFs yield no text – noted in results.
      • Encrypted PDFs – caught, skipped.
      • Garbled/ligature text from bad PDF fonts – best-effort; no crash.
      • Multi-column layouts – pdfplumber preserves reading order reasonably.
    """
    if not PDF_OK:
        return [("ERROR", "pdfplumber not installed – cannot read .pdf files")]
    units = []
    try:
        with pdfplumber.open(str(path)) as pdf:
            if not pdf.pages:
                return [("INFO", "PDF has no pages")]
            for pg_idx, page in enumerate(pdf.pages, start=1):
                text = page.extract_text()
                if not text:
                    # Image-only page – flag it but don't crash
                    units.append((f"Page {pg_idx}", "[no extractable text – possibly scanned image]"))
                    continue
                for ln_idx, line in enumerate(text.splitlines(), start=1):
                    line = line.strip()
                    if line:
                        units.append((f"Page {pg_idx} | Line {ln_idx}", line))
    except Exception as e:
        units.append(("ERROR", f"Could not read .pdf: {e}"))
    return units


def extract_xlsx(path: Path) -> list[tuple[str, str]]:
    """
    Excel workbooks (.xlsx).
    Scans every cell in every worksheet.
    Edge cases:
      • Multiple sheets – all scanned, sheet name included in label.
      • Merged cells – openpyxl returns the value in the top-left cell only;
        other merge members read as None and are skipped.
      • Formula cells – read_only=False so openpyxl computes cached values.
      • Date-formatted cells – converted to string automatically.
      • Empty sheets – skipped silently.
      • Password-protected workbooks – caught, skipped.
    """
    if not XLSX_OK:
        return [("ERROR", "openpyxl not installed – cannot read .xlsx files")]
    units = []
    try:
        wb = openpyxl.load_workbook(str(path), data_only=True)  # data_only=True reads cached formula results
        for sheet in wb.worksheets:
            for row in sheet.iter_rows():
                for cell in row:
                    if cell.value is None:
                        continue
                    text = str(cell.value).strip()
                    if not text:
                        continue
                    col_letter = cell.column_letter
                    label = f"Sheet: {sheet.title} | Cell {col_letter}{cell.row}"
                    units.append((label, text))
    except Exception as e:
        units.append(("ERROR", f"Could not read .xlsx: {e}"))
    return units


# Dispatch table: extension → extractor function
EXTRACTORS = {
    ".txt":  extract_txt,
    ".csv":  extract_csv,
    ".docx": extract_docx,
    ".pdf":  extract_pdf,
    ".xlsx": extract_xlsx,
}


def _col_letter(zero_based_index: int) -> str:
    """Convert a 0-based column index to an Excel-style letter (0→A, 25→Z, 26→AA)."""
    result = ""
    n = zero_based_index
    while True:
        result = chr(65 + n % 26) + result
        n = n // 26 - 1
        if n < 0:
            break
    return result


# =============================================================================
# SECTION 5 – CORE SCANNING LOGIC
# =============================================================================

def scan_units(units: list[tuple[str, str]]) -> list[dict]:
    """
    Given a list of (location_label, text) tuples, run every pattern group
    over every text unit and return deduplicated match records.

    Deduplication rule:
        The same matched value for the same data type at the same location
        is only reported once, even if multiple regex variants fire on it.

    Returns a list of dicts with keys:
        data_type   – "Email Address", "SSN", …
        severity    – "Critical" | "High"
        match       – the exact matched string
        location    – human-readable position ("Page 3 | Line 12", "Row 4 | Col B", …)
        context     – surrounding text (truncated to 120 chars for readability)
    """
    results = []

    for location, text in units:
        # Skip error/info placeholder entries entirely
        if location in ("ERROR", "INFO"):
            continue

        for group in PATTERN_GROUPS:
            seen = set()   # per-group dedup within this text unit

            for pattern in group["patterns"]:
                for m in pattern.finditer(text):
                    value = m.group().strip()

                    # Skip blank or already-seen matches
                    if not value or value in seen:
                        continue
                    seen.add(value)

                    # Build a short context snippet centred on the match
                    start  = max(0, m.start() - 30)
                    end    = min(len(text), m.end() + 30)
                    snippet = text[start:end].strip()
                    if len(snippet) > 120:
                        snippet = snippet[:120] + "…"

                    results.append({
                        "data_type": group["label"],
                        "severity":  group["severity"],
                        "match":     value,
                        "location":  location,
                        "context":   snippet,
                    })

    return results


def scan_file(filepath: str) -> list[dict]:
    """
    Determine the file type, extract text units, and scan them.
    Attaches file metadata to every result record.

    Returns [] for unsupported or unreadable files (no crash).
    """
    path = Path(filepath)
    ext  = path.suffix.lower()

    # Unsupported extension – skip silently
    if ext not in EXTRACTORS:
        return []

    # Empty file – skip
    if path.stat().st_size == 0:
        return []

    try:
        units = EXTRACTORS[ext](path)
    except Exception as e:
        # Completely unreadable file – return a single error record
        return [{
            "data_type": "READ ERROR",
            "severity":  "—",
            "match":     str(e),
            "location":  "—",
            "context":   "—",
            "file_name": path.name,
            "file_path": str(path),
            "file_ext":  ext.upper().lstrip("."),
        }]

    matches = scan_units(units)

    # Stamp every result with file metadata
    for m in matches:
        m["file_name"] = path.name
        m["file_path"] = str(path)
        m["file_ext"]  = ext.upper().lstrip(".")

    return matches


def scan_folder(folder_path: str) -> list[dict]:
    """
    Recursively walk folder_path and scan every supported file.
    Silently skips:
      • Permission-denied directories
      • Files whose extension is not in SUPPORTED_EXTENSIONS
      • Zero-byte files
    """
    all_results = []
    for root, dirs, files in os.walk(folder_path):
        # Skip hidden directories (e.g. .git, .svn) to avoid noise
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in files:
            ext = Path(filename).suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
            full_path = os.path.join(root, filename)
            try:
                all_results.extend(scan_file(full_path))
            except PermissionError:
                pass   # silently skip files we cannot read
    return all_results


# =============================================================================
# SECTION 6 – REPORT GENERATION (CSV)
# =============================================================================

def save_csv_report(results: list[dict], output_path: str) -> str:
    """
    Write all results to a clean, well-organised CSV file.

    Columns (in order):
        #  | Severity | Data Type | Matched Value | File Name | File Type
        File Path | Location | Context
    """
    fieldnames = [
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
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        # utf-8-sig writes a BOM so Excel opens it correctly without encoding issues
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for idx, r in enumerate(results, start=1):
            writer.writerow({
                "#":             idx,
                "Severity":      r.get("severity",  ""),
                "Data Type":     r.get("data_type", ""),
                "Matched Value": r.get("match",     ""),
                "File Name":     r.get("file_name", ""),
                "File Type":     r.get("file_ext",  ""),
                "File Path":     r.get("file_path", ""),
                "Location":      r.get("location",  ""),
                "Context":       r.get("context",   ""),
            })
    return os.path.abspath(output_path)


# =============================================================================
# SECTION 7 – GUI
# =============================================================================

# Severity colour palette
_SEV_ROW  = {"Critical": "#fff1f2", "High": "#fffbeb"}
_SEV_BADGE= {"Critical": "#dc2626", "High": "#d97706"}


class PIIScannerApp:
    """
    Main GUI application.

    Layout:
      ┌─ Header bar ───────────────────────────────────────────────────┐
      │ PII Scanner                                   v1.0             │
      ├─ Control bar ──────────────────────────────────────────────────┤
      │ [Select File] [Select Folder]  <path>  [Run Scan] [Save]       │
      ├─ Summary cards ────────────────────────────────────────────────┤
      │  Total  │  Critical  │  High  │  Files Scanned                 │
      ├─ Filter bar ───────────────────────────────────────────────────┤
      │  Severity ▾   Type ▾   Extension ▾   [Clear Filters]           │
      ├─ Results table (sortable, scrollable) ─────────────────────────┤
      │  #  Sev  Type  Match  File  Ext  Path  Location  Context       │
      └─ Status bar ───────────────────────────────────────────────────┘
    """

    # ── Columns shown in the results table ───────────────────────────────────
    COLUMNS = (
        "#", "Severity", "Data Type", "Matched Value",
        "File Name", "Ext", "File Path", "Location", "Context",
    )
    COL_WIDTHS = {
        "#":             40,
        "Severity":      80,
        "Data Type":     150,
        "Matched Value": 185,
        "File Name":     160,
        "Ext":           50,
        "File Path":     280,
        "Location":      170,
        "Context":       300,
    }
    COL_ANCHOR = {"#": "center", "Severity": "center", "Ext": "center"}

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PII Scanner  |  v1.0")
        self.root.geometry("1200x700")
        self.root.minsize(900, 560)
        self.root.configure(bg="#f1f5f9")

        self._all_results: list[dict] = []
        self._tooltip_win = None

        self._build_styles()
        self._build_ui()

    # ── Style configuration ───────────────────────────────────────────────────

    def _build_styles(self):
        s = ttk.Style()
        s.theme_use("clam")

        s.configure("TFrame",              background="#f1f5f9")
        s.configure("Header.TFrame",       background="#0f172a")
        s.configure("Header.TLabel",       background="#0f172a", foreground="#f8fafc",
                    font=("Segoe UI", 13, "bold"))
        s.configure("HeaderSub.TLabel",    background="#0f172a", foreground="#64748b",
                    font=("Segoe UI", 9))
        s.configure("Card.TFrame",         background="#ffffff")
        s.configure("CardN.TLabel",        background="#ffffff",
                    font=("Segoe UI", 20, "bold"), foreground="#0f172a")
        s.configure("CardL.TLabel",        background="#ffffff",
                    font=("Segoe UI", 8),   foreground="#64748b")
        s.configure("Accent.TButton",      font=("Segoe UI", 9, "bold"),
                    background="#2563eb", foreground="#ffffff", padding=(10, 6))
        s.map("Accent.TButton",
              background=[("active", "#1d4ed8"), ("disabled", "#cbd5e1")],
              foreground=[("disabled", "#94a3b8")])
        s.configure("TButton",             font=("Segoe UI", 9), padding=(8, 5))
        s.configure("Treeview",
                    font=("Segoe UI", 9), rowheight=26,
                    background="#ffffff", fieldbackground="#ffffff", borderwidth=0)
        s.configure("Treeview.Heading",
                    font=("Segoe UI", 9, "bold"), background="#e2e8f0",
                    foreground="#334155", relief="flat", padding=(6, 5))
        s.map("Treeview",
              background=[("selected", "#dbeafe")],
              foreground=[("selected", "#1e40af")])
        s.configure("TCombobox",           font=("Segoe UI", 9))
        s.configure("Status.TLabel",       background="#0f172a", foreground="#94a3b8",
                    font=("Segoe UI", 8), padding=(10, 4))

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        hdr = ttk.Frame(self.root, style="Header.TFrame")
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text="  🔍  PII Scanner",
                  style="Header.TLabel").pack(side=tk.LEFT, pady=12)
        ttk.Label(hdr,
                  text=f"  v1.0  –  .txt  .csv  .docx  .pdf  .xlsx  |  Research Edition",
                  style="HeaderSub.TLabel").pack(side=tk.LEFT, pady=12)

        # ── Control bar ──
        ctrl = tk.Frame(self.root, bg="#f1f5f9", pady=10, padx=14)
        ctrl.pack(fill=tk.X)

        ttk.Button(ctrl, text="📄  Select File",
                   command=self._pick_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(ctrl, text="📁  Select Folder",
                   command=self._pick_folder).pack(side=tk.LEFT, padx=(0, 12))

        # Path display
        path_frame = tk.Frame(ctrl, bg="#e2e8f0", padx=8, pady=5)
        path_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.path_var = tk.StringVar(value="No target selected — choose a file or folder above")
        self._path_lbl = tk.Label(path_frame, textvariable=self.path_var,
                                  bg="#e2e8f0", fg="#94a3b8",
                                  font=("Segoe UI", 9, "italic"), anchor="w")
        self._path_lbl.pack(fill=tk.X)

        tk.Frame(ctrl, width=10, bg="#f1f5f9").pack(side=tk.LEFT)
        self.run_btn = ttk.Button(ctrl, text="▶  Run Scan",
                                  style="Accent.TButton", command=self._run_scan)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.save_btn = ttk.Button(ctrl, text="💾  Save CSV",
                                   state=tk.DISABLED, command=self._save_report)
        self.save_btn.pack(side=tk.LEFT)

        # ── Summary cards ──
        cards = tk.Frame(self.root, bg="#f1f5f9", padx=14, pady=6)
        cards.pack(fill=tk.X)
        self._n_total    = self._make_card(cards, "Total Matches",   "—", "#0f172a")
        self._n_critical = self._make_card(cards, "Critical",        "—", "#dc2626")
        self._n_high     = self._make_card(cards, "High",            "—", "#d97706")
        self._n_files    = self._make_card(cards, "Files Scanned",   "—", "#2563eb")
        self._n_types    = self._make_card(cards, "File Types Found","—", "#0f172a")

        # ── Filter bar ──
        flt = tk.Frame(self.root, bg="#f1f5f9", padx=14, pady=4)
        flt.pack(fill=tk.X)

        self.flt_sev  = self._filter_combo(flt, "Severity:",  ["All","Critical","High"])
        self.flt_type = self._filter_combo(flt, "Data Type:", ["All"] + [g["label"] for g in PATTERN_GROUPS])
        self.flt_ext  = self._filter_combo(flt, "File Type:", ["All",".TXT",".CSV",".DOCX",".PDF",".XLSX"])

        ttk.Button(flt, text="✕ Clear Filters",
                   command=self._clear_filters).pack(side=tk.LEFT, padx=(8, 0))

        self.filter_info = tk.Label(flt, text="", bg="#f1f5f9",
                                    font=("Segoe UI", 8, "italic"), fg="#64748b")
        self.filter_info.pack(side=tk.LEFT, padx=(12, 0))

        # ── Results table ──
        tbl_wrap = tk.Frame(self.root, bg="#f1f5f9", padx=14, pady=(0, 8))
        tbl_wrap.pack(fill=tk.BOTH, expand=True)

        card_frame = tk.Frame(tbl_wrap, bg="#ffffff",
                              highlightbackground="#cbd5e1", highlightthickness=1)
        card_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(card_frame, columns=self.COLUMNS,
                                 show="headings", selectmode="browse")
        for col in self.COLUMNS:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort_col(c))
            self.tree.column(col,
                             width=self.COL_WIDTHS[col],
                             anchor=self.COL_ANCHOR.get(col, "w"),
                             stretch=(col == "Context"))

        # Row colour tags
        self.tree.tag_configure("Critical", background="#fff1f2")
        self.tree.tag_configure("High",     background="#fffbeb")
        self.tree.tag_configure("alt",      background="#f8fafc")   # alternating row

        vsb = ttk.Scrollbar(card_frame, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(card_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        card_frame.rowconfigure(0, weight=1)
        card_frame.columnconfigure(0, weight=1)

        # Hover tooltip for long text columns
        self.tree.bind("<Motion>", self._on_motion)
        self.tree.bind("<Leave>",  self._hide_tip)

        # ── Status bar ──
        sb = ttk.Frame(self.root, style="Header.TFrame")
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar(value="Ready  –  select a file or folder and click Run Scan.")
        ttk.Label(sb, textvariable=self.status_var,
                  style="Status.TLabel").pack(fill=tk.X)

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _make_card(self, parent, label: str, initial: str, colour: str):
        """Return a (number_label) for a small stat card widget."""
        f = tk.Frame(parent, bg="#ffffff",
                     highlightbackground="#e2e8f0", highlightthickness=1,
                     padx=16, pady=8)
        f.pack(side=tk.LEFT, padx=(0, 10))
        n = tk.Label(f, text=initial, bg="#ffffff",
                     font=("Segoe UI", 20, "bold"), fg=colour)
        n.pack()
        tk.Label(f, text=label, bg="#ffffff",
                 font=("Segoe UI", 8), fg="#64748b").pack()
        return n

    def _filter_combo(self, parent, label: str, values: list) -> tk.StringVar:
        tk.Label(parent, text=label, bg="#f1f5f9",
                 font=("Segoe UI", 9), fg="#334155").pack(side=tk.LEFT, padx=(0, 3))
        var = tk.StringVar(value="All")
        cb  = ttk.Combobox(parent, textvariable=var, values=values,
                           state="readonly", width=16)
        cb.pack(side=tk.LEFT, padx=(0, 12))
        cb.bind("<<ComboboxSelected>>", lambda _: self._apply_filters())
        return var

    # ── File / folder selection ───────────────────────────────────────────────

    def _pick_file(self):
        exts = " ".join(f"*{e}" for e in sorted(SUPPORTED_EXTENSIONS))
        path = filedialog.askopenfilename(
            title="Select a file to scan",
            filetypes=[("Supported files", exts), ("All files", "*.*")],
        )
        if path:
            self.path_var.set(path)
            self._path_lbl.config(fg="#0f172a", font=("Segoe UI", 9))

    def _pick_folder(self):
        path = filedialog.askdirectory(title="Select a folder to scan")
        if path:
            self.path_var.set(path)
            self._path_lbl.config(fg="#0f172a", font=("Segoe UI", 9))

    # ── Scan ─────────────────────────────────────────────────────────────────

    def _run_scan(self):
        path = self.path_var.get()
        if not path or "No target" in path:
            messagebox.showwarning("No Target",
                                   "Please select a file or folder first.")
            return

        # Lock UI during scan
        self.run_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)
        self.status_var.set("Scanning …  please wait.")
        self.root.update_idletasks()

        # Clear previous
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._all_results = []

        # Run
        try:
            if os.path.isfile(path):
                results = scan_file(path)
                files_scanned = 1
            elif os.path.isdir(path):
                results = scan_folder(path)
                files_scanned = len({r["file_path"] for r in results}) if results else 0
            else:
                messagebox.showerror("Path Error", f"Not found:\n{path}")
                self.status_var.set("Error – path not found.")
                self.run_btn.config(state=tk.NORMAL)
                return
        except Exception as exc:
            messagebox.showerror("Scan Error", str(exc))
            self.status_var.set("Scan failed – see error dialog.")
            self.run_btn.config(state=tk.NORMAL)
            return

        self._all_results = results

        # Update stat cards
        critical = sum(1 for r in results if r.get("severity") == "Critical")
        high     = sum(1 for r in results if r.get("severity") == "High")
        exts_found = len({r.get("file_ext","") for r in results})
        self._n_total.config(text=str(len(results)))
        self._n_critical.config(text=str(critical))
        self._n_high.config(text=str(high))
        self._n_files.config(text=str(files_scanned))
        self._n_types.config(text=str(exts_found))

        # Reset filters
        self._clear_filters(repopulate=False)
        self._populate_table(results)

        self.run_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.NORMAL if results else tk.DISABLED)

        self.status_var.set(
            f"✔  Scan complete  –  {len(results)} match(es) across "
            f"{files_scanned} file(s)   |   {critical} Critical   {high} High"
        )

    # ── Table population ──────────────────────────────────────────────────────

    def _populate_table(self, results: list[dict]):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for i, r in enumerate(results, start=1):
            sev = r.get("severity", "")
            tag = sev if sev in _SEV_ROW else ("alt" if i % 2 == 0 else "")
            self.tree.insert("", tk.END, tags=(tag,), values=(
                i,
                sev,
                r.get("data_type", ""),
                r.get("match",     ""),
                r.get("file_name", ""),
                r.get("file_ext",  ""),
                r.get("file_path", ""),
                r.get("location",  ""),
                r.get("context",   ""),
            ))

        self.filter_info.config(
            text=f"Showing {len(results)} of {len(self._all_results)} result(s)"
        )

    # ── Filtering ─────────────────────────────────────────────────────────────

    def _apply_filters(self):
        sev  = self.flt_sev.get()
        typ  = self.flt_type.get()
        ext  = self.flt_ext.get()
        filtered = [
            r for r in self._all_results
            if (sev == "All" or r.get("severity") == sev)
            and (typ == "All" or r.get("data_type") == typ)
            and (ext == "All" or r.get("file_ext","").upper() == ext.lstrip("."))
        ]
        self._populate_table(filtered)

    def _clear_filters(self, repopulate: bool = True):
        self.flt_sev.set("All")
        self.flt_type.set("All")
        self.flt_ext.set("All")
        if repopulate:
            self._populate_table(self._all_results)

    # ── Column sort ───────────────────────────────────────────────────────────

    def _sort_col(self, col: str):
        col_idx = self.COLUMNS.index(col)
        data = [(self.tree.item(k)["values"][col_idx], k)
                for k in self.tree.get_children("")]
        rev  = getattr(self, f"_rev_{col}", False)
        # Numeric sort for # column
        if col == "#":
            data.sort(key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0,
                      reverse=rev)
        else:
            data.sort(key=lambda x: str(x[0]).lower(), reverse=rev)
        for idx, (_, k) in enumerate(data):
            self.tree.move(k, "", idx)
        setattr(self, f"_rev_{col}", not rev)

    # ── Save report ───────────────────────────────────────────────────────────

    def _save_report(self):
        if not self._all_results:
            messagebox.showinfo("Nothing to Save", "Run a scan first.")
            return
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        default = f"pii_report_{ts}.csv"
        dest    = filedialog.asksaveasfilename(
            title="Save PII Report",
            initialfile=default,
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not dest:
            return
        saved = save_csv_report(self._all_results, dest)
        messagebox.showinfo("Saved", f"Report written to:\n{saved}")
        self.status_var.set(f"Report saved  →  {saved}")

    # ── Tooltip on hover ──────────────────────────────────────────────────────

    _TIP_COLS = {"File Path", "Context", "Matched Value"}

    def _on_motion(self, event):
        item = self.tree.identify_row(event.y)
        col  = self.tree.identify_column(event.x)
        if not item or not col:
            self._hide_tip(None)
            return
        idx      = int(col.lstrip("#")) - 1
        col_name = self.COLUMNS[idx] if idx < len(self.COLUMNS) else ""
        if col_name not in self._TIP_COLS:
            self._hide_tip(None)
            return
        val = self.tree.item(item, "values")[idx]
        self._show_tip(event.x_root + 16, event.y_root + 16, str(val))

    def _show_tip(self, x, y, text):
        self._hide_tip(None)
        if not text:
            return
        self._tooltip_win = tw = tk.Toplevel(self.root)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=text, bg="#1e293b", fg="#f8fafc",
                 font=("Segoe UI", 8), padx=10, pady=6,
                 wraplength=520, justify="left",
                 relief="flat").pack()

    def _hide_tip(self, _):
        if self._tooltip_win:
            self._tooltip_win.destroy()
            self._tooltip_win = None


# =============================================================================
# SECTION 8 – ENTRY POINT
# =============================================================================

def main():
    root = tk.Tk()
    PIIScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
