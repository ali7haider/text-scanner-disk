"""
pii_scanner.py
=============================================================================
Entry point and GUI for the PII Scanner.

This file is responsible for ONE thing: the user interface.
All pattern loading, file reading, and report generation are handled by
the other three modules in this project.

Project structure
-----------------
  patterns.json    ← add / edit data types and regex here (no coding needed)
  extractors.py    ← file-reading logic (.txt .csv .docx .pdf .xlsx)
  scanner.py       ← loads patterns.json, runs regex, returns matches
  report.py        ← writes CSV reports
  pii_scanner.py   ← this file: GUI only

How to run
----------
  python pii_scanner.py

Requirements
------------
  pip install -r requirements.txt
  Python 3.10 or higher
=============================================================================
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
from pathlib import Path

# ── Local modules ─────────────────────────────────────────────────────────────
from scanner import load_patterns, scan_file, scan_folder
from report  import save_csv, generate_filename, summary_stats
from extractors import SUPPORTED_EXTENSIONS


# =============================================================================
# STARTUP — load and compile patterns once when the application starts.
# If patterns.json is missing or broken, show a clear error and exit.
# =============================================================================

# patterns.json must live in the same directory as this script
_PATTERNS_FILE = Path(__file__).parent / "patterns.json"

try:
    PATTERN_GROUPS = load_patterns(_PATTERNS_FILE)
except (FileNotFoundError, ValueError) as _err:
    # Show a messagebox before the main window is created
    _root = tk.Tk()
    _root.withdraw()
    messagebox.showerror(
        "Configuration Error",
        f"Could not load patterns.json:\n\n{_err}\n\n"
        f"Make sure patterns.json is in the same folder as pii_scanner.py.",
    )
    _root.destroy()
    raise SystemExit(1)


# =============================================================================
# COLOUR CONSTANTS
# =============================================================================
_SEV_ROW = {"Critical": "#fff1f2", "High": "#fffbeb"}   # table row backgrounds


# =============================================================================
# GUI APPLICATION
# =============================================================================

class PIIScannerApp:
    """
    Main application window.

    Layout (top to bottom):
      ┌─ Header bar ────────────────────────────────────────────────┐
      │  PII Scanner  v1.0                                          │
      ├─ Control bar ───────────────────────────────────────────────┤
      │  [Select File]  [Select Folder]  <path>  [Run]  [Save CSV]  │
      ├─ Stat cards ────────────────────────────────────────────────┤
      │  Total │ Critical │ High │ Files Scanned │ File Types Found │
      ├─ Filter bar ────────────────────────────────────────────────┤
      │  Severity ▾  Data Type ▾  File Type ▾  [Clear Filters]      │
      ├─ Results table (sortable columns, both scrollbars) ─────────┤
      │  #  Severity  Type  Match  File  Ext  Path  Location  Ctx   │
      └─ Status bar ────────────────────────────────────────────────┘
    """

    # ── Table column definitions ──────────────────────────────────────────────
    COLUMNS = (
        "#", "Severity", "Data Type", "Matched Value",
        "File Name", "Ext", "File Path", "Location", "Context",
    )
    COL_WIDTHS = {
        "#":             42,
        "Severity":      82,
        "Data Type":     155,
        "Matched Value": 185,
        "File Name":     165,
        "Ext":           52,
        "File Path":     285,
        "Location":      175,
        "Context":       310,
    }
    COL_ANCHOR = {"#": "center", "Severity": "center", "Ext": "center"}

    # Columns that show a hover tooltip (they contain long text)
    _TIP_COLS = {"File Path", "Context", "Matched Value", "Location"}

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PII Scanner  |  v1.0")
        self.root.geometry("1200x700")
        self.root.minsize(900, 560)
        self.root.configure(bg="#f1f5f9")

        # Internal state
        self._all_results: list[dict] = []   # unfiltered results from last scan
        self._tooltip_win = None             # active tooltip window or None

        self._build_styles()
        self._build_ui()

    # =========================================================================
    # STYLE CONFIGURATION
    # =========================================================================

    def _build_styles(self):
        """Configure all ttk widget styles used by the application."""
        s = ttk.Style()
        s.theme_use("clam")

        # Header bar (dark navy background)
        s.configure("Header.TFrame",    background="#0f172a")
        s.configure("Header.TLabel",    background="#0f172a", foreground="#f8fafc",
                    font=("Segoe UI", 13, "bold"))
        s.configure("HeaderSub.TLabel", background="#0f172a", foreground="#64748b",
                    font=("Segoe UI", 9))

        # Generic containers
        s.configure("TFrame", background="#f1f5f9")

        # Buttons
        s.configure("Accent.TButton",
                    font=("Segoe UI", 9, "bold"),
                    background="#2563eb", foreground="#ffffff",
                    padding=(10, 6))
        s.map("Accent.TButton",
              background=[("active", "#1d4ed8"), ("disabled", "#cbd5e1")],
              foreground=[("disabled", "#94a3b8")])
        s.configure("TButton", font=("Segoe UI", 9), padding=(8, 5))

        # Results table
        s.configure("Treeview",
                    font=("Segoe UI", 9), rowheight=26,
                    background="#ffffff", fieldbackground="#ffffff",
                    borderwidth=0)
        s.configure("Treeview.Heading",
                    font=("Segoe UI", 9, "bold"),
                    background="#e2e8f0", foreground="#334155",
                    relief="flat", padding=(6, 5))
        s.map("Treeview",
              background=[("selected", "#dbeafe")],
              foreground=[("selected", "#1e40af")])

        # Filter dropdowns
        s.configure("TCombobox", font=("Segoe UI", 9))

        # Status bar
        s.configure("Status.TLabel",
                    background="#0f172a", foreground="#94a3b8",
                    font=("Segoe UI", 8), padding=(10, 4))

    # =========================================================================
    # UI CONSTRUCTION
    # =========================================================================

    def _build_ui(self):
        """Assemble all widgets in top-to-bottom order."""

        # ── Header ──────────────────────────────────────────────────────────
        hdr = ttk.Frame(self.root, style="Header.TFrame")
        hdr.pack(fill=tk.X)

        ttk.Label(hdr, text="  🔍  PII Scanner",
                  style="Header.TLabel").pack(side=tk.LEFT, pady=12)

        # Show which data types are loaded, dynamically from patterns.json
        loaded_labels = "  ·  ".join(g["label"] for g in PATTERN_GROUPS)
        ttk.Label(hdr,
                  text=f"  v1.0  –  Detecting: {loaded_labels}",
                  style="HeaderSub.TLabel").pack(side=tk.LEFT, pady=12)

        # ── Control bar ─────────────────────────────────────────────────────
        ctrl = tk.Frame(self.root, bg="#f1f5f9", pady=10, padx=14)
        ctrl.pack(fill=tk.X)

        ttk.Button(ctrl, text="📄  Select File",
                   command=self._pick_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(ctrl, text="📁  Select Folder",
                   command=self._pick_folder).pack(side=tk.LEFT, padx=(0, 12))

        # Path display box
        path_box = tk.Frame(ctrl, bg="#e2e8f0", padx=8, pady=5)
        path_box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.path_var = tk.StringVar(
            value="No target selected — choose a file or folder above"
        )
        self._path_lbl = tk.Label(
            path_box, textvariable=self.path_var,
            bg="#e2e8f0", fg="#94a3b8",
            font=("Segoe UI", 9, "italic"), anchor="w",
        )
        self._path_lbl.pack(fill=tk.X)

        # Action buttons
        tk.Frame(ctrl, width=10, bg="#f1f5f9").pack(side=tk.LEFT)
        self.run_btn = ttk.Button(ctrl, text="▶  Run Scan",
                                  style="Accent.TButton",
                                  command=self._run_scan)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.save_btn = ttk.Button(ctrl, text="💾  Save CSV",
                                   state=tk.DISABLED,
                                   command=self._save_report)
        self.save_btn.pack(side=tk.LEFT)

        # ── Stat cards ───────────────────────────────────────────────────────
        cards_frame = tk.Frame(self.root, bg="#f1f5f9", padx=14, pady=6)
        cards_frame.pack(fill=tk.X)

        # Each card is a small white box with a large number and a label below
        self._n_total    = self._make_stat_card(cards_frame, "Total Matches",    "—", "#0f172a")
        self._n_critical = self._make_stat_card(cards_frame, "Critical",         "—", "#dc2626")
        self._n_high     = self._make_stat_card(cards_frame, "High",             "—", "#d97706")
        self._n_files    = self._make_stat_card(cards_frame, "Files Scanned",    "—", "#2563eb")
        self._n_types    = self._make_stat_card(cards_frame, "File Types Found", "—", "#0f172a")

        # ── Filter bar ───────────────────────────────────────────────────────
        flt = tk.Frame(self.root, bg="#f1f5f9", padx=14, pady=4)
        flt.pack(fill=tk.X)

        # Severity filter
        self.flt_sev = self._make_filter_combo(
            flt, "Severity:", ["All", "Critical", "High"]
        )
        # Data type filter — built dynamically from loaded patterns
        type_values = ["All"] + [g["label"] for g in PATTERN_GROUPS]
        self.flt_type = self._make_filter_combo(flt, "Data Type:", type_values)

        # File type filter — built from supported extensions
        ext_values = ["All"] + [e.upper().lstrip(".") for e in sorted(SUPPORTED_EXTENSIONS)]
        self.flt_ext = self._make_filter_combo(flt, "File Type:", ext_values)

        ttk.Button(flt, text="✕  Clear Filters",
                   command=self._clear_filters).pack(side=tk.LEFT, padx=(8, 0))

        self.filter_info = tk.Label(
            flt, text="", bg="#f1f5f9",
            font=("Segoe UI", 8, "italic"), fg="#64748b",
        )
        self.filter_info.pack(side=tk.LEFT, padx=(14, 0))

        # ── Results table ────────────────────────────────────────────────────
        tbl_wrap = tk.Frame(self.root, bg="#f1f5f9", padx=14, pady=(0, 8))
        tbl_wrap.pack(fill=tk.BOTH, expand=True)

        # White card frame with a subtle border
        card = tk.Frame(
            tbl_wrap, bg="#ffffff",
            highlightbackground="#cbd5e1", highlightthickness=1,
        )
        card.pack(fill=tk.BOTH, expand=True)

        # Treeview
        self.tree = ttk.Treeview(
            card, columns=self.COLUMNS,
            show="headings", selectmode="browse",
        )
        for col in self.COLUMNS:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort_col(c))
            self.tree.column(
                col,
                width=self.COL_WIDTHS[col],
                anchor=self.COL_ANCHOR.get(col, "w"),
                stretch=(col == "Context"),   # only the Context column stretches
            )

        # Row background colours by severity
        self.tree.tag_configure("Critical", background="#fff1f2")
        self.tree.tag_configure("High",     background="#fffbeb")
        self.tree.tag_configure("alt",      background="#f8fafc")  # alternating rows

        # Scrollbars
        vsb = ttk.Scrollbar(card, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(card, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        card.rowconfigure(0, weight=1)
        card.columnconfigure(0, weight=1)

        # Hover tooltip for long-text columns
        self.tree.bind("<Motion>", self._on_motion)
        self.tree.bind("<Leave>",  self._hide_tip)

        # ── Status bar ───────────────────────────────────────────────────────
        sb = ttk.Frame(self.root, style="Header.TFrame")
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar(
            value="Ready  –  select a file or folder and click Run Scan."
        )
        ttk.Label(sb, textvariable=self.status_var,
                  style="Status.TLabel").pack(fill=tk.X)

    # =========================================================================
    # WIDGET HELPERS
    # =========================================================================

    def _make_stat_card(
        self, parent, label: str, initial: str, colour: str
    ) -> tk.Label:
        """
        Create a small stat card widget and return the number label
        so the caller can update it later with .config(text=...).
        """
        frame = tk.Frame(
            parent, bg="#ffffff",
            highlightbackground="#e2e8f0", highlightthickness=1,
            padx=16, pady=8,
        )
        frame.pack(side=tk.LEFT, padx=(0, 10))

        # Large number
        num_lbl = tk.Label(
            frame, text=initial, bg="#ffffff",
            font=("Segoe UI", 20, "bold"), fg=colour,
        )
        num_lbl.pack()

        # Small descriptive label below the number
        tk.Label(frame, text=label, bg="#ffffff",
                 font=("Segoe UI", 8), fg="#64748b").pack()

        return num_lbl

    def _make_filter_combo(
        self, parent, label: str, values: list
    ) -> tk.StringVar:
        """
        Create a labelled combobox filter widget.
        Returns the StringVar so the caller can read/reset the selected value.
        """
        tk.Label(parent, text=label, bg="#f1f5f9",
                 font=("Segoe UI", 9), fg="#334155").pack(side=tk.LEFT, padx=(0, 3))
        var = tk.StringVar(value="All")
        cb = ttk.Combobox(parent, textvariable=var, values=values,
                          state="readonly", width=18)
        cb.pack(side=tk.LEFT, padx=(0, 12))
        # Trigger filtering whenever the selection changes
        cb.bind("<<ComboboxSelected>>", lambda _: self._apply_filters())
        return var

    # =========================================================================
    # FILE / FOLDER SELECTION
    # =========================================================================

    def _pick_file(self):
        """Open a file dialog filtered to supported extensions."""
        exts = " ".join(f"*{e}" for e in sorted(SUPPORTED_EXTENSIONS))
        path = filedialog.askopenfilename(
            title="Select a file to scan",
            filetypes=[("Supported files", exts), ("All files", "*.*")],
        )
        if path:
            self.path_var.set(path)
            self._path_lbl.config(fg="#0f172a", font=("Segoe UI", 9))

    def _pick_folder(self):
        """Open a directory dialog."""
        path = filedialog.askdirectory(title="Select a folder to scan")
        if path:
            self.path_var.set(path)
            self._path_lbl.config(fg="#0f172a", font=("Segoe UI", 9))

    # =========================================================================
    # SCAN
    # =========================================================================

    def _run_scan(self):
        """
        Validate the selected path, run the scan, update stats and table.
        The GUI is locked during scanning to prevent double-clicks.
        """
        path = self.path_var.get()
        if not path or "No target selected" in path:
            messagebox.showwarning("No Target",
                                   "Please select a file or folder first.")
            return

        # Lock the UI
        self.run_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)
        self.status_var.set("Scanning …  please wait.")
        self.root.update_idletasks()   # force repaint so the status updates

        # Clear previous results from the table
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._all_results = []

        # ── Run the scan ──────────────────────────────────────────────────
        try:
            if os.path.isfile(path):
                results = scan_file(path, PATTERN_GROUPS)
                files_scanned = 1
            elif os.path.isdir(path):
                results = scan_folder(path, PATTERN_GROUPS)
                files_scanned = len(
                    {r["file_path"] for r in results}
                ) if results else 0
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

        # ── Update stat cards ─────────────────────────────────────────────
        # Use report.summary_stats() so the logic lives in one place
        stats = summary_stats(results)
        stats["files_scanned"] = files_scanned   # override with accurate count

        self._n_total.config(text=str(stats["total"]))
        self._n_critical.config(text=str(stats["critical"]))
        self._n_high.config(text=str(stats["high"]))
        self._n_files.config(text=str(files_scanned))
        self._n_types.config(text=str(len(stats["ext_counts"])))

        # ── Reset filters and populate table ─────────────────────────────
        self._clear_filters(repopulate=False)
        self._populate_table(results)

        # ── Re-enable UI ──────────────────────────────────────────────────
        self.run_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.NORMAL if results else tk.DISABLED)

        self.status_var.set(
            f"✔  Scan complete  –  {stats['total']} match(es) across "
            f"{files_scanned} file(s)   |   "
            f"{stats['critical']} Critical   {stats['high']} High"
        )

    # =========================================================================
    # TABLE POPULATION & FILTERING
    # =========================================================================

    def _populate_table(self, results: list[dict]):
        """
        Clear the treeview and fill it with the given result list.
        Also updates the filter count label.
        """
        for row in self.tree.get_children():
            self.tree.delete(row)

        for i, r in enumerate(results, start=1):
            sev = r.get("severity", "")
            # Critical/High get coloured rows; odd rows get a subtle grey tint
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

    def _apply_filters(self):
        """
        Re-filter _all_results based on the three filter dropdowns and
        repopulate the table.  Called automatically on combobox change.
        """
        sev = self.flt_sev.get()
        typ = self.flt_type.get()
        ext = self.flt_ext.get()

        filtered = [
            r for r in self._all_results
            if (sev == "All" or r.get("severity", "") == sev)
            and (typ == "All" or r.get("data_type", "") == typ)
            and (ext == "All" or r.get("file_ext", "").upper() == ext.lstrip("."))
        ]
        self._populate_table(filtered)

    def _clear_filters(self, repopulate: bool = True):
        """Reset all three filter dropdowns to 'All'."""
        self.flt_sev.set("All")
        self.flt_type.set("All")
        self.flt_ext.set("All")
        if repopulate:
            self._populate_table(self._all_results)

    # =========================================================================
    # COLUMN SORT
    # =========================================================================

    def _sort_col(self, col: str):
        """
        Toggle-sort the treeview rows by the clicked column header.
        Numeric sort is used for the '#' column; string sort for all others.
        """
        col_idx = self.COLUMNS.index(col)
        data = [
            (self.tree.item(k)["values"][col_idx], k)
            for k in self.tree.get_children("")
        ]
        reverse = getattr(self, f"_rev_{col}", False)

        if col == "#":
            data.sort(
                key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0,
                reverse=reverse,
            )
        else:
            data.sort(key=lambda x: str(x[0]).lower(), reverse=reverse)

        for idx, (_, k) in enumerate(data):
            self.tree.move(k, "", idx)

        # Flip sort direction for next click
        setattr(self, f"_rev_{col}", not reverse)

    # =========================================================================
    # SAVE REPORT
    # =========================================================================

    def _save_report(self):
        """
        Open a save-file dialog and write the CSV report via report.save_csv().
        Shows a confirmation dialog with the saved path on success.
        """
        if not self._all_results:
            messagebox.showinfo("Nothing to Save", "Run a scan first.")
            return

        default_name = generate_filename()
        dest = filedialog.asksaveasfilename(
            title="Save PII Report",
            initialfile=default_name,
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not dest:
            return   # user cancelled the dialog

        saved_path = save_csv(self._all_results, dest)
        messagebox.showinfo("Report Saved", f"Report written to:\n{saved_path}")
        self.status_var.set(f"Report saved  →  {saved_path}")

    # =========================================================================
    # HOVER TOOLTIP
    # =========================================================================

    def _on_motion(self, event):
        """Show a tooltip when hovering over a long-text column cell."""
        item = self.tree.identify_row(event.y)
        col  = self.tree.identify_column(event.x)
        if not item or not col:
            self._hide_tip(None)
            return

        col_idx  = int(col.lstrip("#")) - 1
        col_name = self.COLUMNS[col_idx] if col_idx < len(self.COLUMNS) else ""

        if col_name not in self._TIP_COLS:
            self._hide_tip(None)
            return

        val = self.tree.item(item, "values")[col_idx]
        self._show_tip(event.x_root + 16, event.y_root + 16, str(val))

    def _show_tip(self, x: int, y: int, text: str):
        """Create a small popup window near the cursor."""
        self._hide_tip(None)
        if not text:
            return
        self._tooltip_win = tw = tk.Toplevel(self.root)
        tw.wm_overrideredirect(True)   # no title bar or window decoration
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(
            tw, text=text,
            bg="#1e293b", fg="#f8fafc",
            font=("Segoe UI", 8),
            padx=10, pady=6,
            wraplength=520, justify="left",
            relief="flat",
        ).pack()

    def _hide_tip(self, _event):
        """Destroy the tooltip window if it exists."""
        if self._tooltip_win:
            self._tooltip_win.destroy()
            self._tooltip_win = None


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    root = tk.Tk()
    PIIScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
