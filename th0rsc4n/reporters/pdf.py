"""
PDF Reporter — fpdf2 (clean & precise)
Cover + Summary + Findings + Disclaimer.
Auto-sanitize unicode → ASCII.
"""
from datetime import datetime
from pathlib import Path


# ==========================================
# UNICODE → ASCII SANITIZER
# ==========================================
def _sanitize(text):
    """Convert unicode chars ke ASCII equivalents (fpdf2 Helvetica safe)."""
    if not text:
        return ""
    replacements = {
        "—": "-",   # em dash
        "–": "-",   # en dash
        "•": "*",   # bullet
        "·": "*",   # middle dot
        "“": '"',   # smart quotes
        "”": '"',
        "‘": "'",
        "’": "'",
        "…": "...", # ellipsis
        "™": "(TM)",
        "©": "(C)",
        "®": "(R)",
        "→": "->",
        "←": "<-",
        "↔": "<->",
        "≥": ">=",
        "≤": "<=",
        "≠": "!=",
        "×": "x",
        "÷": "/",
        "√": "sqrt",
        "∞": "inf",
        "≈": "~",
        "α": "alpha",
        "β": "beta",
        "π": "pi",
        "°": " deg",
        "⚠": "!",
        "✓": "v",
        "✗": "x",
        "⚡": "!",
        "🔴": "[C]",
        "🟠": "[H]",
        "🟡": "[M]",
        "🔵": "[L]",
        "⚪": "[i]",
        "🟢": "[S]",
    }
    out = str(text)
    for src, dst in replacements.items():
        out = out.replace(src, dst)
    # Buang karakter non-ASCII yang tersisa
    out = out.encode("ascii", "ignore").decode("ascii")
    return out.strip()


# ==========================================
# COLOR PALETTE
# ==========================================
C_RED       = (200, 16, 46)
C_ORANGE    = (232, 93, 4)
C_YELLOW    = (255, 186, 8)
C_BLUE      = (0, 150, 199)
C_GRAY      = (108, 117, 125)
C_GREEN     = (6, 167, 125)
C_DARK      = (26, 26, 26)
C_TEXT      = (60, 60, 60)
C_LIGHT_BG  = (248, 249, 250)
C_WHITE     = (255, 255, 255)

SEV_COLORS = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_BLUE,
    "INFO":     C_GRAY,
    "SAFE":     C_GREEN,
}

SEV_TEXT_COLOR = {
    "CRITICAL": C_WHITE,
    "HIGH":     C_WHITE,
    "MEDIUM":   (0, 0, 0),
    "LOW":      C_WHITE,
    "INFO":     C_WHITE,
    "SAFE":     C_WHITE,
}


# ==========================================
# PDF BUILDER
# ==========================================
class ReportPDF:
    def __init__(self, target, report_id, date_str, stats, findings, grouped):
        from fpdf import FPDF

        self.pdf = FPDF(orientation="P", unit="mm", format="A4")
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.pdf.set_margins(left=15, top=15, right=15)

        self.target = _sanitize(target)
        self.report_id = report_id
        self.date_str = date_str
        self.stats = stats
        self.findings = findings
        self.grouped = grouped

    # ---------- HELPERS ----------
    def _page_header(self, title):
        self.pdf.set_font("Helvetica", "B", 9)
        self.pdf.set_text_color(*C_RED)
        self.pdf.cell(90, 5, "TH0RSC4N", align="L")

        self.pdf.set_text_color(*C_GRAY)
        self.pdf.set_font("Helvetica", "", 8)
        self.pdf.cell(0, 5, _sanitize(title), align="R",
                      new_x="LMARGIN", new_y="NEXT")

        self.pdf.set_draw_color(*C_RED)
        self.pdf.set_line_width(0.4)
        y = self.pdf.get_y()
        self.pdf.line(15, y, 195, y)
        self.pdf.ln(4)

    def _check_page_space(self, needed_mm):
        if self.pdf.get_y() + needed_mm > 275:
            self.pdf.add_page()

    def _write_wrapped(self, text, size=9, style="", color=C_TEXT, h=4.5):
        self.pdf.set_font("Helvetica", style, size)
        self.pdf.set_text_color(*color)
        self.pdf.multi_cell(0, h, _sanitize(text))

    # ---------- COVER ----------
    def _build_cover(self):
        self.pdf.add_page()
        self.pdf.ln(40)

        # Logo
        self.pdf.set_font("Courier", "B", 48)
        self.pdf.set_text_color(*C_RED)
        self.pdf.cell(0, 20, "TH0RSC4N", align="C",
                      new_x="LMARGIN", new_y="NEXT")

        # Subtitle
        self.pdf.set_font("Helvetica", "", 11)
        self.pdf.set_text_color(*C_GRAY)
        self.pdf.ln(2)
        self.pdf.cell(0, 6, "B R U T A L   S E C U R I T Y   S C A N N E R",
                      align="C", new_x="LMARGIN", new_y="NEXT")

        # Divider
        self.pdf.ln(15)
        self.pdf.set_draw_color(*C_RED)
        self.pdf.set_line_width(0.5)
        self.pdf.line(60, self.pdf.get_y(), 150, self.pdf.get_y())
        self.pdf.ln(10)

        # Title
        self.pdf.set_font("Helvetica", "B", 22)
        self.pdf.set_text_color(*C_DARK)
        self.pdf.cell(0, 12, "VULNERABILITY", align="C",
                      new_x="LMARGIN", new_y="NEXT")
        self.pdf.cell(0, 12, "ASSESSMENT REPORT", align="C",
                      new_x="LMARGIN", new_y="NEXT")

        # Divider
        self.pdf.ln(10)
        self.pdf.line(60, self.pdf.get_y(), 150, self.pdf.get_y())
        self.pdf.ln(15)

        # Info table
        info = [
            ("Target:", self.target),
            ("Scan Date:", self.date_str),
            ("Tool Version:", "TH0RSC4N v1.0.0"),
            ("Report ID:", self.report_id),
            ("Total Findings:", str(len(self.findings))),
        ]
        for label, value in info:
            self.pdf.set_text_color(*C_GRAY)
            self.pdf.set_font("Helvetica", "B", 9)
            self.pdf.cell(45, 7, label, align="L")

            self.pdf.set_text_color(*C_DARK)
            self.pdf.set_font("Helvetica", "", 9)
            disp = value if len(value) < 60 else value[:57] + "..."
            self.pdf.cell(0, 7, _sanitize(disp), align="L",
                          new_x="LMARGIN", new_y="NEXT")

        # Cover footer
        self.pdf.set_y(260)
        self.pdf.set_font("Helvetica", "", 8)
        self.pdf.set_text_color(*C_GRAY)
        self.pdf.cell(0, 4, "Generated by TH0RSC4N - Cyber Intelligence",
                      align="C", new_x="LMARGIN", new_y="NEXT")
        self.pdf.cell(0, 4, "by Thorranov", align="C")

    # ---------- STATS BLOCK ----------
    def _build_stats_block(self):
        self.pdf.ln(2)
        stats_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]

        box_w = 165 / 6
        box_h = 22
        x_start = 15
        y_start = self.pdf.get_y()

        for i, sev in enumerate(stats_order):
            x = x_start + (i * box_w)

            self.pdf.set_fill_color(*SEV_COLORS[sev])
            self.pdf.rect(x, y_start, box_w, box_h, style="F")

            self.pdf.set_draw_color(*C_WHITE)
            self.pdf.set_line_width(0.5)
            self.pdf.rect(x, y_start, box_w, box_h, style="D")

            self.pdf.set_font("Helvetica", "B", 16)
            self.pdf.set_text_color(*SEV_TEXT_COLOR[sev])
            self.pdf.set_xy(x, y_start + 4)
            self.pdf.cell(box_w, 8, str(self.stats[sev]), align="C")

            self.pdf.set_font("Helvetica", "B", 6.5)
            self.pdf.set_xy(x, y_start + 14)
            self.pdf.cell(box_w, 5, sev, align="C")

        self.pdf.set_y(y_start + box_h + 5)

    # ---------- RISK TABLE ----------
    def _build_risk_table(self):
        self._write_wrapped("RISK BREAKDOWN", size=11, style="B",
                            color=C_DARK, h=6)
        self.pdf.ln(1)

        # Header
        self.pdf.set_fill_color(26, 26, 26)
        self.pdf.set_text_color(*C_WHITE)
        self.pdf.set_font("Helvetica", "B", 8.5)

        self.pdf.cell(28, 7, "  SEVERITY", border=1, align="L", fill=True)
        self.pdf.cell(15, 7, "COUNT", border=1, align="C", fill=True)
        self.pdf.cell(0, 7, "DESCRIPTION", border=1, align="L", fill=True,
                      new_x="LMARGIN", new_y="NEXT")

        desc_map = {
            "CRITICAL": "Perbaikan segera - potensi RCE / data breach",
            "HIGH":     "Prioritas tinggi - exploit mudah, dampak serius",
            "MEDIUM":   "Perlu perhatian - butuh kondisi tertentu",
            "LOW":      "Risiko rendah - hardening & best practice",
            "INFO":     "Informasi - teknologi & signature detection",
            "SAFE":     "Tidak ada celah - konfigurasi sudah benar",
        }

        alt = False
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]:
            if alt:
                self.pdf.set_fill_color(*C_LIGHT_BG)
                fill = True
            else:
                fill = False
            alt = not alt

            row_y = self.pdf.get_y()

            # Badge
            badge_x = 16
            badge_w = 24
            badge_h = 5.5
            badge_y = row_y + 0.8
            self.pdf.set_fill_color(*SEV_COLORS[sev])
            self.pdf.rect(badge_x, badge_y, badge_w, badge_h, style="F")

            self.pdf.set_font("Helvetica", "B", 7)
            self.pdf.set_text_color(*SEV_TEXT_COLOR[sev])
            self.pdf.set_xy(badge_x, badge_y + 0.3)
            self.pdf.cell(badge_w, badge_h, sev, align="C")

            # Count
            self.pdf.set_xy(44, row_y)
            self.pdf.set_font("Helvetica", "B", 9)
            self.pdf.set_text_color(*C_DARK)
            self.pdf.cell(15, 7, str(self.stats[sev]), border=1,
                          align="C", fill=fill, new_x="RIGHT", new_y="TOP")

            # Description
            self.pdf.set_xy(59, row_y)
            self.pdf.set_font("Helvetica", "", 8.5)
            self.pdf.set_text_color(*C_TEXT)
            self.pdf.cell(0, 7, "  " + desc_map[sev], border=1, align="L",
                          fill=fill, new_x="LMARGIN", new_y="NEXT")

        self.pdf.ln(3)

    # ---------- FINDING CARD ----------
    def _build_finding(self, item):
        msg = _sanitize(item.get("message", ""))
        url = _sanitize(item.get("url", ""))
        mit = _sanitize(item.get("mitigation", ""))
        evi = _sanitize(item.get("evidence", ""))
        sev = item.get("severity", "INFO")

        est_h = 8
        if url and url != self.target: est_h += 5
        if mit: est_h += 6
        if evi: est_h += 6

        self._check_page_space(est_h + 5)

        sidebar_color = SEV_COLORS.get(sev, C_GRAY)
        start_y = self.pdf.get_y()
        start_x = 15
        card_w = 180

        # Sidebar
        self.pdf.set_fill_color(*sidebar_color)
        self.pdf.rect(start_x, start_y, 1.8, est_h, style="F")

        # Background
        self.pdf.set_fill_color(*C_LIGHT_BG)
        self.pdf.rect(start_x + 1.8, start_y, card_w - 1.8, est_h, style="F")

        # Badge
        self.pdf.set_fill_color(*sidebar_color)
        self.pdf.set_text_color(*SEV_TEXT_COLOR[sev])
        self.pdf.set_font("Helvetica", "B", 7)
        badge_y = start_y + 1.5
        self.pdf.rect(start_x + 3, badge_y, 18, 4, style="F")
        self.pdf.set_xy(start_x + 3, badge_y + 0.2)
        self.pdf.cell(18, 4, sev, align="C")

        # Message
        self.pdf.set_xy(start_x + 23, start_y + 1)
        self.pdf.set_text_color(*C_DARK)
        self.pdf.set_font("Helvetica", "B", 9)
        self.pdf.multi_cell(card_w - 25, 4.5, msg)

        # URL
        if url and url != self.target:
            self.pdf.set_x(start_x + 5)
            self.pdf.set_text_color(0, 86, 179)
            self.pdf.set_font("Courier", "", 7.5)
            self.pdf.multi_cell(card_w - 8, 3.8, f"Endpoint: {url}")

        # Mitigasi
        if mit:
            self.pdf.set_x(start_x + 5)
            self.pdf.set_text_color(139, 105, 20)
            self.pdf.set_font("Helvetica", "", 8)
            self.pdf.multi_cell(card_w - 8, 4, f"Mitigasi: {mit}")

        # Evidence
        if evi:
            self.pdf.set_x(start_x + 5)
            self.pdf.set_text_color(*C_GRAY)
            self.pdf.set_font("Courier", "", 7.5)
            self.pdf.multi_cell(card_w - 8, 3.8, f"Evidence: {evi}")

        end_y = self.pdf.get_y()
        self.pdf.set_y(end_y + 1)

    # ---------- BUILD ----------
    def build(self, output_path):
        pdf = self.pdf

        # Override footer
        def footer():
            if pdf.page_no() > 1:
                pdf.set_y(-12)
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(*C_GRAY)
                pdf.cell(
                    0, 5,
                    f"Page {pdf.page_no()} | TH0RSC4N Confidential | {self.report_id}",
                    align="C",
                )
        pdf.footer = footer

        # --- COVER ---
        self._build_cover()

        # --- EXECUTIVE SUMMARY ---
        self.pdf.add_page()
        self._page_header("Executive Summary")

        self._write_wrapped("1. EXECUTIVE SUMMARY", size=13, style="B",
                            color=C_DARK, h=8)
        self.pdf.ln(1)

        summary_text = (
            f"Automated security assessment conducted on {self.target}. "
            f"Total {len(self.findings)} findings were identified across "
            f"{len(self.grouped)} categories. Report generated on {self.date_str}."
        )
        self._write_wrapped(summary_text, size=9, color=C_TEXT, h=4.5)
        self.pdf.ln(3)

        self._build_stats_block()
        self.pdf.ln(2)
        self._build_risk_table()

        # --- FINDINGS ---
        self.pdf.add_page()
        self._page_header("Findings")

        self._write_wrapped("2. FINDINGS", size=13, style="B",
                            color=C_DARK, h=8)
        self.pdf.ln(2)

        for idx, (category, items) in enumerate(self.grouped.items(), 1):
            self._check_page_space(15)

            # Category header
            self.pdf.set_fill_color(*C_DARK)
            self.pdf.set_text_color(*C_WHITE)
            self.pdf.set_font("Helvetica", "B", 10)
            self.pdf.cell(0, 7, f"  2.{idx} {_sanitize(category)}", border=0,
                          align="L", fill=True, new_x="LMARGIN", new_y="NEXT")
            self.pdf.ln(1)

            self.pdf.set_font("Helvetica", "I", 8)
            self.pdf.set_text_color(*C_GRAY)
            self.pdf.cell(0, 4, f"    {len(items)} finding(s) in this category.",
                          new_x="LMARGIN", new_y="NEXT")
            self.pdf.ln(2)

            for item in items:
                self._build_finding(item)

            self.pdf.ln(2)

        # --- DISCLAIMER ---
        self._check_page_space(50)
        self.pdf.ln(3)
        self._page_header("Disclaimer")

        self._write_wrapped(f"{len(self.grouped) + 2}. DISCLAIMER",
                            size=13, style="B", color=C_DARK, h=8)
        self.pdf.ln(2)

        disc = (
            "This vulnerability assessment was performed using automated tools "
            "and may contain false positives or false negatives. Manual verification "
            "is strongly recommended before drawing conclusions. The assessment "
            f"reflects the state of the target at the time of scanning ({self.date_str}) "
            "and may not include vulnerabilities introduced afterwards."
        )

        self.pdf.set_fill_color(255, 241, 244)
        self.pdf.set_draw_color(*C_RED)
        self.pdf.set_line_width(0.3)

        x = 15
        y = self.pdf.get_y()
        w = 180
        self.pdf.rect(x, y, w, 30, style="DF")

        self.pdf.set_xy(x + 3, y + 3)
        self.pdf.set_font("Helvetica", "B", 8.5)
        self.pdf.set_text_color(*C_RED)
        self.pdf.cell(0, 4, "DISCLAIMER:", new_x="LMARGIN", new_y="NEXT")

        self.pdf.set_x(x + 3)
        self.pdf.set_font("Helvetica", "", 8.5)
        self.pdf.set_text_color(*C_TEXT)
        self.pdf.multi_cell(w - 6, 4, _sanitize(disc))

        self.pdf.set_y(y + 35)
        self.pdf.set_font("Helvetica", "I", 8)
        self.pdf.set_text_color(*C_GRAY)
        self.pdf.cell(0, 5, "- END OF REPORT -", align="C")

        # Output
        self.pdf.output(str(output_path))
        return output_path


# ==========================================
# REPORTER FUNCTION (entry point)
# ==========================================
def report(findings, target, output_path):
    """Generate PDF report menggunakan fpdf2."""
    try:
        from fpdf import FPDF  # noqa: F401
    except ImportError:
        raise ImportError("fpdf2 tidak terinstall. Jalankan: pip install fpdf2")

    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "SAFE": 0}
    grouped = {}

    for f in findings:
        stats[f.severity] = stats.get(f.severity, 0) + 1
        grouped.setdefault(f.category, []).append(f)

    grouped = dict(sorted(grouped.items()))

    now = datetime.now()
    report_id = now.strftime("TH0RSC4N-%Y%m%d-%H%M%S")
    date_str = now.strftime("%Y-%m-%d %H:%M:%S")

    findings_dicts = [f.to_dict() for f in findings]
    grouped_dicts = {k: [f.to_dict() for f in v] for k, v in grouped.items()}

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    builder = ReportPDF(
        target=target,
        report_id=report_id,
        date_str=date_str,
        stats=stats,
        findings=findings_dicts,
        grouped=grouped_dicts,
    )
    builder.build(output_path)

    return output_path