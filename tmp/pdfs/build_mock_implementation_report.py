from __future__ import annotations

import html
import re
import textwrap
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


ROOT = Path(r"D:\honeypot_v2")
SOURCE = ROOT / "MOCK_IMPLEMENTATION_REPORT.md"
OUTPUT = ROOT / "output" / "pdf" / "MOCK_IMPLEMENTATION_REPORT.pdf"

PAGE_W, PAGE_H = A4
MARGIN_X = 17 * mm
MARGIN_TOP = 19 * mm
MARGIN_BOTTOM = 17 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X

NAVY = HexColor("#071522")
INK = HexColor("#132538")
CYAN = HexColor("#00A7C4")
TEAL = HexColor("#007D83")
GREEN = HexColor("#18A66A")
AMBER = HexColor("#D88916")
RED = HexColor("#CF4457")
PALE_CYAN = HexColor("#E9F8FB")
PALE_GREEN = HexColor("#EAF8F1")
PALE_AMBER = HexColor("#FFF5E5")
PALE_RED = HexColor("#FCECEF")
PALE_BLUE = HexColor("#EEF4FA")
LIGHT = HexColor("#F5F7FA")
MID = HexColor("#D4DEE7")
MUTED = HexColor("#587083")
WHITE = colors.white


def register_fonts() -> tuple[str, str, str]:
    candidates = [
        (Path(r"C:\Windows\Fonts\segoeui.ttf"), "SegoeUI"),
        (Path(r"C:\Windows\Fonts\segoeuib.ttf"), "SegoeUI-Bold"),
        (Path(r"C:\Windows\Fonts\consola.ttf"), "Consolas"),
    ]
    names = []
    for path, name in candidates:
        if path.exists():
            pdfmetrics.registerFont(TTFont(name, str(path)))
            names.append(name)
        else:
            names.append("Helvetica-Bold" if "Bold" in name else "Helvetica")
    return tuple(names)


BODY_FONT, BOLD_FONT, MONO_FONT = register_fonts()


def clean_text(value: str) -> str:
    replacements = {
        "â€”": " - ",
        "â€“": "-",
        "—": " - ",
        "–": "-",
        "’": "'",
        "“": '"',
        "”": '"',
        "…": "...",
        "≥": ">=",
        "≤": "<=",
    }
    for old, new in replacements.items():
        value = value.replace(old, new)
    return value


def rich(value: str) -> str:
    value = html.escape(clean_text(value.strip()))
    value = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"`([^`]+)`", rf'<font name="{MONO_FONT}" color="#006E7A">\1</font>', value)
    return value


styles = getSampleStyleSheet()
BODY = ParagraphStyle(
    "Body",
    parent=styles["BodyText"],
    fontName=BODY_FONT,
    fontSize=9.2,
    leading=13.4,
    textColor=INK,
    spaceAfter=6,
    alignment=TA_LEFT,
)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=7.4, leading=10.2, textColor=MUTED)
LIST_BODY = ParagraphStyle(
    "ListBody", parent=BODY, leftIndent=16, rightIndent=2, firstLineIndent=0, bulletIndent=0,
    spaceBefore=0, spaceAfter=3.5, leading=13.2,
)
TABLE_BODY = ParagraphStyle("TableBody", parent=BODY, fontSize=7.3, leading=9.4, spaceAfter=0)
TABLE_HEAD = ParagraphStyle(
    "TableHead", parent=TABLE_BODY, fontName=BOLD_FONT, textColor=WHITE, fontSize=7.4, leading=9.5
)
H1 = ParagraphStyle(
    "Heading1",
    parent=styles["Heading1"],
    fontName=BOLD_FONT,
    fontSize=18,
    leading=22,
    textColor=NAVY,
    spaceBefore=12,
    spaceAfter=8,
    keepWithNext=True,
)
H2 = ParagraphStyle(
    "Heading2",
    parent=styles["Heading2"],
    fontName=BOLD_FONT,
    fontSize=12.3,
    leading=15,
    textColor=TEAL,
    spaceBefore=10,
    spaceAfter=5,
    keepWithNext=True,
)
FRONT_H1 = ParagraphStyle("FrontHeading", parent=H1)
CODE = ParagraphStyle(
    "Code",
    parent=BODY,
    fontName=MONO_FONT,
    fontSize=7.5,
    leading=10.2,
    leftIndent=8,
    rightIndent=8,
    borderColor=MID,
    borderWidth=0.6,
    borderPadding=7,
    backColor=LIGHT,
    spaceBefore=4,
    spaceAfter=8,
)
COVER_TITLE = ParagraphStyle(
    "CoverTitle", fontName=BOLD_FONT, fontSize=27, leading=31, textColor=WHITE, alignment=TA_LEFT
)
COVER_SUB = ParagraphStyle(
    "CoverSub", fontName=BODY_FONT, fontSize=13.5, leading=19, textColor=HexColor("#B9DDE7")
)
COVER_META = ParagraphStyle(
    "CoverMeta", fontName=BODY_FONT, fontSize=9, leading=13, textColor=HexColor("#DCE8EE")
)
CALLOUT = ParagraphStyle(
    "Callout", parent=BODY, fontSize=9.2, leading=13.2, borderPadding=9, backColor=PALE_CYAN, borderColor=CYAN,
    borderWidth=0.8, leftIndent=0, rightIndent=0, spaceBefore=4, spaceAfter=10,
)


class ReportDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str):
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=MARGIN_X,
            rightMargin=MARGIN_X,
            topMargin=MARGIN_TOP,
            bottomMargin=MARGIN_BOTTOM,
            title="Mock Implementation Report",
            author="Project Team",
            subject="Secure and Intelligent Honeypot Framework",
        )
        cover_frame = Frame(0, 0, PAGE_W, PAGE_H, leftPadding=MARGIN_X, rightPadding=MARGIN_X, topPadding=0, bottomPadding=0, id="cover")
        body_frame = Frame(MARGIN_X, MARGIN_BOTTOM, CONTENT_W, PAGE_H - MARGIN_TOP - MARGIN_BOTTOM, id="body")
        self.addPageTemplates([
            PageTemplate(id="Cover", frames=[cover_frame], onPage=draw_cover),
            PageTemplate(id="Body", frames=[body_frame], onPage=draw_body_page),
        ])

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            style_name = flowable.style.name
            if style_name in ("Heading1", "Heading2"):
                level = 0 if style_name == "Heading1" else 1
                text = flowable.getPlainText()
                key = "h%d-%s" % (level, abs(hash((text, self.page))))
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(text, key, level=level, closed=False)
                if level == 0:
                    self.notify("TOCEntry", (level, text, self.page, key))


def draw_cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#09293A"))
    canvas.circle(PAGE_W - 22 * mm, PAGE_H - 23 * mm, 56 * mm, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#0A3F52"))
    canvas.circle(PAGE_W - 15 * mm, PAGE_H - 15 * mm, 30 * mm, fill=1, stroke=0)
    canvas.setStrokeColor(CYAN)
    canvas.setLineWidth(2)
    canvas.line(MARGIN_X, PAGE_H - 35 * mm, MARGIN_X + 30 * mm, PAGE_H - 35 * mm)
    canvas.setFont(BOLD_FONT, 8)
    canvas.setFillColor(HexColor("#8DDAE6"))
    canvas.drawString(MARGIN_X, PAGE_H - 28 * mm, "CYBERSECURITY IMPLEMENTATION DOSSIER")
    canvas.setFont(BODY_FONT, 8)
    canvas.setFillColor(HexColor("#A9C5CF"))
    canvas.drawRightString(PAGE_W - MARGIN_X, 13 * mm, "Controlled local-lab prototype | 6 September 2026")
    canvas.restoreState()


def draw_body_page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(MID)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN_X, PAGE_H - 12 * mm, PAGE_W - MARGIN_X, PAGE_H - 12 * mm)
    canvas.setFont(BOLD_FONT, 7.2)
    canvas.setFillColor(TEAL)
    canvas.drawString(MARGIN_X, PAGE_H - 9.4 * mm, "MOCK IMPLEMENTATION REPORT")
    canvas.setFont(BODY_FONT, 7.2)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 9.4 * mm, "SECURE HONEYPOT AND HYBRID IDS")
    canvas.setStrokeColor(MID)
    canvas.line(MARGIN_X, 11 * mm, PAGE_W - MARGIN_X, 11 * mm)
    canvas.setFont(BODY_FONT, 7.2)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN_X, 7 * mm, "Branch mock | Baseline a4f8382")
    canvas.drawRightString(PAGE_W - MARGIN_X, 7 * mm, f"Page {doc.page}")
    canvas.restoreState()


def box(d: Drawing, x, y, w, h, label, fill=PALE_BLUE, stroke=TEAL, font_size=7.1):
    d.add(Rect(x, y, w, h, rx=5, ry=5, fillColor=fill, strokeColor=stroke, strokeWidth=0.8))
    lines = textwrap.wrap(clean_text(label), width=max(10, int(w / 5.1)))[:3]
    total = len(lines) * (font_size + 1)
    start = y + h / 2 + total / 2 - font_size
    for i, line in enumerate(lines):
        d.add(String(x + w / 2, start - i * (font_size + 1), line, fontName=BOLD_FONT if i == 0 else BODY_FONT,
                     fontSize=font_size, fillColor=INK, textAnchor="middle"))


def arrow(d: Drawing, x1, y1, x2, y2, color=MUTED):
    d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=1))
    dx, dy = x2 - x1, y2 - y1
    if abs(dx) >= abs(dy):
        sign = 1 if dx >= 0 else -1
        d.add(Polygon([x2, y2, x2 - sign * 5, y2 + 3, x2 - sign * 5, y2 - 3], fillColor=color, strokeColor=color))
    else:
        sign = 1 if dy >= 0 else -1
        d.add(Polygon([x2, y2, x2 - 3, y2 - sign * 5, x2 + 3, y2 - sign * 5], fillColor=color, strokeColor=color))


def diagram_title(d: Drawing, title: str, subtitle: str):
    d.add(String(0, d.height - 12, title, fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    d.add(String(0, d.height - 25, subtitle, fontName=BODY_FONT, fontSize=6.8, fillColor=MUTED))


def architecture_diagram() -> Drawing:
    d = Drawing(CONTENT_W, 215)
    diagram_title(d, "End-to-end architecture", "Attacker interaction is transformed into durable evidence, explanation, response, and alerting.")
    bw, bh = 82, 31
    xs = [3, 103, 203, 303, 403]
    labels = ["Authorized tester", "Decoy surfaces\n5173 / 2222 / 2121 / 8080", "Common event\nJSONL + Express", "Hybrid IDS\nRules + ML", "Threat + XAI\nSix agents"]
    fills = [PALE_AMBER, PALE_CYAN, PALE_BLUE, PALE_GREEN, PALE_GREEN]
    for i, (x, label) in enumerate(zip(xs, labels)):
        box(d, x, 133, bw, bh, label, fill=fills[i], stroke=TEAL)
        if i:
            arrow(d, xs[i-1] + bw, 148, x, 148)
    box(d, 118, 60, 115, 34, "SQLite audit store\n:5000", PALE_BLUE, CYAN)
    box(d, 278, 60, 115, 34, "Defender dashboard\n:5050", PALE_CYAN, TEAL)
    arrow(d, 244, 133, 176, 94)
    arrow(d, 233, 77, 278, 77)
    box(d, 399, 60, 92, 34, "n8n :5678\nTelegram", PALE_AMBER, AMBER)
    arrow(d, 445, 133, 445, 94)
    d.add(String(3, 24, "Safety boundary: fictional exposure only; no real SQL execution, unrestricted JavaScript, or host firewall changes.",
                 fontName=BOLD_FONT, fontSize=7.4, fillColor=RED))
    return d


def trust_diagram() -> Drawing:
    d = Drawing(CONTENT_W, 195)
    diagram_title(d, "Trust-boundary design", "The public decoy experience and local defender controls are intentionally isolated.")
    d.add(Rect(3, 48, 235, 105, rx=8, ry=8, fillColor=HexColor("#FFF8EE"), strokeColor=AMBER, strokeWidth=1.2))
    d.add(String(14, 137, "UNTRUSTED / ATTACKER-FACING", fontName=BOLD_FONT, fontSize=7.3, fillColor=AMBER))
    box(d, 18, 78, 82, 38, "Browser", WHITE, AMBER)
    box(d, 140, 78, 82, 38, "React portal\n:5173", WHITE, AMBER)
    arrow(d, 100, 97, 140, 97, AMBER)
    d.add(Rect(260, 48, 239, 105, rx=8, ry=8, fillColor=PALE_CYAN, strokeColor=TEAL, strokeWidth=1.2))
    d.add(String(271, 137, "LOCAL DEFENDER BOUNDARY", fontName=BOLD_FONT, fontSize=7.3, fillColor=TEAL))
    box(d, 275, 78, 88, 38, "Flask dashboard\n:5050", WHITE, TEAL)
    box(d, 398, 78, 85, 38, "Protected APIs\n:5000", WHITE, TEAL)
    arrow(d, 363, 97, 398, 97, TEAL)
    arrow(d, 222, 97, 398, 97, MUTED)
    d.add(String(309, 60, "loopback + internal token", fontName=BODY_FONT, fontSize=6.7, fillColor=MUTED))
    d.add(String(3, 22, "The internal token remains server-side and is never shipped to browser JavaScript.", fontName=BOLD_FONT, fontSize=7.4, fillColor=NAVY))
    return d


def sqli_diagram() -> Drawing:
    d = Drawing(CONTENT_W, 188)
    diagram_title(d, "SQL injection demonstration flow", "A believable result is returned and audited without querying a real database.")
    labels = ["Tester submits\nSQLi-style input", "Express detects\nbounded pattern", "Six fictional rows\nreturned safely", "Exposure audit +\ncommon event", "IDS / XAI / IPS /\nalert pipeline"]
    xs = [2, 103, 204, 305, 406]
    for i, (x, label) in enumerate(zip(xs, labels)):
        box(d, x, 88, 88, 45, label, PALE_CYAN if i not in (0, 4) else PALE_AMBER, TEAL if i not in (0, 4) else AMBER)
        if i:
            arrow(d, xs[i-1] + 88, 110, x, 110)
    d.add(String(3, 53, "Audited: displayed columns, rows, entry point, and safety flags", fontName=BOLD_FONT, fontSize=7.5, fillColor=TEAL))
    d.add(String(3, 35, "Not performed: raw SQL query, real database dump, or credential disclosure", fontName=BOLD_FONT, fontSize=7.5, fillColor=RED))
    return d


def alert_diagram() -> Drawing:
    d = Drawing(CONTENT_W, 180)
    diagram_title(d, "Alert eligibility and delivery", "Only enriched High/Critical attacks progress to privacy-safe notification.")
    labels = ["Final IDS result", "Attack +\nHigh/Critical?", "Remove secrets", "5-minute\ndeduplication", "n8n + Telegram"]
    xs = [2, 104, 206, 308, 410]
    for i, (x, label) in enumerate(zip(xs, labels)):
        fill = PALE_GREEN if i == 4 else PALE_BLUE
        stroke = GREEN if i == 4 else CYAN
        box(d, x, 85, 86, 43, label, fill, stroke)
        if i:
            arrow(d, xs[i-1] + 86, 106, x, 106)
    d.add(String(117, 65, "No", fontName=BOLD_FONT, fontSize=7, fillColor=RED))
    arrow(d, 147, 85, 147, 43, RED)
    box(d, 103, 16, 88, 27, "Skip safely", PALE_RED, RED)
    return d


def learning_diagram() -> Drawing:
    d = Drawing(CONTENT_W, 202)
    diagram_title(d, "Controlled continuous-learning lifecycle", "Training remains offline; promotion is gated, explicit, reversible, and performed with consumers stopped.")
    top = ["Stored IDS result", "Append-only\nanalyst feedback", "Sanitized corrected\ndataset", "Versioned candidate"]
    xs = [3, 127, 251, 375]
    for i, (x, label) in enumerate(zip(xs, top)):
        box(d, x, 121, 112, 38, label, PALE_BLUE, CYAN)
        if i:
            arrow(d, xs[i-1] + 112, 140, x, 140)
    box(d, 375, 55, 112, 38, "Quality gates", PALE_AMBER, AMBER)
    arrow(d, 431, 121, 431, 93)
    box(d, 251, 55, 112, 38, "Explicit promotion", PALE_GREEN, GREEN)
    arrow(d, 375, 74, 363, 74, GREEN)
    box(d, 127, 55, 112, 38, "Previous version\nretained", PALE_GREEN, GREEN)
    arrow(d, 251, 74, 239, 74, GREEN)
    d.add(String(3, 24, "If gates fail: retain the active model. If promotion regresses: roll back to the retained version.",
                 fontName=BOLD_FONT, fontSize=7.3, fillColor=NAVY))
    return d


DIAGRAMS = [architecture_diagram, trust_diagram, sqli_diagram, alert_diagram, learning_diagram]


def make_table(rows: list[list[str]]) -> Table:
    cols = max(len(row) for row in rows)
    normalized = [row + [""] * (cols - len(row)) for row in rows]
    if cols == 2:
        widths = [CONTENT_W * 0.34, CONTENT_W * 0.66]
    elif cols == 3:
        widths = [CONTENT_W * 0.20, CONTENT_W * 0.24, CONTENT_W * 0.56]
    elif cols == 4:
        widths = [CONTENT_W * 0.14, CONTENT_W * 0.22, CONTENT_W * 0.23, CONTENT_W * 0.41]
    else:
        widths = [CONTENT_W / cols] * cols
    data = []
    for r_idx, row in enumerate(normalized):
        style = TABLE_HEAD if r_idx == 0 else TABLE_BODY
        data.append([Paragraph(rich(cell), style) for cell in row])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, MID),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for idx in range(1, len(data)):
        if idx % 2 == 0:
            commands.append(("BACKGROUND", (0, idx), (-1, idx), LIGHT))
    table.setStyle(TableStyle(commands))
    return table


def parse_markdown(md: str):
    lines = clean_text(md).splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("## 1."))
    lines = lines[start:]
    story = []
    i = 0
    diagram_index = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        stripped = raw.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("```mermaid"):
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                i += 1
            if diagram_index < len(DIAGRAMS):
                story.extend([Spacer(1, 3), DIAGRAMS[diagram_index](), Spacer(1, 9)])
                diagram_index += 1
            i += 1
            continue
        if stripped.startswith("```"):
            language = stripped[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(clean_text(lines[i]))
                i += 1
            code = "<br/>".join(html.escape(line).replace(" ", "&nbsp;") for line in code_lines)
            if language:
                code = f'<font color="#587083">{html.escape(language.upper())}</font><br/>{code}'
            story.append(Paragraph(code, CODE))
            i += 1
            continue
        if stripped.startswith("## "):
            story.append(Paragraph(rich(stripped[3:]), H1))
            story.append(HRFlowable(width="100%", thickness=1.1, color=CYAN, spaceAfter=7))
            i += 1
            continue
        if stripped.startswith("### "):
            story.append(Paragraph(rich(stripped[4:]), H2))
            i += 1
            continue
        if stripped.startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            rows = []
            for idx, line in enumerate(table_lines):
                cells = [cell.strip() for cell in line.strip("|").split("|")]
                if idx == 1 and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                    continue
                rows.append(cells)
            story.extend([Spacer(1, 2), make_table(rows), Spacer(1, 8)])
            continue
        bullet_match = re.match(r"^[-*]\s+(.+)$", stripped)
        number_match = re.match(r"^\d+\.\s+(.+)$", stripped)
        if bullet_match or number_match:
            ordered = number_match is not None
            item_number = 1
            while i < len(lines):
                current = lines[i].strip()
                match = re.match(r"^\d+\.\s+(.+)$", current) if ordered else re.match(r"^[-*]\s+(.+)$", current)
                if not match:
                    break
                bullet = str(item_number) if ordered else "-"
                story.append(Paragraph(rich(match.group(1)), LIST_BODY, bulletText=bullet))
                item_number += 1
                i += 1
            story.append(Spacer(1, 3))
            continue
        paragraph_lines = [stripped]
        i += 1
        while i < len(lines):
            nxt = lines[i].strip()
            if (not nxt or nxt.startswith("#") or nxt.startswith("|") or nxt.startswith("```")
                    or re.match(r"^[-*]\s+", nxt) or re.match(r"^\d+\.\s+", nxt)):
                break
            paragraph_lines.append(nxt)
            i += 1
        story.append(Paragraph(rich(" ".join(paragraph_lines)), BODY))
    return story


def cover_story():
    status_data = [
        [Paragraph("IMPLEMENTATION STATUS", TABLE_HEAD), Paragraph("SCOPE", TABLE_HEAD), Paragraph("SAFETY POSTURE", TABLE_HEAD)],
        [Paragraph("Complete controlled prototype", TABLE_BODY), Paragraph("Academic and authorized local lab", TABLE_BODY), Paragraph("Simulation-only response", TABLE_BODY)],
    ]
    status = Table(status_data, colWidths=[CONTENT_W / 3] * 3)
    status.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0B5064")),
        ("BACKGROUND", (0, 1), (-1, 1), HexColor("#E9F8FB")),
        ("GRID", (0, 0), (-1, -1), 0.4, HexColor("#4E8794")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return [
        Spacer(1, 73 * mm),
        Paragraph("MOCK IMPLEMENTATION REPORT", COVER_TITLE),
        Spacer(1, 5 * mm),
        Paragraph("A Secure and Intelligent Framework for Detecting and Understanding Malicious Digital Activities", COVER_SUB),
        Spacer(1, 13 * mm),
        status,
        Spacer(1, 11 * mm),
        Paragraph("Implementation branch&nbsp;&nbsp; <b>mock</b><br/>Implementation baseline&nbsp;&nbsp; <b>a4f8382</b><br/>Report date&nbsp;&nbsp; <b>6 September 2026</b>", COVER_META),
        Spacer(1, 18 * mm),
        Paragraph("This report documents the complete implementation: architecture, trust boundaries, data flow, attacker simulations, hybrid detection, XAI, agents, dashboard operation, alerts, analyst feedback, simulated IPS, validation, limitations, and upgrade roadmap.", COVER_META),
        NextPageTemplate("Body"),
        PageBreak(),
    ]


def front_matter():
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle("TOC1", fontName=BOLD_FONT, fontSize=9.3, leading=14, leftIndent=0, firstLineIndent=0, textColor=NAVY, spaceBefore=3),
        ParagraphStyle("TOC2", fontName=BODY_FONT, fontSize=8.2, leading=12, leftIndent=14, firstLineIndent=0, textColor=MUTED),
    ]
    summary = Table([
        [Paragraph("7", TABLE_HEAD), Paragraph("6", TABLE_HEAD), Paragraph("4", TABLE_HEAD), Paragraph("6", TABLE_HEAD)],
        [Paragraph("runtime services", TABLE_BODY), Paragraph("intelligent agents", TABLE_BODY), Paragraph("detection components", TABLE_BODY), Paragraph("fictional SQLi rows", TABLE_BODY)],
    ], colWidths=[CONTENT_W / 4] * 4)
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TEAL),
        ("BACKGROUND", (0, 1), (-1, 1), PALE_CYAN),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, MID),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return [
        Paragraph("Document guide", FRONT_H1),
        HRFlowable(width="100%", thickness=1.1, color=CYAN, spaceAfter=8),
        Paragraph("This is the complete implementation record for the mock branch. It explains what was built, where it lives, why each boundary exists, how every major workflow operates, how the system is verified, and what should be upgraded next.", CALLOUT),
        summary,
        Spacer(1, 11),
        Paragraph("Contents", FRONT_H1),
        HRFlowable(width="100%", thickness=1.1, color=CYAN, spaceAfter=8),
        toc,
        PageBreak(),
    ]


def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    md = SOURCE.read_text(encoding="utf-8")
    story = cover_story() + front_matter() + parse_markdown(md)
    doc = ReportDocTemplate(str(OUTPUT))
    doc.multiBuild(story)
    print(OUTPUT)


if __name__ == "__main__":
    build()
