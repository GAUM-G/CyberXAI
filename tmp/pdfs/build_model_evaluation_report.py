from __future__ import annotations

import csv
import html
import json
import math
import textwrap
from pathlib import Path

import numpy as np
from reportlab.graphics.shapes import Circle, Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
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
DATA = ROOT / "data"
OUTPUT = ROOT / "output" / "pdf" / "MODEL_EVALUATION_PERFORMANCE_AND_DATASET_REPORT.pdf"
LSTM_AUDIT = ROOT / "report_evidence" / "lstm_robustness"

PAGE_W, PAGE_H = A4
MARGIN_X = 17 * mm
MARGIN_TOP = 19 * mm
MARGIN_BOTTOM = 17 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X

NAVY = HexColor("#071522")
INK = HexColor("#17283A")
CYAN = HexColor("#00A7C4")
TEAL = HexColor("#007D83")
GREEN = HexColor("#18A66A")
AMBER = HexColor("#D88916")
RED = HexColor("#CF4457")
PURPLE = HexColor("#7056B8")
PALE_CYAN = HexColor("#E9F8FB")
PALE_GREEN = HexColor("#EAF8F1")
PALE_AMBER = HexColor("#FFF5E5")
PALE_RED = HexColor("#FCECEF")
PALE_PURPLE = HexColor("#F0ECFA")
LIGHT = HexColor("#F5F7FA")
MID = HexColor("#D4DEE7")
MUTED = HexColor("#587083")
WHITE = colors.white


def register_fonts():
    specs = [
        (r"C:\Windows\Fonts\segoeui.ttf", "SegoeUI", "Helvetica"),
        (r"C:\Windows\Fonts\segoeuib.ttf", "SegoeUI-Bold", "Helvetica-Bold"),
        (r"C:\Windows\Fonts\consola.ttf", "Consolas", "Courier"),
    ]
    result = []
    for raw_path, name, fallback in specs:
        path = Path(raw_path)
        if path.exists():
            pdfmetrics.registerFont(TTFont(name, str(path)))
            result.append(name)
        else:
            result.append(fallback)
    return tuple(result)


BODY_FONT, BOLD_FONT, MONO_FONT = register_fonts()


def safe(value) -> str:
    text = str(value)
    replacements = {
        "â€”": " - ", "â€“": "-", "—": " - ", "–": "-", "‑": "-",
        "’": "'", "“": '"', "”": '"', "…": "...", "≥": ">=", "≤": "<=",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def rich(value) -> str:
    text = html.escape(safe(value))
    text = text.replace("\n", "<br/>")
    return text


styles = getSampleStyleSheet()
BODY = ParagraphStyle(
    "Body", parent=styles["BodyText"], fontName=BODY_FONT, fontSize=9.2,
    leading=13.3, textColor=INK, spaceAfter=6,
)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=7.5, leading=10.4, textColor=MUTED)
CAPTION = ParagraphStyle(
    "Caption", parent=SMALL, fontSize=7.2, leading=9.5, alignment=TA_CENTER,
    textColor=MUTED, spaceBefore=3, spaceAfter=8,
)
TABLE_BODY = ParagraphStyle("TableBody", parent=BODY, fontSize=7.1, leading=9.3, spaceAfter=0)
TABLE_SMALL = ParagraphStyle("TableSmall", parent=TABLE_BODY, fontSize=6.35, leading=8.0)
TABLE_HEAD = ParagraphStyle(
    "TableHead", parent=TABLE_BODY, fontName=BOLD_FONT, textColor=WHITE,
    fontSize=7.1, leading=9.0,
)
H1 = ParagraphStyle(
    "Heading1", parent=styles["Heading1"], fontName=BOLD_FONT, fontSize=18,
    leading=22, textColor=NAVY, spaceBefore=12, spaceAfter=7, keepWithNext=True,
)
H2 = ParagraphStyle(
    "Heading2", parent=styles["Heading2"], fontName=BOLD_FONT, fontSize=12.2,
    leading=15, textColor=TEAL, spaceBefore=10, spaceAfter=5, keepWithNext=True,
)
H3 = ParagraphStyle(
    "Heading3", parent=styles["Heading3"], fontName=BOLD_FONT, fontSize=10.3,
    leading=13, textColor=INK, spaceBefore=7, spaceAfter=4, keepWithNext=True,
)
FRONT_H1 = ParagraphStyle("FrontHeading", parent=H1)
COVER_TITLE = ParagraphStyle(
    "CoverTitle", fontName=BOLD_FONT, fontSize=26, leading=30, textColor=WHITE,
)
COVER_SUB = ParagraphStyle(
    "CoverSub", fontName=BODY_FONT, fontSize=13.5, leading=19, textColor=HexColor("#B9DDE7"),
)
COVER_META = ParagraphStyle(
    "CoverMeta", fontName=BODY_FONT, fontSize=9, leading=13, textColor=HexColor("#DCE8EE"),
)
CALLOUT = ParagraphStyle(
    "Callout", parent=BODY, borderPadding=9, backColor=PALE_CYAN,
    borderColor=CYAN, borderWidth=0.8, spaceBefore=4, spaceAfter=9,
)
WARNING = ParagraphStyle(
    "Warning", parent=BODY, borderPadding=9, backColor=PALE_AMBER,
    borderColor=AMBER, borderWidth=0.8, spaceBefore=4, spaceAfter=9,
)
CODE = ParagraphStyle(
    "Code", parent=BODY, fontName=MONO_FONT, fontSize=7.1, leading=9.7,
    borderPadding=7, backColor=LIGHT, borderColor=MID, borderWidth=0.6,
    leftIndent=5, rightIndent=5, spaceBefore=3, spaceAfter=7,
)
LIST = ParagraphStyle(
    "List", parent=BODY, leftIndent=16, bulletIndent=0, spaceAfter=3.5, leading=13.1,
)


def p(text, style=BODY):
    return Paragraph(rich(text), style)


def bullet(text, marker="-"):
    return Paragraph(rich(text), LIST, bulletText=marker)


class EvaluationDoc(BaseDocTemplate):
    def __init__(self, filename):
        super().__init__(
            filename, pagesize=A4, leftMargin=MARGIN_X, rightMargin=MARGIN_X,
            topMargin=MARGIN_TOP, bottomMargin=MARGIN_BOTTOM,
            title="Model Evaluation, Performance and Dataset Report",
            author="Honeypot Project Team",
            subject="Evaluation parameters, performance results, dataset samples, inputs and outputs",
        )
        cover_frame = Frame(0, 0, PAGE_W, PAGE_H, leftPadding=MARGIN_X, rightPadding=MARGIN_X,
                            topPadding=0, bottomPadding=0, id="cover")
        body_frame = Frame(MARGIN_X, MARGIN_BOTTOM, CONTENT_W,
                           PAGE_H - MARGIN_TOP - MARGIN_BOTTOM, id="body")
        self.addPageTemplates([
            PageTemplate(id="Cover", frames=[cover_frame], onPage=draw_cover),
            PageTemplate(id="Body", frames=[body_frame], onPage=draw_body_page),
        ])

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name in {"Heading1", "Heading2"}:
            level = 0 if flowable.style.name == "Heading1" else 1
            title = flowable.getPlainText()
            key = f"section-{level}-{abs(hash((title, self.page)))}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, level=level, closed=False)
            if level == 0:
                self.notify("TOCEntry", (level, title, self.page, key))


def draw_cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#09293A"))
    canvas.circle(PAGE_W - 20 * mm, PAGE_H - 25 * mm, 58 * mm, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#0A465A"))
    canvas.circle(PAGE_W - 13 * mm, PAGE_H - 16 * mm, 30 * mm, fill=1, stroke=0)
    canvas.setStrokeColor(CYAN)
    canvas.setLineWidth(2)
    canvas.line(MARGIN_X, PAGE_H - 35 * mm, MARGIN_X + 32 * mm, PAGE_H - 35 * mm)
    canvas.setFont(BOLD_FONT, 8)
    canvas.setFillColor(HexColor("#8DDAE6"))
    canvas.drawString(MARGIN_X, PAGE_H - 28 * mm, "MODEL AND DATASET EVALUATION DOSSIER")
    canvas.setFont(BODY_FONT, 8)
    canvas.setFillColor(HexColor("#A9C5CF"))
    canvas.drawRightString(PAGE_W - MARGIN_X, 13 * mm, "Controlled evaluation artifacts | 7 September 2026")
    canvas.restoreState()


def draw_body_page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(MID)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN_X, PAGE_H - 12 * mm, PAGE_W - MARGIN_X, PAGE_H - 12 * mm)
    canvas.setFont(BOLD_FONT, 7.2)
    canvas.setFillColor(TEAL)
    canvas.drawString(MARGIN_X, PAGE_H - 9.4 * mm, "MODEL EVALUATION REPORT")
    canvas.setFont(BODY_FONT, 7.2)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 9.4 * mm, "HYBRID HONEYPOT IDS")
    canvas.line(MARGIN_X, 11 * mm, PAGE_W - MARGIN_X, 11 * mm)
    canvas.drawString(MARGIN_X, 7 * mm, "Branch mock | Dataset v1.0 | Evaluation v1.0")
    canvas.drawRightString(PAGE_W - MARGIN_X, 7 * mm, f"Page {doc.page}")
    canvas.restoreState()


def section(title):
    return [p(title, H1), HRFlowable(width="100%", thickness=1.1, color=CYAN, spaceAfter=7)]


def table(rows, widths=None, small=False, header=True, alignments=None):
    col_count = max(len(row) for row in rows)
    normalized = [list(row) + [""] * (col_count - len(row)) for row in rows]
    if widths is None:
        widths = [CONTENT_W / col_count] * col_count
    body_style = TABLE_SMALL if small else TABLE_BODY
    data = []
    for row_index, row in enumerate(normalized):
        cell_style = TABLE_HEAD if header and row_index == 0 else body_style
        data.append([p(value, cell_style) for value in row])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, MID),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
    ]
    if header:
        commands.extend([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE)])
    for idx in range(1 if header else 0, len(data)):
        if idx % 2 == 0:
            commands.append(("BACKGROUND", (0, idx), (-1, idx), LIGHT))
    if alignments:
        for col, alignment in enumerate(alignments):
            commands.append(("ALIGN", (col, 0), (col, -1), alignment))
    t.setStyle(TableStyle(commands))
    return t


def metric_card(value, label, accent):
    top = p(value, ParagraphStyle("CardValue" + label, parent=BODY, fontName=BOLD_FONT,
                                  fontSize=17, leading=20, textColor=accent, alignment=TA_CENTER, spaceAfter=1))
    bottom = p(label, ParagraphStyle("CardLabel" + label, parent=SMALL, fontName=BOLD_FONT,
                                     alignment=TA_CENTER, textColor=MUTED))
    t = Table([[top], [bottom]], colWidths=[CONTENT_W / 4 - 5])
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.7, accent),
        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
    ]))
    return t


def add_arrow(d, x1, y1, x2, y2, color=MUTED):
    d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=1))
    d.add(Polygon([x2, y2, x2 - 5, y2 + 3, x2 - 5, y2 - 3], fillColor=color, strokeColor=color))


def add_box(d, x, y, w, h, label, fill=PALE_CYAN, stroke=TEAL):
    d.add(Rect(x, y, w, h, rx=5, ry=5, fillColor=fill, strokeColor=stroke, strokeWidth=0.9))
    parts = []
    for logical_line in safe(label).split("\n"):
        parts.extend(textwrap.wrap(logical_line, width=max(10, int(w / 5.4))) or [""])
    parts = parts[:3]
    start = y + h / 2 + (len(parts) - 1) * 4
    for index, line in enumerate(parts):
        d.add(String(x + w / 2, start - index * 9, line, fontName=BOLD_FONT if index == 0 else BODY_FONT,
                     fontSize=7, fillColor=INK, textAnchor="middle"))


def pipeline_diagram():
    d = Drawing(CONTENT_W, 150)
    d.add(String(0, 135, "Evaluation data pipeline", fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    labels = ["Raw JSONL\n5,193 events", "Validate + sanitize\n4,080 accepted", "Causal feature\nengineering", "Chronological\n80/20 split", "Tabular + sequence\nmodel inputs"]
    xs = [2, 104, 206, 308, 410]
    fills = [PALE_AMBER, PALE_CYAN, PALE_CYAN, PALE_GREEN, PALE_PURPLE]
    strokes = [AMBER, CYAN, CYAN, GREEN, PURPLE]
    for i, label in enumerate(labels):
        add_box(d, xs[i], 62, 86, 45, label, fills[i], strokes[i])
        if i:
            add_arrow(d, xs[i - 1] + 86, 84, xs[i], 84)
    d.add(String(2, 31, "Safety: credentials redacted; source IP replaced by hash and scope; raw payload is not a direct model feature.",
                 fontName=BOLD_FONT, fontSize=7.2, fillColor=RED))
    return d


def grouped_metric_chart(rows):
    d = Drawing(CONTENT_W, 245)
    left, bottom, plot_w, plot_h = 42, 48, CONTENT_W - 55, 158
    d.add(String(0, 228, "Primary supervised metrics by explicitly labelled evaluation scope", fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    for tick in range(0, 101, 20):
        y = bottom + plot_h * tick / 100
        d.add(Line(left, y, left + plot_w, y, strokeColor=MID, strokeWidth=0.4))
        d.add(String(left - 6, y - 3, f"{tick}%", fontName=BODY_FONT, fontSize=6.4, fillColor=MUTED, textAnchor="end"))
    models = ["Decision Tree", "Random Forest", "LSTM"]
    metrics = [("Accuracy", "accuracy", CYAN), ("Balanced", "balanced_accuracy", GREEN), ("Macro F1", "f1_score", PURPLE)]
    group_w = plot_w / len(models)
    bar_w = 24
    mapping = {safe(r["model"]): r for r in rows}
    keys = {"Decision Tree": "decision_tree", "Random Forest": "random_forest", "LSTM": "lstm_classifier"}
    for model_index, model in enumerate(models):
        center = left + group_w * (model_index + 0.5)
        row = mapping[keys[model]]
        for metric_index, (label, key, color) in enumerate(metrics):
            value = float(row[key])
            x = center + (metric_index - 1) * (bar_w + 5) - bar_w / 2
            h = value * plot_h
            d.add(Rect(x, bottom, bar_w, h, fillColor=color, strokeColor=color))
            d.add(String(x + bar_w / 2, bottom + h + 5, f"{value:.3f}", fontName=BOLD_FONT,
                         fontSize=6.1, fillColor=INK, textAnchor="middle"))
        d.add(String(center, bottom - 16, model, fontName=BOLD_FONT, fontSize=7, fillColor=INK, textAnchor="middle"))
    for idx, (label, _, color) in enumerate(metrics):
        x = left + idx * 115
        d.add(Rect(x, 12, 9, 9, fillColor=color, strokeColor=color))
        d.add(String(x + 14, 13, label, fontName=BODY_FONT, fontSize=7, fillColor=INK))
    return d


def class_distribution_chart(train_counts, test_counts):
    d = Drawing(CONTENT_W, 255)
    left, bottom, plot_w, plot_h = 45, 70, CONTENT_W - 58, 145
    d.add(String(0, 238, "Chronological split by class", fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    labels = list(train_counts)
    max_value = max(max(train_counts.values()), max(test_counts.values()))
    upper = int(math.ceil(max_value / 100) * 100)
    for tick in range(0, upper + 1, 100):
        y = bottom + plot_h * tick / upper
        d.add(Line(left, y, left + plot_w, y, strokeColor=MID, strokeWidth=0.4))
        d.add(String(left - 6, y - 3, str(tick), fontName=BODY_FONT, fontSize=6.2, fillColor=MUTED, textAnchor="end"))
    group_w = plot_w / len(labels)
    for idx, label in enumerate(labels):
        center = left + group_w * (idx + 0.5)
        train_v = train_counts[label]
        test_v = test_counts[label]
        for offset, value, color in [(-8, train_v, CYAN), (8, test_v, AMBER)]:
            h = plot_h * value / upper
            d.add(Rect(center + offset - 6, bottom, 12, h, fillColor=color, strokeColor=color))
        short = {"directory_scanning": "Dir scan", "ftp_bruteforce": "FTP brute", "other_anomaly": "Other",
                 "port_scanning": "Port scan", "sql_injection": "SQLi", "ssh_bruteforce": "SSH brute"}.get(label, label.upper())
        d.add(String(center, bottom - 13, short, fontName=BOLD_FONT, fontSize=5.8, fillColor=INK, textAnchor="middle"))
        d.add(String(center, bottom - 24, f"{train_v}/{test_v}", fontName=BODY_FONT, fontSize=5.8, fillColor=MUTED, textAnchor="middle"))
    d.add(Rect(left, 20, 9, 9, fillColor=CYAN, strokeColor=CYAN))
    d.add(String(left + 14, 21, "Train", fontName=BODY_FONT, fontSize=7, fillColor=INK))
    d.add(Rect(left + 78, 20, 9, 9, fillColor=AMBER, strokeColor=AMBER))
    d.add(String(left + 92, 21, "Test", fontName=BODY_FONT, fontSize=7, fillColor=INK))
    d.add(String(left + 160, 21, "Numbers under each class are train/test counts.", fontName=BODY_FONT, fontSize=6.8, fillColor=MUTED))
    return d


def latency_chart(rows):
    d = Drawing(CONTENT_W, 205)
    left, bottom, plot_w, plot_h = 120, 32, CONTENT_W - 145, 140
    d.add(String(0, 188, "Median inference latency for 816 rows", fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    models = ["Decision Tree", "Random Forest", "LSTM", "Isolation Forest"]
    keys = ["decision_tree", "random_forest", "lstm_classifier", "isolation_forest"]
    colors_list = [CYAN, TEAL, PURPLE, AMBER]
    mapping = {safe(r["model"]): r for r in rows}
    max_v = max(float(mapping[k]["median_total_ms"]) for k in keys)
    for idx, (model, key, color) in enumerate(zip(models, keys, colors_list)):
        y = bottom + plot_h - idx * 34
        value = float(mapping[key]["median_total_ms"])
        width = plot_w * value / max_v
        d.add(String(left - 8, y + 3, model, fontName=BOLD_FONT, fontSize=7.1, fillColor=INK, textAnchor="end"))
        d.add(Rect(left, y, max(width, 1), 16, fillColor=color, strokeColor=color))
        d.add(String(left + max(width, 1) + 7, y + 4, f"{value:.4f} ms", fontName=BOLD_FONT, fontSize=6.8, fillColor=INK))
    d.add(String(left, 10, "30 timed runs after 3 warmups; artifact and array loading excluded.", fontName=BODY_FONT, fontSize=6.8, fillColor=MUTED))
    return d


def per_class_chart(eval_report):
    d = Drawing(CONTENT_W, 260)
    left, bottom, plot_w, plot_h = 47, 65, CONTENT_W - 62, 158
    d.add(String(0, 243, "Per-class F1: Decision Tree vs Random Forest", fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    labels = list(eval_report["model_results"]["decision_tree"]["metrics"]["per_class"])
    dt = eval_report["model_results"]["decision_tree"]["metrics"]["per_class"]
    rf = eval_report["model_results"]["random_forest"]["metrics"]["per_class"]
    for tick in range(0, 101, 20):
        y = bottom + plot_h * tick / 100
        d.add(Line(left, y, left + plot_w, y, strokeColor=MID, strokeWidth=0.4))
        d.add(String(left - 6, y - 3, f"{tick}%", fontName=BODY_FONT, fontSize=6.2, fillColor=MUTED, textAnchor="end"))
    group_w = plot_w / len(labels)
    for idx, label in enumerate(labels):
        center = left + group_w * (idx + 0.5)
        for offset, value, color in [(-6, dt[label]["f1_score"], CYAN), (6, rf[label]["f1_score"], TEAL)]:
            h = plot_h * value
            d.add(Rect(center + offset - 5, bottom, 10, h, fillColor=color, strokeColor=color))
        short = {"directory_scanning": "Dir", "ftp_bruteforce": "FTP", "other_anomaly": "Other", "port_scanning": "Port",
                 "sql_injection": "SQLi", "ssh_bruteforce": "SSH", "normal": "Normal", "xss": "XSS"}[label]
        d.add(String(center, bottom - 14, short, fontName=BOLD_FONT, fontSize=6.2, fillColor=INK, textAnchor="middle"))
    d.add(Rect(left, 20, 9, 9, fillColor=CYAN, strokeColor=CYAN))
    d.add(String(left + 14, 21, "Decision Tree", fontName=BODY_FONT, fontSize=7, fillColor=INK))
    d.add(Rect(left + 115, 20, 9, 9, fillColor=TEAL, strokeColor=TEAL))
    d.add(String(left + 129, 21, "Random Forest", fontName=BODY_FONT, fontSize=7, fillColor=INK))
    return d


def lstm_curve(history):
    d = Drawing(CONTENT_W, 255)
    left, bottom, plot_w, plot_h = 45, 48, CONTENT_W - 60, 165
    d.add(String(0, 238, "LSTM training curve across 50 epochs", fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    for tick in range(0, 101, 20):
        y = bottom + plot_h * tick / 100
        d.add(Line(left, y, left + plot_w, y, strokeColor=MID, strokeWidth=0.4))
        d.add(String(left - 6, y - 3, f"{tick}%", fontName=BODY_FONT, fontSize=6.2, fillColor=MUTED, textAnchor="end"))
    def point(epoch, value):
        return left + plot_w * (epoch - 1) / (len(history) - 1), bottom + plot_h * value
    acc_points = [point(item["epoch"], item["accuracy"]) for item in history]
    max_loss = max(item["loss"] for item in history)
    loss_points = [point(item["epoch"], 1 - item["loss"] / max_loss) for item in history]
    for points, color in [(acc_points, CYAN), (loss_points, AMBER)]:
        for a, b in zip(points, points[1:]):
            d.add(Line(a[0], a[1], b[0], b[1], strokeColor=color, strokeWidth=1.5))
    for epoch in [1, 10, 20, 30, 40, 50]:
        x = left + plot_w * (epoch - 1) / (len(history) - 1)
        d.add(String(x, bottom - 14, str(epoch), fontName=BODY_FONT, fontSize=6.2, fillColor=MUTED, textAnchor="middle"))
    d.add(String(left + plot_w / 2, bottom - 28, "Epoch", fontName=BOLD_FONT, fontSize=7, fillColor=INK, textAnchor="middle"))
    d.add(Rect(left, 15, 9, 9, fillColor=CYAN, strokeColor=CYAN))
    d.add(String(left + 14, 16, "Training accuracy", fontName=BODY_FONT, fontSize=7, fillColor=INK))
    d.add(Rect(left + 130, 15, 9, 9, fillColor=AMBER, strokeColor=AMBER))
    d.add(String(left + 144, 16, "1 - normalized loss", fontName=BODY_FONT, fontSize=7, fillColor=INK))
    return d


def confusion_pair(confusions, first, second):
    d = Drawing(CONTENT_W, 270)
    d.add(String(0, 252, "Multiclass confusion matrices", fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    abbreviations = ["N", "SSH", "FTP", "SQLi", "XSS", "DIR", "PORT", "OTH"]
    configs = [(first, 5), (second, CONTENT_W / 2 + 7)]
    for model, origin_x in configs:
        values = confusions[model]["values"]
        title = {"decision_tree": "Decision Tree", "random_forest": "Random Forest", "lstm_classifier": "LSTM"}[model]
        d.add(String(origin_x + 108, 230, title, fontName=BOLD_FONT, fontSize=8.5, fillColor=TEAL, textAnchor="middle"))
        cell = 23
        start_x, start_y = origin_x + 30, 198
        maximum = max(max(row) for row in values)
        for row_idx, row in enumerate(values):
            for col_idx, value in enumerate(row):
                intensity = value / maximum if maximum else 0
                color = colors.Color(0.92 - 0.66 * intensity, 0.97 - 0.45 * intensity, 0.98 - 0.30 * intensity)
                x, y = start_x + col_idx * cell, start_y - row_idx * cell
                d.add(Rect(x, y, cell, cell, fillColor=color, strokeColor=WHITE, strokeWidth=0.5))
                d.add(String(x + cell / 2, y + 8, str(value), fontName=BOLD_FONT, fontSize=5.8,
                             fillColor=WHITE if intensity > 0.65 else INK, textAnchor="middle"))
        for idx, label in enumerate(abbreviations):
            d.add(String(start_x + idx * cell + cell / 2, start_y + cell + 4, label,
                         fontName=BOLD_FONT, fontSize=5.5, fillColor=INK, textAnchor="middle"))
            d.add(String(start_x - 4, start_y - idx * cell + 8, label,
                         fontName=BOLD_FONT, fontSize=5.5, fillColor=INK, textAnchor="end"))
    d.add(String(CONTENT_W / 2, 3, "Rows = actual class; columns = predicted class. N normal, DIR directory scanning, OTH other anomaly.",
                 fontName=BODY_FONT, fontSize=6.8, fillColor=MUTED, textAnchor="middle"))
    return d


def isolation_matrix(confusions):
    values = confusions["isolation_forest"]["values"]
    d = Drawing(CONTENT_W, 190)
    d.add(String(0, 173, "Isolation Forest binary threshold result", fontName=BOLD_FONT, fontSize=10, fillColor=NAVY))
    cell, x0, y0 = 70, 185, 78
    maximum = max(max(row) for row in values)
    for row_idx, row in enumerate(values):
        for col_idx, value in enumerate(row):
            intensity = value / maximum
            color = colors.Color(0.95 - 0.70 * intensity, 0.97 - 0.42 * intensity, 0.98 - 0.15 * intensity)
            x, y = x0 + col_idx * cell, y0 - row_idx * cell
            d.add(Rect(x, y, cell, cell, fillColor=color, strokeColor=WHITE))
            d.add(String(x + cell / 2, y + 27, str(value), fontName=BOLD_FONT, fontSize=12,
                         fillColor=WHITE if intensity > 0.5 else INK, textAnchor="middle"))
    labels = ["Normal", "Attack/anomaly"]
    for idx, label in enumerate(labels):
        d.add(String(x0 + idx * cell + cell / 2, y0 + cell + 5, label, fontName=BOLD_FONT, fontSize=6.5, fillColor=INK, textAnchor="middle"))
        d.add(String(x0 - 8, y0 - idx * cell + 27, label, fontName=BOLD_FONT, fontSize=6.5, fillColor=INK, textAnchor="end"))
    d.add(String(CONTENT_W / 2, 4, "At contamination=0.05, the saved threshold flagged 14 of 737 attacks and no normal rows.",
                 fontName=BODY_FONT, fontSize=7, fillColor=MUTED, textAnchor="middle"))
    return d


def load_data():
    eval_dir = DATA / "ml_ready" / "evaluation"
    eval_report = json.loads((eval_dir / "evaluation_report.json").read_text(encoding="utf-8"))
    confusions = json.loads((eval_dir / "confusion_matrices.json").read_text(encoding="utf-8"))
    preprocess = json.loads((DATA / "ml_ready" / "preprocessing_manifest.json").read_text(encoding="utf-8"))
    dataset = json.loads((DATA / "processed" / "dataset_manifest.json").read_text(encoding="utf-8"))
    training = json.loads((DATA / "ml_ready" / "models" / "training_manifest.json").read_text(encoding="utf-8"))
    lstm = json.loads((DATA / "ml_ready" / "models" / "lstm_metrics.json").read_text(encoding="utf-8"))
    with (eval_dir / "evaluation_summary.csv").open(encoding="utf-8", newline="") as handle:
        summary = list(csv.DictReader(handle))
    samples = {}
    with (DATA / "processed" / "honeypot_dataset.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            samples.setdefault(row["label"], row)
    outputs = {}
    with (DATA / "detections" / "hybrid_ids_results.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = row.get("attack_type")
            if label:
                outputs[label] = row
    features = json.loads((DATA / "ml_ready" / "feature_names.json").read_text(encoding="utf-8"))
    X_test = np.load(DATA / "ml_ready" / "X_test.npy", allow_pickle=False)
    y_test = np.load(DATA / "ml_ready" / "y_test.npy", allow_pickle=False)
    with (LSTM_AUDIT / "aggregate_results.csv").open(encoding="utf-8", newline="") as handle:
        robust_runs = list(csv.DictReader(handle))
    robust_summary = json.loads((LSTM_AUDIT / "aggregate_summary.json").read_text(encoding="utf-8"))
    audit_dirs = ["20260907_group_isolated_audit", "20260907_group_isolated_seed43", "20260907_group_isolated_seed44"]
    robust_audits = [json.loads((LSTM_AUDIT / name / "audit_results.json").read_text(encoding="utf-8")) for name in audit_dirs]
    return eval_report, confusions, preprocess, dataset, training, lstm, summary, samples, outputs, features, X_test, y_test, robust_runs, robust_summary, robust_audits


def build_story(data):
    eval_report, confusions, preprocess, dataset, training, lstm, summary, samples, outputs, features, X_test, y_test, robust_runs, robust_summary, robust_audits = data
    primary_summary = [dict(row, evaluation_scope="legacy chronological holdout") for row in summary if row["model"] in ("decision_tree", "random_forest")]
    macro_precision = float(np.mean([audit["metrics"]["test"]["classification_report"]["macro avg"]["precision"] for audit in robust_audits]))
    macro_recall = float(np.mean([audit["metrics"]["test"]["classification_report"]["macro avg"]["recall"] for audit in robust_audits]))
    normal_fpr = float(np.mean([1.0-audit["metrics"]["test"]["classification_report"]["normal"]["recall"] for audit in robust_audits]))
    primary_summary.append({"model":"lstm_classifier","evaluation_scope":"source-group-isolated 3-run audit","accuracy":robust_summary["accuracy"]["mean"],"balanced_accuracy":macro_recall,"precision":macro_precision,"recall":macro_recall,"f1_score":robust_summary["macro_f1"]["mean"],"false_positive_rate":normal_fpr})
    story = []

    # Cover
    story.extend([
        Spacer(1, 70 * mm),
        p("MODEL EVALUATION, PERFORMANCE AND DATASET REPORT", COVER_TITLE),
        Spacer(1, 5 * mm),
        p("Evaluation parameters, quantitative results, charts, model inputs, dataset samples, and representative system outputs", COVER_SUB),
        Spacer(1, 14 * mm),
    ])
    cover_table = Table([
        [p("EVALUATION", TABLE_HEAD), p("DATASET", TABLE_HEAD), p("SYSTEM", TABLE_HEAD)],
        [p("Evaluation v1.0", TABLE_BODY), p("4,080 accepted events", TABLE_BODY), p("Hybrid IDS prototype", TABLE_BODY)],
    ], colWidths=[CONTENT_W / 3] * 3)
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0B5064")),
        ("BACKGROUND", (0, 1), (-1, 1), PALE_CYAN),
        ("GRID", (0, 0), (-1, -1), 0.4, HexColor("#4E8794")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([
        cover_table, Spacer(1, 12 * mm),
        p("Branch  mock\nEvaluation generated  6 September 2026 UTC\nReport prepared  7 September 2026 IST", COVER_META),
        Spacer(1, 17 * mm),
        p("This document reports both the legacy controlled holdout and a three-seed source-group-isolated LSTM robustness audit. It does not claim production or external generalization. All displayed samples are fictional, sanitized, redacted, or pseudonymized.", COVER_META),
        NextPageTemplate("Body"), PageBreak(),
    ])

    # Guide and TOC
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("TOC1", fontName=BOLD_FONT, fontSize=8.5, leading=13,
                                      leftIndent=0, textColor=NAVY, spaceBefore=2)]
    story.extend([
        p("Document guide", FRONT_H1), HRFlowable(width="100%", thickness=1.1, color=CYAN, spaceAfter=7),
        p("The report answers three questions: which parameters define the evaluation, how the models performed, and what data entered and left the system. Legacy figures use protected saved artifacts. A separately labelled audit trained three isolated LSTM candidates; none was promoted or substituted into runtime.", CALLOUT),
        Table([[metric_card("4,080", "accepted events", CYAN), metric_card("816", "test rows", GREEN),
                metric_card("23", "encoded features", PURPLE), metric_card("8", "classes", AMBER)]],
              colWidths=[CONTENT_W / 4] * 4, style=[("VALIGN", (0, 0), (-1, -1), "TOP")]),
        Spacer(1, 12), p("Contents", FRONT_H1), HRFlowable(width="100%", thickness=1.1, color=CYAN, spaceAfter=7), toc,
        PageBreak(),
    ])

    # Executive summary
    story += section("Executive summary")
    story.extend([
        p("The legacy evaluation uses a fixed chronological 80/20 holdout: 3,264 training rows and 816 test rows. The tabular classifiers consume 23 encoded features, while the LSTM consumes causal sequences of shape 10 x 23. A separate robustness audit uses source-IP-hash group-isolated train/validation/test partitions with training-only preprocessing and best-validation-loss checkpoints for seeds 42, 43, and 44."),
        p("Decision Tree is the selected tabular classifier with 98.04% accuracy, 94.65% balanced accuracy, 95.82% macro F1, and a 1.27% normal-as-attack false-positive rate. Random Forest records 96.45% accuracy and 95.10% macro F1 but misclassifies 24 of 79 normal rows. The active LSTM reproduces 100% on the legacy split; the source-group-isolated audit instead estimates 97.61% mean accuracy (population SD 0.35 percentage points) and 96.75% mean macro F1 (SD 0.33 points). Isolation Forest ranks anomalies well (ROC-AUC 0.9358) but its saved threshold has only 1.90% attack recall."),
        p("The source dataset contains 5,193 raw events. Validation accepted 4,080 events - exactly 510 per class - and rejected 1,113. Credentials are redacted, source addresses are replaced by a hash and scope, and raw payload text is excluded from direct model inputs."),
        p("Headline conclusion: the LSTM's legacy 100% is explained by an optimistic evaluation design, not hidden. Source-group isolation lowers the defensible internal estimate to 97.61% mean accuracy while keeping performance strong. Template/campaign and external isolation are still required, and the Isolation Forest threshold still requires calibration.", WARNING),
    ])

    # Scope
    story += section("1. Evaluation scope and design")
    story.extend([
        p("1.1 Evaluation objective", H2),
        p("The objective is to measure how accurately, evenly, and efficiently the saved models classify the legacy holdout, then test LSTM robustness under source-group isolation. Protected active artifacts are never fitted or modified; the audit creates separately named candidates only. Each result is tied to its evaluation scope and model role."),
        table([
            ["Model", "Role", "Input", "Fit scope"],
            ["Decision Tree", "Known-attack tabular classifier", "816 x 23", "3,264 training rows"],
            ["Random Forest", "Known-attack tabular comparison", "816 x 23", "3,264 training rows"],
            ["LSTM (active)", "Causal sequence classifier; legacy split", "816 x 10 x 23", "3,264 training sequences"],
            ["LSTM (audit)", "Source-group-isolated candidates; not promoted", "710/710/711 test", "2,778-2,779 train; 591-592 validation"],
            ["Isolation Forest", "Unknown/anomaly signal", "816 x 23", "431 normal training rows only"],
        ], [CONTENT_W * .19, CONTENT_W * .34, CONTENT_W * .19, CONTENT_W * .28]),
        p("1.2 Data separation and leakage controls", H2),
        bullet("Chronological split with test size 20%; transform fitting uses training rows only."),
        bullet("Feature engineering uses current and past events only; no future event or label is used."),
        bullet("Test sequences target test rows only and use no context labels."),
        bullet("Direct identifiers, raw payloads, event labels, event text, paths, and metadata are excluded from direct model inputs."),
        bullet("Legacy evaluation loads fixed artifacts; model fit is not called and protected hashes remain unchanged."),
        bullet("The LSTM audit groups by source_ip_hash, fits preprocessing on training only, constructs sequences within isolated partitions, and selects the best epoch using validation loss."),
        p("The legacy split is chronology-aware but not independent: 791/816 test rows share a source hash with training, all 816 reuse a training service/event/path template, and the train-end and test-start timestamps are identical. No byte-identical train/test sequences were found. The audit reduces source-group dependence to zero overlap in each split, but controlled templates still repeat across groups."),
        p("1.3 Model configuration", H2),
        table([
            ["Model", "Implemented configuration"],
            ["Decision Tree", "Gini; max_depth=12; min_samples_leaf=2; class_weight=balanced; random_state=42"],
            ["Random Forest", "200 trees; Gini; max_depth=16; max_features=sqrt; min_samples_leaf=2; class_weight=balanced_subsample; n_jobs=1; seed=42"],
            ["Isolation Forest", "200 estimators; contamination=0.05; n_jobs=1; trained only on 431 normal rows; seed=42"],
            ["LSTM (active)", "PyTorch; hidden_size=64; one recurrent layer; dropout=0.30; 50 epochs; batch=32; Adam lr=0.001; weight_decay=0.0001; class-weighted cross entropy; CPU; saved legacy artifact"],
            ["LSTM (audit)", "Same 64-unit/one-layer/dropout=0.30 architecture; batch=64; max 40 epochs; Adam lr=0.001; weight_decay=0.0001; seeds 42-44; best validation-loss checkpoint; CPU; not promoted"],
        ], [CONTENT_W * .20, CONTENT_W * .80]),
    ])

    # Parameters
    story += section("2. Evaluation parameters")
    story.extend([
        p("2.1 Core classification metrics", H2),
        table([
            ["Parameter", "Definition", "Why it matters"],
            ["Accuracy", "Correct predictions / all predictions", "Overall correctness; can hide minority-class weakness."],
            ["Precision", "TP / (TP + FP)", "How often an alert for a class is correct."],
            ["Recall", "TP / (TP + FN)", "How many real instances of a class are detected."],
            ["F1 score", "2 x precision x recall / (precision + recall)", "Balances missed attacks and false alerts."],
            ["Balanced accuracy", "Mean recall across classes", "Gives every class equal importance despite test imbalance."],
            ["Macro precision/recall/F1", "Unweighted mean across the eight classes", "Exposes weak performance on small classes such as other_anomaly."],
            ["Weighted F1", "Class-support-weighted mean F1", "Summarizes operational volume but favors common classes."],
            ["False-positive rate", "FP / (FP + TN)", "Here the headline supervised FPR is true normal predicted as any attack."],
            ["Confusion matrix", "Counts by actual row and predicted column", "Shows exactly which classes are confused."],
        ], [CONTENT_W * .20, CONTENT_W * .36, CONTENT_W * .44], small=True),
        p("2.2 Anomaly-ranking metrics", H2),
        table([
            ["Parameter", "Interpretation"],
            ["ROC-AUC", "Probability that a random attack/anomaly receives a higher anomaly score than a random normal record across thresholds."],
            ["Average precision", "Precision-recall ranking summary; particularly relevant to imbalanced anomaly detection."],
            ["Specificity", "True-normal rate: TN / (TN + FP)."],
            ["Threshold recall", "Fraction of attacks flagged at the saved contamination-based operating threshold."],
        ], [CONTENT_W * .25, CONTENT_W * .75]),
        p("Isolation Forest's binary accuracy and F1 are not directly comparable with the eight-class supervised models. It is trained label-free on normal rows and should be interpreted through ranking quality plus its selected threshold."),
        p("2.3 Timing protocol and selection rule", H2),
        bullet("Inference timing: 3 warmup runs, followed by 30 timed runs over all 816 test rows."),
        bullet("Reported median excludes artifact and array loading; both total milliseconds and per-row microseconds are saved."),
        bullet("Tabular selection order: higher macro F1, balanced accuracy, macro recall, accuracy, then lower normal-as-attack FPR."),
        bullet("Decision Tree is selected over Random Forest. LSTM and Isolation Forest retain separate hybrid roles and do not replace it."),
    ])

    # Dataset
    story += section("3. Dataset used and model inputs")
    story.extend([
        p("3.1 Dataset construction", H2), pipeline_diagram(),
        p("Figure 1. Dataset validation, sanitization, causal engineering, splitting, and model-input construction.", CAPTION),
        Table([[metric_card("5,193", "raw events", AMBER), metric_card("4,080", "accepted", GREEN),
                metric_card("1,113", "rejected", RED), metric_card("510", "events per class", CYAN)]],
              colWidths=[CONTENT_W / 4] * 4, style=[("VALIGN", (0, 0), (-1, -1), "TOP")]),
        Spacer(1, 8),
        p("Acceptance rate: 78.57%. Rejection rate: 21.43%. Duplicate accepted event IDs removed: 0. The accepted dataset is deliberately balanced before chronological splitting."),
        p("3.2 Class distribution after chronological split", H2),
        class_distribution_chart(preprocess["labels"]["train_counts"], preprocess["labels"]["test_counts"]),
        p("Figure 2. Training and test counts by class. The total dataset is balanced, but chronology changes the class mix inside each split.", CAPTION),
        table([
            ["Class", "Train", "Test", "Total"],
            *[[label, str(preprocess["labels"]["train_counts"][label]), str(preprocess["labels"]["test_counts"][label]), "510"]
              for label in preprocess["labels"]["train_counts"]],
            ["Total", "3,264", "816", "4,080"],
        ], [CONTENT_W * .46, CONTENT_W * .18, CONTENT_W * .18, CONTENT_W * .18], alignments=["LEFT", "RIGHT", "RIGHT", "RIGHT"]),
        p("The test set has only 25 other_anomaly rows but 134 port_scanning rows. Macro metrics and per-class tables are therefore essential; accuracy alone would overweight the larger test classes."),
    ])

    story.extend([
        p("3.3 Dataset fields and privacy treatment", H2),
        table([
            ["Field group", "Fields", "Treatment"],
            ["Identity and time", "event_id, timestamp_utc, source_ip_hash, source_ip_scope", "Source IP is replaced by pseudonymous hash and coarse scope."],
            ["Network", "source_port, destination_port, service, protocol", "Retained for behavior and service context."],
            ["Event", "event_type, event, severity, status", "Retained in sanitized dataset but excluded from direct model inputs."],
            ["Presence flags", "username_present, session_id_present", "Boolean presence only; raw credentials and session IDs are excluded."],
            ["HTTP context", "request_method, request_path", "Method may be encoded; path is not a direct model input."],
            ["Payload and metadata", "payload_length, payload_json, metadata_json", "Length/derived pattern counts may be features; raw text is not direct input."],
            ["Target", "label", "Eight approved classes; used for supervised training/evaluation only."],
        ], [CONTENT_W * .19, CONTENT_W * .38, CONTENT_W * .43], small=True),
        p("3.4 Engineered and encoded feature set", H2),
        p("Twelve numerical features are standardized with training medians/scaling. Four categorical fields are one-hot encoded, producing 11 indicator columns and 23 total encoded features."),
        table([
            ["Numerical feature", "Definition"],
            ["source_port / destination_port", "Connection context."],
            ["username_present / session_id_present", "Binary presence flags; values are not exposed."],
            ["failed_attempts", "Same source/service failures in the current and previous 60 seconds."],
            ["requests_per_minute", "Same source/service events in the current and previous 60 seconds."],
            ["payload_length", "Length of sanitized payload with safe fallback."],
            ["session_duration", "Seconds since current source/service session start; gap >300 seconds resets."],
            ["suspicious_keyword_count", "Reconnaissance, sensitive-file, and command-tool indicators."],
            ["username_repetition", "Earlier uses of the same in-memory pseudonymized username in 300 seconds."],
            ["time_between_requests", "Seconds since previous event in the same source/service group."],
            ["sqli_xss_pattern_count", "SQLi and XSS matches in sanitized request/payload/metadata text."],
        ], [CONTENT_W * .31, CONTENT_W * .69], small=True),
        p("One-hot fields: source_ip_scope={loopback, private}; service={ftp, http, ssh}; protocol={ftp, http, ssh}; request_method={GET, missing, POST}. Unknown test categories are ignored."),
    ])

    story.extend([
        p("3.5 Controlled sample inputs", H2),
        p("The following are safe demonstration examples used only against the local honeypot/decoy services. They are not instructions for attacking external systems.", WARNING),
        table([
            ["Scenario", "Example input", "Expected dataset label"],
            ["Normal search", "GET /search?q=step4-central-test", "normal"],
            ["SQL injection", "Username: admin' OR '1'='1 ; Password: [REDACTED]", "sql_injection"],
            ["XSS", "<img src=x onerror=alert(1)>", "xss"],
            ["Directory traversal", "../../etc/passwd or /.env", "directory_scanning"],
            ["SSH brute force", "Three failed fake credential attempts to port 2222", "ssh_bruteforce"],
            ["FTP brute force", "Repeated failed fake logins to port 2121", "ftp_bruteforce"],
            ["Port scan", "Connections to 2121, 2222, and 8080 inside 30 seconds", "port_scanning"],
            ["Other anomaly", "Unexpected FTP connection/open behavior not mapped to a named attack", "other_anomaly"],
        ], [CONTENT_W * .20, CONTENT_W * .52, CONTENT_W * .28], small=True),
        p("3.6 Representative sanitized dataset rows", H2),
    ])
    sample_order = ["normal", "ssh_bruteforce", "ftp_bruteforce", "sql_injection", "xss", "directory_scanning", "port_scanning", "other_anomaly"]
    sample_rows = [["Label", "Service", "Event", "Port", "Method/path", "Payload len", "Status"]]
    for label in sample_order:
        row = samples[label]
        method_path = " ".join(part for part in [row.get("request_method", ""), row.get("request_path", "")] if part) or "-"
        sample_rows.append([label, row["service"], row["event"], row["destination_port"], method_path, row["payload_length"], row["status"]])
    story.extend([
        table(sample_rows, [CONTENT_W * .17, CONTENT_W * .09, CONTENT_W * .25, CONTENT_W * .08,
                            CONTENT_W * .20, CONTENT_W * .10, CONTENT_W * .11], small=True),
        p("Sample rows are drawn from data/processed/honeypot_dataset.csv. Source hashes, session identifiers, headers, usernames, and payload bodies are intentionally omitted from this report."),
        p("3.7 Encoded input sample", H2),
        p("The first saved X_test row is a 23-value float32 vector. Its mapped target is port_scanning. Values below are already standardized or one-hot encoded; they are not raw traffic fields."),
    ])
    vector_rows = [["Feature", "Value", "Feature", "Value", "Feature", "Value"]]
    vector = X_test[0].tolist()
    for start in range(0, len(features), 3):
        row = []
        for index in range(start, min(start + 3, len(features))):
            row += [features[index].replace("numeric__", "").replace("categorical__", ""), f"{vector[index]:.6f}"]
        while len(row) < 6:
            row += ["", ""]
        vector_rows.append(row)
    story.extend([
        table(vector_rows, [CONTENT_W * .23, CONTENT_W * .10] * 3, small=True),
        p("The sequence input uses shape 816 x 10 x 23. Each target receives up to ten current/past feature rows from the same pseudonymous source/service group, with left zero padding for short histories."),
    ])

    # Performance
    story += section("4. Performance evaluation")
    story.extend([
        p("4.1 Primary model comparison", H2), grouped_metric_chart(primary_summary),
        p("Figure 3. Primary reported metrics: tabular models use the labelled legacy holdout; LSTM uses the source-group-isolated three-run mean.", CAPTION),
    ])
    overall_rows = [["Model", "Evaluation scope", "Accuracy", "Balanced acc.", "Macro precision", "Macro recall", "Macro F1", "Normal FPR"]]
    display_names = {"decision_tree": "Decision Tree", "random_forest": "Random Forest", "lstm_classifier": "LSTM", "isolation_forest": "Isolation Forest"}
    for row in primary_summary:
        overall_rows.append([
            display_names[row["model"]], row["evaluation_scope"], f'{float(row["accuracy"]):.4f}', f'{float(row["balanced_accuracy"]):.4f}',
            f'{float(row["precision"]):.4f}', f'{float(row["recall"]):.4f}', f'{float(row["f1_score"]):.4f}',
            f'{float(row["false_positive_rate"]):.4f}',
        ])
    story.extend([
        table(overall_rows, [CONTENT_W * .14, CONTENT_W * .22] + [CONTENT_W * .1067] * 6, small=True, alignments=["LEFT", "LEFT"] + ["RIGHT"] * 6),
        p("Decision Tree wins the tabular selection rule: its macro F1 is 0.9582 versus 0.9510 for Random Forest, balanced accuracy is higher, and its normal-as-attack FPR is 0.0127 versus 0.3038. The primary LSTM row is the group-isolated mean (accuracy 0.9761; macro F1 0.9675), not the legacy 1.0000 result. The evaluation scopes are explicit and should not be treated as a single shared test set."),
        p("4.2 Inference latency", H2), latency_chart(summary),
        p("Figure 4. Median total prediction time for 816 rows. Decision Tree is approximately 128 times faster than Random Forest in this saved benchmark.", CAPTION),
        p("Latency was measured on the local CPU runtime. It excludes model loading, preprocessing, storage, XAI, agents, dashboard delivery, and alert transport; therefore it is model inference latency, not end-to-end incident latency."),
        p("4.3 Per-class performance", H2), per_class_chart(eval_report),
        p("Figure 5. Per-class F1 exposes differences hidden by overall accuracy. The active legacy LSTM is omitted because every saved per-class F1 equals 1.0000; source-group audit results are reported separately in Section 4.5.", CAPTION),
    ])
    dt_per = eval_report["model_results"]["decision_tree"]["metrics"]["per_class"]
    rf_per = eval_report["model_results"]["random_forest"]["metrics"]["per_class"]
    per_rows = [["Class", "Support", "DT precision", "DT recall", "DT F1", "RF precision", "RF recall", "RF F1"]]
    for label in dt_per:
        per_rows.append([label, str(dt_per[label]["support"]), f'{dt_per[label]["precision"]:.4f}', f'{dt_per[label]["recall"]:.4f}',
                         f'{dt_per[label]["f1_score"]:.4f}', f'{rf_per[label]["precision"]:.4f}', f'{rf_per[label]["recall"]:.4f}',
                         f'{rf_per[label]["f1_score"]:.4f}'])
    story.extend([
        table(per_rows, [CONTENT_W * .21, CONTENT_W * .09] + [CONTENT_W * .1167] * 6, small=True,
              alignments=["LEFT"] + ["RIGHT"] * 7),
        p("Decision Tree's weakest class is other_anomaly (recall 0.6400, F1 0.7805). Random Forest's weakest result is normal (recall 0.6962, F1 0.8209), driven by 24 normal rows labeled directory_scanning."),
        p("4.4 Confusion matrices", H2), confusion_pair(confusions, "decision_tree", "random_forest"),
        p("Figure 6. Decision Tree and Random Forest multiclass confusion matrices.", CAPTION),
        confusion_pair(confusions, "lstm_classifier", "decision_tree"),
        p("Figure 7. The active legacy LSTM is perfectly diagonal on the original holdout; Decision Tree is repeated as a visual reference. This is not the source-group audit confusion matrix.", CAPTION),
        p("Decision Tree errors: 1 normal -> directory_scanning, 6 directory_scanning -> normal, and 9 other_anomaly -> ssh_bruteforce. Random Forest errors: 24 normal -> directory_scanning, 1 SQLi -> XSS, and 4 other_anomaly -> SSH brute force."),
    ])

    audit_table = [["Evaluation", "Seed", "Best epoch", "Train", "Validation", "Test", "Test accuracy", "Balanced acc.", "Macro F1"]]
    audit_table.append(["Legacy chronological", "saved", "50", "3,264", "0", "816", "1.0000", "1.0000", "1.0000"])
    for row in robust_runs:
        audit_table.append(["Source-group audit", row["seed"], row["best_epoch"], row["train_rows"], row["validation_rows"], row["test_rows"], f'{float(row["test_accuracy"]):.4f}', f'{float(row["test_balanced_accuracy"]):.4f}', f'{float(row["test_macro_f1"]):.4f}'])
    audit_table.append(["Audit mean", "42-44", "-", "-", "-", "710/710/711", f'{robust_summary["accuracy"]["mean"]:.4f}', f'{np.mean([float(row["test_balanced_accuracy"]) for row in robust_runs]):.4f}', f'{robust_summary["macro_f1"]["mean"]:.4f}'])
    story.extend([
        p("4.5 LSTM legacy result and robustness audit", H2), lstm_curve(lstm["training_history"]),
        p("Figure 8. Training accuracy rises from 0.6360 to approximately 0.9770 while loss falls from 1.3267 to 0.0572.", CAPTION),
        table([
            ["Split", "Accuracy", "Balanced accuracy", "Macro F1"],
            ["Training", f'{lstm["train_metrics"]["accuracy"]:.4f}', f'{lstm["train_metrics"]["balanced_accuracy"]:.4f}', f'{lstm["train_metrics"]["macro_f1"]:.4f}'],
            ["Controlled test", f'{lstm["test_metrics"]["accuracy"]:.4f}', f'{lstm["test_metrics"]["balanced_accuracy"]:.4f}', f'{lstm["test_metrics"]["macro_f1"]:.4f}'],
        ], [CONTENT_W * .31, CONTENT_W * .23, CONTENT_W * .23, CONTENT_W * .23], alignments=["LEFT", "RIGHT", "RIGHT", "RIGHT"]),
        p("The saved training accuracy is 0.9792 while the legacy test score is 1.0000. That is not the classic signature of memorizing the training set; it is evidence that the held-out distribution is easier or closely related. Direct auditing confirms that 791/816 legacy test rows share a source hash with training, 816/816 reuse a service/event/path template, and the boundary timestamp is identical. No byte-identical train/test sequences were found."),
        table(audit_table, [CONTENT_W * .18, CONTENT_W * .07, CONTENT_W * .09, CONTENT_W * .09, CONTENT_W * .10, CONTENT_W * .10, CONTENT_W * .12, CONTENT_W * .12, CONTENT_W * .13], small=True, alignments=["LEFT", "RIGHT", "RIGHT", "RIGHT", "RIGHT", "RIGHT", "RIGHT", "RIGHT", "RIGHT"]),
        p("Across three source-group-isolated runs, test accuracy is 0.9761 mean with 0.0035 population standard deviation (range 0.9718-0.9803); macro F1 is 0.9675 mean with 0.0033 standard deviation (range 0.9635-0.9715). Every outer train/test and inner train/validation source-group intersection is zero. The active model hash remained unchanged. The seed-42 checkpoint and matching preprocessor are packaged only as a reproducible candidate, not as a promoted runtime model. Because service/event/path templates still repeat across groups, external or template/campaign-isolated testing remains required.", WARNING),
        p("4.6 Isolation Forest threshold evaluation", H2), isolation_matrix(confusions),
        p("Figure 9. Binary confusion matrix at the saved contamination=0.05 operating point.", CAPTION),
        table([
            ["Metric", "Value", "Interpretation"],
            ["ROC-AUC", "0.9358", "Good cross-threshold ranking on this controlled binary view."],
            ["Average precision", "0.9929", "High ranking score, influenced by 737/816 positives."],
            ["Threshold recall", "0.0190", "Only 14 of 737 attacks were flagged at the saved threshold."],
            ["Specificity", "1.0000", "All 79 normal rows remained normal."],
            ["Balanced accuracy", "0.5095", "Near chance at the selected threshold."],
        ], [CONTENT_W * .24, CONTENT_W * .16, CONTENT_W * .60]),
        p("The ranking metrics and threshold metrics tell different stories. The anomaly score orders many attacks above normal, but contamination=0.05 is too conservative for this evaluation distribution. Threshold calibration must use a validation set and an explicit operational false-positive budget."),
    ])

    # Outputs
    story += section("5. Sample outputs")
    story.extend([
        p("5.1 Representative final IDS outputs", H2),
        p("The table below is derived from the latest saved result for each class. Raw source IPs, credentials, payloads, session IDs, and full event identifiers are excluded."),
    ])
    output_order = ["normal", "sql_injection", "xss", "ssh_bruteforce", "ftp_bruteforce", "directory_scanning", "port_scanning", "other_anomaly"]
    output_rows = [["Attack type", "Decision", "Confidence", "Anomaly", "Model used", "Threat", "Score", "Action"]]
    for label in output_order:
        row = outputs.get(label, {})
        response = ((row.get("agents") or {}).get("response") or {})
        output_rows.append([
            label, row.get("prediction", "-"), f'{float(row.get("confidence", 0)):.4f}', f'{float(row.get("anomaly_score", 0)):.4f}',
            row.get("model_used", "-"), row.get("threat_level", "-"), str(row.get("threat_score", "-")), response.get("recommended_action", "-"),
        ])
    story.extend([
        table(output_rows, [CONTENT_W * .17, CONTENT_W * .10, CONTENT_W * .10, CONTENT_W * .10, CONTENT_W * .20,
                            CONTENT_W * .10, CONTENT_W * .07, CONTENT_W * .16], small=True),
        p("Normal activity is preserved as normal with Low score 0/no response. Named attacks become High or Critical and receive simulation-only recommendations. These rows represent live hybrid results, not just offline test predictions."),
        p("5.2 Detailed SQL injection result", H2),
    ])
    sql = outputs["sql_injection"]
    human = (sql.get("xai") or {}).get("human_reason") or {}
    response = ((sql.get("agents") or {}).get("response") or {})
    top_features = (((sql.get("xai") or {}).get("shap") or {}).get("top_features") or [])[:5]
    story.extend([
        table([
            ["Output field", "Saved value"],
            ["Prediction", f'{sql.get("prediction")} / {sql.get("attack_type")}'],
            ["Decision source", f'{sql.get("model_used")} - {sql.get("fusion_reason")}'],
            ["Confidence / anomaly score", f'{sql.get("confidence"):.2f} / {sql.get("anomaly_score"):.6f}'],
            ["Threat", f'{sql.get("threat_level")} ({sql.get("threat_score")}/100)'],
            ["Human reason", human.get("summary", "-")],
            ["Agent recommendation", f'{response.get("recommended_action")} for {response.get("duration_seconds")} seconds; analyst approval required={response.get("requires_analyst_approval")}'],
            ["Safety", "mode=simulation; automatic_host_blocking=false; host_firewall_changed=false; os_command_executed=false"],
        ], [CONTENT_W * .24, CONTENT_W * .76]),
        p("Top SHAP contributions for the selected Decision Tree component", H3),
        table([["Feature", "Value", "SHAP value", "Direction"]] + [[f["feature"], f'{f["value"]:.6f}', f'{f["shap_value"]:.6f}', f["direction"]] for f in top_features],
              [CONTENT_W * .37, CONTENT_W * .15, CONTENT_W * .15, CONTENT_W * .33], small=True),
        p("The final SQLi decision was rule-driven. SHAP explains the selected tabular component and explicitly does not claim to be the final decision source. The saved XAI privacy flags confirm no credentials, raw payload, or source IP is included."),
        p("5.3 Attacker-visible fictional output", H2),
        p("For a detected SQL injection, the portal returns six deterministic fictional employee-directory rows. For XSS it returns the first four rows plus a fake session and fake user. React renders values as text; no SQL query or submitted JavaScript executes."),
    ])
    employees = [
        ["NS-1042", "Aarav Mehta", "Finance", "Senior Accountant", "finance-internal"],
        ["NS-1187", "Maya Chen", "People Operations", "HR Business Partner", "hr-confidential"],
        ["NS-1214", "Noah Williams", "Infrastructure", "Systems Engineer", "it-operations"],
        ["NS-1308", "Isha Kapoor", "Legal", "Compliance Analyst", "legal-review"],
        ["NS-1421", "Lucas Martin", "Sales", "Regional Manager", "sales-internal"],
        ["NS-1503", "Sara Ahmed", "Executive Office", "Executive Assistant", "executive-confidential"],
    ]
    story.extend([
        table([["Employee ID", "Name", "Department", "Role", "Access level"]] + employees,
              [CONTENT_W * .15, CONTENT_W * .18, CONTENT_W * .22, CONTENT_W * .25, CONTENT_W * .20], small=True),
        table([
            ["Simulation", "Additional fictional exposure", "Record count", "Safety"],
            ["SQL injection", "northstar_hr.employee_directory", "6", "fictional_data_only=true; real_database_access=false"],
            ["XSS", "Session ns_demo_session_7f31c9; user guest.contractor@northstar.example", "4", "unrestricted_javascript=false; rendering=react_text_nodes"],
        ], [CONTENT_W * .17, CONTENT_W * .42, CONTENT_W * .13, CONTENT_W * .28], small=True),
        p("All names, addresses under the reserved .example domain, database names, sessions, access levels, and records are fictional. The exact displayed result is stored in the exposure audit for defender review."),
    ])

    # Findings
    story += section("6. Interpretation, limitations, and next steps")
    story.extend([
        p("6.1 What the results support", H2),
        bullet("The saved Decision Tree is a strong and efficient tabular component for the current controlled known-attack distribution."),
        bullet("SQLi, XSS, FTP brute force, and port scanning have perfect Decision Tree test F1 in this artifact."),
        bullet("The source-group-isolated LSTM audit provides a more defensible internal estimate than the legacy 100%: 97.61% mean accuracy and 96.75% mean macro F1 across seeds 42-44."),
        bullet("The hybrid design benefits from role separation: deterministic rules, interpretable tabular classification, temporal classification, and anomaly ranking."),
        bullet("Privacy controls are embedded in dataset construction, XAI output, and reporting."),
        p("6.2 What the results do not support", H2),
        bullet("They do not prove production performance or resistance to novel adversarial payloads."),
        bullet("They do not establish that the LSTM will retain 97.61% mean accuracy on unseen templates, campaigns, collection environments, or an external dataset."),
        bullet("They do not show that the current Isolation Forest threshold is operationally useful; its recall is 1.90%."),
        bullet("Model-only latency does not equal end-to-end alert latency."),
        bullet("The controlled/synthetic balance does not reproduce real-world base rates."),
        p("6.3 Priority evaluation upgrades", H2),
        bullet("Create a permanent external holdout with unseen payload templates, sources, sessions, and collection time periods.", "1"),
        bullet("Extend the implemented source-group audit to session/campaign and template isolation; remove semantic near-duplicates before sequence construction.", "2"),
        bullet("Add benign hard negatives containing suspicious punctuation, keywords, HTML fragments, and administrator terminology.", "3"),
        bullet("Add obfuscated, encoded, mixed-case, and multi-step SQLi/XSS variants while preserving containment.", "4"),
        bullet("Keep the implemented group-isolated validation-loss checkpointing; add probability calibration and Isolation Forest threshold selection.", "5"),
        bullet("Expand beyond the current three-seed mean/variance to more folds or formal confidence intervals; add calibration error and end-to-end latency percentiles.", "6"),
        bullet("Record model/data version with every live result and add drift/unknown-rate monitoring.", "7"),
        p("6.4 Recommended acceptance criteria", H2),
        table([
            ["Area", "Suggested gate"],
            ["Known attacks", "External/grouped macro F1 and macro recall thresholds agreed before testing; no metric selected after seeing test labels."],
            ["Normal traffic", "Normal-as-attack FPR within an explicit analyst alert budget."],
            ["Anomaly detector", "Validation-selected threshold with minimum recall and maximum FPR; report ROC/PR curves plus operating point."],
            ["Calibration", "Reliability diagram and expected calibration error; calibrate confidence before threat-score use."],
            ["Latency", "Measure p50/p95 end-to-end from event write through IDS, XAI, agents, storage, and alert acceptance."],
            ["Reproducibility", "Artifact hashes, random seeds, dependency versions, immutable test set, and one command to regenerate the report."],
        ], [CONTENT_W * .22, CONTENT_W * .78]),
        p("Final assessment", H2),
        p("The current artifacts are internally consistent and suitable for an academic controlled demonstration. The most defensible headline is not 'the system is 100% accurate'; it is 'the active LSTM reproduces 100% on a leakage-prone legacy split, while a source-group-isolated three-seed audit estimates 97.61% mean accuracy and 96.75% mean macro F1; external/template-isolated validation and anomaly-threshold calibration remain required.'", CALLOUT),
    ])

    # Appendix
    story += section("Appendix A. Artifact provenance and reproduction")
    story.extend([
        p("A.1 Source artifacts", H2),
        table([
            ["Artifact", "Purpose"],
            ["data/processed/dataset_manifest.json", "Raw, accepted, rejected, label, field, and sanitization counts."],
            ["data/processed/honeypot_dataset.csv", "4,080-row sanitized modeling dataset."],
            ["data/ml_ready/preprocessing_manifest.json", "Split, features, sequence contract, safeguards, and array hashes."],
            ["data/ml_ready/models/training_manifest.json", "Tabular/anomaly configuration, fit scopes, and artifact hashes."],
            ["data/ml_ready/models/lstm_metrics.json", "LSTM history, training/test metrics, class weights, and confusion matrices."],
            ["report_evidence/lstm_robustness/aggregate_results.csv", "Seed-level source-group-isolated LSTM test metrics."],
            ["report_evidence/lstm_robustness/aggregate_summary.json", "Three-run accuracy/macro-F1 mean, population SD, and range."],
            ["report_evidence/lstm_robustness/*/audit_results.json", "Exact split overlap, configuration, per-class results, and active-model integrity."],
            ["report_evidence/lstm_robustness/20260907_candidate_bundle_seed42", "Unpromoted checkpoint, matching preprocessor, split assignments, predictions, confusion matrix, and history."],
            ["data/ml_ready/evaluation/evaluation_report.json", "Complete evaluation metrics and timing protocol."],
            ["data/ml_ready/evaluation/evaluation_summary.csv", "Legacy saved-holdout metrics and latency inputs; LSTM primary comparison uses the separate robustness audit."],
            ["data/ml_ready/evaluation/confusion_matrices.json", "Matrices used in Figures 6, 7, and 9."],
            ["data/ml_ready/evaluation/model_selection.json", "Selection criteria and hybrid model roles."],
            ["data/detections/hybrid_ids_results.jsonl", "Representative live hybrid outputs used in Section 5."],
            ["website/backend/decoy_simulation.js", "Deterministic fictional SQLi/XSS result definitions."],
        ], [CONTENT_W * .43, CONTENT_W * .57], small=True),
        p("A.2 Reproduction commands", H2),
        p("The project services must remain stopped while retraining or replacing model artifacts. Legacy evaluation loads saved artifacts without retraining. The commands below reproduce the separate audit candidates and do not promote them."),
        p("cd D:\\honeypot_v2\n.\\.venv\\Scripts\\Activate.ps1\npython -m machine_learning.evaluate_models", CODE),
        p("data\\runtime\\python312\\python.exe scripts\\audit_lstm_generalization.py --seed 42\ndata\\runtime\\python312\\python.exe scripts\\audit_lstm_generalization.py --seed 43\ndata\\runtime\\python312\\python.exe scripts\\audit_lstm_generalization.py --seed 44", CODE),
        p("Optional end-to-end regression verification:", BODY),
        p("python .\\scripts\\final_system_test.py", CODE),
        p("A.3 Evaluation integrity statement", H2),
        p("The legacy evaluation manifest states: chronological split preserved; test labels used only for evaluation; inference timing excludes artifact loading; model fit was not called; and protected artifacts were not modified. The separate audit records seeds 42-44, source-group-isolated outer and validation splits, training-only preprocessing, best-validation-loss checkpointing, exact predictions/confusion matrices, and active-model hashes. Neither evaluation proves external or unseen-template generalization. Prepared from local project artifacts on branch mock; all seven runtime service ports were closed before generation."),
    ])
    return story


def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    data = load_data()
    doc = EvaluationDoc(str(OUTPUT))
    doc.multiBuild(build_story(data))
    print(OUTPUT)


if __name__ == "__main__":
    build()
