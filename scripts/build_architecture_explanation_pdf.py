"""Build the project-specific architecture explanation PDF.

The document is intentionally generated from repository facts and the verified
report evidence.  It does not start services, modify models, or contact external
systems.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "pdf" / "PROJECT_ARCHITECTURE_EXPLANATION.pdf"
RUN = ROOT / "report_evidence" / "runs" / "20260907_final_report_evidence"

NAVY = colors.HexColor("#102A43")
BLUE = colors.HexColor("#1769AA")
CYAN = colors.HexColor("#0E91A5")
GREEN = colors.HexColor("#1B7F5A")
AMBER = colors.HexColor("#B26A00")
RED = colors.HexColor("#B83A4B")
INK = colors.HexColor("#243B53")
MUTED = colors.HexColor("#627D98")
PALE = colors.HexColor("#EAF2F8")
PALE_GREEN = colors.HexColor("#E8F5EF")
PALE_AMBER = colors.HexColor("#FFF4DE")
LINE_GREY = colors.HexColor("#CBD5E1")
WHITE = colors.white


def register_fonts() -> tuple[str, str]:
    regular = Path(r"C:\Windows\Fonts\arial.ttf")
    bold = Path(r"C:\Windows\Fonts\arialbd.ttf")
    if regular.exists() and bold.exists():
        pdfmetrics.registerFont(TTFont("ProjectSans", str(regular)))
        pdfmetrics.registerFont(TTFont("ProjectSans-Bold", str(bold)))
        return "ProjectSans", "ProjectSans-Bold"
    return "Helvetica", "Helvetica-Bold"


FONT, BOLD = register_fonts()


def git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except Exception:
        return "unavailable"


styles = getSampleStyleSheet()
BODY = ParagraphStyle(
    "Body",
    parent=styles["BodyText"],
    fontName=FONT,
    fontSize=9.4,
    leading=13.2,
    textColor=INK,
    alignment=TA_JUSTIFY,
    spaceAfter=5,
)
SMALL = ParagraphStyle(
    "Small", parent=BODY, fontSize=7.8, leading=10.2, alignment=TA_LEFT, spaceAfter=2
)
TABLE_HEADER = ParagraphStyle(
    "TableHeader", parent=SMALL, fontName=BOLD, textColor=WHITE, leading=9.5
)
H1 = ParagraphStyle(
    "H1",
    parent=styles["Heading1"],
    fontName=BOLD,
    fontSize=18,
    leading=22,
    textColor=NAVY,
    spaceBefore=0,
    spaceAfter=10,
)
H2 = ParagraphStyle(
    "H2",
    parent=styles["Heading2"],
    fontName=BOLD,
    fontSize=12.5,
    leading=15,
    textColor=BLUE,
    spaceBefore=8,
    spaceAfter=5,
)
H3 = ParagraphStyle(
    "H3",
    parent=styles["Heading3"],
    fontName=BOLD,
    fontSize=10,
    leading=12,
    textColor=NAVY,
    spaceBefore=5,
    spaceAfter=3,
)
CAPTION = ParagraphStyle(
    "Caption",
    parent=SMALL,
    alignment=TA_CENTER,
    textColor=MUTED,
    spaceBefore=4,
    spaceAfter=7,
)
CALLOUT = ParagraphStyle(
    "Callout",
    parent=BODY,
    fontName=BOLD,
    textColor=NAVY,
    backColor=PALE,
    borderColor=colors.HexColor("#9CC4DD"),
    borderWidth=0.6,
    borderPadding=8,
    leading=13.5,
    spaceBefore=4,
    spaceAfter=9,
)
WARNING = ParagraphStyle(
    "Warning",
    parent=BODY,
    textColor=colors.HexColor("#704000"),
    backColor=PALE_AMBER,
    borderColor=colors.HexColor("#E4AE4E"),
    borderWidth=0.6,
    borderPadding=8,
    spaceBefore=4,
    spaceAfter=8,
)
BULLET = ParagraphStyle(
    "Bullet",
    parent=BODY,
    leftIndent=13,
    firstLineIndent=-7,
    bulletIndent=2,
    alignment=TA_LEFT,
    spaceAfter=3,
)


def p(text: str, style: ParagraphStyle = BODY) -> Paragraph:
    return Paragraph(text, style)


def bullet(text: str) -> Paragraph:
    return Paragraph(f"• {text}", BULLET)


def table(rows, widths, *, header=True, font_size=7.8) -> Table:
    converted = []
    for row_index, row in enumerate(rows):
        cell_style = TABLE_HEADER if header and row_index == 0 else SMALL
        converted.append([p(str(cell), cell_style) for cell in row])
    t = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE_GREY),
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
    ]
    if header:
        commands += [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), BOLD),
        ]
    for row in range(1 if header else 0, len(rows)):
        if row % 2 == 0:
            commands.append(("BACKGROUND", (0, row), (-1, row), colors.HexColor("#F5F8FA")))
    t.setStyle(TableStyle(commands))
    return t


def box(d: Drawing, x, y, w, h, title, subtitle="", fill=PALE, stroke=BLUE):
    d.add(Rect(x, y, w, h, rx=6, ry=6, fillColor=fill, strokeColor=stroke, strokeWidth=1.1))
    d.add(String(x + w / 2, y + h * 0.61, title, textAnchor="middle", fontName=BOLD, fontSize=8.2, fillColor=NAVY))
    if subtitle:
        d.add(String(x + w / 2, y + h * 0.31, subtitle, textAnchor="middle", fontName=FONT, fontSize=6.3, fillColor=MUTED))


def arrow(d: Drawing, x1, y1, x2, y2, label="", color=MUTED):
    d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=1.1))
    import math

    angle = math.atan2(y2 - y1, x2 - x1)
    size = 5
    left = (x2 - size * math.cos(angle - 0.55), y2 - size * math.sin(angle - 0.55))
    right = (x2 - size * math.cos(angle + 0.55), y2 - size * math.sin(angle + 0.55))
    d.add(Polygon([x2, y2, left[0], left[1], right[0], right[1]], fillColor=color, strokeColor=color))
    if label:
        d.add(String((x1 + x2) / 2, (y1 + y2) / 2 + 4, label, textAnchor="middle", fontName=FONT, fontSize=5.8, fillColor=MUTED))


def topology_diagram() -> Drawing:
    d = Drawing(500, 275)
    box(d, 8, 167, 102, 63, "Attacker lab", "authorized localhost only", PALE_AMBER, AMBER)
    box(d, 145, 204, 102, 48, "SSH / FTP / HTTP", ":2222 / :2121 / :8080")
    box(d, 145, 127, 102, 48, "React decoy portal", ":5173 — attacker-facing")
    box(d, 282, 163, 102, 65, "Detection core", "rules + DT + IF + LSTM", PALE_GREEN, GREEN)
    box(d, 411, 204, 82, 48, "Express API", ":5000 + SQLite")
    box(d, 411, 127, 82, 48, "Flask dashboard", ":5050 — defender")
    box(d, 282, 50, 102, 48, "n8n alert workflow", ":5678 → Telegram")
    box(d, 411, 50, 82, 48, "Analyst actions", "feedback + simulated IPS")
    arrow(d, 110, 198, 145, 228, "traffic")
    arrow(d, 110, 188, 145, 151, "forms/search")
    arrow(d, 247, 228, 282, 201, "events")
    arrow(d, 247, 151, 282, 188, "events")
    arrow(d, 384, 196, 411, 228, "persist")
    arrow(d, 411, 151, 384, 178, "server-side read")
    arrow(d, 333, 163, 333, 98, "High/Critical")
    arrow(d, 384, 74, 411, 74, "review")
    arrow(d, 452, 127, 452, 98, "feedback")
    return d


def online_flow_diagram() -> Drawing:
    d = Drawing(500, 300)
    stages = [
        ("1  Capture", "honeypots / portal"),
        ("2  Validate", "versioned common event"),
        ("3  Sanitize", "causal 60s / 300s features"),
        ("4  Infer", "rules + DT + IF + LSTM"),
        ("5  Fuse", "deterministic precedence"),
        ("6  Explain", "severity + SHAP + reason"),
        ("7  Operate", "six agents + persistence"),
        ("8  Present", "dashboard / safe response"),
    ]
    x_positions = [5, 130, 255, 380]
    y_positions = [205, 80]
    coords = []
    for row, y in enumerate(y_positions):
        items = stages[row * 4 : row * 4 + 4]
        order = range(4) if row == 0 else reversed(range(4))
        for col in order:
            stage = items[col if row == 0 else 3 - col]
            x = x_positions[col]
            box(d, x, y, 105, 62, stage[0], stage[1], PALE if row == 0 else PALE_GREEN, BLUE if row == 0 else GREEN)
            coords.append((x, y, stage[0]))
    # top row left-to-right
    for x in x_positions[:-1]:
        arrow(d, x + 105, 236, x + 125, 236)
    # bend downward, then bottom row right-to-left
    arrow(d, 432, 205, 432, 142)
    for x in [380, 255, 130]:
        arrow(d, x, 111, x - 20, 111)
    d.add(String(250, 37, "All stages retain event_id/run_id traceability; failures are logged and do not silently become normal.", textAnchor="middle", fontName=FONT, fontSize=7, fillColor=MUTED))
    return d


def fusion_diagram() -> Drawing:
    d = Drawing(500, 260)
    items = [
        ("Deterministic rule?", "strongest matched rule", RED),
        ("Tabular attack?", "Decision Tree result", BLUE),
        ("LSTM attack ≥ 0.60?", "sequence decision", CYAN),
        ("Isolation anomaly?", "other_anomaly", AMBER),
        ("Otherwise", "normal", GREEN),
    ]
    y = 205
    for i, (title, sub, color) in enumerate(items):
        fill = colors.Color((color.red + 1) / 2, (color.green + 1) / 2, (color.blue + 1) / 2, alpha=0.22)
        box(d, 145, y, 210, 38, title, sub, fill, color)
        if i < len(items) - 1:
            arrow(d, 250, y, 250, y - 18, "no")
        if i < 4:
            d.add(String(370, y + 16, "yes → final class", fontName=BOLD, fontSize=7, fillColor=color))
        y -= 47
    return d


class ArchitectureDoc(BaseDocTemplate):
    def __init__(self, filename: str):
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=17 * mm,
            title="Project Architecture Explanation",
            author="Project Team",
            subject="Verified architecture of the cybersecurity honeypot and hybrid IDS prototype",
        )
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates([PageTemplate(id="main", frames=frame, onPage=self._decorate)])

    def _decorate(self, canvas, doc):
        canvas.saveState()
        if doc.page > 1:
            canvas.setStrokeColor(LINE_GREY)
            canvas.setLineWidth(0.5)
            canvas.line(18 * mm, A4[1] - 13 * mm, A4[0] - 18 * mm, A4[1] - 13 * mm)
            canvas.setFont(FONT, 7.3)
            canvas.setFillColor(MUTED)
            canvas.drawString(18 * mm, A4[1] - 10 * mm, "SECURE & INTELLIGENT FRAMEWORK — ARCHITECTURE")
            canvas.drawCentredString(A4[0] / 2, 9 * mm, str(doc.page))
            canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, "Verified repository explanation")
        canvas.restoreState()


def build() -> Path:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    story = []
    commit = git_commit()
    aggregate = json.loads((RUN / "lstm_robustness" / "aggregate_summary.json").read_text(encoding="utf-8"))

    # Cover
    story += [
        Spacer(1, 30 * mm),
        p("ARCHITECTURE EXPLANATION", ParagraphStyle("Eyebrow", parent=H2, alignment=TA_CENTER, textColor=CYAN, fontSize=11)),
        p("A Secure and Intelligent Framework for Detecting and Understanding Malicious Digital Activities", ParagraphStyle("CoverTitle", parent=H1, alignment=TA_CENTER, fontSize=24, leading=29, spaceAfter=14)),
        p("Project-specific system architecture, trust boundaries, online detection path, defender workflows, and controlled learning lifecycle", ParagraphStyle("CoverSub", parent=BODY, alignment=TA_CENTER, fontSize=11.5, leading=16, textColor=MUTED)),
        Spacer(1, 14 * mm),
        p("ARCHITECTURE AT A GLANCE", ParagraphStyle("Band", parent=H2, alignment=TA_CENTER, textColor=WHITE, backColor=NAVY, borderPadding=8)),
        p("The implementation separates the attacker-facing decoy portal from the defender dashboard. Authorized local interactions become normalized events, pass through a deterministic hybrid IDS, gain threat and explanation context, and are persisted for analyst review. Responses are simulated; the host firewall is not changed.", CALLOUT),
        Spacer(1, 24 * mm),
        table([
            ["Evidence basis", "Repository source, protected saved artifacts, and run 20260907_final_report_evidence"],
            ["Repository state", f"Branch mock; base commit {commit}; generated 08 September 2026"],
            ["Deployment boundary", "Windows localhost / explicitly authorized isolated lab"],
            ["Safety posture", "Fictional decoy records, sanitized evidence, simulated IPS, no unrestricted SQL/JavaScript"],
        ], [42 * mm, 120 * mm], header=False),
    ]

    # 1
    story += [PageBreak(), p("1. Architectural intent and boundaries", H1),
        p("The system is an academic cyber-defence prototype. Its architecture is designed to make malicious techniques observable without giving the attacker access to defender controls or real organizational data."),
        p("Three boundaries govern the design", H2),
        bullet("<b>Exposure boundary:</b> ports 2222, 2121, 8080, and 5173 emulate attack surfaces. Port 5173 contains fictional company resources and safe SQLi/XSS result simulations."),
        bullet("<b>Defender boundary:</b> the Flask dashboard on port 5050 is localhost-only and has no login/signup screen. It relays protected analyst requests to port 5000 using a server-side credential that is never sent to the attacker portal."),
        bullet("<b>Control boundary:</b> prevention actions are recommendations or auditable simulations. No Windows Firewall or OS-level blocking is performed."),
        KeepTogether([topology_diagram(), p("Figure 1. Deployed components, ports, and primary trust boundaries.", CAPTION)]),
        p("The data path is deliberately one-way at the attacker boundary: the portal can create decoy interactions and receive controlled fictional responses, but it cannot read IDS, IPS, XAI, feedback, or dashboard APIs."),
    ]

    # 2
    story += [PageBreak(), p("2. Runtime services and ownership", H1),
        p("Each process has one clear operational responsibility. Keeping presentation, collection, detection, storage, and alerting separate makes failure modes observable and prevents the decoy interface from becoming an analyst interface."),
        table([
            ["Port", "Component", "Responsibility", "Boundary"],
            ["2222", "SSH honeypot", "Controlled authentication decoy and brute-force telemetry", "Attacker-facing"],
            ["2121", "FTP honeypot", "Login, command, and decoy-file activity", "Attacker-facing"],
            ["8080", "HTTP honeypot", "Login attacks, SQLi, XSS, and scanning telemetry", "Attacker-facing"],
            ["5173", "React/Vite portal", "Fictional company portal, tracked files, safe SQLi/XSS outcomes", "Attacker-facing"],
            ["5000", "Express API + SQLite", "Central persistence and protected analyst APIs", "Internal service"],
            ["5050", "Flask dashboard", "IDS/IPS, XAI, event, feedback, and system-monitor views", "Defender-only localhost"],
            ["5678", "n8n", "High/Critical workflow to Telegram when explicitly enabled", "External-notification bridge"],
        ], [15 * mm, 33 * mm, 82 * mm, 35 * mm]),
        p("Process separation", H2),
        bullet("The Python runtime owns honeypots, event validation, feature state, hybrid inference, XAI, agents, JSONL output, and dashboard serving."),
        bullet("The Express service owns protected API access and SQLite-backed events, IDS results, feedback, and simulated IPS audit records."),
        bullet("The React portal calls only decoy endpoints. The Flask server performs defender-side relaying; browser JavaScript does not receive the internal analyst credential."),
        bullet("The n8n forwarder reads enriched IDS records, not raw events, so severity, XAI, agents, and IPS context are available to the alert workflow."),
        p("Operational note: duplicate alert suppression intentionally limits repeated notifications of the same attack type for five minutes. Recorded activity and alert delivery are therefore related but not identical counts.", WARNING),
    ]

    # 3
    story += [PageBreak(), p("3. End-to-end online event workflow", H1),
        KeepTogether([online_flow_diagram(), p("Figure 2. Implemented online detection and evidence flow.", CAPTION)]),
        p("The common event contract", H2),
        p("Every producer emits a versioned normalized event. The record carries a stable event identifier, timestamp, source information, service, event type, request/path or command context, sanitized credential indicators, and metadata required for traceability. Validation rejects malformed inputs before detection."),
        p("Stateful causal processing", H2),
        p("Feature history is grouped by pseudonymous source and service. Frequency features use only current and prior events inside 60-second windows; session and username-repetition logic use 300 seconds. This prevents future events from leaking into a present-time prediction."),
        p("Persistence and correlation", H2),
        p("The same event ID links the captured event, component predictions, final class, threat report, explanation, agent output, SQLite record, feedback, and simulated response. JSONL files preserve append-order evidence; SQLite supports defender queries and audit views."),
        p("Failure behavior", H2),
        p("Validation, delivery, or processing failures are logged. The bounded delivery queue prevents unbounded growth, and the evidence harness records failed ingestion or missing outputs instead of interpreting them as normal activity."),
    ]

    # 4
    story += [PageBreak(), p("4. Honeypots and safe attack-result simulation", H1),
        p("The honeypot layer collects observable behavior rather than exposing production services. SSH and FTP provide narrow protocol emulation; HTTP and the React portal provide controlled web interactions. All demonstrations are restricted to localhost or an explicitly authorized isolated lab."),
        table([
            ["Surface", "Captured behavior", "Controlled outcome"],
            ["SSH :2222", "Authentication attempts and repetition", "Decoy protocol responses; no host shell"],
            ["FTP :2121", "Credentials, commands, and decoy-file access", "Fictional files; activity remains auditable"],
            ["HTTP :8080", "Login, SQLi, XSS, directory/port scanning patterns", "Honeypot response and normalized event"],
            ["React :5173", "Employee login and resource-search inputs", "Fictional SQL rows or fake exposed session/user data"],
        ], [28 * mm, 72 * mm, 65 * mm]),
        p("SQL injection demonstration", H2),
        p("A SQL-shaped login value is pattern-detected and recorded. The response can display believable fictional employee/database rows so the observer can explain what an attacker might see. The backend does not concatenate the input into unrestricted SQL and does not dump a real database."),
        p("Cross-site scripting demonstration", H2),
        p("An XSS-shaped search value is recorded and may display a deterministic fake session/user exposure panel. The payload is rendered as data; arbitrary browser JavaScript is not executed. This preserves the learning objective without turning the demo into an execution platform."),
        p("Decoy-file tracking", H2),
        p("Fictional documents remain attacker-facing. Requests and downloads create activity evidence that can be correlated on the defender dashboard. Decoy content and captured credentials are synthetic and must remain free of real personal or organizational secrets."),
        p("Safety invariant: demonstrated impact is fictional, deterministic, and attributable to the submitted event. It is never evidence that a real database or browser session was compromised.", WARNING),
    ]

    # 5
    story += [PageBreak(), p("5. Hybrid detection architecture", H1),
        p("The detector combines complementary components but does not average them blindly. Rules supply high-precision deterministic findings; supervised models classify known attack families; the LSTM models causal sequences; and Isolation Forest supplies an unknown-anomaly fallback."),
        table([
            ["Component", "Runtime role", "Verified configuration / interpretation"],
            ["Rules", "First-priority deterministic findings", "Strongest matching SQLi, XSS, scan, or repeated-login rule"],
            ["Decision Tree", "Selected tabular known-attack classifier", "Gini; max depth 12; min leaf 2; balanced class weights"],
            ["Random Forest", "Evaluated candidate, not selected runtime tabular model", "200 trees; depth 16; sqrt features; min leaf 2"],
            ["LSTM", "Sequence classification", "10 × 23 causal inputs; 64 hidden units; one layer; dropout 0.30"],
            ["Isolation Forest", "Unknown anomaly fallback", "200 estimators; contamination 0.05; −decision_function is anomaly score, not probability"],
        ], [33 * mm, 55 * mm, 77 * mm]),
        KeepTogether([fusion_diagram(), p("Figure 3. Implemented hybrid fusion precedence.", CAPTION)]),
        p("When the tabular and LSTM predictions agree, confidence may be averaged. Otherwise, component scope and precedence are preserved. This avoids presenting an Isolation Forest decision score as calibrated confidence and avoids inventing a substitute fusion formula."),
    ]

    # 6
    story += [PageBreak(), p("6. LSTM evaluation boundary and model integrity", H1),
        p("The runtime still uses the protected active LSTM artifact. Report generation never promotes an evaluation candidate, rewrites the model, or tunes against the test set."),
        p("Why the old 1.0000 required investigation", H2),
        p("The saved chronological holdout reproduces 1.0000 accuracy on 816 sequences, but 791 of 816 test rows share a source hash with training, all 816 reuse a service/event/path template, and the split boundary timestamp is identical. There are no byte-identical train/test sequences; the risk is related-group and template dependence."),
        p("Preferred internal estimate", H2),
        table([
            ["Evaluation", "Runs", "Test rows", "Accuracy", "Macro F1", "Source overlap"],
            ["Legacy chronological holdout", "1", "816", "1.0000", "1.0000", "791/816 rows"],
            ["Source-IP-group-isolated audit", "3", "710 / 710 / 711", f"{aggregate['accuracy']['mean']:.4f} ± {aggregate['accuracy']['population_std']:.4f}", f"{aggregate['macro_f1']['mean']:.4f} ± {aggregate['macro_f1']['population_std']:.4f}", "0 in every run"],
        ], [47 * mm, 14 * mm, 27 * mm, 28 * mm, 28 * mm, 25 * mm]),
        p("The source-group audit is the primary internal LSTM result: mean accuracy 0.9761 and mean macro F1 0.9675 across seeds 42–44. It fits preprocessing on training only and selects checkpoints by validation loss. Templates still repeat across isolated groups, so external or template/campaign-isolated validation remains necessary."),
        p("Model lifecycle separation", H2),
        bullet("Active artifact hashes are recorded before and after evaluation."),
        bullet("Audit candidates and their preprocessors use separate names and directories."),
        bullet("Candidate promotion is an explicit offline action and must occur only while runtime consumers are stopped."),
        bullet("Rollback restores a retained version; automatic online learning is not implemented or claimed."),
    ]

    # 7
    story += [PageBreak(), p("7. Threat reporting, XAI, and operational agents", H1),
        p("A final classification is converted into an operationally readable incident without allowing explanation code to alter the protected prediction."),
        table([
            ["Layer", "What it contributes", "Boundary"],
            ["Threat reporter", "Deterministic points and Low / Medium / High / Critical levels", "Scores are 0–100; bands are 0–24, 25–49, 50–74, 75–100"],
            ["Tree SHAP", "Local/global feature contributions for the selected tree", "Supporting explanation only; not causal proof and not an LSTM explanation"],
            ["Human reason", "Readable synthesis of final class, rules, confidence, and context", "Raw secrets and untrusted payloads are not echoed"],
            ["Six agents", "Detection, correlation, severity, explanation, response recommendation, daily reporting", "Deterministic bounded processors; not LLM agents"],
        ], [35 * mm, 75 * mm, 55 * mm]),
        p("Agent sequence", H2),
        bullet("Detection agent validates and summarizes component evidence."),
        bullet("Correlation agent connects related activity within the available local event history."),
        bullet("Severity agent checks threat factors and operational priority."),
        bullet("Explanation agent produces a bounded analyst-facing rationale."),
        bullet("Response agent recommends a simulated containment action."),
        bullet("Daily-report agent aggregates auditable records for review."),
        p("High/Critical enriched IDS records can be forwarded by n8n to Telegram. Webhook acceptance and Telegram receipt are distinct: receipt is claimed only when visibly observed. External delivery was disabled during the packaged evidence run.", WARNING),
    ]

    # 8
    story += [PageBreak(), p("8. Defender dashboard architecture", H1),
        p("Port 5050 is a defender workspace, not a second attacker portal. Its login/signup/logout UI has been removed. Localhost binding and server-side API relaying preserve the separation from port 5173."),
        table([
            ["Dashboard area", "Data source and behavior", "Analyst value"],
            ["System Monitor", "Enriched live IDS stream plus service/status summaries", "Current totals, threats, source count, uptime, event feed, and resource indicators"],
            ["Honeypot / captured activity", "Normalized event records from SSH, FTP, HTTP, and portal interactions", "Inspect inputs, service, attack pattern, time, and correlated event ID"],
            ["IDS", "Final hybrid class, component outputs, confidence/score, and threat report", "Distinguish rules, tabular, sequence, and anomaly evidence"],
            ["XAI", "Tree SHAP where supported and deterministic textual rationale", "Understand contributing features without overstating causation"],
            ["Agents", "Six ordered deterministic processor outputs and daily report", "Operational context and review trail"],
            ["IPS", "Recommendation, feedback, and simulated-response audit records", "Demonstrate containment workflow while host firewall remains unchanged"],
        ], [36 * mm, 79 * mm, 50 * mm]),
        p("System Monitor consistency", H2),
        p("System Monitor must consume the same enriched detection stream as the IDS and captured-activity views. An XSS recorded only in a credential/activity table but absent from the live event feed indicates a presentation/query mismatch, not a different detector. The current implementation maps portal XSS/SQLi events into the enriched feed so all relevant dashboard panels update from the same final record."),
        p("Analyst feedback", H2),
        p("Feedback is stored as an auditable correction or confirmation. It can feed the offline learning preparation stage, but it never retrains or changes the live model immediately."),
    ]

    # 9
    story += [PageBreak(), p("9. Offline learning and governance", H1),
        p("Continuous learning is deliberately outside the online request path. This protects availability and prevents one attacker interaction from modifying the active model."),
        table([
            ["Stage", "Action", "Guardrail"],
            ["1. Prepare", "Join sanitized analyst feedback with eligible evidence", "No training; provenance and schema checks"],
            ["2. Retrain", "Create a separately versioned candidate", "Active artifacts remain untouched"],
            ["3. Compare", "Evaluate macro F1, macro recall, FPR, and minimum sample gates", "No decision from accuracy alone"],
            ["4. Decide", "Candidate manifest records promote/reject recommendation", "Promotion is never automatic"],
            ["5. Promote", "Explicitly replace active version after services are stopped", "Operator confirmation and retained rollback"],
            ["6. Roll back", "Restore a retained model tree", "Explicit operator action"],
        ], [25 * mm, 76 * mm, 64 * mm]),
        p("Evidence-generation architecture", H2),
        p("The report harness has separate inspection, offline evaluation, live-demo, and render modes. Offline mode loads protected saved models and held-out arrays without fitting them. Live mode uses bounded localhost scenarios, isolated storage, disabled external notifications, and simulated responses. Render mode creates every chart from its CSV source and packages a sanitized evidence archive."),
        p("This separation allows the report to distinguish fresh offline inference, fresh live measurement, historical training evidence, verified source-code behavior, and pending/unverified claims."),
    ]

    # 10
    story += [PageBreak(), p("10. Deployment, startup, and failure containment", H1),
        p("Normal demonstration startup uses five terminals: n8n; Express backend; React portal; the Python honeypot/IDS/dashboard process; and the enriched IDS alert forwarder. The deployed listener set is then checked explicitly."),
        table([
            ["Order", "Command / process", "Expected ports or effect"],
            ["1", "n8n.cmd start", "5678"],
            ["2", "website/backend — npm.cmd run dev", "5000"],
            ["3", "website/frontend — npm.cmd run dev:local", "5173"],
            ["4", "python run.py with external webhook disabled by default", "2222, 2121, 8080, 5050"],
            ["5", "python simulation/n8n.py --mode local --source ids", "tails enriched IDS results and posts eligible alerts"],
        ], [15 * mm, 95 * mm, 55 * mm]),
        p("Containment principles", H2),
        bullet("Never run attack simulations against systems outside the authorized local lab."),
        bullet("Do not start a model promotion or rollback while run.py or another active model consumer is running."),
        bullet("Keep tokens, Telegram credentials, databases, raw logs, model files, and runtime configuration out of report archives."),
        bullet("Treat alerting as optional: detection and dashboard persistence continue to provide local evidence if n8n or Telegram is unavailable."),
        bullet("Treat the decoy result as demonstration data, never as authorization to execute unrestricted SQL, JavaScript, shell commands, or firewall changes."),
        p("The architecture is appropriate for a controlled final-year project demonstration. It is not a production SOC platform, universal zero-day detector, or autonomous prevention system.", WARNING),
    ]

    # 11
    story += [PageBreak(), p("11. Verification map and recommended upgrades", H1),
        p("Primary repository evidence", H2),
        table([
            ["Architecture claim", "Source of truth"],
            ["Ports and startup", "howtostart.md; run.py; website package scripts"],
            ["Portal/dashboard boundary", "README.md; dashboard routes/templates; website frontend/backend routes"],
            ["Fusion and confidence", "machine_learning/hybrid_ids.py"],
            ["Threat bands", "machine_learning/threat_reporting.py"],
            ["LSTM architecture/evaluation", "machine_learning/lstm_model.py; train_lstm.py; report_evidence/lstm_robustness"],
            ["Evaluation evidence", "scripts/report_evidence.py; run manifest; prediction CSVs; integrity checks"],
            ["Learning governance", "continuous_learning/pipeline.py and version manifests"],
        ], [52 * mm, 113 * mm]),
        p("Recommended upgrades", H2),
        bullet("Collect an external or template/campaign-isolated dataset before making broader generalization claims."),
        bullet("Calibrate classifier confidence and the Isolation Forest operating threshold on a separate validation set."),
        bullet("Measure sustained throughput, database/network latency, queue backlog, drops, and process-level CPU/RAM under a documented load."),
        bullet("Add session/campaign identifiers at collection time so every model can be evaluated with stronger grouped splits."),
        bullet("Automate sanitized dashboard screenshot capture and link each image to the documented run and event IDs."),
        bullet("Add monitored health checks for the Express relay, SQLite writes, IDS tailer, n8n workflow, and Telegram delivery acknowledgement."),
        bullet("Keep the attacker and defender interfaces independently deployable, and replace the local server-side shared credential with managed service identity if deployment expands beyond localhost."),
        p("Interpretation", H2),
        p("The architecture already demonstrates the complete controlled flow from interaction to detection, explanation, alerting, review, and simulated response. Its strongest evidence is traceable and reproducible; its remaining work is primarily stronger external validation, calibration, sustained-load measurement, and operational hardening."),
        Spacer(1, 5 * mm),
        p(f"Generated from repository branch <b>mock</b> at base commit <b>{commit}</b>. Evidence run: <b>20260907_final_report_evidence</b>. No active model was modified.", CALLOUT),
    ]

    ArchitectureDoc(str(OUT)).build(story)
    print(OUT)
    return OUT


if __name__ == "__main__":
    build()
