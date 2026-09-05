from __future__ import annotations

from pathlib import Path
from datetime import date

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_ROW_HEIGHT_RULE, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


OUT = Path(r"D:\MAJORPROJECT_TEAMMATE_GUIDES\05_PROJECT_IMPROVEMENT_AUDIT_AND_ROADMAP.docx")
OUT.parent.mkdir(parents=True, exist_ok=True)

BLUE = "2E74B5"
DARK_BLUE = "1F4D78"
NAVY = "16324F"
TEAL = "147D88"
GREEN = "2E7D32"
AMBER = "B26A00"
RED = "B42318"
PALE_BLUE = "EAF2F8"
PALE_GREEN = "EAF5EA"
PALE_AMBER = "FFF4DF"
PALE_RED = "FDECEC"
LIGHT = "F2F4F7"
MID = "D0D5DD"
TEXT = "243447"
MUTED = "667085"
WHITE = "FFFFFF"


def rgb(hex_value: str) -> RGBColor:
    return RGBColor.from_string(hex_value)


def set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def set_cell_margins(cell, top=80, start=120, bottom=80, end=120) -> None:
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for tag, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tc_mar.find(qn(f"w:{tag}"))
        if node is None:
            node = OxmlElement(f"w:{tag}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_cell_width(cell, width: int) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_w = tc_pr.find(qn("w:tcW"))
    if tc_w is None:
        tc_w = OxmlElement("w:tcW")
        tc_pr.append(tc_w)
    tc_w.set(qn("w:w"), str(width))
    tc_w.set(qn("w:type"), "dxa")


def set_table_geometry(table, widths: list[int], indent: int = 120) -> None:
    total = sum(widths)
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    table.autofit = False
    tbl_pr = table._tbl.tblPr
    tbl_w = tbl_pr.find(qn("w:tblW"))
    if tbl_w is None:
        tbl_w = OxmlElement("w:tblW")
        tbl_pr.append(tbl_w)
    tbl_w.set(qn("w:w"), str(total))
    tbl_w.set(qn("w:type"), "dxa")
    tbl_ind = tbl_pr.find(qn("w:tblInd"))
    if tbl_ind is None:
        tbl_ind = OxmlElement("w:tblInd")
        tbl_pr.append(tbl_ind)
    tbl_ind.set(qn("w:w"), str(indent))
    tbl_ind.set(qn("w:type"), "dxa")
    layout = tbl_pr.find(qn("w:tblLayout"))
    if layout is None:
        layout = OxmlElement("w:tblLayout")
        tbl_pr.append(layout)
    layout.set(qn("w:type"), "fixed")
    grid = table._tbl.tblGrid
    for child in list(grid):
        grid.remove(child)
    for width in widths:
        col = OxmlElement("w:gridCol")
        col.set(qn("w:w"), str(width))
        grid.append(col)
    for row in table.rows:
        row.height_rule = WD_ROW_HEIGHT_RULE.AT_LEAST
        for index, cell in enumerate(row.cells):
            set_cell_width(cell, widths[min(index, len(widths) - 1)])
            set_cell_margins(cell)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER


def remove_table_borders(table) -> None:
    tbl_pr = table._tbl.tblPr
    borders = tbl_pr.find(qn("w:tblBorders"))
    if borders is None:
        borders = OxmlElement("w:tblBorders")
        tbl_pr.append(borders)
    for name in ("top", "left", "bottom", "right", "insideH", "insideV"):
        edge = borders.find(qn(f"w:{name}"))
        if edge is None:
            edge = OxmlElement(f"w:{name}")
            borders.append(edge)
        edge.set(qn("w:val"), "nil")


def set_repeat_table_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def prevent_row_split(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    cant_split.set(qn("w:val"), "true")
    tr_pr.append(cant_split)


def keep_with_next(paragraph) -> None:
    paragraph.paragraph_format.keep_with_next = True


def add_field(paragraph, instruction: str) -> None:
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = instruction
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend([begin, instr, separate, end])


def add_hyperlink(paragraph, text: str, url: str, color: str = BLUE) -> None:
    part = paragraph.part
    rel_id = part.relate_to(url, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", is_external=True)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), rel_id)
    run = OxmlElement("w:r")
    r_pr = OxmlElement("w:rPr")
    clr = OxmlElement("w:color")
    clr.set(qn("w:val"), color)
    u = OxmlElement("w:u")
    u.set(qn("w:val"), "single")
    r_pr.extend([clr, u])
    text_node = OxmlElement("w:t")
    text_node.text = text
    run.extend([r_pr, text_node])
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


def set_run_font(run, name="Calibri", size=11, color=TEXT, bold=None, italic=None) -> None:
    run.font.name = name
    run._element.rPr.rFonts.set(qn("w:eastAsia"), name)
    run.font.size = Pt(size)
    run.font.color.rgb = rgb(color)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic


def add_numbering(doc: Document) -> tuple[int, int, int]:
    numbering = doc.part.numbering_part.element
    abstract_ids = [int(e.get(qn("w:abstractNumId"))) for e in numbering.findall(qn("w:abstractNum"))]
    num_ids = [int(e.get(qn("w:numId"))) for e in numbering.findall(qn("w:num"))]
    next_abstract = max(abstract_ids, default=0) + 1
    next_num = max(num_ids, default=0) + 1

    def make_abstract(abstract_id: int, num_id: int, fmt: str, text: str, font: str | None = None):
        abstract = OxmlElement("w:abstractNum")
        abstract.set(qn("w:abstractNumId"), str(abstract_id))
        multi = OxmlElement("w:multiLevelType")
        multi.set(qn("w:val"), "singleLevel")
        abstract.append(multi)
        lvl = OxmlElement("w:lvl")
        lvl.set(qn("w:ilvl"), "0")
        start = OxmlElement("w:start")
        start.set(qn("w:val"), "1")
        num_fmt = OxmlElement("w:numFmt")
        num_fmt.set(qn("w:val"), fmt)
        lvl_text = OxmlElement("w:lvlText")
        lvl_text.set(qn("w:val"), text)
        suff = OxmlElement("w:suff")
        suff.set(qn("w:val"), "tab")
        p_pr = OxmlElement("w:pPr")
        tabs = OxmlElement("w:tabs")
        tab = OxmlElement("w:tab")
        tab.set(qn("w:val"), "num")
        tab.set(qn("w:pos"), "720")
        tabs.append(tab)
        ind = OxmlElement("w:ind")
        ind.set(qn("w:left"), "720")
        ind.set(qn("w:hanging"), "360")
        p_pr.extend([tabs, ind])
        lvl.extend([start, num_fmt, lvl_text, suff, p_pr])
        if font:
            r_pr = OxmlElement("w:rPr")
            fonts = OxmlElement("w:rFonts")
            fonts.set(qn("w:ascii"), font)
            fonts.set(qn("w:hAnsi"), font)
            r_pr.append(fonts)
            lvl.append(r_pr)
        abstract.append(lvl)
        first_num = numbering.find(qn("w:num"))
        if first_num is None:
            numbering.append(abstract)
        else:
            numbering.insert(list(numbering).index(first_num), abstract)
        num = OxmlElement("w:num")
        num.set(qn("w:numId"), str(num_id))
        abstract_ref = OxmlElement("w:abstractNumId")
        abstract_ref.set(qn("w:val"), str(abstract_id))
        num.append(abstract_ref)
        numbering.append(num)
        return num_id

    bullet_num = make_abstract(next_abstract, next_num, "bullet", "•", "Calibri")
    decimal_num = make_abstract(next_abstract + 1, next_num + 1, "decimal", "%1.")
    return bullet_num, decimal_num, next_abstract + 1


def new_number_sequence(doc: Document, abstract_id: int) -> int:
    numbering = doc.part.numbering_part.element
    num_ids = [int(e.get(qn("w:numId"))) for e in numbering.findall(qn("w:num"))]
    next_num_id = max(num_ids, default=0) + 1
    num = OxmlElement("w:num")
    num.set(qn("w:numId"), str(next_num_id))
    abstract_ref = OxmlElement("w:abstractNumId")
    abstract_ref.set(qn("w:val"), str(abstract_id))
    num.append(abstract_ref)
    lvl_override = OxmlElement("w:lvlOverride")
    lvl_override.set(qn("w:ilvl"), "0")
    start_override = OxmlElement("w:startOverride")
    start_override.set(qn("w:val"), "1")
    lvl_override.append(start_override)
    num.append(lvl_override)
    numbering.append(num)
    return next_num_id


def apply_num(paragraph, num_id: int) -> None:
    p_pr = paragraph._p.get_or_add_pPr()
    num_pr = p_pr.find(qn("w:numPr"))
    if num_pr is None:
        num_pr = OxmlElement("w:numPr")
        p_pr.append(num_pr)
    ilvl = OxmlElement("w:ilvl")
    ilvl.set(qn("w:val"), "0")
    num_id_el = OxmlElement("w:numId")
    num_id_el.set(qn("w:val"), str(num_id))
    num_pr.extend([ilvl, num_id_el])


doc = Document()
doc.core_properties.title = "Project Improvement Audit and Implementation Roadmap"
doc.core_properties.subject = "Security, frontend, ML validity, reliability, testing, and documentation improvement plan"
doc.core_properties.author = "Prepared for the CEC01 project team"
doc.core_properties.keywords = "honeypot, IDS, XAI, security, frontend, roadmap, major project"

section = doc.sections[0]
section.page_width = Inches(8.5)
section.page_height = Inches(11)
section.top_margin = Inches(1.0)
section.bottom_margin = Inches(1.0)
section.left_margin = Inches(1.0)
section.right_margin = Inches(1.0)
section.header_distance = Inches(0.492)
section.footer_distance = Inches(0.492)
section.different_first_page_header_footer = True

styles = doc.styles
normal = styles["Normal"]
normal.font.name = "Calibri"
normal._element.rPr.rFonts.set(qn("w:eastAsia"), "Calibri")
normal.font.size = Pt(11)
normal.font.color.rgb = rgb(TEXT)
normal.paragraph_format.space_after = Pt(6)
normal.paragraph_format.line_spacing = 1.10

for style_name, size, color, before, after in (
    ("Heading 1", 16, BLUE, 16, 8),
    ("Heading 2", 13, BLUE, 12, 6),
    ("Heading 3", 12, DARK_BLUE, 8, 4),
):
    st = styles[style_name]
    st.font.name = "Calibri"
    st._element.rPr.rFonts.set(qn("w:eastAsia"), "Calibri")
    st.font.size = Pt(size)
    st.font.bold = True
    st.font.color.rgb = rgb(color)
    st.paragraph_format.space_before = Pt(before)
    st.paragraph_format.space_after = Pt(after)
    st.paragraph_format.keep_with_next = True

styles["Title"].font.name = "Calibri"
styles["Title"]._element.rPr.rFonts.set(qn("w:eastAsia"), "Calibri")
styles["Title"].font.size = Pt(27)
styles["Title"].font.bold = True
styles["Title"].font.color.rgb = rgb(NAVY)

bullet_num, decimal_num, decimal_abstract = add_numbering(doc)


def p(text: str = "", bold_lead: str | None = None, italic=False, color=TEXT, align=None, after=6):
    para = doc.add_paragraph()
    if align is not None:
        para.alignment = align
    para.paragraph_format.space_after = Pt(after)
    if bold_lead and text.startswith(bold_lead):
        r1 = para.add_run(bold_lead)
        set_run_font(r1, bold=True, color=color)
        r2 = para.add_run(text[len(bold_lead):])
        set_run_font(r2, italic=italic, color=color)
    else:
        r = para.add_run(text)
        set_run_font(r, italic=italic, color=color)
    return para


def bullet(text: str, bold_lead: str | None = None):
    para = doc.add_paragraph()
    apply_num(para, bullet_num)
    para.paragraph_format.space_after = Pt(8)
    para.paragraph_format.line_spacing = 1.167
    if bold_lead and text.startswith(bold_lead):
        r1 = para.add_run(bold_lead)
        set_run_font(r1, bold=True)
        r2 = para.add_run(text[len(bold_lead):])
        set_run_font(r2)
    else:
        set_run_font(para.add_run(text))
    return para


def numbered(text: str, bold_lead: str | None = None):
    para = doc.add_paragraph()
    apply_num(para, decimal_num)
    para.paragraph_format.space_after = Pt(8)
    para.paragraph_format.line_spacing = 1.167
    if bold_lead and text.startswith(bold_lead):
        set_run_font(para.add_run(bold_lead), bold=True)
        set_run_font(para.add_run(text[len(bold_lead):]))
    else:
        set_run_font(para.add_run(text))
    return para


def heading(text: str, level=1):
    return doc.add_heading(text, level=level)


def page_break():
    doc.add_page_break()


def callout(title: str, body: str, fill=PALE_BLUE, accent=BLUE):
    table = doc.add_table(rows=1, cols=2)
    prevent_row_split(table.rows[0])
    set_table_geometry(table, [180, 9180], indent=0)
    remove_table_borders(table)
    set_cell_shading(table.cell(0, 0), accent)
    set_cell_shading(table.cell(0, 1), fill)
    cell = table.cell(0, 1)
    cell.text = ""
    pp = cell.paragraphs[0]
    pp.paragraph_format.space_after = Pt(3)
    set_run_font(pp.add_run(title), bold=True, color=NAVY)
    pp2 = cell.add_paragraph()
    pp2.paragraph_format.space_after = Pt(0)
    set_run_font(pp2.add_run(body), color=TEXT)
    doc.add_paragraph().paragraph_format.space_after = Pt(1)
    return table


def make_table(headers: list[str], rows: list[list[str]], widths: list[int], font_size=9):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    set_table_geometry(table, widths)
    header = table.rows[0]
    prevent_row_split(header)
    set_repeat_table_header(header)
    for idx, text in enumerate(headers):
        cell = header.cells[idx]
        set_cell_shading(cell, LIGHT)
        cell.text = ""
        pp = cell.paragraphs[0]
        pp.paragraph_format.space_after = Pt(0)
        set_run_font(pp.add_run(text), size=font_size, bold=True, color=NAVY)
    for r_index, values in enumerate(rows):
        row = table.add_row()
        prevent_row_split(row)
        for c_index, text in enumerate(values):
            cell = row.cells[c_index]
            if r_index % 2 == 1:
                set_cell_shading(cell, "FAFBFC")
            cell.text = ""
            pp = cell.paragraphs[0]
            pp.paragraph_format.space_after = Pt(0)
            pp.paragraph_format.line_spacing = 1.0
            set_run_font(pp.add_run(str(text)), size=font_size, color=TEXT)
    doc.add_paragraph().paragraph_format.space_after = Pt(1)
    return table


# Running header and footer.
header = section.header
ht = header.add_table(rows=1, cols=2, width=Inches(6.5))
set_table_geometry(ht, [6000, 3360], indent=0)
remove_table_borders(ht)
hp = ht.cell(0, 0).paragraphs[0]
hp.paragraph_format.space_after = Pt(0)
set_run_font(hp.add_run("PROJECT IMPROVEMENT AUDIT"), size=8, bold=True, color=MUTED)
hp2 = ht.cell(0, 1).paragraphs[0]
hp2.alignment = WD_ALIGN_PARAGRAPH.RIGHT
hp2.paragraph_format.space_after = Pt(0)
set_run_font(hp2.add_run("CEC01 • 27 AUG 2026"), size=8, color=MUTED)

footer = section.footer
fp = footer.paragraphs[0]
fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
set_run_font(fp.add_run("Internal project planning  •  "), size=8, color=MUTED)
add_field(fp, "PAGE")

# Cover.
accent = doc.add_table(rows=1, cols=1)
set_table_geometry(accent, [9360], indent=0)
remove_table_borders(accent)
set_cell_shading(accent.cell(0, 0), BLUE)
accent.cell(0, 0).paragraphs[0].paragraph_format.space_after = Pt(0)
accent.cell(0, 0).paragraphs[0].add_run(" ")

doc.add_paragraph().paragraph_format.space_after = Pt(60)
small = p("MAJOR PROJECT • TECHNICAL AND PRODUCT AUDIT", color=TEAL, after=12)
small.alignment = WD_ALIGN_PARAGRAPH.CENTER
for run in small.runs:
    run.font.size = Pt(10)
    run.bold = True

title = doc.add_paragraph(style="Title")
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
title.paragraph_format.space_after = Pt(16)
title.add_run("Project Improvement Audit\nand Implementation Roadmap")

subtitle = p(
    "A Secure and Intelligent Framework for Detecting and Understanding Malicious Digital Activities",
    color=DARK_BLUE,
    align=WD_ALIGN_PARAGRAPH.CENTER,
    after=34,
)
for run in subtitle.runs:
    run.font.size = Pt(15)

cover_table = doc.add_table(rows=4, cols=2)
set_table_geometry(cover_table, [2600, 6760], indent=0)
remove_table_borders(cover_table)
cover_rows = [
    ("Prepared for", "CEC01 project team"),
    ("Assessment date", "27 August 2026"),
    ("Code baseline", "D:\\honeypot_v2 • main • commit 7ab745a"),
    ("Review scope", "Security, backend, frontend, ML/XAI, agents, automation, testing, operations, and academic documentation"),
]
for index, (label, value) in enumerate(cover_rows):
    set_cell_shading(cover_table.cell(index, 0), LIGHT)
    set_cell_shading(cover_table.cell(index, 1), "FAFBFC")
    cover_table.cell(index, 0).text = ""
    cover_table.cell(index, 1).text = ""
    set_run_font(cover_table.cell(index, 0).paragraphs[0].add_run(label.upper()), size=8, bold=True, color=MUTED)
    set_run_font(cover_table.cell(index, 1).paragraphs[0].add_run(value), size=10, color=TEXT)

doc.add_paragraph().paragraph_format.space_after = Pt(32)
notice = p(
    "Purpose: convert the current working prototype into a secure, repeatable, academically defensible, and presentation-ready system.",
    color=MUTED,
    align=WD_ALIGN_PARAGRAPH.CENTER,
    after=0,
)
for run in notice.runs:
    run.italic = True
    run.font.size = Pt(9)

page_break()

heading("Executive verdict", 1)
callout(
    "Overall assessment",
    "The project is a substantial and credible major-project prototype. It already integrates three honeypots, centralized telemetry, multiple ML approaches, explainability, six analysis agents, analyst feedback, simulated IPS actions, dashboards, and alert automation. It is not yet safe to describe as production-ready. The next release should prioritize security boundaries, measurable evidence, frontend correctness, and one consistent project story.",
    PALE_BLUE,
    BLUE,
)

p("The best improvement strategy is not to add more algorithms immediately. First make the existing system trustworthy, reproducible, and easy to demonstrate. Then strengthen the ML evaluation and user experience. This sequencing protects the work already completed and produces clearer academic evidence.")

heading("Decision summary", 2)
make_table(
    ["Area", "Current position", "Target for final submission"],
    [
        ["Core implementation", "Broad prototype is implemented and internally integrated.", "Stable one-command lab release with health checks and rollback."],
        ["Security", "Several demo-oriented defaults and weak trust boundaries remain.", "Local-by-default, fail-closed secrets, authenticated ingestion, redacted operational logs."],
        ["Frontend", "Useful pages exist, but duplicated dashboards, hard-coded integration URLs, and random KPIs reduce trust.", "One responsive SOC dashboard backed entirely by real data."],
        ["ML evidence", "Strong internal metrics on a small balanced synthetic dataset; leakage and generalization are not yet ruled out.", "Group-aware and temporal evaluation, confidence intervals, calibration, drift and external/generalization tests."],
        ["Documentation", "Abstract, presentation, report, README, and implementation disagree about CNN/LSTM and LIME/SHAP.", "One evidence-backed architecture and claims set across all deliverables."],
    ],
    [1700, 3600, 4060],
    9,
)

heading("Recommended priority order", 2)
decimal_num = new_number_sequence(doc, decimal_abstract)
numbered("Secure the trust boundaries and remove misleading or unsafe behavior.")
numbered("Rebuild a reproducible development and demo environment, then run the complete verification suite.")
numbered("Replace fake or hard-coded dashboard behavior and converge on one frontend.")
numbered("Upgrade ML evaluation so the results demonstrate generalization rather than memorization.")
numbered("Operationalize alerting, continuous learning, audit trails, and recovery paths.")
numbered("Align every academic document and final demonstration with the implemented system.")

callout(
    "Release recommendation",
    "Do not add public internet exposure, automatic blocking, or automatic model promotion for the final version. Keep the system in an authorized, isolated lab; keep IPS actions simulated; and require a human approval step for model promotion.",
    PALE_AMBER,
    AMBER,
)

page_break()

heading("1. Scope, method, and evidence", 1)
p("This assessment reviewed the active repository, preserved artifacts, teammate guides, and the newly attached academic project material. It is a code-and-evidence audit, not a penetration test. Findings are therefore prioritized by likely impact, demonstrability, and implementation effort.")

heading("Evidence reviewed", 2)
bullet("141 tracked repository files, including 80 Python modules, React source, Node/Express backend, Flask dashboard, n8n integration code, model artifacts, datasets, reports, and tests.")
bullet("Current data snapshot: 4,080 sanitized and balanced events across eight labels; 3,264 training rows and 816 held-out test rows; 23 encoded features; sequence length 10.")
bullet("Current model evaluation outputs, artifact manifests and checksums, test suites, frontend production build, and stored end-to-end run evidence.")
bullet("Three attached academic PDFs: the project abstract, 29-slide presentation, and 56-page final report.")

heading("Verification snapshot", 2)
make_table(
    ["Check", "Observed result", "Interpretation"],
    [
        ["Backend tests", "18 of 18 passed", "Node API baseline is healthy."],
        ["Frontend build", "Production build passed", "Current React source compiles."],
        ["Python static parse", "80 files passed", "No syntax-level Python failure detected."],
        ["Python test suite", "181 tests discovered but not executed", "Repository virtual environment points to a missing Python 3.12 installation; rebuild required."],
        ["Artifact integrity", "13 protected hashes and 18 manifest hashes matched", "Active model/data artifact set is internally consistent."],
        ["Stored end-to-end evidence", "5 PASS, 0 WARN, 0 FAIL; seven scenarios and 52 events", "A prior controlled demo run succeeded, but services were not currently running during this audit."],
        ["n8n runtime", "Command not available", "Final workflow must be installed, pinned, exported, and tested again."],
    ],
    [1800, 2700, 4860],
    9,
)

heading("Current model snapshot", 2)
make_table(
    ["Model", "Accuracy", "Macro F1", "Important observation"],
    [
        ["Decision Tree", "98.04%", "95.82%", "Best balanced conventional model in current held-out results; normal-as-attack FPR 1.27%."],
        ["Random Forest", "96.45%", "95.10%", "Strong macro score, but current normal-as-attack FPR is 30.38% and needs investigation."],
        ["LSTM", "100.00%", "100.00%", "Perfect performance on a small synthetic held-out set is a leakage/generalization warning, not proof of production accuracy."],
        ["Isolation Forest", "11.40%", "3.73%", "Threshold/feature setup is ineffective for the evaluated label task; recall is 1.90%."],
    ],
    [1850, 1200, 1200, 5110],
    9,
)

page_break()

heading("2. Prioritized fault register", 1)
p("Priority meanings: P0 blocks a trustworthy demo or creates avoidable security risk; P1 materially affects quality, correctness, reliability, or academic validity; P2 improves maintainability and future readiness.")

make_table(
    ["ID", "Priority", "Finding", "Why it matters", "Primary fix"],
    [
        ["F-01", "P0", "Services bind to all interfaces by default", "A local demo can become reachable from the LAN without an explicit decision.", "Bind to 127.0.0.1; require an authorized-lab flag for external binding."],
        ["F-02", "P0", "Fallback JWT and Flask secrets", "Known defaults make signed sessions/tokens forgeable if environment setup is missed.", "Fail startup when secrets are absent, weak, or equal to defaults."],
        ["F-03", "P0", "Real portal login payload may include the password in logs", "Operational authentication data must not be treated like honeypot telemetry.", "Never log the real portal password; redact and regression-test."],
        ["F-04", "P0", "Event and IDS result ingestion lack authentication", "A caller can inject fake events and poison analytics/evidence.", "Separate ingestion credential or HMAC, timestamp, nonce, replay rejection, rate limits."],
        ["F-05", "P0", "Hard-coded legacy webhook and raw sensitive fields", "It bypasses the finalized sanitization path and may leak captured data.", "Remove legacy UI trigger; use the canonical sanitized alert contract."],
        ["F-06", "P0", "Dashboard KPIs include Math.random()", "A security dashboard must never display fabricated operational numbers.", "Compute alerts and suspicious logins from deterministic stored queries."],
        ["F-07", "P0", "Academic documents disagree with implementation", "CNN/LIME and stronger automation claims are not supported by the current code.", "Update abstract, slides, report, diagram, and viva script to LSTM/SHAP and simulated IPS."],
        ["F-08", "P1", "JWT stored in localStorage", "Any successful script injection can read the token.", "Prefer secure HttpOnly SameSite cookie; add CSP and focused XSS controls."],
        ["F-09", "P1", "Duplicate Flask and React dashboards", "Features and fixes can diverge; reviewers may see conflicting numbers.", "Select React as the primary UI and keep Flask only as a minimal fallback/API if needed."],
        ["F-10", "P1", "Collector queue can silently drop and block records", "Loss and head-of-line blocking weaken evidence completeness.", "Durable outbox, bounded retries, dead-letter storage, drop counters, health alarms."],
        ["F-11", "P1", "Logs and dashboard reads lack lifecycle controls", "JSONL growth and full-file reads will slow the system and complicate retention.", "Rotate/partition logs; paginate/query SQLite; define retention and backups."],
        ["F-12", "P1", "ML split may not isolate campaigns/generators", "Near-duplicate synthetic events can appear in train and test, inflating scores.", "Group-aware, temporal, deduplicated and out-of-generator evaluation."],
        ["F-13", "P1", "Anomaly model and RF false-positive behavior", "Current outputs are not suitable as reliable voting components without tuning.", "Tune thresholds and features on validation data; calibrate and report per-class errors."],
        ["F-14", "P1", "Continuous-learning path is not demonstrated end to end", "Code existence is weaker evidence than a reproducible candidate/promotion/rollback run.", "Stage the complete lifecycle and record immutable manifests."],
        ["F-15", "P1", "Five-terminal manual startup and no supervisor", "Demos are fragile; partial service failures are difficult to detect.", "One-command orchestration, health/readiness, graceful shutdown, startup preflight."],
        ["F-16", "P2", "Limited frontend test coverage and accessibility evidence", "UI regressions can break the primary demo path.", "Component, integration, end-to-end, responsive, keyboard and WCAG checks."],
        ["F-17", "P2", "Legacy backup generation can be mistaken for current artifacts", "Older 30-feature/862-row files are incompatible with the active generation.", "Label archives as historical; enforce manifest generation IDs and restore tests."],
    ],
    [520, 650, 2050, 3000, 3140],
    7.5,
)

page_break()

heading("3. P0 remediation: make the current system trustworthy", 1)

heading("3.1 Network exposure and secrets", 2)
p("The honeypot launcher defaults SSH, FTP, and HTTP to 0.0.0.0, and the Node server does not provide an explicit host to app.listen. This is convenient for a lab but unsafe as a default. The secure default should be loopback-only; wider binding should require an explicit environment setting such as AUTHORIZED_LAB_MODE=true plus a displayed warning.")
bullet("Add BIND_HOST=127.0.0.1 as the default for every service, including dashboards and collectors.")
bullet("Fail closed when JWT_SECRET, Flask session secret, ingestion secret, or alert signing secret is missing, too short, or matches a known development value.")
bullet("Store only .env.example in version control. Rotate any credentials ever included in ZIP handoffs, old workflows, screenshots, or guide packages.")
bullet("Add a startup preflight that prints safe configuration status without printing secret values.")

heading("3.2 Separate operational authentication from decoy capture", 2)
p("Captured credentials are valid research telemetry inside explicit honeypot services, but the analyst/admin portal is an operational system. Its real login password must never be copied into event payloads or logs. OWASP recommends excluding authentication passwords, access tokens, and session identifiers from application logs [S1].")
bullet("At the portal boundary, retain username, result, timestamp, source class, request ID, and coarse client metadata; replace the password with a fixed redaction marker before any logger call.")
bullet("Keep credential capture only in clearly named decoy modules and label those fields as sensitive research data.")
bullet("Add automated tests that submit a unique canary password and assert that it does not appear in JSONL, SQLite, backend logs, webhook payloads, UI state, or test artifacts.")

heading("3.3 Authenticate and validate ingestion", 2)
p("POST /api/events and POST /api/ids-results currently accept data without an independent service credential. Login protection does not protect machine-to-machine ingestion. Use a separate trust boundary as recommended for protected REST endpoints [S2].")
bullet("Sign each ingestion request with HMAC-SHA256 over a canonical body, timestamp, and nonce; or use a long scoped API key over TLS in a contained lab.")
bullet("Reject timestamps outside a narrow window and repeated nonces. Rate-limit by credential and source address; return 429 with retry guidance.")
bullet("Validate an explicit JSON schema, cap body size, reject unknown or overlong fields, and store a validation failure counter.")
bullet("Never reuse the analyst JWT as the collector credential. Rotate independently and assign only the exact ingestion permission.")

heading("3.4 Make dashboard data honest", 2)
p("The backend currently generates two dashboard KPI values with Math.random(). This is a critical credibility fault. Replace them with deterministic queries and display data freshness. A missing metric should show “Unavailable” rather than a plausible random number.")
bullet("Define every KPI formally: source table, filter, time window, aggregation, timezone, and refresh interval.")
bullet("Return generated_at, data_from, data_to, and model_version with dashboard responses.")
bullet("Add snapshot tests that seed a known database and assert exact KPI values.")

heading("3.5 Canonical alert path", 2)
p("Remove the frontend’s hard-coded localhost n8n URL and the older XAI webhook action. The browser should never send sensitive alert fields directly to an automation service. The server should generate one sanitized, schema-versioned alert and submit it through the existing canonical integration path.")
bullet("Export the final n8n workflow into version control with no credentials, pin the n8n version, and add an import-and-smoke-test guide.")
bullet("Use a single contract: event ID, time, service, coarse source, threat score, severity, model votes, redacted evidence summary, explanation summary, and dashboard deep link.")
bullet("Record delivery status, response code, attempts, next retry, and dead-letter reason without storing secret webhook values.")

page_break()

heading("4. Frontend improvement specification", 1)
callout(
    "Product direction",
    "Make the React interface the single primary SOC experience. It should answer four questions immediately: What is happening? What is most serious? Why was it classified that way? What action or review is required?",
    PALE_GREEN,
    GREEN,
)

heading("4.1 Proposed information architecture", 2)
make_table(
    ["Page", "Purpose", "Essential content"],
    [
        ["Overview", "Immediate operational picture", "Real event count, high-severity count, top attack type/service/source, trend, ingestion freshness, queue and alert health."],
        ["Incidents", "Triage and investigation", "Filterable table, severity, attack, service, source, score, status, model agreement, timestamp, owner, feedback state."],
        ["Incident detail", "Explain one decision", "Timeline, sanitized evidence, component votes, calibrated confidence, SHAP summary, agent outputs, alert attempts, analyst feedback, simulated IPS action, audit trail."],
        ["Models", "Evidence and lifecycle", "Active versions, artifact hashes, training data generation, metrics, per-class confusion, thresholds, drift, candidate status, rollback history."],
        ["System health", "Detect partial failure", "Service readiness, last event, queue depth/drops, database status, n8n status, agent latency/errors, disk/log retention."],
        ["Settings & audit", "Controlled administration", "User/session controls, safe configuration status, integration status, audit log, export controls; never display secrets."],
    ],
    [1500, 2500, 5360],
    9,
)

heading("4.2 Overview layout", 2)
decimal_num = new_number_sequence(doc, decimal_abstract)
numbered("Top bar: project/lab name, environment badge, data freshness, authenticated user, logout.")
numbered("First row: four real KPI cards—events in selected window, high-severity incidents, unresolved reviews, and alert-delivery failures.")
numbered("Second row: event trend by severity and attack distribution. Keep colors consistent and color-blind safe.")
numbered("Third row: live incident table and a compact system-health panel.")
numbered("Persistent warning banners: stale data, failed integration, queue drops, model mismatch, or unauthorized lab exposure.")

heading("4.3 Incident detail—the project’s strongest demonstration screen", 2)
bullet("Summary strip: label, severity, score, status, model version, event time, service and a privacy-safe source representation.")
bullet("Evidence tab: sanitized request/command summary, protocol facts, rule matches, and sequence context.")
bullet("Model tab: Decision Tree, Random Forest, Isolation Forest and LSTM outputs; show disagreement explicitly instead of hiding it in one score.")
bullet("Explainability tab: top SHAP contributions in plain language, expected baseline, direction of influence, and an explanation limitation note.")
bullet("Agent tab: six agent outputs with status, duration, confidence or evidence basis, schema version, and any partial failure.")
bullet("Response tab: analyst label/correction, notes, alert-delivery history, simulated IPS proposal, approval and audit entries.")

heading("4.4 UX and accessibility requirements", 2)
p("Target WCAG 2.2 Level AA [S4]. Security dashboards often overuse color, dense charts, and tiny type; the improved UI should remain usable by keyboard and on a 1366×768 presentation screen.")
bullet("Use text labels and icons in addition to severity color. Maintain visible focus, logical tab order, landmark headings, accessible names, and useful error messages.")
bullet("Provide loading skeletons, empty states, permission-denied states, partial-service errors, stale-data states, and retry actions.")
bullet("Use responsive breakpoints: cards stack, charts preserve labels, and tables convert to a scrollable or card-based view without losing essential fields.")
bullet("Keep chart interactions optional; the same conclusion must be available in text or a table.")
bullet("Do not place secrets or raw captured credentials in the DOM. Provide a redacted default and a separately authorized evidence-export workflow if academically required.")

heading("4.5 Frontend engineering tasks", 2)
make_table(
    ["Work item", "Implementation note", "Acceptance check"],
    [
        ["Configuration", "Use environment-based API base URL; no hard-coded localhost webhook.", "Repository search finds no environment-specific URL in UI source."],
        ["Authentication", "Move from localStorage JWT to HttpOnly, Secure where applicable, SameSite cookie; add CSRF strategy.", "Token is unreadable from browser JavaScript; logout invalidates the session."],
        ["Data layer", "Centralize requests, cancellation, retry policy, schema validation and error mapping.", "Network failures produce deterministic UI states and no duplicate submissions."],
        ["Components", "Reusable cards, charts, filters, tables, drawers, badges, health indicators and audit timeline.", "Story/example coverage for all normal and failure states."],
        ["Testing", "Vitest/React Testing Library for units; Playwright for primary flows.", "Login, overview, filter, incident detail, feedback, alert retry and logout pass."],
        ["Quality", "Responsive, keyboard, contrast and performance checks.", "No serious automated accessibility violations; usable at 1366×768 and mobile width."],
    ],
    [1800, 4300, 3260],
    8.5,
)

page_break()

heading("5. Data, ML, and XAI improvement plan", 1)

heading("5.1 Treat perfect accuracy as a question", 2)
p("The 100% LSTM result may be correct for the current held-out synthetic split, but it is not sufficient evidence of generalization. A balanced synthetic dataset can contain repeated templates, generator-specific wording, shared campaign patterns, or sequences that cross the train/test boundary. The final evaluation must separate related groups. GroupKFold is designed so the same group does not appear in both training and test sets [S3].")

heading("5.2 Evaluation design", 2)
decimal_num = new_number_sequence(doc, decimal_abstract)
numbered("Assign group IDs before splitting: campaign/session, source generator seed, payload family, or attack script. Preserve those IDs only for evaluation, not as predictive features.")
numbered("Canonicalize and deduplicate payloads. Report exact and near-duplicate rates before and after splitting.")
numbered("Create train, validation, and final test sets. Tune thresholds and hyperparameters only on validation; open the final test once for the report.")
numbered("Run a temporal backtest and an out-of-generator test using newly produced scenarios that did not create the training set.")
numbered("Add a small external or manually curated challenge set with clear licensing and provenance. Do not silently mix external data into the main synthetic result.")
numbered("Repeat training across several seeds. Report mean, standard deviation, confidence intervals, confusion matrices, per-class precision/recall/F1, macro F1, balanced accuracy, false-positive rate, calibration and latency.")
numbered("Run leakage tests: label shuffling, feature ablation, duplicate-group removal, and a simple lexical baseline. Suspiciously high performance after these checks should trigger dataset inspection.")

heading("5.3 Component-specific work", 2)
make_table(
    ["Component", "Current issue", "Improvement"],
    [
        ["Decision Tree", "Strong baseline; may overfit rules/templates.", "Depth/min-leaf tuning, grouped validation, stability across seeds, rule extraction for interpretation."],
        ["Random Forest", "30.38% normal-as-attack FPR in current output.", "Inspect class mapping/threshold, calibrate probabilities, tune class weights, analyze false-positive clusters."],
        ["Isolation Forest", "Very low recall and F1 for current evaluation.", "Train on appropriate normal baseline, validate contamination/threshold, reconsider features, report anomaly task separately from multiclass classification."],
        ["LSTM", "Perfect score on small synthetic held-out data.", "Session-safe sequences, grouped/temporal split, padded-mask checks, out-of-generator challenge, calibration and inference latency."],
        ["Hybrid score", "Weights can hide component disagreement.", "Tune on validation data, expose votes and uncertainty, define abstain/review state, document threshold rationale."],
        ["SHAP/XAI", "Strong tabular explanation path; sequential explanation is less clear.", "Component-specific explanations, Integrated Gradients or equivalent for LSTM if added, stability/fidelity checks, plain-language limitations."],
    ],
    [1650, 3300, 4410],
    7.8,
)

heading("5.4 Model governance", 2)
p("Use the NIST AI Risk Management Framework as a lightweight structure: govern the process, map the context, measure performance and risk, and manage changes [S5]. For this project, that means reproducible manifests rather than heavy bureaucracy.")
bullet("Dataset card: origin, generator, labels, balance, sanitization, exclusions, known limitations, privacy and license/provenance.")
bullet("Model card: intended lab use, prohibited use, training generation, features, thresholds, metrics, slice results, limitations and ethical boundaries.")
bullet("Immutable candidate manifest: code commit, environment lock, data hashes, feature schema hash, random seeds, training config, model hashes and evaluation output.")
bullet("Human promotion gate: no candidate becomes active without passing fixed tests and recording the approver and reason. Keep a tested rollback to the previous active version.")
bullet("Drift signals: feature missingness/range, attack distribution, prediction distribution, confidence, disagreement, feedback corrections, false positives and latency.")

page_break()

heading("6. Reliability, storage, automation, and agents", 1)

heading("6.1 Durable event pipeline", 2)
p("The current JSONL fallback is useful, but silent queue drops and infinite per-record retry can hide loss or block later records. Convert the asynchronous collector path into an observable, bounded pipeline.")
bullet("Persist outgoing records to a local outbox before delivery; acknowledge/delete only after the destination commits.")
bullet("Use exponential backoff with a maximum attempt count, then move the record to a dead-letter store with the last error.")
bullet("Expose queue depth, oldest age, total dropped, retry count, dead-letter count and destination status on the health page.")
bullet("Use idempotency keys so retried events do not create duplicate incidents.")

heading("6.2 SQLite and logs", 2)
p("SQLite is suitable for this single-machine lab when configured deliberately. WAL mode permits readers and writers to proceed concurrently in common cases [S6].")
bullet("Enable WAL and a sensible busy_timeout; validate behavior under concurrent API/dashboard writes.")
bullet("Add schema versioning/migrations and indexes for timestamp, severity, attack type, service, event ID and feedback status.")
bullet("Paginate and filter queries in SQL; do not read and split the complete JSONL file for routine dashboard requests.")
bullet("Rotate JSONL by date/size, compress closed segments, define retention, and verify backup/restore from a clean directory.")
bullet("Keep an append-only audit trail for feedback, alert retries, model promotion and simulated IPS decisions.")

heading("6.3 Agent orchestration", 2)
bullet("Define a versioned input/output schema for each of the six agents; reject invalid output and record schema version.")
bullet("Set per-agent timeout and total incident budget. One failed agent must not block the complete dashboard result.")
bullet("Record started/completed/failed/timeout, duration, error class and evidence references. Show partial completion honestly.")
bullet("Use circuit breakers for repeatedly failing integrations and allow a safe retry from the incident page.")
bullet("Treat ATT&CK mappings as evidence-linked hypotheses. Do not show a technique ID unless a rule or observable supports it.")

heading("6.4 One-command operation", 2)
make_table(
    ["Command goal", "Required behavior"],
    [
        ["setup", "Check supported Python/Node/n8n versions, create environments, install locked dependencies, copy .env.example, and verify model artifacts."],
        ["start", "Start only after preflight passes; print URLs and health; save PID/state safely; default to loopback."],
        ["verify", "Run 181 Python tests, 18 backend tests, frontend tests/build, artifact integrity, schema checks and end-to-end smoke scenarios."],
        ["stop", "Gracefully stop listeners/workers, flush queues, checkpoint storage, and confirm ports are released."],
        ["backup/restore", "Create dated data/config-free backup; restore into a clean temporary directory and verify hashes and migrations."],
    ],
    [2100, 7260],
    9,
)

heading("7. Step-by-step implementation roadmap", 1)
p("The sequence below is deliberately dependency-aware. Each step has a clear exit condition; do not begin major feature work while a preceding P0 gate remains open.")

roadmap = [
    ("Step 1 — Freeze and inventory the baseline", "Create a named release branch/tag, preserve the clean active artifacts, record commit 7ab745a, and produce a machine-readable inventory of source, data, schemas, models, workflows and current hashes.", "A clean clone can identify the exact active generation and distinguish the historical 30-feature/862-row backup."),
    ("Step 2 — Rebuild the reproducible toolchain", "Create a fresh Python 3.12 environment, lock Python and Node dependencies, pin n8n, and document supported versions. Remove the stale virtual-environment reference.", "All dependency installs succeed from the lock files on a clean machine."),
    ("Step 3 — Run the full baseline verification", "Execute 181 Python tests, 18 backend tests, frontend production build, static checks, artifact integrity and stored/e2e scenarios. Capture failures before editing behavior.", "A dated baseline report lists every command, version, pass/fail result and artifact hash."),
    ("Step 4 — Close P0 security gaps", "Loopback binding, fail-closed secrets, secret rotation, portal password redaction, authenticated ingestion, schema/body limits, rate limits, safe file path containment and exact CORS origins.", "Security regression tests pass; no canary password or secret is found in logs/build/workflows; unauthorized ingestion is rejected."),
    ("Step 5 — Repair alerting and KPI correctness", "Remove hard-coded legacy webhook calls, export the canonical sanitized workflow, add delivery audit/retry/dead letter, and replace random KPIs with deterministic queries.", "Seeded data produces exact expected KPIs and a sanitized Telegram alert; failure/retry is visible."),
    ("Step 6 — Harden the event pipeline and storage", "Durable outbox, bounded retries, idempotency, log rotation, SQL pagination/indexes/migrations, WAL/busy timeout, backup and restore.", "A failure-injection test loses no accepted events, surfaces dead letters, and restores the database correctly."),
    ("Step 7 — Converge on one frontend", "Make React the primary dashboard, centralize API handling, secure sessions, implement real overview, incidents, models, system health and audit pages.", "All primary demo flows work without Flask/React data disagreement or hard-coded environment URLs."),
    ("Step 8 — Finish UX, accessibility and frontend tests", "Responsive states, keyboard use, contrast, loading/empty/error/stale behavior, component tests and Playwright flows.", "Required flows pass at desktop/mobile widths and no serious automated accessibility issue remains."),
    ("Step 9 — Rebuild ML evaluation", "Group-aware/temporal splits, deduplication, validation/test separation, repeated seeds, calibration, uncertainty, per-class analysis, latency and leakage tests.", "A reproducible evaluation report supports each claimed metric and explains perfect or weak component results."),
    ("Step 10 — Operationalize XAI, agents and learning", "Component-specific explanations, agent schemas/timeouts/audit, candidate manifests, fixed promotion gates, rollback and drift dashboard.", "A staging run creates a candidate, blocks/approves it by policy, promotes with audit, and successfully rolls back."),
    ("Step 11 — Add continuous integration and release packaging", "Automate tests/build/lint, dependency and secret scanning, schema compatibility, artifact hashes and release bundle generation.", "A pull request cannot merge when a required gate fails; a generated release contains no secrets or historical incompatible artifacts."),
    ("Step 12 — Align academic evidence and rehearse", "Rewrite abstract/report/slides, update diagrams and screenshots, create a claim-to-evidence matrix, run the final scenario suite, and rehearse expected failures.", "Every viva claim points to current code, a metric, a screenshot or a repeatable demonstration; terminology is consistent everywhere."),
]

for title_text, actions, done in roadmap:
    heading(title_text, 2)
    p("Actions: " + actions, bold_lead="Actions: ")
    p("Done when: " + done, bold_lead="Done when: ")

page_break()

heading("8. Suggested eight-week delivery plan", 1)
make_table(
    ["Week", "Primary objective", "Outputs", "Gate"],
    [
        ["1", "Baseline and P0 security", "Inventory, clean environments, baseline tests, secret rotation, loopback defaults, redaction tests", "No known P0 secret/log/exposure issue remains"],
        ["2", "API, alerting and reliability", "Authenticated ingestion, validation/rate limits, canonical workflow, KPI fixes, outbox design", "Injected/invalid data rejected; real KPIs verified"],
        ["3", "Frontend foundation", "Single React shell, secure session, API layer, overview and health", "Primary dashboard uses only real backend data"],
        ["4", "Frontend investigation flow", "Incidents, detail drawer/page, XAI, agents, feedback, audit, responsive/accessibility tests", "End-to-end analyst flow passes"],
        ["5", "Dataset and evaluation rebuild", "Groups, dedupe, split manifests, challenge set, repeated evaluation", "Leakage checks and per-class report complete"],
        ["6", "Model/XAI/agent refinement", "Thresholds, calibration, disagreement, model cards, explanation checks, agent budgets", "Hybrid output is calibrated and inspectable"],
        ["7", "Learning, CI and recovery", "Candidate/promotion/rollback, drift, CI gates, backup/restore, release packaging", "Full lifecycle and recovery drill passes"],
        ["8", "Academic alignment and final rehearsal", "Updated abstract/report/slides, screenshots, evidence matrix, final verification", "One-command demo and viva checklist pass twice"],
    ],
    [650, 2100, 4300, 2310],
    8,
)

heading("Work allocation suggestion", 2)
make_table(
    ["Stream", "Best owner profile", "Coordination points"],
    [
        ["Security/API/reliability", "Backend teammate", "Agrees schemas and auth/session contract with frontend and collector work."],
        ["Frontend/UX", "React teammate", "Uses seeded API fixtures and co-owns acceptance flows."],
        ["ML/data/XAI", "ML teammate", "Publishes immutable feature/split/model manifests and dashboard-ready metrics."],
        ["Integration/testing/docs", "Integration or project lead", "Owns n8n, end-to-end evidence, CI, diagrams, claims and release checklist."],
    ],
    [1900, 2800, 4660],
    9,
)

callout(
    "Planning note",
    "If time is shorter than eight weeks, complete Weeks 1–4 and the documentation corrections first. A secure, honest, coherent prototype is stronger than a larger system with unverified claims.",
    PALE_AMBER,
    AMBER,
)

page_break()

heading("9. Acceptance and test plan", 1)

heading("9.1 Security acceptance", 2)
bullet("All services are loopback-only unless an explicit authorized-lab configuration is enabled.")
bullet("Startup fails for missing/default secrets; repository and release secret scans are clean.")
bullet("A unique real-portal password never appears in any log, database event, webhook payload, UI state, test report, screenshot, or exported bundle.")
bullet("Unauthenticated, expired, replayed, oversized and schema-invalid ingestion requests are rejected and counted.")
bullet("Role and session tests cover login throttling, logout, expiry, privilege checks and CSRF strategy.")
bullet("File download tests cover encoded traversal, mixed separators, absolute paths and unexpected extensions.")

heading("9.2 Functional and reliability acceptance", 2)
bullet("A controlled attack scenario appears in JSONL/SQLite, IDS result, XAI, agent output, dashboard, alert and audit trail with one consistent event ID.")
bullet("Stopping the collector or n8n does not silently lose accepted events; retry/dead-letter status is visible and recovery is idempotent.")
bullet("Every dashboard KPI equals a known seeded database query; no random or placeholder metric is displayed as operational truth.")
bullet("Backup/restore, artifact integrity, schema migration and rollback pass from a clean temporary directory.")
bullet("Graceful shutdown flushes pending work and releases the required ports.")

heading("9.3 ML/XAI acceptance", 2)
bullet("Train/validation/test groups are disjoint and split manifests are hashed.")
bullet("Results include per-class and aggregate metrics, confidence intervals or multi-seed variation, calibration, latency and the exact decision thresholds.")
bullet("Challenge events generated after the split definition are evaluated separately and not used for tuning.")
bullet("Each explanation names the component being explained and never implies SHAP explains the complete hybrid decision unless it actually does.")
bullet("Model candidate promotion and rollback are human-approved, auditable and reproducible.")

heading("9.4 Frontend acceptance", 2)
bullet("Login → overview → filtered incident → detail/XAI/agents → analyst feedback → simulated action → logout passes end to end.")
bullet("Loading, empty, stale, partial-error and permission-denied states are implemented and tested.")
bullet("Keyboard-only use reaches all required actions; focus is visible; severity is not communicated by color alone.")
bullet("The core demo remains readable at 1366×768 and a narrow mobile viewport.")

heading("10. Academic report and presentation corrections", 1)
callout(
    "Most important documentation correction",
    "The attached abstract, slide deck, and final report describe CNN and LIME in several places, while the current implementation and README use LSTM and SHAP. They also imply broader ransomware, real-world, adaptive, and automated-response capability than the present evidence supports. Correct this before the next review.",
    PALE_RED,
    RED,
)

heading("Use this consistent implementation statement", 2)
p("The system is an authorized-lab hybrid honeypot and intrusion-analysis prototype. It collects SSH, FTP, and HTTP decoy events; stores normalized telemetry; combines rule-based detection, Decision Tree, Random Forest, Isolation Forest, and LSTM outputs; calculates a hybrid threat score; provides SHAP-based tabular explanations and structured multi-agent analysis; supports analyst feedback; sends sanitized n8n/Telegram alerts; and demonstrates simulated IPS recommendations and an offline, human-gated continuous-learning workflow.")

heading("Claim correction matrix", 2)
make_table(
    ["Current/legacy claim", "Replace with", "Evidence required"],
    [
        ["CNN is implemented", "LSTM sequence model is implemented; CNN is not part of the active baseline.", "Model code, manifest, evaluation output and architecture diagram."],
        ["LIME explains predictions", "SHAP explains the supported tabular model contribution; scope and limitations are stated.", "Explanation example tied to a model/version and event."],
        ["Automatically blocks malicious users", "Produces simulated IPS actions in an authorized lab; no production firewall mutation.", "Before/after firewall check and audit record."],
        ["Detects ransomware", "Detects the eight documented event labels/scenarios in the current dataset unless a distinct ransomware experiment is added.", "Label taxonomy and evaluation set."],
        ["Works in real-world applications", "Demonstrated in a controlled lab; external validity remains future work.", "Deployment boundary and limitations section."],
        ["Continuously adapts automatically", "Offline candidate training is human-gated with explicit promotion and rollback.", "Candidate registry and staged lifecycle evidence."],
        ["100% accurate", "Achieved 100% on the present held-out synthetic LSTM test set; group-aware and external/generalization evaluation is pending.", "Final split manifest and expanded evaluation."],
    ],
    [2600, 4300, 2460],
    8,
)

heading("Required document updates", 2)
bullet("Abstract: problem, implemented architecture, dataset/evaluation boundaries, verified results, and explicit controlled-lab limitation.")
bullet("Architecture diagram: show three honeypots → normalized event store → rules/models/hybrid score → XAI/agents → dashboard/feedback → sanitized alert → offline candidate lifecycle.")
bullet("Methodology: distinguish supervised multiclass classification, unsupervised anomaly detection, sequence classification, scoring, explanation and agent enrichment.")
bullet("Results: include per-class metrics, false positives, latency, confusion matrices, generalization tests, limitations and failed/weak components—not only best accuracy.")
bullet("Slides: use real dashboard screenshots, one end-to-end event trace, one explanation, one failure/retry example, and one ethics/scope slide.")
bullet("Viva preparation: create a claim-to-evidence table so each answer points to a code file, artifact hash, test, metric, screenshot or reproducible command.")

heading("11. Final definition of done", 1)
p("The improved project is ready for final evaluation only when the following statements are all true.")

make_table(
    ["Gate", "Definition of done", "Evidence"],
    [
        ["Security", "Local-by-default, fail-closed secrets, no operational password leakage, authenticated ingestion, bounded input and protected sessions.", "Automated security tests and clean scans."],
        ["Correctness", "All KPIs, alerts and incident states are deterministic and traceable to stored data.", "Seeded database assertions and event-ID trace."],
        ["Reproducibility", "Clean setup, start, verify, stop, backup and restore are documented and automated.", "Two clean-machine rehearsals."],
        ["ML validity", "Group-aware and temporal/generalization tests support the claims; weak models are tuned, scoped or excluded.", "Signed/hashed evaluation bundle and model card."],
        ["Usability", "One responsive React dashboard supports complete triage and explanation flows with accessible states.", "Frontend/e2e/accessibility evidence."],
        ["Reliability", "No silent loss, bounded retry/dead letter, visible health, migrations and rollback.", "Failure-injection and recovery report."],
        ["Academic integrity", "Abstract, report, slides, diagrams and demo describe the same implemented system and limitations.", "Claim-to-evidence matrix and supervisor review."],
        ["Ethics", "Authorized-lab-only use, data minimization, retention, redaction, simulated response and prohibited-use boundaries are explicit.", "Ethics/scope section and configuration defaults."],
    ],
    [1500, 4980, 2880],
    8.5,
)

heading("Recommended final demonstration flow", 2)
decimal_num = new_number_sequence(doc, decimal_abstract)
numbered("Run startup preflight and show all services healthy on loopback.")
numbered("Generate one known SSH/FTP/HTTP attack scenario in the authorized lab.")
numbered("Trace the same event ID through telemetry, normalized storage, detector votes, hybrid score, SHAP explanation, agent enrichment and dashboard.")
numbered("Show a sanitized alert, then intentionally stop n8n and demonstrate visible retry/dead-letter behavior without data loss.")
numbered("Submit analyst feedback and show the immutable audit entry.")
numbered("Demonstrate a simulated IPS recommendation and prove the host firewall is unchanged.")
numbered("Show active model/data hashes, an evaluation limitation, and candidate promotion/rollback evidence.")
numbered("Run the verification command and close with the exact scope: controlled lab prototype, not autonomous production defense.")

callout(
    "Bottom line",
    "The project already contains enough technical breadth. Its strongest path to a higher-quality final submission is disciplined consolidation: secure the boundaries, make every number real, validate generalization, build one excellent dashboard, and make the documents tell exactly the same story as the code.",
    PALE_GREEN,
    GREEN,
)

heading("Appendix A — Repository evidence references", 1)
p("Line numbers reflect the reviewed baseline and may move after remediation. These references support the principal findings and should be converted into tracked issues before implementation.")
make_table(
    ["Evidence ID", "Location", "Observation"],
    [
        ["E1", "core/launcher.py:15–17", "SSH, FTP and HTTP bind host defaults are 0.0.0.0."],
        ["E2", "backend/server.js:775", "Express listens without an explicit loopback host."],
        ["E3", "backend/middleware/auth.js:12; backend/server.js:658", "JWT secret falls back to dev_secret."],
        ["E4", "dashboard/app.py:58–60", "Flask dashboard secret has a known development fallback."],
        ["E5", "backend/server.js:631–648", "Portal login failure path constructs a username/password payload for logging."],
        ["E6", "frontend/src/api.js:6,30", "JWT is persisted in browser localStorage."],
        ["E7", "backend/server.js:245,296", "Event and IDS-result POST endpoints do not use the analyst auth middleware or a separate ingestion credential."],
        ["E8", "frontend/src/pages/DashboardPage.jsx:95", "Hard-coded n8n URL and older xai-honeypot webhook path."],
        ["E9", "backend/server.js:693–694", "Two dashboard KPIs are generated with Math.random()."],
        ["E10", "core/logger.py", "Asynchronous queue can drop on full; retry behavior can block later collector records; raw webhook payload path exists."],
        ["E11", "README.md:84", "Active project explicitly states CNN and LIME are not implemented."],
        ["E12", "D:\\mj sem6 work\\*.pdf", "Attached academic abstract/slides/report use CNN/LIME and broader capability language."],
        ["E13", "D:\\honeypot_v2_artifact_backups", "Historical 30-feature/862-row generation differs from the current active artifacts."],
    ],
    [900, 3450, 5010],
    8,
)

heading("Appendix B — Standards and authoritative references", 1)
sources = [
    ("S1", "OWASP Logging Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html", "Sensitive-data exclusion, sanitization, monitoring and log handling."),
    ("S2", "OWASP REST Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html", "Endpoint authentication, API keys, rate limiting, validation and transport expectations."),
    ("S3", "scikit-learn GroupKFold", "https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html", "Non-overlapping grouped cross-validation."),
    ("S4", "W3C Web Content Accessibility Guidelines (WCAG) 2.2", "https://www.w3.org/TR/wcag/", "Accessibility target for the dashboard."),
    ("S5", "NIST AI Risk Management Framework", "https://www.nist.gov/itl/ai-risk-management-framework", "Govern, map, measure and manage structure for AI risk and evidence."),
    ("S6", "SQLite Write-Ahead Logging", "https://www.sqlite.org/wal.html", "WAL behavior and operational considerations."),
    ("S7", "OWASP Application Security Verification Standard", "https://owasp.org/www-project-application-security-verification-standard/", "Structured security-verification requirements."),
]
for sid, name, url, note in sources:
    para = doc.add_paragraph()
    para.paragraph_format.space_after = Pt(8)
    set_run_font(para.add_run(f"{sid} — "), bold=True, color=NAVY)
    add_hyperlink(para, name, url)
    set_run_font(para.add_run(f". {note}"), color=TEXT)

heading("Appendix C — First backlog to create", 1)
p("Create these as separate tracked tasks so progress is visible and reviewable.")
first_backlog = [
    "SEC-001 Loopback defaults and authorized-lab override",
    "SEC-002 Fail-closed secret validation and credential rotation",
    "SEC-003 Remove real portal password logging and add canary tests",
    "API-001 Signed/authenticated event and IDS ingestion",
    "API-002 Input schema, size limits, rate limits and file containment",
    "ALERT-001 Remove legacy browser webhook and export canonical sanitized workflow",
    "DASH-001 Replace random KPIs with tested database queries",
    "OPS-001 Fresh Python 3.12 environment and locked dependency setup",
    "OPS-002 One-command start/verify/stop with health/readiness",
    "DATA-001 Durable outbox, dead letter, log rotation and retention",
    "UI-001 React information architecture and secure session migration",
    "UI-002 Incident detail/XAI/agents/audit workflow",
    "ML-001 Group-aware split, dedupe and split manifest",
    "ML-002 RF false-positive and Isolation Forest threshold analysis",
    "ML-003 LSTM generalization, leakage and calibration evaluation",
    "MLOPS-001 Candidate promotion/rollback and drift evidence",
    "CI-001 Full automated quality, secret and artifact integrity gates",
    "DOC-001 Rewrite abstract, report, slides and architecture diagram",
]
for item in first_backlog:
    bullet(item)

doc.save(OUT)
print(OUT)
