"""Remove a verified blank page from the generated report-sections PDF."""

from pathlib import Path

from pypdf import PdfReader, PdfWriter


PDF = Path(
    r"D:\honeypot_v2\report_evidence\runs\20260907_final_report_evidence\report_sections.pdf"
)
TEMP = PDF.with_name("report_sections.without_blank.pdf")
BLANK_PAGE_NUMBER = 15  # one-based; visually verified to contain only its footer number

reader = PdfReader(PDF)
page = reader.pages[BLANK_PAGE_NUMBER - 1]
visible_text = (page.extract_text() or "").strip()
if visible_text not in {"", str(BLANK_PAGE_NUMBER)}:
    raise RuntimeError(
        f"Refusing to remove page {BLANK_PAGE_NUMBER}; extracted text was {visible_text!r}"
    )

writer = PdfWriter()
for index, source_page in enumerate(reader.pages, start=1):
    if index != BLANK_PAGE_NUMBER:
        writer.add_page(source_page)
writer.add_metadata(reader.metadata or {})
with TEMP.open("wb") as handle:
    writer.write(handle)
TEMP.replace(PDF)
print(f"removed blank page {BLANK_PAGE_NUMBER}; pages {len(reader.pages)} -> {len(writer.pages)}")
