"""Renumber visible centered footers after removing the verified blank page."""

from io import BytesIO
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas


PDF = Path(
    r"D:\honeypot_v2\report_evidence\runs\20260907_final_report_evidence\report_sections.pdf"
)
TEMP = PDF.with_name("report_sections.renumbered.pdf")

reader = PdfReader(PDF)
writer = PdfWriter()
for page_number, page in enumerate(reader.pages, start=1):
    width = float(page.mediabox.width)
    height = float(page.mediabox.height)
    buffer = BytesIO()
    overlay = canvas.Canvas(buffer, pagesize=(width, height))
    overlay.setFillColorRGB(1, 1, 1)
    # Word placed the original number slightly higher than the PDF overlay.
    # Cover the full centered footer band before drawing a single clean number.
    overlay.rect(width / 2 - 35, 14, 70, 48, stroke=0, fill=1)
    overlay.setFillColorRGB(0, 0, 0)
    overlay.setFont("Times-Roman", 9)
    overlay.drawCentredString(width / 2, 28, str(page_number))
    overlay.save()
    buffer.seek(0)
    page.merge_page(PdfReader(buffer).pages[0])
    writer.add_page(page)
writer.add_metadata(reader.metadata or {})
with TEMP.open("wb") as handle:
    writer.write(handle)
TEMP.replace(PDF)
print(f"renumbered {len(writer.pages)} visible page footers")
