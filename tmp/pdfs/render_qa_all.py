from pathlib import Path

import pypdfium2 as pdfium
from PIL import Image, ImageDraw, ImageOps


ROOT = Path(r"D:\honeypot_v2")
SOURCES = {
    "sections": ROOT / "report_evidence/runs/20260907_final_report_evidence/report_sections.pdf",
    "implementation": ROOT / "output/pdf/MOCK_IMPLEMENTATION_REPORT.pdf",
    "model_evaluation": ROOT / "output/pdf/MODEL_EVALUATION_PERFORMANCE_AND_DATASET_REPORT.pdf",
    "architecture": ROOT / "output/pdf/PROJECT_ARCHITECTURE_EXPLANATION.pdf",
}
QA_ROOT = ROOT / "tmp/pdfs/qa_all"


for key, pdf_path in SOURCES.items():
    output = QA_ROOT / key
    output.mkdir(parents=True, exist_ok=True)
    pdf = pdfium.PdfDocument(pdf_path)
    page_paths = []
    for index in range(len(pdf)):
        image = pdf[index].render(scale=1.55).to_pil().convert("RGB")
        page_path = output / f"page-{index + 1:02d}.png"
        image.save(page_path)
        page_paths.append(page_path)

    thumb = (390, 552)
    for sheet_index, start in enumerate(range(0, len(page_paths), 6), start=1):
        canvas = Image.new("RGB", (1220, 1145), (238, 242, 246))
        draw = ImageDraw.Draw(canvas)
        for slot, page_path in enumerate(page_paths[start : start + 6]):
            page = Image.open(page_path).convert("RGB")
            page.thumbnail(thumb)
            x = 12 + (slot % 3) * 402
            y = 12 + (slot // 3) * 567
            canvas.paste(ImageOps.expand(page, border=1, fill=(110, 125, 140)), (x, y))
            draw.rectangle((x + 4, y + 4, x + 82, y + 25), fill=(7, 21, 34))
            draw.text((x + 9, y + 7), page_path.stem, fill=(255, 255, 255))
        canvas.save(QA_ROOT / f"{key}-contact-{sheet_index}.png")
    print(f"{key}: {len(page_paths)} pages")
