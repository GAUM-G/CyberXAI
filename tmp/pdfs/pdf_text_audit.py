from pathlib import Path
import sys

from pypdf import PdfReader

sys.stdout.reconfigure(encoding="utf-8")


pdf_path = Path(sys.argv[1])
needles = sys.argv[2:]
reader = PdfReader(pdf_path)
print(f"pages={len(reader.pages)}")
for number, page in enumerate(reader.pages, start=1):
    text = page.extract_text() or ""
    if not needles or any(needle.lower() in text.lower() for needle in needles):
        print(f"\n--- PAGE {number} ---\n{text}")
