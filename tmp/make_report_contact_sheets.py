from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

qa_dir = Path(r"D:\honeypot_v2\tmp\report_qa4")
pages = sorted(qa_dir.glob("page-*.png"), key=lambda path: int(path.stem.split("-")[-1]))
font = ImageFont.load_default()

for group_start in range(0, len(pages), 4):
    group = pages[group_start:group_start + 4]
    thumbs = []
    for path in group:
        image = Image.open(path).convert("RGB")
        target_width = 720
        target_height = round(image.height * target_width / image.width)
        thumbs.append((path, image.resize((target_width, target_height), Image.Resampling.LANCZOS)))
    cell_w = 760
    cell_h = max(image.height for _, image in thumbs) + 50
    sheet = Image.new("RGB", (cell_w * 2, cell_h * 2), "#D8DEE8")
    draw = ImageDraw.Draw(sheet)
    for index, (path, image) in enumerate(thumbs):
        x = (index % 2) * cell_w + 20
        y = (index // 2) * cell_h + 30
        draw.text((x, 8 + (index // 2) * cell_h), f"Page {path.stem.split('-')[-1]}", fill="#1F2937", font=font)
        sheet.paste(image, (x, y))
    out = qa_dir / f"contact-{group_start + 1:02d}-{group_start + len(group):02d}.png"
    sheet.save(out)
    print(out)
