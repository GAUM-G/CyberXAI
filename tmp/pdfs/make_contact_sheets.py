from pathlib import Path

from PIL import Image, ImageDraw, ImageOps


root = Path(r"D:\honeypot_v2\tmp\pdfs")
pages = sorted((root / "rendered").glob("page-*.png"))
thumb = (350, 495)
for group_index, group in enumerate((pages[:7], pages[7:]), start=1):
    canvas = Image.new("RGB", (thumb[0] * 4 + 60, thumb[1] * 2 + 60), (238, 242, 246))
    draw = ImageDraw.Draw(canvas)
    for item_index, page_path in enumerate(group):
        page = Image.open(page_path).convert("RGB")
        page.thumbnail(thumb)
        x = 15 + (item_index % 4) * (thumb[0] + 10)
        y = 15 + (item_index // 4) * (thumb[1] + 15)
        canvas.paste(ImageOps.expand(page, border=1, fill=(130, 140, 150)), (x, y))
        draw.rectangle((x + 4, y + 4, x + 66, y + 22), fill=(7, 21, 34))
        draw.text((x + 8, y + 6), page_path.stem, fill=(255, 255, 255))
    canvas.save(root / f"contact-{group_index}.png")

print(f"Created 2 contact sheets from {len(pages)} pages")
