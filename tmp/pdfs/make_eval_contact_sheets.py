from pathlib import Path

from PIL import Image, ImageDraw, ImageOps


root = Path(r"D:\honeypot_v2\tmp\pdfs")
pages = sorted((root / "eval_rendered").glob("page-*.png"))
groups = [pages[index:index + 6] for index in range(0, len(pages), 6)]
thumb = (390, 552)

for group_index, group in enumerate(groups, start=1):
    canvas = Image.new("RGB", (thumb[0] * 3 + 50, thumb[1] * 2 + 55), (238, 242, 246))
    draw = ImageDraw.Draw(canvas)
    for item_index, page_path in enumerate(group):
        page = Image.open(page_path).convert("RGB")
        page.thumbnail(thumb)
        x = 12 + (item_index % 3) * (thumb[0] + 10)
        y = 12 + (item_index // 3) * (thumb[1] + 15)
        canvas.paste(ImageOps.expand(page, border=1, fill=(130, 140, 150)), (x, y))
        draw.rectangle((x + 4, y + 4, x + 70, y + 23), fill=(7, 21, 34))
        draw.text((x + 8, y + 7), page_path.stem, fill=(255, 255, 255))
    canvas.save(root / f"eval-contact-{group_index}.png")

print(f"Created {len(groups)} contact sheets from {len(pages)} pages")
