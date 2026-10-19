"""Generate DedSecLab Inno Setup wizard images (dark brand look)."""
from __future__ import annotations
from pathlib import Path
from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

HERE = Path(__file__).resolve().parent
A = HERE / "assets"
LOGO = A / "dedsec_logo.png"

BG = (6, 6, 6)
BG2 = (10, 22, 36)
TEAL = (34, 211, 238)       # #22d3ee
TEAL_DIM = (14, 116, 144)   # #0e7490
TEXT = (232, 240, 255)
MUTED = (120, 140, 160)
LINE = (20, 60, 75)

FONT_BOLD = [
    "/usr/share/fonts/truetype/sand-box/google/Rajdhani/Rajdhani-Bold.ttf",
    "C:/Windows/Fonts/segoeuib.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]
FONT_REG = [
    "/usr/share/fonts/truetype/sand-box/google/Rajdhani/Rajdhani-SemiBold.ttf",
    "C:/Windows/Fonts/segoeui.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]


def font(cands, size: int):
    for c in cands:
        try:
            return ImageFont.truetype(c, size)
        except OSError:
            continue
    return ImageFont.load_default()


def gradient(w: int, h: int) -> Image.Image:
    im = Image.new("RGB", (w, h), BG)
    px = im.load()
    for y in range(h):
        t = y / max(1, h - 1)
        r = int(BG[0] + (BG2[0] - BG[0]) * t)
        g = int(BG[1] + (BG2[1] - BG[1]) * t)
        b = int(BG[2] + (BG2[2] - BG[2]) * t)
        for x in range(w):
            edge = min(x, w - 1 - x) / max(1, w // 2)
            f = 0.85 + 0.15 * edge
            px[x, y] = (int(r * f), int(g * f), int(b * f))
    return im


def add_glow(base, cx, cy, radius, color, strength=0.55):
    layer = Image.new("RGB", base.size, (0, 0, 0))
    ImageDraw.Draw(layer).ellipse((cx - radius, cy - radius, cx + radius, cy + radius), fill=color)
    layer = layer.filter(ImageFilter.GaussianBlur(radius // 2))
    darkened = Image.eval(layer, lambda v: int(v * strength))
    return ImageChops.add(base, darkened)


def logo_rgba(size: int):
    lg = Image.open(LOGO).convert("RGBA")
    lg.thumbnail((size, size), Image.Resampling.LANCZOS)
    return lg


def paste_center(base, overlay, cx, cy):
    base.paste(overlay, (cx - overlay.width // 2, cy - overlay.height // 2), overlay)


def wordmark(draw, cx, y, scale):
    f1 = font(FONT_BOLD, 28 * scale)
    f2 = font(FONT_BOLD, 22 * scale)
    b1 = draw.textbbox((0, 0), "DEDSEC", font=f1)
    draw.text((cx - (b1[2] - b1[0]) // 2, y), "DEDSEC", font=f1, fill=TEXT)
    y2 = y + (b1[3] - b1[1]) + 2 * scale
    b2 = draw.textbbox((0, 0), "LAB", font=f2)
    draw.text((cx - (b2[2] - b2[0]) // 2, y2), "LAB", font=f2, fill=TEAL)
    return y2 + (b2[3] - b2[1])


def grid_lines(im, scale):
    overlay = Image.new("RGBA", im.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)
    step = 18 * scale
    w, h = im.size
    col = (*LINE, 50)
    for x in range(0, w, step):
        d.line([(x, 0), (x, h)], fill=col, width=1)
    for y in range(0, h, step):
        d.line([(0, y), (w, y)], fill=col, width=1)
    return Image.alpha_composite(im.convert("RGBA"), overlay).convert("RGB")


def wizard_image(scale):
    w, h = 164 * scale, 314 * scale
    im = gradient(w, h)
    im = add_glow(im, w // 2, int(h * 0.30), int(72 * scale), TEAL_DIM, 0.48)
    im = grid_lines(im, scale)
    base = im.convert("RGBA")
    paste_center(base, logo_rgba(int(100 * scale)), w // 2, int(h * 0.30))
    im = base.convert("RGB")
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, w, 3 * scale], fill=TEAL)
    d.rectangle([0, h - 3 * scale, w, h], fill=TEAL)
    y = int(h * 0.52)
    d.line([(int(w * 0.22), y), (int(w * 0.78), y)], fill=TEAL, width=max(2, 2 * scale))
    y = wordmark(d, w // 2, y + 10 * scale, scale)
    tag = font(FONT_REG, 11 * scale)
    label = "SECURITY LAB"
    bb = d.textbbox((0, 0), label, font=tag)
    d.text(((w - (bb[2] - bb[0])) // 2, y + 14 * scale), label, font=tag, fill=MUTED)
    return im


def wizard_small(scale):
    w, h = 55 * scale, 58 * scale
    im = gradient(w, h)
    im = add_glow(im, w // 2, h // 2, int(28 * scale), TEAL_DIM, 0.55)
    base = im.convert("RGBA")
    paste_center(base, logo_rgba(int(42 * scale)), w // 2, h // 2)
    im = base.convert("RGB")
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, w, max(1, scale)], fill=TEAL)
    d.rectangle([0, h - max(1, scale), w, h], fill=TEAL)
    return im


def main():
    A.mkdir(parents=True, exist_ok=True)
    if not LOGO.is_file():
        raise SystemExit(f"Missing logo: {LOGO}")
    w1, w2 = wizard_image(1), wizard_image(2)
    s1, s2 = wizard_small(1), wizard_small(2)
    w1.save(A / "wizard_image.png", optimize=True)
    w2.save(A / "wizard_image@2x.png", optimize=True)
    s1.save(A / "wizard_small.png", optimize=True)
    s2.save(A / "wizard_small@2x.png", optimize=True)
    w1.save(A / "wizard_image.bmp")
    s1.save(A / "wizard_small.bmp")
    print("Wrote:")
    for p in sorted(A.glob("wizard_*")):
        print(f"  {p.name}  {Image.open(p).size}")


if __name__ == "__main__":
    main()
