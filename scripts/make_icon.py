"""Generate assets/app.ico - the R-VPN application icon.

A dark rounded tile carrying a shield in the connected-state green, with the
tray's white status dot at its centre. Same geometry as `icon_rgba` in
tray.rs, which draws the window and tray icons at runtime in the phase
colour.

Each size is drawn at 4x and downsampled, and the small sizes get a slightly
larger shield and dot so they stay readable at 16 px.

    python scripts/make_icon.py            # writes assets/app.ico
    python scripts/make_icon.py --preview  # also writes a contact sheet
"""

import math
import struct
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ICO = ROOT / "assets" / "app.ico"
PREVIEW = ROOT / "target" / "icon-preview.png"

SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
SUPERSAMPLE = 4

TILE_RADIUS = 0.21
TILE_TOP = (27, 37, 53)
TILE_BOTTOM = (11, 15, 23)
SHIELD = (46, 184, 114)
SHIELD_LIGHT = (72, 206, 140)
DOT = (255, 255, 255)


def geometry(size: int) -> dict:
    """Shield and dot in tile-relative units (0..1 across the tile)."""
    if size <= 24:
        return dict(hw=0.29, top=0.17, tip=0.86, curve=2.6, corner=0.08, dot=0.105, dot_y=0.46)
    return dict(hw=0.27, top=0.19, tip=0.84, curve=2.6, corner=0.055, dot=0.075, dot_y=0.455)


def shield_polygon(g: dict, scale: float) -> list:
    hw, top, tip, curve, corner = g["hw"], g["top"], g["tip"], g["curve"], g["corner"]

    def half_width(y: float) -> float:
        s = min(max((y - top) / (tip - top), 0.0), 1.0)
        return hw * math.sqrt(max(0.0, 1.0 - s**curve))

    def arc(cx, cy, start, end, steps=14):
        return [
            (cx + corner * math.cos(math.radians(start + (end - start) * i / steps)),
             cy + corner * math.sin(math.radians(start + (end - start) * i / steps)))
            for i in range(steps + 1)
        ]

    pts = []
    # top-left corner: from the left edge round to the top edge
    pts += arc(0.5 - hw + corner, top + corner, 180, 270)
    # top edge to the top-right corner, round down to the right edge
    pts += arc(0.5 + hw - corner, top + corner, 270, 360)
    # right side down to the tip
    steps = 120
    for i in range(1, steps + 1):
        y = top + corner + (tip - top - corner) * i / steps
        pts.append((0.5 + half_width(y), y))
    # left side back up
    for i in range(steps, -1, -1):
        y = top + corner + (tip - top - corner) * i / steps
        pts.append((0.5 - half_width(y), y))
    return [(x * scale, y * scale) for x, y in pts]


def render(size: int) -> Image.Image:
    g = geometry(size)
    w = size * SUPERSAMPLE
    canvas = Image.new("RGBA", (w, w), (0, 0, 0, 0))

    # tile: vertical gradient seen through a rounded-rectangle mask
    tile = Image.new("RGB", (w, w))
    tile.putdata(
        [
            tuple(round(a + (b - a) * y / (w - 1)) for a, b in zip(TILE_TOP, TILE_BOTTOM))
            for y in range(w)
            for _ in range(w)
        ]
    )
    mask = Image.new("L", (w, w), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, w - 1, w - 1), radius=w * TILE_RADIUS, fill=255)
    canvas.paste(tile, (0, 0), mask)

    # shield: accent that lightens a little towards the top
    shield_mask = Image.new("L", (w, w), 0)
    ImageDraw.Draw(shield_mask).polygon(shield_polygon(g, w), fill=255)
    shield = Image.new("RGB", (w, w))
    top, tip = g["top"] * w, g["tip"] * w
    shield.putdata(
        [
            tuple(round(b + (a - b) * max(0.0, min(1.0, (tip - y) / (tip - top))))
                  for a, b in zip(SHIELD_LIGHT, SHIELD))
            for y in range(w)
            for _ in range(w)
        ]
    )
    canvas.paste(shield, (0, 0), shield_mask)

    # status dot
    r = g["dot"] * w
    cx, cy = 0.5 * w, g["dot_y"] * w
    ImageDraw.Draw(canvas).ellipse((cx - r, cy - r, cx + r, cy + r), fill=DOT + (255,))

    return canvas.resize((size, size), Image.LANCZOS)


def bmp_entry(img: Image.Image) -> bytes:
    """32-bit BMP icon entry: BITMAPINFOHEADER, BGRA rows, AND mask."""
    w, h = img.size
    rgba = img.tobytes()
    rows = []
    mask_rows = []
    stride = ((w + 31) // 32) * 4
    for y in range(h - 1, -1, -1):
        row = bytearray()
        mask = bytearray(stride)
        for x in range(w):
            r, g, b, a = rgba[(y * w + x) * 4:(y * w + x) * 4 + 4]
            row += bytes((b, g, r, a))
            if a == 0:
                mask[x // 8] |= 0x80 >> (x % 8)
        rows.append(bytes(row))
        mask_rows.append(bytes(mask))
    header = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    return header + b"".join(rows) + b"".join(mask_rows)


def png_entry(img: Image.Image) -> bytes:
    import io

    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def write_ico(images: dict, path: Path) -> None:
    entries = []
    for size in SIZES:
        img = images[size]
        data = png_entry(img) if size >= 256 else bmp_entry(img)
        entries.append((size, data))
    offset = 6 + 16 * len(entries)
    out = bytearray(struct.pack("<HHH", 0, 1, len(entries)))
    for size, data in entries:
        out += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _, data in entries:
        out += data
    path.write_bytes(out)


def preview(images: dict, path: Path) -> None:
    """Contact sheet: every size at 1x on a light and a dark strip."""
    shown = [s for s in SIZES]
    pad = 16
    width = pad + sum(s + pad for s in shown) + 256 + pad * 2
    sheet = Image.new("RGBA", (width, 256 + 64 + 64 + 48), (0, 0, 0, 0))
    light = Image.new("RGBA", sheet.size, (243, 243, 243, 255))
    dark = Image.new("RGBA", sheet.size, (32, 32, 32, 255))
    for bg, y0 in ((light, 0), (dark, 256 + 64 + 48)):
        x = pad
        for s in shown:
            bg.alpha_composite(images[s], (x, y0 + pad + (64 - s) // 2 if s <= 64 else y0 + pad))
            x += s + pad
        bg.alpha_composite(images[256], (x, y0 + pad))
        sheet.alpha_composite(bg, (0, y0))
    sheet.save(path)


def main() -> int:
    images = {size: render(size) for size in SIZES}
    ICO.parent.mkdir(parents=True, exist_ok=True)
    write_ico(images, ICO)
    print(f"wrote {ICO} ({ICO.stat().st_size} bytes, sizes {SIZES})")
    if "--preview" in sys.argv[1:]:
        PREVIEW.parent.mkdir(parents=True, exist_ok=True)
        preview(images, PREVIEW)
        print(f"wrote {PREVIEW}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
