"""Rasterize the actual egui headless mesh exports; never opens the desktop app.

Run the routing_ui headless test with RVPN_UI_PREVIEW_DIR, then pass each JSON
export here. Requires Pillow and NumPy. Font shaping and widget geometry come
from egui; this small software renderer approximates the GPU's blending.
"""
import argparse
import json
from pathlib import Path

import numpy as np
from PIL import Image


def render(source: Path):
    data = json.loads(source.read_text(encoding="utf-8"))
    width, height = map(int, data["size"])
    tw, th = data["atlas_size"]
    texture = np.array(data["atlas_rgba"], dtype=np.float32).reshape(th, tw, 4)
    canvas = np.zeros((height, width, 4), dtype=np.float32)
    canvas[:] = [27, 27, 30, 255]
    for mesh in data["meshes"]:
        vertices = np.array(mesh["vertices"], dtype=np.float32)
        indices = np.array(mesh["indices"], dtype=np.int32).reshape(-1, 3)
        clip = mesh["clip"]
        for tri in indices:
            v = vertices[tri]
            left = max(0, int(np.floor(max(v[:, 0].min(), clip[0]))))
            top = max(0, int(np.floor(max(v[:, 1].min(), clip[1]))))
            right = min(width, int(np.ceil(min(v[:, 0].max(), clip[2]))))
            bottom = min(height, int(np.ceil(min(v[:, 1].max(), clip[3]))))
            if left >= right or top >= bottom:
                continue
            x0, y0 = v[0, :2]
            x1, y1 = v[1, :2]
            x2, y2 = v[2, :2]
            denom = (y1-y2)*(x0-x2)+(x2-x1)*(y0-y2)
            if abs(denom) < 1e-7:
                continue
            yy, xx = np.mgrid[top:bottom, left:right].astype(np.float32)
            xx += 0.5
            yy += 0.5
            a = ((y1-y2)*(xx-x2)+(x2-x1)*(yy-y2))/denom
            b = ((y2-y0)*(xx-x2)+(x0-x2)*(yy-y2))/denom
            c = 1-a-b
            inside = (a >= 0) & (b >= 0) & (c >= 0)
            if not inside.any():
                continue
            weights = np.stack((a[inside], b[inside], c[inside]), axis=1)
            uv = weights @ v[:, 2:4]
            color = weights @ v[:, 4:8]
            tx = np.clip(uv[:, 0]*tw-0.5, 0, tw-1)
            ty = np.clip(uv[:, 1]*th-0.5, 0, th-1)
            ix, iy = tx.astype(int), ty.astype(int)
            jx, jy = np.minimum(ix+1, tw-1), np.minimum(iy+1, th-1)
            fx, fy = (tx-ix)[:, None], (ty-iy)[:, None]
            sample = (texture[iy, ix]*(1-fx)*(1-fy)+texture[iy, jx]*fx*(1-fy)
                      + texture[jy, ix]*(1-fx)*fy+texture[jy, jx]*fx*fy)
            rgba = color*sample/255
            target = canvas[top:bottom, left:right]
            target[inside] = rgba+target[inside]*(1-rgba[:, 3:4]/255)
    result = source.with_suffix(".png")
    Image.fromarray(np.clip(canvas, 0, 255).astype(np.uint8)).save(result)
    print(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("sources", type=Path, nargs="+")
    for source in parser.parse_args().sources:
        render(source)
