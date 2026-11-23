"""Build the release and package it, refusing anything that is not a
complete release binary.

Why this exists: `cargo test --no-default-features` (used so test executables
do not demand elevation) also rebuilds the plain binary *without* the
admin-manifest feature and overwrites target/release/rvpn-windows.exe. v0.1.9
was packaged from that file: it had no manifest and ran unelevated. This
script builds and packages in one go and verifies the artifact itself:

  * the PE has a .rsrc section with the requireAdministrator manifest,
  * a VERSIONINFO whose FileVersion is the workspace version,
  * the application icon (compared against the artwork in assets/app.ico),
  * wintun.dll is in the archive next to the exe.

    python scripts/package_release.py
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "target" / "release" / "rvpn-windows.exe"
ICO = ROOT / "assets" / "app.ico"
DIST = ROOT / "dist"


def workspace_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version = "):
            return line.split('"')[1]
    raise SystemExit("no `version = ` line in Cargo.toml")


def run(*cmd: str) -> None:
    print("+", " ".join(cmd), flush=True)
    result = subprocess.run(cmd, cwd=ROOT, env=os.environ)
    if result.returncode != 0:
        raise SystemExit(f"command failed with status {result.returncode}")


def check_pe(data: bytes, version: str) -> None:
    def fail(what: str) -> None:
        raise SystemExit(f"REFUSING TO PACKAGE: {what}")

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        fail("not a PE file")
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    sections = []
    for i in range(nsec):
        off = pe + 24 + optsz + 40 * i
        name = data[off:off + 8].rstrip(b"\0").decode("latin1")
        _vsize, _va, rsize, raw = struct.unpack_from("<IIII", data, off + 8)
        sections.append((name, raw, rsize))
    rsrc = next((s for s in sections if s[0] == ".rsrc"), None)
    if rsrc is None or rsrc[2] == 0:
        fail("no .rsrc section — this is a --no-default-features build; "
             "it would run without Administrator rights")
    resources = data[rsrc[1]:rsrc[1] + rsrc[2]]
    if b"requireAdministrator" not in resources:
        fail(".rsrc has no requireAdministrator manifest")
    if "VS_VERSION_INFO".encode("utf-16-le") not in resources:
        fail(".rsrc has no VERSIONINFO")
    if version.encode("utf-16-le") not in resources:
        fail(f"VERSIONINFO does not carry version {version}")
    if b"\x89PNG\r\n\x1a\n" not in resources:
        fail(".rsrc has no (256 px PNG) icon")


def check_icon(exe: Path) -> None:
    """The icon Windows reads from the exe is the one in assets/app.ico."""
    ico = Image.open(ICO)
    expected = ico.ico.getimage((32, 32)).convert("RGBA")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "extracted.png"
        script = (
            "Add-Type -AssemblyName System.Drawing; "
            f"$i = [System.Drawing.Icon]::ExtractAssociatedIcon('{exe}'); "
            f"$i.ToBitmap().Save('{out}', [System.Drawing.Imaging.ImageFormat]::Png)"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", script], check=True,
            capture_output=True, text=True,
        )
        got = Image.open(out).convert("RGBA")
    if got.size != expected.size:
        got = got.resize(expected.size, Image.LANCZOS)
    diff = sum(
        abs(a - b) for a, b in zip(expected.tobytes(), got.tobytes())
    ) / (expected.size[0] * expected.size[1] * 4)
    print(f"icon in the exe vs assets/app.ico: mean channel difference {diff:.1f}")
    if diff > 24:
        raise SystemExit(f"REFUSING TO PACKAGE: the exe does not carry the app icon (difference {diff:.1f})")


def main() -> int:
    version = workspace_version()
    run("cargo", "build", "--release")
    if not EXE.is_file():
        raise SystemExit(f"{EXE} was not built")
    data = EXE.read_bytes()
    check_pe(data, version)
    check_icon(EXE)
    digest = hashlib.sha256(data).hexdigest()

    DIST.mkdir(exist_ok=True)
    name = f"rvpn-windows-v{version}-win64.zip"
    archive = DIST / name
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(DIST / "QUICKSTART.txt", "QUICKSTART.txt")
        z.write(EXE, "rvpn-windows.exe")
        z.write(ROOT / "assets" / "wintun.dll", "wintun.dll")

    with zipfile.ZipFile(archive) as z:
        inside = z.read("rvpn-windows.exe")
        check_pe(inside, version)
        if hashlib.sha256(inside).hexdigest() != digest:
            raise SystemExit("REFUSING TO PACKAGE: the exe in the archive differs from the verified build")
        names = sorted(z.namelist())
    if names != ["QUICKSTART.txt", "rvpn-windows.exe", "wintun.dll"]:
        raise SystemExit(f"REFUSING TO PACKAGE: unexpected archive contents {names}")

    print(f"packaged {archive} ({archive.stat().st_size} bytes)")
    print(f"exe sha256 {digest}")
    print(f"zip sha256 {hashlib.sha256(archive.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
