#!/usr/bin/env python3
"""Refresh dependency notices from the locked Cargo registry sources. Never scan state."""
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", str(ROOT / "Cargo.toml")
]))
rows = []
for package in sorted(metadata["packages"], key=lambda p: p["name"]):
    if not package.get("source", "") or not package["source"].startswith("registry+"):
        continue
    source = Path(package["manifest_path"]).parent
    files = sorted({p for pattern in ("LICENSE*", "COPYING*", "NOTICE*", "license*", "copying*", "notice*") for p in source.glob(pattern) if p.is_file()})
    if not files:
        raise SystemExit("Missing license notice: " + package["name"])
    dest = ROOT / "licenses" / (package["name"] + "-" + package["version"])
    dest.mkdir(parents=True, exist_ok=True)
    links = []
    for file in files:
        shutil.copyfile(file, dest / file.name)
        links.append(f"[{file.name}](licenses/{dest.name}/{file.name})")
    rows.append(f"| {package['name']} {package['version']} | {package['license']} | {', '.join(links)} |")
(ROOT / "THIRD-PARTY.md").write_text(
    "# Third-party notices\n\nreadb's noncommercial license covers readb code. Dependencies keep their own\nlicenses and rights. This list follows Cargo.lock, including platform/build dependencies.\nAndroid companion notices will be added with that build.\n\n"
    "| Dependency | License | Notices |\n|---|---|---|\n" + "\n".join(rows) + "\n"
)
