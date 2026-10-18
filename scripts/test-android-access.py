#!/usr/bin/env python3
"""Check upfront permission sequencing without Android or a device."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="readb-access-") as out:
    subprocess.run(["javac", "-d", out,
        str(root / "android/src/dev/readb/companion/PermissionFlow.java"),
        str(root / "android/tests/host/dev/readb/companion/PermissionFlowTest.java")], check=True)
    subprocess.run(["java", "-cp", out, "dev.readb.companion.PermissionFlowTest"], check=True)
