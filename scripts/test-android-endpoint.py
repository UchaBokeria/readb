#!/usr/bin/env python3
"""Check foreground endpoint freshness without a device or Android SDK."""
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='readb-endpoint-') as out:
    subprocess.run(['javac','-d',out,str(root/'android/src/dev/readb/companion/EndpointState.java'),str(root/'android/tests/host/dev/readb/companion/EndpointStateTest.java')],check=True)
    subprocess.run(['java','-cp',out,'dev.readb.companion.EndpointStateTest'],check=True)
