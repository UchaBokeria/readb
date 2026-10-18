#!/usr/bin/env python3
"""Host crypto/format checks. Does not contact devices or use real profiles."""
from pathlib import Path
import subprocess, tempfile, argparse
p=argparse.ArgumentParser(description=__doc__)
p.add_argument("--quest-source",type=Path,help="Optional legacy helper src directory; checks shared-class parity")
p.add_argument("--pixel-source",type=Path,help="Optional legacy helper src directory; checks shared-class parity")
a=p.parse_args()
root=Path(__file__).resolve().parents[1]
source=root/'android/src/dev/readb/handover/HandoverProtocol.java'
with tempfile.TemporaryDirectory(prefix='readb-handover-') as tmp:
 subprocess.run(['javac','-d',tmp,str(source),str(source.parent/'HandoverJournal.java'),*[str(p) for p in (root/'android/tests/host').glob('Handover*Test.java')]],check=True)
 subprocess.run(['java','-cp',tmp,'HandoverProtocolTest'],check=True)
 subprocess.run(['java','-cp',tmp,'HandoverJournalTest'],check=True)

for legacy in [a.quest_source,a.pixel_source]:
 if legacy:
  for canonical in source.parent.glob("*.java"):
   copy=legacy/"dev/readb/handover"/canonical.name
   if not copy.is_file() or copy.read_bytes()!=canonical.read_bytes():
    raise SystemExit("legacy shared source drift: "+str(copy))
  print("legacy shared source parity passed:",legacy)
