import importlib.util
from pathlib import Path
import struct
import unittest
spec=importlib.util.spec_from_file_location('native_check',Path(__file__).resolve().parents[1]/'native_check.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def elf(alignment=16384,machine=183):
    b=bytearray(128);b[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',b,16,3,machine);struct.pack_into('<Q',b,32,64);struct.pack_into('<HH',b,54,56,1);struct.pack_into('<IIQQQQQQ',b,64,1,5,0,0,0,128,128,alignment);return bytes(b)
class Check(unittest.TestCase):
 def test_native_machine_loads_and_page_size(self):
  native.validate(elf())
  for data in (elf(4096),elf(machine=62),b'',b'not a library',elf()[:80]):
   with self.assertRaises(ValueError):native.validate(data)
if __name__=='__main__':unittest.main()
