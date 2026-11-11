#!/usr/bin/env python3
"""Mark coexistence checks without live routing mutations."""
import importlib.util,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('wgu_marks',BASE/'root/usr/libexec/wg-uplink.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
class Marks(unittest.TestCase):
 def test_generated_marks_ignore_other_owners(self):
  for slot in range(1,33):
   value=w.SOCKET_MARK_BASE+slot;selector=w.selection_mark(hex(value))
   target,mask=map(lambda x:int(x,0),selector.split('/'))
   self.assertEqual(value&0x3f00,0);self.assertEqual(value&0x40000,0);self.assertEqual(value&0x3f000000,0)
   for foreign in [0,0x100,0x400,0x500,0x3f00,0x3000000]:
    self.assertEqual((value|foreign)&mask,target)
 def test_new_mark_and_original_restore_metadata(self):
  with tempfile.TemporaryDirectory() as tmp:
   old=w.RUN;w.RUN=Path(tmp)
   try:
    mark=w.mark_for({'interface':'wg0','slot':'1'},{'mark':'off'})
    self.assertEqual(mark,'0x80000001')
    self.assertEqual(w.readjson(w.RUN/'interfaces/wg0.json')['original_mark'],'off')
   finally:w.RUN=old
 def test_existing_mark_preserved(self):
  with tempfile.TemporaryDirectory() as tmp:
   old=w.RUN;w.RUN=Path(tmp)
   try:self.assertEqual(w.mark_for({'interface':'wg0','slot':'1'},{'mark':'0x40000'}),'0x40000')
   finally:w.RUN=old
 def test_existing_identity_survives_mwan_mask(self):
  result=type('Result',(),{'returncode':0,'stdout':'0x3f00'})()
  with patch.object(w.Path,'exists',return_value=True),patch.object(w,'command',return_value=result):
   target,mask=map(lambda x:int(x,0),w.selection_mark('0x40000').split('/'))
   self.assertEqual((0x40000|0x500)&mask,target)
   with self.assertRaises(ValueError):w.selection_mark('0x400')
if __name__=='__main__':unittest.main(verbosity=2)
