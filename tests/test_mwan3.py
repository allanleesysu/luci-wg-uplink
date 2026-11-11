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
 def test_configurable_namespace_and_mwan3_changes(self):
  settings={'socket_mark_base':'0x80000000','socket_mark_mask':'0x8000ff00'}
  reply=type('Result',(),{'returncode':0,'stdout':'0xff'})()
  with patch.object(w.Path,'exists',return_value=True),patch.object(w,'command',return_value=reply):
   config=w.validate_mark_settings(settings)
   self.assertEqual(w.generated_mark(1,config),'0x80000100')
   target,mask=map(lambda x:int(x,0),w.selection_mark('0x80000100',config).split('/'))
   self.assertEqual((0x80000100|0x5)&mask,target)
   with self.assertRaises(ValueError):w.validate_mark_settings({})
 def test_mark_configuration_validation(self):
  for settings in [{'socket_mark_base':'bad'},{'socket_mark_mask':'0xfffffffff'},{'socket_mark_base':'0x80000000','socket_mark_mask':'0xff'},{'socket_mark_mask':'0x80000001'}]:
   with self.subTest(settings=settings),self.assertRaises(ValueError):w.mark_config(settings)
 def test_external_routing_mark_collision_rejected(self):
  result=type('Result',(),{'returncode':0,'stdout':'[{"priority":850,"fwmark":"0x40000","fwmask":"0x40000"}]'})()
  settings={'socket_mark_base':'0x80000000','socket_mark_mask':'0x8000003f'}
  with patch.object(w,'mwan3_mark_mask',return_value=0),patch.object(w,'command',return_value=result):
   w.validate_mark_settings(settings,check_rules=True)
   with self.assertRaises(ValueError):w.validate_mark_settings({'socket_mark_base':'0x80000000','socket_mark_mask':'0x803f0000'},check_rules=True)
 def test_probe_source_rules_exclude_foreign_socket_marks(self):
  with tempfile.TemporaryDirectory() as tmp:
   old=w.RUN;w.RUN=Path(tmp);calls=[]
   reply=type('Result',(),{'returncode':0,'stdout':''})()
   try:
    with patch.object(w,'mwan3_mark_mask',return_value=0x3f00),patch.object(w,'command',return_value=reply),patch.object(w,'rule',side_effect=lambda af,pref,args,known:calls.append(args)):
     w.install_resources([{'af':4,'table':48008,'pref':504,'available':True,'gateway':'192.0.2.1','device':'eth1','source':'192.0.2.2'}],{})
    args=calls[0];mark,mask=map(lambda x:int(x,0),args[args.index('fwmark')+1].split('/'))
    self.assertEqual(0x500&mask,mark)
    self.assertNotEqual(0x40000&mask,mark)
    self.assertNotEqual(0x80000001&mask,mark)
   finally:w.RUN=old
if __name__=='__main__':unittest.main(verbosity=2)
