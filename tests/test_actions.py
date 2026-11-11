#!/usr/bin/env python3
"""Persistent action journal, quiet reconciliation and change evidence regressions."""
import importlib.util,json,tempfile,copy,sys
from pathlib import Path
base=Path(__file__).resolve().parents[1]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
a=module("action_test",base/"root/usr/libexec/wg_uplink_actions.py")
w=module("uplink_test",base/"root/usr/libexec/wg-uplink.py")
rx=module("receiver_test",base/"receiver/root/usr/libexec/wg-sticky-receiver.py")
core=module("receiver_core_test",base/"receiver/root/usr/libexec/wg-sticky-core.py")
count=0
def check(ok,label):
 global count
 assert ok,label
 count+=1;print("PASS",label)
with tempfile.TemporaryDirectory() as tmp:
 a.BASE=Path(tmp)/"etc";a.LOCKBASE=Path(tmp)/"lock";a._zone="UTC"
 a.emit("uplink","change_settings",{"type":"update_settings"},{"changes":{"interval":{"before":10,"after":20}},"password":"secret","nested":{"private_key":"secret"}})
 record=a.read("uplink")[0]
 check(all(k in record for k in ("date","time","timezone","utc_offset","scope","trigger","action","data")),"structured date/time/timezone, scope, trigger, action and data")
 check(record["data"]["changes"]["interval"]=={"before":10,"after":20},"before/after setting values retained")
 check("secret" not in json.dumps(record),"credential fields recursively redacted")
 check((a.directory("uplink")/"actions.jsonl").stat().st_mode&0o777==0o600,"journal file root-only")
 fresh=module("fresh_action_test",base/"root/usr/libexec/wg_uplink_actions.py");fresh.BASE=a.BASE
 check(fresh.read("uplink")==a.read("uplink"),"new process can read existing persistent journal")
 with (a.directory("uplink")/"actions.jsonl").open("ab") as f:f.write(b'{interrupted write\n')
 check(len(a.read("uplink"))==1,"incomplete final record does not hide older entries")
 a.LIMIT=600
 for n in range(9):a.emit("receiver","change_settings",{"type":"test","n":n},{"before":n,"after":n+1})
 check(len(list(a.directory("receiver").glob("actions.jsonl*")))<=3 and a.read("receiver")[0]["action"]["n"]==8,"rotation bounded to three files and newest entries readable")
# A stable guard must not rewrite nftables or create false changes from counters.
with tempfile.TemporaryDirectory() as tmp:
 w.RUN=Path(tmp);present=True;mutations=[];packet=0;drift=False
 def command(argv,**kw):
  global packet
  stdout="";rc=0
  if argv[:3]==["nft","-j","list"]:stdout=json.dumps({"nftables":[{"rule":{"handle":9,"expr":[{"counter":{"packets":packet,"bytes":packet*80}},{"drop":None}],"comment":"drift" if drift else "stable"}}]})
  elif argv[:2]==["nft","-f"]:mutations.append(kw["stdin"])
  return type("R",(),{"stdout":stdout,"stderr":"","returncode":rc})()
 w.command=command
 check(w.update_guard([]),"initial guard reconciliation recorded as mutation")
 mutations.clear();packet=27
 check(not w.update_guard([]) and not mutations,"counter-only updates and unchanged guard do not rewrite nftables")
 drift=True
 check(w.update_guard([]) and mutations,"actual guard drift triggers repair")
 target={"af":4,"ips":["203.0.113.1"],"device":"eth0"}
 state=lambda n,port:{"id":n,"initialized":True,"active":target,"listen_port":port,"paths":[{"af":4,"ips":["203.0.113.1"],"port":51820}]}
 first=[state("a",51821),state("b",51822)]
 w.update_guard(first);mutations.clear()
 check(not w.update_guard(list(reversed(first))) and not mutations,"peer enumeration order changes do not rewrite equivalent guard rules")
# Same-settings saves are genuinely quiet, changed settings record only changed fields.
with tempfile.TemporaryDirectory() as tmp:
 w.RUN=Path(tmp);events=[];writes=[]
 w.audit.emit=lambda *args:events.append(args)
 peer={"interface":"wg0","key":"public","endpoint_host":"example.com","endpoint_port":51820,"disabled":False}
 ident=w.id_for("wg0","public")
 policy=dict(w.DEFAULTS,interface="wg0",peer_key="public",slot="1",**{".name":ident})
 d={"interfaces":[{"name":"wg0","proto":"wireguard"},{"name":"wan1","proto":"dhcp"},{"name":"wan2","proto":"dhcp"}],"runtime":[],"peers":[peer],"policies":[policy],"settings":{"interval":10}}
 w.inventory=lambda:d;w.write_config=lambda *args:writes.append(args);w.kick=lambda:None
 payload={k:v for k,v in policy.items() if k in set(w.DEFAULTS)|{"interface","peer_key"}}
 w.save_locked(payload)
 check(not writes and not events,"unchanged peer save neither writes configuration nor logs")
 w.save_locked(dict(payload,label="renamed"))
 check(len(writes)==1 and len(events)==1 and list(events[0][3]["changes"])==["label"],"changed setting logs the exact changed field and values")
 w.save_locked({"action":"settings","interval":"10"})
 check(len(events)==1,"unchanged global interval is silent")
# Receiver reconciliation: real core against an isolated simulated kernel.
with tempfile.TemporaryDirectory() as tmp:
 rx.RUN=Path(tmp)/"run";rx.audit.BASE=Path(tmp)/"etc";rx.audit.LOCKBASE=Path(tmp)/"lock";rx.audit._zone="UTC"
 rx.action_trigger="start_service";tables=set();rules={};nft=False;writes=[]
 def command(argv,**kw):
  global nft
  argv=[str(x) for x in argv];out="";rc=0
  if argv[:3]==["wg","show","all"]:
   out="wg0 off\n" if argv[-1]=="fwmark" else "wg0 51820\n"
  elif argv[:3]==["nft","-j","list"]:
   rc=0 if nft else 1;out='{"nftables":[]}' if nft else ""
  elif argv[:2]==["nft","-f"]:
   nft=True;writes.append("nft")
  elif argv[:3]==["nft","delete","table"]:nft=False
  elif "route" in argv and "table" in argv:
   key=(argv[1],argv[argv.index("table")+1])
   if "show" in argv:out="unreachable default" if key in tables else ""
   elif "replace" in argv:tables.add(key)
  elif argv[:3]==["ip","-j","-6"]:out="[]"
  return type("R",(),{"stdout":out,"stderr":"","returncode":rc})()
 rx.command=command
 def rule(af,pref,args,known):
  key=(af,pref);changed=rules.get(key)!=args;rules[key]=args;rx.atomic(rx.RUN/"rules"/(str(af)+"-"+str(pref)+".json"),{"args":args});return changed
 rx.rule=rule;rx.delrule=lambda af,pref:rules.pop((af,pref),None)
 d={"interfaces":[{"name":"wan","proto":"dhcp"}],"runtime":[{"interface":"wan","up":True,"l3_device":"eth0","ipv4-address":[{"address":"192.0.2.2"}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.0.2.1"}]}],"settings":{"receiver_enabled":"1","receiver_uplinks":["wan"],"receiver_gateways":[]}}
 core.sync(rx,d,[]);records=rx.audit.read("receiver");initial=len(records);writes.clear()
 check(initial==1 and records[0]["trigger"]=="start_service","receiver start logs actual applied routes/firewall")
 core.sync(rx,d,[])
 check(len(rx.audit.read("receiver"))==initial and not writes,"receiver unchanged discovery produces no log or nftables rewrite")
 nft=False;rx.action_trigger="interface_detail_update_observed";core.sync(rx,d,[])
 check(len(rx.audit.read("receiver"))==initial+1 and writes,"receiver missing nft table repair logged")
 d["settings"]["receiver_enabled"]="0";core.sync(rx,d,[])
 check(rx.audit.read("receiver")[0]["action"]["type"]=="disable_receiver","receiver cleanup logs removed network configuration")
 n=len(rx.audit.read("receiver"));core.sync(rx,d,[])
 check(len(rx.audit.read("receiver"))==n,"already disabled receiver remains quiet")
# Switch and rollback entries retain the checks and observation that caused them.
events=[];w.audit.emit=lambda *args:events.append(args)
w.update_guard=lambda *args:False;w.select_route=lambda *args:None
w.verify_inner=lambda p:True
w.command=lambda *args,**kw:type("R",(),{"returncode":0,"stdout":"203.0.113.1 dev eth2 src 198.51.100.2","stderr":""})()
w.peer_runtime=lambda *args:{"endpoint":"203.0.113.1:51820"}
target={"id":"fallback4","role":"wan2","af":4,"device":"eth2","source":"198.51.100.2","ips":["203.0.113.1"],"port":51820,"table":48010}
old=dict(target,id="preferred4",role="wan1",device="eth1")
state={"id":"p_test","mark":"0x4a01","active":old,"selected":"preferred4","initialized":True,"timer":{"elapsed":300,"window":300},"reason":"Observing selected-path failure","paths":[dict(old,checks={"fo":{"ping":{"sent":5,"received":0,"loss":100}}})]}
policy={"interface":"wg0","peer_key":"public","slot":"1"}
w.apply_path(policy,state,target,[state])
e=events[-1]
check(e[1]=="check_condition_met" and e[2]["type"]=="switch_path" and e[3]["support"]["observation"]["elapsed"]==300 and e[3]["support"]["candidates"][0]["checks"]["fo"]["ping"]["loss"]==100,"switch records observation and supporting loss results")
w.verify_inner=lambda p:False
try:w.apply_path(policy,state,old,[state])
except ValueError:pass
e=events[-1]
check(e[2]["type"]=="rollback_switch" and e[3]["attempted"]["role"]=="wan1" and e[3]["after"]["role"]=="wan2","failed switch records attempted path and restored path")
print("ALL",count,"ACTION LOG CHECKS PASSED")
