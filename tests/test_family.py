#!/usr/bin/env python3
"""Family-child/alias resolution fixtures; no host routing changes."""
import copy,importlib.util,sys,tempfile
from pathlib import Path
base=Path(__file__).resolve().parents[1]
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
modules=[module(base/"root/usr/libexec/wg-uplink.py","selector"),module(base/"receiver/root/usr/libexec/wg-sticky-receiver.py","receiver")]
count=0
def check(ok,label):
 global count
 assert ok,label
 count+=1;print("PASS",label)
for w in modules:
 def cmd(argv,**kwargs):return type("Result",(),{"returncode":0,"stdout":"[]","stderr":""})()
 w.command=cmd
 d={"interfaces":[{"name":"wan","proto":"mbim"}],"runtime":[
  {"interface":"wan","proto":"mbim","up":True,"l3_device":"control0","ipv4-address":[],"ipv6-address":[],"route":[]},
  {"interface":"wan_4","proto":"static","up":True,"dynamic":True,"l3_device":"cell4","ipv4-address":[{"address":"10.1.0.2"}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"10.1.0.1"}]},
  {"interface":"wan_6","proto":"static","up":True,"dynamic":True,"l3_device":"cell6","ipv6-address":[{"address":"2606:4700:1::2"}],"route":[{"target":"::","mask":0,"nexthop":"fe80::1"}]}]}
 r4=w.resource("wan",4,"",d);r6=w.resource("wan",6,"",d)
 check(r4["available"] and r4["logical_interface"]=="wan_4" and r4["device"]=="cell4",w.__name__+" MBIM IPv4 child resolves independently of control device")
 check(r6["available"] and r6["logical_interface"]=="wan_6" and r6["device"]=="cell6",w.__name__+" MBIM IPv6 child resolves independently of control device")
 down=copy.deepcopy(d);down["runtime"][1]["up"]=False
 check(not w.resource("wan",4,"",down)["available"] and w.resource("wan",6,"",down)["available"],w.__name__+" down IPv4 child cannot borrow stale addresses; IPv6 remains available")
 parentdown=copy.deepcopy(d);parentdown["runtime"][0]["up"]=False
 check(not w.resource("wan",6,"",parentdown)["available"],w.__name__+" down parent blocks stale active children")
 d["interfaces"][0]["proto"]="pppoe";d["runtime"][0]["proto"]="pppoe"
 d["runtime"][0].update(l3_device="pppoe-wan",**{"ipv4-address":[{"address":"198.51.100.2"}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"0.0.0.0"}]})
 d["runtime"]=[d["runtime"][0],d["runtime"][2]]
 check(w.resource("wan",4,"",d)["point_to_point"],w.__name__+" PPPoE IPv4 device-only default supported")
 check(w.resource("wan",6,"",d)["logical_interface"]=="wan_6",w.__name__+" PPPoE _6 dynamic child supported")
 alias=copy.deepcopy(d);alias["runtime"][1]["interface"]="provider6"
 alias["interfaces"].append({"name":"provider6","proto":"dhcpv6","device":"@wan"})
 check(w.resource("wan",6,"",alias)["logical_interface"]=="provider6",w.__name__+" configured IPv6 @parent alias supported")
 alias["runtime"][1]["route"]=[{"target":"::","mask":0,"nexthop":"::"}]
 check(w.resource("wan",6,"",alias)["point_to_point"],w.__name__+" PPP IPv6 device-only default supported")
# Check installed-route construction through the selector.
w=modules[0];calls=[]
def command(argv,**kwargs):
 calls.append(argv);return type("Result",(),{"returncode":0,"stdout":"","stderr":""})()
w.command=command
with tempfile.TemporaryDirectory() as tmp:
 w.RUN=Path(tmp)
 w.install_resources([{"af":4,"table":48008,"pref":504,"available":True,"gateway":"","device":"pppoe-wan","source":"198.51.100.2"}],{})
 check(any("default" in x and "pppoe-wan" in x and "via" not in x for x in calls),"PPP selected default omits a nonexistent gateway")
 check(not any("/32" in str(x) for x in calls if "route" in x),"PPP does not create an empty gateway host route")
with tempfile.TemporaryDirectory() as tmp:
 w.RUN=Path(tmp);removed=[]
 w.delrule=lambda af,pref:removed.append((af,pref))
 w.atomic(w.RUN/"rules"/"6-504.json",{"args":["from","2606:4700::2","lookup","48008"]})
 w.atomic(w.RUN/"rules"/"4-504.json",{"args":["from","198.51.100.2","lookup","48008"]})
 w.install_resources([{"af":4,"table":48008,"pref":504,"available":False}],{})
 check((6,504) in removed and (4,504) in removed,"family changes and down paths remove owned stale source rules")
print("ALL",count,"FAMILY CHECKS PASSED")
