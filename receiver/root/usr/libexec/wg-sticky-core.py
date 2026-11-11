"""Optional receiver-only WireGuard sticky replies using per-flow conntrack marks."""
import json,re,ipaddress
MASK=0x3f000000
KEEP=0xc0ffffff
TABLE="wg_uplink_receiver"
def overrides(settings,policies):
 out={}
 for p in policies:
  for role in ("preferred","fallback"):
   for af in (4,6):
    v=p.get(role+"_gateway"+str(af))
    if v:out[(p[role],af)]=v
 for item in settings.get("receiver_gateways",[]):
  role,gw=item.split("=",1);out[(role,ipaddress.ip_address(gw).version)]=gw
 return out
def discover(w,d):
 settings=d["settings"];allowed=settings.get("receiver_uplinks",[])
 if isinstance(allowed,str):allowed=[allowed]
 roles=[x["name"] for x in d["interfaces"] if x["proto"]!="wireguard" and x["name"]!="loopback" and (not allowed or x["name"] in allowed)]
 gw=overrides(settings,w.policies(d));bydevice={}
 for role in roles:
  paths=[w.resource(role,af,gw.get((role,af),""),d) for af in (4,6)]
  available=[p for p in paths if p["available"]]
  if not available:continue
  dev=available[0]["device"]
  if dev not in bydevice:bydevice[dev]={"role":role,"device":dev,"paths":paths}
 return list(bydevice.values())
def build_rules(uplinks,ports,states,slots=None):
 """Local-input learning only. Never accepts traffic or opens firewall ports."""
 lines=["add table inet "+TABLE,
  "add chain inet "+TABLE+" input { type filter hook input priority -140; policy accept; }",
  "add chain inet "+TABLE+" output { type route hook output priority -140; policy accept; }"]
 if not ports:return lines
 portset="{ "+", ".join(str(x) for x in sorted(set(ports)))+" }"
 # A locally managed outbound peer has an explicit path; it must not be
 # reclassified as a receiver-only connection after a conntrack timeout.
 seen=set()
 for state in states:
  if not state.get("initialized"):continue
  listen=state.get("listen_port")
  for path in state.get("paths",[]):
   for addr in path.get("ips",[]):
    key=(addr,path["port"],listen)
    if key in seen:continue
    seen.add(key);af=ipaddress.ip_address(addr).version;ip="ip6" if af==6 else "ip"
    lines.append("add rule inet "+TABLE+" input "+ip+" saddr "+addr+" udp sport "+str(path["port"])+" udp dport "+str(listen)+" return")
    lines.append("add rule inet "+TABLE+" output "+ip+" daddr "+addr+" udp dport "+str(path["port"])+" udp sport "+str(listen)+" return")
 for uplink in uplinks:
  mark=int(uplink["slot"])<<24
  for path in uplink["paths"]:
   if not path.get("available"):continue
   nf="ipv6" if path["af"]==6 else "ipv4"
   lines.append("add rule inet "+TABLE+" input meta nfproto "+nf+" iifname "+json.dumps(path["device"])+" udp dport "+portset+" ct mark & "+hex(MASK)+" == 0 ct mark set (ct mark & "+hex(KEEP)+") | "+hex(mark))
 for slot in (slots if slots is not None else [u["slot"] for u in uplinks]):
  value=slot<<24
  lines.append("add rule inet "+TABLE+" output udp sport "+portset+" ct mark & "+hex(MASK)+" == "+hex(value)+" counter meta mark set (meta mark & "+hex(KEEP)+") | "+hex(value))
 return lines
def cleanup(w,owned):
 w.command(["nft","delete","table","inet",TABLE])
 for slot in owned.get("slots",[]):
  for af in (4,6):
   pref=200+slot;cache=w.RUN/"rules"/(str(af)+"-"+str(pref)+".json")
   if cache.exists():w.delrule(af,pref);cache.unlink()
   table=49000+slot*2+(af==6);cache=w.RUN/"receiver-tables"/(str(af)+"-"+str(table)+".json")
   if cache.exists():
    w.command(["ip","-"+str(af),"route","flush","table",table]);cache.unlink()
def sync(w,d,states):
 settings=d["settings"];enabled=str(settings.get("receiver_enabled","0"))=="1"
 owned=w.readjson(w.RUN/"receiver-owned.json")
 if not enabled:
  if owned.get("active") or owned.get("slots"):
   cleanup(w,owned);w.atomic(w.RUN/"receiver-owned.json",{"active":False,"slots":[],"priorities":[]})
  out={"enabled":False,"active":False,"uplinks":[],"ports":[]}
  w.atomic(w.RUN/"receiver.json",out);return out
 # Do not overwrite a WG socket mark which already reserves our high bits.
 for line in w.command(["wg","show","all","fwmark"]).stdout.splitlines():
  a=line.split()
  if len(a)>1 and a[1]!="off" and int(a[1],0)&MASK:raise ValueError("Receiver sticky mark bits are already used by a WG interface")
 ports=[]
 for line in w.command(["wg","show","all","listen-port"]).stdout.splitlines():
  a=line.split()
  if len(a)>1 and int(a[1])>0:ports.append(int(a[1]))
 uplinks=discover(w,d)
 sources={}
 for u in uplinks:
  for p in u["paths"]:
   if not p["available"]:continue
   key=(p["af"],p["source"])
   if key in sources and sources[key]!=p["device"]:raise ValueError("Receiver upstreams share a source IP on different devices")
   sources[key]=p["device"]
 ids=w.readjson(w.RUN/"receiver-ids.json")
 for uplink in uplinks:
  role=uplink["role"]
  if role not in ids:
   slot=next((i for i in range(1,33) if i not in ids.values()),None)
   if slot is None:raise ValueError("Receiver sticky uplink slot limit reached")
   ids[role]=slot
  uplink["slot"]=ids[role]
 w.atomic(w.RUN/"receiver-ids.json",ids)
 w.atomic(w.RUN/"receiver-owned.json",{"active":owned.get("active",False),"slots":list(ids.values()),"priorities":[200+i for i in ids.values()]})
 # Retired slots keep unreachable defaults while enabled, so stale flow
 # marks cannot fall through to another uplink or be reused in this boot.
 for slot in ids.values():
  for af in (4,6):
   table=49000+slot*2+(af==6);pref=200+slot
   cache=w.RUN/"receiver-tables"/(str(af)+"-"+str(table)+".json")
   if not cache.exists():
    if w.command(["ip","-"+str(af),"route","show","table",table]).stdout.strip():raise ValueError("Receiver routing table is already used")
    w.atomic(cache,{"owned":True})
   w.command(["ip","-"+str(af),"route","replace","unreachable","default","table",table,"metric","42760"],check=True)
   path=next((p for u in uplinks if u["slot"]==slot for p in u["paths"] if p["af"]==af and p["available"]),None)
   if path:
    if path["gateway"]:
     w.command(["ip","-"+str(af),"route","replace","table",table,path["gateway"]+("/128" if af==6 else "/32"),"dev",path["device"],"scope","link"],check=True)
    route=["ip","-"+str(af),"route","replace","table",table,"default"]
    if path["gateway"]:route+=["via",path["gateway"]]
    route+=["dev",path["device"],"src",path["source"]]
    if path["gateway"]:route+=["onlink"]
    w.command(route+["metric","10"],check=True)
   else:w.command(["ip","-"+str(af),"route","flush","table",table,"type","unicast"])
   w.rule(af,pref,["fwmark",hex(slot<<24)+"/"+hex(MASK),"lookup",table],pref in owned.get("priorities",[]))
 batch=[]
 if w.command(["nft","list","table","inet",TABLE]).returncode==0:batch.append("delete table inet "+TABLE)
 batch+=build_rules(uplinks,ports,states,list(ids.values()))
 w.command(["nft","-c","-f","-"],stdin="\n".join(batch)+"\n",check=True)
 w.command(["nft","-f","-"],stdin="\n".join(batch)+"\n",check=True)
 w.atomic(w.RUN/"receiver-owned.json",{"active":True,"slots":list(ids.values()),"priorities":[200+i for i in ids.values()]})
 out={"enabled":True,"active":True,"uplinks":[{"interface":x["role"],"device":x["device"],"families":[p["af"] for p in x["paths"] if p["available"]]} for x in uplinks],"ports":ports,"mark_mask":hex(MASK)}
 w.atomic(w.RUN/"receiver.json",out);return out
