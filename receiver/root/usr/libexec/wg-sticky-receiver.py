#!/usr/bin/env python3
"""Standalone WG receiver sticky replies. No LuCI or uplink-selector dependency."""
import os,sys,json,time,re,subprocess,fcntl,ipaddress,shlex,hashlib,importlib.util
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import wg_sticky_actions as audit
RUN=Path("/var/run/wg-sticky-receiver")
BASE=Path(__file__).resolve().parent
LOCK="/var/lock/wg-sticky-receiver.lock"
def command(argv,timeout=8,check=False,stdin=None):
 p=subprocess.run([str(x) for x in argv],input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
 if check and p.returncode: raise ValueError("Command failed: "+str(argv[0])+" "+p.stderr.strip()[:180])
 return p
def atomic(path,data):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_name(path.name+".new")
 with open(tmp,"w") as f: json.dump(data,f,separators=(",",":"))
 os.chmod(tmp,0o600);os.replace(tmp,path)
def readjson(path,default=None):
 try:return json.loads(Path(path).read_text())
 except (OSError,ValueError):return {} if default is None else default
def family_rows(role,af,d):
 """Prefer netifd's family child, then configured @parent aliases and the parent."""
 rt=d["runtime"];base=next((x for x in rt if x["interface"]==role),{})
 dev=base.get("l3_device") or base.get("device")
 aliases={x["name"] for x in d["interfaces"] if (x.get("device") or x.get("ifname"))=="@"+role and (x.get("proto") not in ("dhcp","dhcpv6") or x.get("proto")==("dhcp" if af==4 else "dhcpv6"))}
 names=[role+"_"+str(af)]+sorted(aliases)+[role]
 out=[]
 for name in names:
  row=next((x for x in rt if x["interface"]==name),None)
  if row and row not in out:out.append(row)
 for row in rt:
  if dev and row.get("l3_device")==dev and row not in out:out.append(row)
 return base,out

def resource(role,af,override,d):
 base,rows=family_rows(role,af,d)
 common={"available":False,"role":role,"af":af,"device":base.get("l3_device") or base.get("device") or "","logical_interface":role}
 if not base.get("up"):return dict(common,error="Uplink is down")
 child=next((x for x in rows if x["interface"]==role+"_"+str(af)),None)
 # Do not borrow stale kernel addresses from a stopped family child.
 if child and not child.get("up") and not base.get("ipv"+str(af)+"-address"):
  return dict(common,logical_interface=child["interface"],error="IPv"+str(af)+" child is down")
 seen=set()
 for row in rows:
  if not row.get("up"):continue
  dev=row.get("l3_device") or row.get("device")
  if not dev or dev.startswith("@") or dev in seen:continue
  seen.add(dev)
  siblings=[row]+[x for x in rows if x is not row and x.get("up") and (x.get("l3_device") or x.get("device"))==dev]
  candidates=[]
  for x in siblings:
   for a in x.get("ipv"+str(af)+"-address",[]):
    try:
     ip=ipaddress.ip_address(a["address"])
     if ip.version==af and (af==4 or ip.is_global) and a.get("preferred",1)!=0:candidates.append((str(ip),x["interface"]))
    except ValueError:pass
  if not candidates:
   try:
    for x in json.loads(command(["ip","-j","-"+str(af),"addr","show","dev",dev],check=True).stdout):
     for a in x.get("addr_info",[]):
      ip=ipaddress.ip_address(a["local"])
      if ip.version==af and (af==4 or ip.is_global) and a.get("preferred_life_time",1)!=0:candidates.append((str(ip),row["interface"]))
   except (ValueError,KeyError):pass
  source,logical=next(iter(candidates),("",row["interface"]))
  gw=override;direct=False
  for x in siblings:
   for r in x.get("route",[]):
    if r.get("mask")==0 and r.get("target") in (("0.0.0.0",) if af==4 else ("::",)):
     hop=r.get("nexthop","")
     if not gw and hop not in ("","0.0.0.0","::"):gw=hop
     direct=True
  conf=next((x for x in d["interfaces"] if x["name"]==role),{})
  if not gw:gw=conf.get("gateway" if af==4 else "ip6gw","")
  if not gw:
   try:
    for r in json.loads(command(["ip","-j","-"+str(af),"route","show","default","dev",dev]).stdout):
     if r.get("gateway"):gw=r["gateway"];break
     direct=True
   except ValueError:pass
  if gw in ("0.0.0.0","::"):gw=""
  ppp=base.get("proto") in ("ppp","pppoe","pppoa","pptp","l2tp") or dev.startswith("ppp")
  point_to_point=not gw and direct and ppp
  common.update(device=dev,logical_interface=logical)
  if source and (gw or point_to_point):
   return dict(common,available=True,source=source,gateway=gw,point_to_point=point_to_point)
 return dict(common,error="No native IPv"+str(af)+" address or default route; a gateway override may be needed")
def delrule(af,pref):
 for _ in range(8):
  if command(["ip","-"+str(af),"rule","del","pref",pref]).returncode:break
def rule(af,pref,args,known):
 lines=command(["ip","-"+str(af),"rule","show","pref",pref]).stdout.strip()
 sig=[str(x) for x in args]
 cache=RUN/"rules"/(str(af)+"-"+str(pref)+".json")
 old=readjson(cache)
 if lines and not old:raise ValueError("Routing priority "+str(pref)+" is already used")
 if old.get("args")==sig and lines:return False
 delrule(af,pref)
 command(["ip","-"+str(af),"rule","add","pref",pref]+sig,check=True)
 atomic(cache,{"args":sig})
 return True

def policies(d):return []
def inventory():
 d=json.loads(command(["ucode",str(BASE/"wg-sticky-discover.uc")],check=True).stdout)
 d["runtime"]=json.loads(command(["ubus","-t","3","call","network.interface","dump"],check=True).stdout).get("interface",[])
 for k in ("receiver_uplinks","receiver_gateways"):
  if isinstance(d["settings"].get(k),str):d["settings"][k]=[d["settings"][k]]
 return d
def configured_outbound(d):
 states=[]
 for peer in d["peers"]:
  if not peer["endpoint_host"]:continue
  row=command(["wg","show",peer["interface"],"endpoints"])
  endpoint=next((x.split()[1] for x in row.stdout.splitlines() if x.split() and x.split()[0]==peer["key"]),None)
  if not endpoint or endpoint=="(none)":continue
  addr=endpoint[1:].split("]:")[0] if endpoint.startswith("[") else endpoint.rsplit(":",1)[0]
  try:af=ipaddress.ip_address(addr).version
  except ValueError:continue
  port=int(endpoint.rsplit(":",1)[1])
  listen=int(command(["wg","show",peer["interface"],"listen-port"]).stdout.strip() or 0)
  if listen:states.append({"initialized":True,"listen_port":listen,"paths":[{"ips":[addr],"port":port}]})
 return states
def core():
 spec=importlib.util.spec_from_file_location("wg_sticky_core",str(BASE/"wg-sticky-core.py"))
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def peer_pins(d):
 ids=readjson(RUN/"receiver-ids.json")
 roles={slot:role for role,slot in ids.items()}
 runtime=readjson(RUN/"receiver.json");active=runtime.get("active",False)
 devs={x["interface"]:x["device"] for x in runtime.get("uplinks",[])}
 flows=[]
 try:text=Path("/proc/net/nf_conntrack").read_text()
 except OSError:
  p=command(["conntrack","-L","-p","udp"],timeout=3);text=p.stdout
 for line in text.splitlines():
  if not re.search(r"\budp\b",line):continue
  mark=re.search(r"\bmark=(\d+)",line)
  if not mark:continue
  slot=(int(mark[1])&0x3f000000)>>24
  if slot not in roles:continue
  src=re.findall(r"\bsrc=(\S+)",line);sport=re.findall(r"\bsport=(\d+)",line);dport=re.findall(r"\bdport=(\d+)",line)
  for i in range(min(len(src),len(sport),len(dport),2)):
   flows.append({"ip":str(ipaddress.ip_address(src[i])),"remote_port":int(sport[i]),"listen":int(dport[i]),"uplink":roles[slot]})
 interfaces=[]
 for row in command(["wg","show","all","listen-port"]).stdout.splitlines():
  a=row.split()
  if len(a)<2:continue
  interface,listen=a[0],int(a[1]);peers=[]
  for line in command(["wg","show",interface,"endpoints"]).stdout.splitlines():
   bits=line.split()
   if len(bits)<2:continue
   key,endpoint=bits[:2]
   conf=next((x for x in d["peers"] if x["interface"]==interface and x["key"]==key),{})
   inbound=not conf.get("endpoint_host")
   ip="";port=0
   if endpoint!="(none)":
    ip=endpoint[1:].split("]:")[0] if endpoint.startswith("[") else endpoint.rsplit(":",1)[0]
    port=int(endpoint.rsplit(":",1)[1]);ip=str(ipaddress.ip_address(ip))
   matches=[x for x in flows if x["ip"]==ip and x["remote_port"]==port and x["listen"]==listen]
   pin=matches[0] if matches and active and inbound else None
   peers.append({"key":key,"description":conf.get("description",key[:10]),"endpoint":endpoint,"inbound":inbound,
    "pin_enabled":bool(active and inbound),"pinned":bool(pin),"uplink":pin["uplink"] if pin else "",
    "device":devs.get(pin["uplink"],"") if pin else "",
    "family":ipaddress.ip_address(ip).version if ip else None,"flows":len(matches) if pin else 0})
  interfaces.append({"interface":interface,"listen_port":listen,"peers":peers})
 return interfaces

def status():
 d=inventory();return {"ok":True,"installed":True,"settings":{
  "enabled":str(d["settings"]["receiver_enabled"]),"uplinks":d["settings"]["receiver_uplinks"],
  "gateways":d["settings"]["receiver_gateways"],"interval":d["settings"]["interval"]},
  "runtime":readjson(RUN/"receiver.json"),"interfaces":peer_pins(d)}
def configure(data):
 if not isinstance(data,dict) or set(data)-{"enabled","uplinks","gateways","interval"}:raise ValueError("Unknown receiver setting")
 d=inventory();s=d["settings"]
 enabled=str(data.get("enabled",s["receiver_enabled"]))
 if enabled not in ("0","1"):raise ValueError("Invalid enable flag")
 uplinks=data.get("uplinks",s["receiver_uplinks"]);gateways=data.get("gateways",s["receiver_gateways"])
 interval=int(data.get("interval",s["interval"]))
 if not 5<=interval<=60:raise ValueError("Interval must be 5–60 seconds")
 names={x["name"] for x in d["interfaces"] if x["proto"]!="wireguard" and x["name"]!="loopback"}
 if not isinstance(uplinks,list) or len(uplinks)>32 or any(x not in names for x in uplinks):raise ValueError("Unknown receiver uplink")
 if not isinstance(gateways,list) or len(gateways)>64:raise ValueError("Invalid gateway overrides")
 for item in gateways:
  role,sep,ip=item.partition("=")
  if not sep or role not in names:raise ValueError("Use interface=IP for gateway overrides")
  ipaddress.ip_address(ip)
 before={"enabled":str(s["receiver_enabled"]),"uplinks":s["receiver_uplinks"],"gateways":s["receiver_gateways"],"interval":int(s["interval"])}
 after={"enabled":enabled,"uplinks":uplinks,"gateways":gateways,"interval":interval}
 changes=audit.diff(before,after)
 if not changes:return {"ok":True,"message":"Settings unchanged."}
 text="config receiver 'main'\n\toption enabled '"+enabled+"'\n\toption interval '"+str(interval)+"'\n"
 for k,items in (("uplinks",uplinks),("gateways",gateways)):
  for item in items:text+="\tlist "+k+" "+shlex.quote(item)+"\n"
 conf=Path("/etc/config/wg_sticky");tmp=conf.with_name("wg_sticky.new")
 tmp.write_text(text);tmp.chmod(0o600);os.replace(tmp,conf)
 command(["uci","-q","revert","wg_sticky"])
 audit.emit("receiver","change_settings",{"type":"update_settings"},{"changes":changes})
 if enabled=="1":
  command(["/etc/init.d/wg-sticky-receiver","enable"])
  if command(["/etc/init.d/wg-sticky-receiver","status"]).returncode:command(["/etc/init.d/wg-sticky-receiver","start"])
 subprocess.Popen(["/usr/sbin/wg-sticky-receiver","tick"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 return {"ok":True,"message":"Saved; receiver state updates independently."}
def tick(trigger="interface_detail_update_observed"):
 RUN.mkdir(parents=True,exist_ok=True)
 with open(LOCK,"w") as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return {"ok":True,"busy":True}
  d=inventory();m=core();sys.modules[__name__].action_trigger=trigger
  try:r=m.sync(sys.modules[__name__],d,configured_outbound(d) if str(d["settings"]["receiver_enabled"])=="1" else [])
  except Exception as e:
   r={"enabled":str(d["settings"]["receiver_enabled"])=="1","active":False,"error":str(e)}
   atomic(RUN/"receiver.json",r)
   raise
  return {"ok":True,"receiver":r}
def main():
 action=sys.argv[1] if len(sys.argv)>1 else "status"
 try:
  if action=="status":out=status()
  elif action=="logs":out={"ok":True,"entries":audit.read("receiver")}
  elif action=="configure":
   raw=sys.argv[2] if len(sys.argv)>2 else sys.stdin.read(16385)
   if len(raw)>16384:raise ValueError("Request too large")
   out=configure(json.loads(raw))
  elif action in ("enable","disable"):out=configure({"enabled":"1" if action=="enable" else "0"})
  elif action=="tick":out=tick()
  elif action=="plan":
   d=inventory();m=core();us=m.discover(sys.modules[__name__],d)
   for i,u in enumerate(us,1):u["slot"]=i
   ports=[int(x.split()[1]) for x in command(["wg","show","all","listen-port"]).stdout.splitlines() if len(x.split())>1 and int(x.split()[1])>0]
   print("\n".join(m.build_rules(us,ports,configured_outbound(d))));return
  elif action=="daemon":
   first=True
   while True:
    start=time.monotonic()
    try:tick(trigger="start_service" if first else "interface_detail_update_observed");first=False
    except Exception as e:print("WG sticky receiver: "+str(e),file=sys.stderr)
    try:interval=int(inventory()["settings"]["interval"])
    except Exception:interval=10
    time.sleep(max(1,interval-(time.monotonic()-start)))
  else:raise ValueError("Unknown receiver command")
 except Exception as e:out={"ok":False,"error":str(e)}
 print(json.dumps(out,separators=(",",":")))
 if not out.get("ok"):sys.exit(1)
if __name__=="__main__":main()
