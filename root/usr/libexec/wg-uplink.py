#!/usr/bin/env python3
"""WG Uplink: source-pinned health checks and per-peer WireGuard uplink policy."""
import os,sys,json,time,re,socket,struct,subprocess,fcntl,ipaddress,hashlib,threading,queue,shutil,shlex
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import wg_uplink_actions as audit
VERSION="1.1.1"
RUN=Path("/var/run/wg-uplink")
PERSIST=Path("/etc/wg-uplink")
DISCOVER="/usr/libexec/wg-uplink-discover.uc"
LOCK="/var/lock/wg-uplink.lock"
DEFAULTS={
 "enabled":"0","label":"","preferred":"","preferred_family":"6","fallback":"","fallback_family":"4",
 "preferred_other":"1","fallback_other":"0","observe_seconds":"300","recovery_seconds":"300","fast_seconds":"10",
 "preferred_gateway4":"","preferred_gateway6":"","fallback_gateway4":"","fallback_gateway6":"",
 "endpoint4":"","endpoint6":"","verify_targets":[],
 "fo_ping":"1","fo_ping_count":"5","fo_ping_loss":"100","fo_ping_targets":[],
 "fo_tcp":"0","fo_tcp_host":"","fo_tcp_port":"443","fo_tcp_mode":"connect",
 "fo_dns":"0","fo_dns_name":"example.com","fo_dns_servers":[],
 "fo_combine":"all",
 "rec_ping":"1","rec_ping_count":"5","rec_ping_loss":"99.9","rec_ping_targets":[],
 "rec_tcp":"0","rec_tcp_host":"","rec_tcp_port":"443","rec_tcp_mode":"connect",
 "rec_dns":"0","rec_dns_name":"example.com","rec_dns_servers":[],
 "rec_combine":"any",
}
LISTS={"verify_targets","fo_ping_targets","rec_ping_targets","fo_dns_servers","rec_dns_servers"}
BOOLS={"enabled","preferred_other","fallback_other","fo_ping","fo_tcp","fo_dns","rec_ping","rec_tcp","rec_dns"}
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
def inventory():
 p=command(["ucode",DISCOVER],check=True)
 d=json.loads(p.stdout)
 raw=command(["ubus","-t","3","call","network.interface","dump"],check=True)
 d["runtime"]=json.loads(raw.stdout).get("interface",[])
 return d
def cfg(raw):
 out=dict(DEFAULTS)
 out.update({k:v for k,v in raw.items() if not k.startswith(".")})
 for k in LISTS:
  v=out.get(k,[])
  out[k]=v if isinstance(v,list) else ([v] if v else [])
 return out
def policies(d):
 return [dict(cfg(x),id=x[".name"]) for x in d["policies"]]
def id_for(interface,key):return "p_"+hashlib.sha256((interface+"\0"+key).encode()).hexdigest()[:12]
def valid_host(value,allow_empty=True):
 if not value:return allow_empty
 if len(value)>253 or any(ord(c)<33 for c in value):return False
 try:ipaddress.ip_address(value);return True
 except ValueError:return bool(re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?",value)) and ".." not in value
def validate(data,d):
 allowed=set(DEFAULTS)|{"interface","peer_key","id"}
 if not isinstance(data,dict) or set(data)-allowed:raise ValueError("Unknown policy fields")
 p=cfg(data)
 peer=next((x for x in d["peers"] if x["interface"]==p.get("interface") and x["key"]==p.get("peer_key")),None)
 if not peer or not peer["endpoint_host"] or peer["disabled"]:raise ValueError("Only enabled peers with a configured endpoint can be managed")
 names={x["name"] for x in d["interfaces"] if x["proto"]!="wireguard" and x["name"]!="loopback"}
 for k in ("preferred","fallback"):
  if str(p["enabled"])=="1" and p[k] not in names:raise ValueError("Select a configured "+k+" uplink")
 if str(p["enabled"])=="1" and p["preferred"]==p["fallback"]:raise ValueError("Preferred and fallback uplinks must differ")
 def root(role):
  visited=set()
  while role not in visited:
   visited.add(role)
   conf=next((x for x in d["interfaces"] if x["name"]==role),{})
   link=conf.get("device") or conf.get("ifname") or ""
   if not link.startswith("@"):break
   role=link[1:]
  return role
 if str(p["enabled"])=="1" and root(p["preferred"])==root(p["fallback"]):raise ValueError("Preferred and fallback aliases belong to the same parent uplink")
 rt={x["interface"]:x for x in d.get("runtime",[])}
 a=rt.get(p["preferred"],{}).get("l3_device");b=rt.get(p["fallback"],{}).get("l3_device")
 if str(p["enabled"])=="1" and a and a==b:raise ValueError("Select two different uplink devices, not two aliases of the same uplink")
 for k in BOOLS:
  p[k]=str(p[k])
  if p[k] not in ("0","1"):raise ValueError("Invalid option: "+k)
 for k in ("preferred_family","fallback_family"):
  if str(p[k]) not in ("4","6"):raise ValueError("Protocol must be IPv4 or IPv6")
  p[k]=str(p[k])
 for k,lo,hi in (("observe_seconds",10,86400),("recovery_seconds",10,86400),("fast_seconds",1,300),("fo_tcp_port",1,65535),("rec_tcp_port",1,65535),("fo_ping_count",1,20),("rec_ping_count",1,20)):
  if k.endswith("_ping_count") and not re.fullmatch(r"[0-9]+",str(p[k])):raise ValueError("Pings per check must be a whole number")
  try:v=int(p[k])
  except (ValueError,TypeError):raise ValueError("Invalid number: "+k)
  if not lo<=v<=hi:raise ValueError(k+" must be between "+str(lo)+" and "+str(hi))
  p[k]=str(v)
 for pre in ("fo","rec"):
  if p[pre+"_combine"] not in ("all","any"):raise ValueError("Invalid policy combination")
  if p[pre+"_tcp_mode"] not in ("connect","iperf3"):raise ValueError("Invalid TCP check")
  try:loss=float(p[pre+"_ping_loss"])
  except (ValueError,TypeError):raise ValueError("Invalid ping loss")
  if not 0<=loss<=100:raise ValueError("Ping loss must be 0–100%")
  p[pre+"_ping_loss"]=str(loss)
  if not any(p[pre+"_"+m]=="1" for m in ("ping","tcp","dns")):raise ValueError("Enable at least one check in each policy")
  for k in (pre+"_tcp_host",pre+"_dns_name"):
   if not isinstance(p[k],str) or not valid_host(p[k],k.endswith("_host")):raise ValueError("Invalid hostname: "+k)
 for k in ("endpoint4","endpoint6"):
  if not isinstance(p[k],str) or not valid_host(p[k]):raise ValueError("Invalid endpoint alias")
 for k in ("preferred_gateway4","preferred_gateway6","fallback_gateway4","fallback_gateway6"):
  if p[k]:
   try:a=ipaddress.ip_address(p[k])
   except ValueError:raise ValueError("Gateway must be an IP address")
   if a.version!=int(k[-1]):raise ValueError("Gateway address family does not match")
 for k in LISTS:
  if not isinstance(p[k],list) or len(p[k])>8:raise ValueError("Use at most eight targets")
  if any(not isinstance(v,str) or not valid_host(v,False) for v in p[k]):raise ValueError("Invalid target in "+k)
 if any(not _is_ip(x) for x in p["verify_targets"]):raise ValueError("Tunnel verification targets must be IP addresses")
 if not isinstance(p["label"],str) or len(p["label"])>80 or any(ord(c)<32 for c in p["label"]):raise ValueError("Invalid label")
 p["id"]=id_for(p["interface"],p["peer_key"])
 # Per-peer destination/port rules cannot distinguish duplicate remote tuples.
 if p["enabled"]=="1":
  for other in policies(d):
   if other.get("id")==p["id"] or other["enabled"]!="1" or other["interface"]!=p["interface"]:continue
   op=findpeer(other,d)
   if op and op["endpoint_host"]==peer["endpoint_host"] and op["endpoint_port"]==peer["endpoint_port"]:
    raise ValueError("This endpoint and port are already managed on the same WG interface")
 return {k:v for k,v in p.items() if k in allowed}
def _is_ip(x):
 try:ipaddress.ip_address(x);return True
 except ValueError:return False
def write_config(ps,settings):
 text="config globals 'main'\n\toption interval '"+str(int(settings.get("interval",10)))+"'\n"
 keys=set(DEFAULTS)|{"interface","peer_key","slot"}
 for p in ps:
  ident=p.get("id") or id_for(p["interface"],p["peer_key"])
  text+="\nconfig policy "+shlex.quote(ident)+"\n"
  for k in sorted(keys):
   if k not in p:continue
   v=p[k]
   for item in (v if isinstance(v,list) else [v]):
    text+="\t"+("list" if isinstance(v,list) else "option")+" "+k+" "+shlex.quote(str(item))+"\n"
 target=Path("/etc/config/wg_uplink");tmp=target.with_name("wg_uplink.new")
 tmp.write_text(text);tmp.chmod(0o600);os.replace(tmp,target)
 command(["uci","-q","revert","wg_uplink"])
def save(data):
 with open("/var/lock/wg-uplink-config.lock","w") as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  return save_locked(data)
def receiver_status():
 if not Path("/usr/sbin/wg-sticky-receiver").exists():return {"installed":False}
 try:return json.loads(command(["/usr/sbin/wg-sticky-receiver","status"],timeout=6,check=True).stdout)
 except Exception as e:return {"installed":True,"ok":False,"error":str(e)[:200]}
def settings_view(p):
 out={k:p.get(k,DEFAULTS.get(k)) for k in set(DEFAULTS)|{"interface","peer_key"}}
 for k in ("fo_ping_loss","rec_ping_loss"):
  try:out[k]=float(out[k])
  except (ValueError,TypeError):pass
 return out
def action_logs():
 entries=audit.read("uplink")
 if Path("/usr/sbin/wg-sticky-receiver").exists():
  try:entries+=json.loads(command(["/usr/sbin/wg-sticky-receiver","logs"],timeout=5,check=True).stdout).get("entries",[])
  except Exception:pass
 entries=sorted(entries,key=lambda x:x.get("epoch",0),reverse=True)[:100]
 while len(entries)>1 and len(json.dumps(entries))>192*1024:entries.pop()
 return {"ok":True,"entries":entries}
def save_locked(data):
 if data.get("action")=="receiver":
  if not Path("/usr/sbin/wg-sticky-receiver").exists():raise ValueError("Standalone receiver service is not installed")
  payload={k:v for k,v in data.items() if k!="action"}
  result=command(["/usr/sbin/wg-sticky-receiver","configure",json.dumps(payload)],timeout=12)
  return json.loads(result.stdout)
 d=inventory()
 if data.get("action")=="settings":
  if set(data)-{"action","interval"}:raise ValueError("Unknown setting")
  interval=int(data["interval"])
  if not 5<=interval<=60:raise ValueError("Probe interval must be 5–60 seconds")
  before=int(d["settings"].get("interval",10))
  if before==interval:return {"ok":True}
  write_config(policies(d),{"interval":interval})
  audit.emit("uplink","change_settings",{"type":"update_settings"},{"changes":{"interval":{"before":before,"after":interval}}});kick()
  return {"ok":True}
 p=validate(data,d)
 if p["enabled"]=="1":
  peer=findpeer(p,d)
  for role in ("preferred","fallback"):
   af=int(p[role+"_family"]);host=p["endpoint"+str(af)] or peer["endpoint_host"]
   if not resolve(host,af):raise ValueError(role.capitalize()+" protocol has no endpoint address. Select the other family or set an endpoint alias.")
 used={int(x.get("slot",0)) for x in policies(d)}
 existing=next((x for x in policies(d) if x.get("id")==p["id"] or x.get(".name")==p["id"]),{})
 slot=int(existing.get("slot",0)) or next((n for n in range(1,33) if n not in used),0)
 if not slot:raise ValueError("Maximum 32 managed peers")
 p["slot"]=str(slot)
 changes=audit.diff(settings_view(existing),settings_view(p))
 if not changes and existing:return {"ok":True,"id":p["id"],"message":"Settings unchanged."}
 existing_policies=[x for x in policies(d) if x.get("id")!=p["id"]]
 write_config(existing_policies+[p],d["settings"])
 audit.emit("uplink","change_settings",{"type":"update_peer_policy","interface":p["interface"],"peer":p["id"]},{"changes":changes})
 kick()
 return {"ok":True,"id":p["id"],"message":"Saved; the controller applies the configured observation windows."}
def kick():
 subprocess.Popen(["/usr/sbin/wg-uplink","tick"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
def findpeer(p,d):
 return next((x for x in d["peers"] if x["interface"]==p["interface"] and x["key"]==p["peer_key"] and x["endpoint_host"] and not x["disabled"]),None)
def resolve(host,af,cache=True):
 try:
  a=ipaddress.ip_address(host)
  return [str(a)] if a.version==af else []
 except ValueError:pass
 if not valid_host(host,False):return []
 path=RUN/"dns"/(hashlib.sha256((host+str(af)).encode()).hexdigest()[:24]+".json")
 old=readjson(path);now=time.time()
 if cache and now-old.get("time",0)<60:return old.get("addresses",[])
 try:r=command(["resolveip","-"+str(af),"-t","2",host],timeout=3)
 except subprocess.TimeoutExpired:r=None
 addresses=[]
 for x in (r.stdout.split() if r else []):
  try:
   a=ipaddress.ip_address(x)
   if a.version==af and str(a) not in addresses:addresses.append(str(a))
  except ValueError:pass
 if addresses:atomic(path,{"time":now,"addresses":addresses})
 return addresses or old.get("addresses",[])
def peer_runtime(interface,key):
 def rows(field):
  r=command(["wg","show",interface,field])
  return [x.split("\t") for x in r.stdout.splitlines()] if not r.returncode else []
 endpoint=next((x[1] for x in rows("endpoints") if len(x)>1 and x[0]==key),None)
 if endpoint is None:return {}
 hs=next((int(x[1]) for x in rows("latest-handshakes") if len(x)>1 and x[0]==key),0)
 counts=next((x for x in rows("transfer") if len(x)>2 and x[0]==key),[key,"0","0"])
 return {"listen_port":int(command(["wg","show",interface,"listen-port"]).stdout.strip() or 0),
  "mark":command(["wg","show",interface,"fwmark"]).stdout.strip(),"endpoint":endpoint,
  "handshake":hs,"rx":int(counts[1]),"tx":int(counts[2])}
def endpoint_tuple(endpoint):
 if endpoint.startswith("["):
  a,port=endpoint[1:].split("]:",1);return a,int(port)
 if ":" in endpoint:
  a,port=endpoint.rsplit(":",1);return a,int(port)
 return "",0
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
def paths_for(p,peer,d):
 out=[]
 slot=int(p["slot"])
 for group in ("preferred","fallback"):
  fam=int(p[group+"_family"])
  for af in (fam,10-fam):
   idx=(0 if group=="preferred" else 2)+(0 if af==fam else 1)
   r=resource(p[group],af,p[group+"_gateway"+str(af)],d)
   host=p["endpoint"+str(af)] or peer["endpoint_host"]
   ips=resolve(host,af)
   r.update(id=group+str(af),group=group,selectable=(af==fam or p[group+"_other"]=="1"),endpoint_host=host,ips=ips,port=peer["endpoint_port"],
     table=48000+slot*8+idx,pref=500+slot*4+idx)
   if not ips:r["error"]="Endpoint has no IPv"+str(af)+" address"
   r["usable"]=r["available"] and bool(ips)
   out.append(r)
 seen={}
 for x in out:
  if not x["available"]:continue
  key=(x["af"],x["source"])
  if key in seen and seen[key]!=x["device"]:raise ValueError("Uplinks share the same source IP on different devices; use distinct addresses/subnets")
  seen[key]=x["device"]
 return out
def parallel(items):
 results={};lock=threading.Lock();sem=threading.Semaphore(12);threads=[]
 def worker(k,fn):
  with sem:
   try:value=fn()
   except Exception as e:value={"ok":False,"error":str(e)[:160]}
   with lock:results[k]=value
 for key,fn in items:
  t=threading.Thread(target=worker,args=(key,fn));t.start();threads.append(t)
 for t in threads:t.join()
 return results
def ping(src,host,af,count=5):
 try:
  r=command(["ping","-"+str(af),"-n","-q","-I",src,"-c",str(count),"-W","1","-w",str(count+2),host],timeout=count+3)
  text=r.stdout
 except subprocess.TimeoutExpired:text=""
 m=re.search(r"(\d+) packets transmitted,\s*(\d+)\s+(?:packets\s+)?received",text)
 sent,got=(int(m[1]),int(m[2])) if m else (count,0)
 m=re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)",text)
 return {"ok":got>0,"sent":sent,"received":got,"loss":round(100*(sent-got)/max(sent,1),2),"rtt":float(m[2]) if m else None}
def tcp(src,host,af,port,mode):
 start=time.monotonic()
 try:
  with socket.socket(socket.AF_INET6 if af==6 else socket.AF_INET,socket.SOCK_STREAM) as s:
   s.settimeout(2);s.bind((src,0));s.connect((host,port))
   state=None
   if mode=="iperf3":
    s.sendall(os.urandom(18).hex().encode()+b"\0")
    b=s.recv(1)
    if not b or b[0] not in (9,254,255):return {"ok":False,"error":"No iperf3 protocol response"}
    state=b[0]
   return {"ok":True,"ms":round((time.monotonic()-start)*1000,1),"state":state}
 except OSError as e:return {"ok":False,"error":type(e).__name__}
def recv_exact(s,n):
 b=b""
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c:break
  b+=c
 return b
def dns(src,server,af,name):
 qid=os.urandom(2);labels=b"".join(bytes([len(x)])+x.encode("ascii") for x in name.rstrip(".").split("."))+b"\0"
 q=qid+b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+labels+struct.pack("!HH",28 if af==6 else 1,1)
 last=""
 for transport in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
  try:
   with socket.socket(socket.AF_INET6 if af==6 else socket.AF_INET,transport) as s:
    s.settimeout(1.5);s.bind((src,0));s.connect((server,53))
    if transport==socket.SOCK_DGRAM:s.send(q);b=s.recv(4096)
    else:
     s.sendall(struct.pack("!H",len(q))+q);h=recv_exact(s,2)
     b=recv_exact(s,struct.unpack("!H",h)[0]) if len(h)==2 else b""
    if len(b)>=12 and b[:2]==qid:
     flags=struct.unpack("!H",b[2:4])[0];answers=struct.unpack("!H",b[6:8])[0]
     if flags&0x8000 and not flags&0xF and answers>0:return {"ok":True,"server":server,"transport":"UDP" if transport==socket.SOCK_DGRAM else "TCP"}
     last="DNS response has no answer"
    else:last="Invalid DNS response"
  except OSError as e:last=type(e).__name__
 return {"ok":False,"error":last}
def policy_test(result,p,pre):
 values=[]
 if p[pre+"_ping"]=="1":
  loss=result.get("ping",{}).get("loss",100)
  values.append(loss>=float(p[pre+"_ping_loss"]) if pre=="fo" else loss<=float(p[pre+"_ping_loss"]) and result.get("ping",{}).get("received",0)>0)
 for m in ("tcp","dns"):
  if p[pre+"_"+m]=="1":
   ok=result.get(m,{}).get("ok",False);values.append(not ok if pre=="fo" else ok)
 return (all(values) if p[pre+"_combine"]=="all" else any(values)) if values else False
def check_path(path,p):
 if not path["usable"]:return dict(path,failed=True,recovered=False,checks={},error=path.get("error","Unavailable"))
 src=path["source"];af=path["af"];ip=path["ips"][0]
 specs={};mapping={}
 for pre in ("fo","rec"):
  mapping[pre]={}
  if p[pre+"_ping"]=="1":
   hosts=p[pre+"_ping_targets"] or [ip]
   targets=[a for h in hosts for a in resolve(h,af)[:1]]
   count=int(p[pre+"_ping_count"])
   key=("ping",tuple(targets),count);mapping[pre]["ping"]=key
   def ping_group(targets=targets,count=count):
    # Probe targets together so larger samples do not multiply check duration.
    results=parallel([(i,lambda t=t:ping(src,t,af,count)) for i,t in enumerate(targets)])
    rs=list(results.values())
    sent=sum(x["sent"] for x in rs);got=sum(x["received"] for x in rs)
    rtts=[x["rtt"] for x in rs if x["rtt"] is not None]
    return {"ok":got>0,"sent":sent,"received":got,"loss":100*(sent-got)/max(sent,1) if sent else 100,"rtt":sum(rtts)/len(rtts) if rtts else None}
   specs[key]=ping_group
  if p[pre+"_tcp"]=="1":
   target=(resolve(p[pre+"_tcp_host"],af)[:1] if p[pre+"_tcp_host"] else [ip])
   host=target[0] if target else "";port=int(p[pre+"_tcp_port"]);mode=p[pre+"_tcp_mode"]
   key=("tcp",host,port,mode);mapping[pre]["tcp"]=key
   specs[key]=lambda host=host,port=port,mode=mode:tcp(src,host,af,port,mode) if host else {"ok":False,"error":"No address for this family"}
  if p[pre+"_dns"]=="1":
   servers=p[pre+"_dns_servers"] or (["2606:4700:4700::1111","2001:4860:4860::8888"] if af==6 else ["1.1.1.1","8.8.8.8"])
   targets=[a for h in servers for a in resolve(h,af)[:1]]
   name=p[pre+"_dns_name"];key=("dns",tuple(targets),name);mapping[pre]["dns"]=key
   def dns_group(targets=targets,name=name):
    rs=[dns(src,t,af,name) for t in targets]
    return next((x for x in rs if x["ok"]),{"ok":False,"error":"No resolver answered"})
   specs[key]=dns_group
 results=parallel(list(specs.items()))
 checks={pre:{m:results[k] for m,k in row.items()} for pre,row in mapping.items()}
 return dict(path,checks=checks,failed=policy_test(checks["fo"],p,"fo"),recovered=policy_test(checks["rec"],p,"rec"))
def general_health(paths):
 available=[x for x in paths if x["group"]=="preferred" and x["available"]]
 if not available:return {"ok":False,"reason":"Preferred uplink has no usable native address/gateway"}
 jobs=[]
 for x in available:
  for host in (["2606:4700:4700::1111","2001:4860:4860::8888"] if x["af"]==6 else ["1.1.1.1","8.8.8.8"]):
   jobs.append((x["id"]+host,lambda x=x,host=host:ping(x["source"],host,x["af"],2)))
  target="2606:4700:4700::1111" if x["af"]==6 else "1.1.1.1"
  jobs.append((x["id"]+"tcp",lambda x=x,target=target:tcp(x["source"],target,x["af"],443,"connect")))
 rs=parallel(jobs)
 return {"ok":any(v.get("ok") for v in rs.values()),"checks":rs}
def transition(p,s,paths,local_ok,now):
 """Pure decision: no routes, probes or clock calls. All windows use elapsed time."""
 s=dict(s);by={x["id"]:x for x in paths};current=by.get(s.get("selected"))
 def reset(k):s.pop(k,None)
 def observe(k,window,candidate):
  last=s.get(k+"_last",now)
  if k not in s or s.get(k+"_candidate")!=candidate or now-last>max(100,3*int(p.get("_interval",10))):s[k]=now
  s[k+"_candidate"]=candidate
  s[k+"_last"]=now;s["timer"]={"kind":k,"elapsed":max(0,now-s[k]),"window":int(window)}
  return now-s[k]>=int(window)
 # Shared remote failure: no reachable candidate, never switch ISPs blindly.
 if not any(not x["failed"] for x in paths):
  reset("failure_since");reset("recovery_since");s["reason"]="Hub/shared failure or all paths fail policy; retaining current";s["timer"]=None
  return s,None
 preferred=[x for x in paths if x["group"]=="preferred" and x.get("selectable",True)]
 fallback=[x for x in paths if x["group"]=="fallback" and x.get("selectable",True)]
 def best(seq):
  for x in seq:
   if x["recovered"]:return x
   # A healthier lower-priority family cannot displace a reachable preferred one.
   if not x["failed"]:return None
  return None
 pb=best(preferred);fb=best(fallback)
 if not current:
  candidate=pb or fb
  s["reason"]="Initial selection"
  return s,candidate["id"] if candidate else None
 if current["group"]=="fallback" or (pb and current["group"]=="preferred" and preferred.index(pb)<next((i for i,x in enumerate(preferred) if x["id"]==current["id"]),99)):
  if pb and pb["id"]!=current["id"]:
   reset("failure_since");s["reason"]="Observing preferred-path recovery"
   if observe("recovery_since",p["recovery_seconds"],pb["id"]):return s,pb["id"]
   return s,None
 reset("recovery_since")
 if not current["failed"]:
  reset("failure_since");s["timer"]=None;s["reason"]="Keeping selected path"
  return s,None
 candidate=pb if pb and pb["id"]!=current["id"] else fb
 if current["group"]=="fallback" and not candidate:candidate=next((x for x in fallback if x["recovered"] and x["id"]!=current["id"]),None)
 if not candidate:
  reset("failure_since");s["reason"]="No verified better candidate; retaining current";s["timer"]=None
  return s,None
 fast=not local_ok and candidate["group"]=="fallback"
 s["reason"]="Confirming local uplink failure" if fast else "Observing selected-path failure"
 if observe("failure_since",p["fast_seconds"] if fast else p["observe_seconds"],candidate["id"]):return s,candidate["id"]
 return s,None
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
def install_resources(paths,s):
 changed=False
 for x in paths:
  af=x["af"];table=x["table"];pref=x["pref"]
  opposite=RUN/"rules"/(str(10-af)+"-"+str(pref)+".json")
  if opposite.exists():delrule(10-af,pref);opposite.unlink();changed=True
  owned=RUN/"tables"/(str(af)+"-"+str(table)+".json")
  table_present=bool(command(["ip","-"+str(af),"route","show","table",table]).stdout.strip())
  if not table_present:changed=True
  if not owned.exists():
   if table_present:raise ValueError("Routing table "+str(table)+" is already used")
   atomic(owned,{"owned":True})
  command(["ip","-"+str(af),"route","replace","unreachable","default","table",table,"metric","42760"],check=True)
  if not x["available"]:
   command(["ip","-"+str(af),"route","flush","table",table,"type","unicast"])
   cache=RUN/"rules"/(str(af)+"-"+str(pref)+".json")
   if cache.exists():delrule(af,pref);cache.unlink();changed=True
   continue
  if x["gateway"]:
   command(["ip","-"+str(af),"route","replace","table",table,x["gateway"]+("/128" if af==6 else "/32"),"dev",x["device"],"scope","link"],check=True)
  route=["ip","-"+str(af),"route","replace","table",table,"default"]
  if x["gateway"]:route+=["via",x["gateway"]]
  route+=["dev",x["device"],"src",x["source"]]
  if x["gateway"]:route+=["onlink"]
  command(route+["metric","10"],check=True)
  changed=bool(rule(af,pref,["from",x["source"]+("/128" if af==6 else "/32"),"lookup",table],s.get("initialized",False))) or changed
 return changed
# Keep generated socket identity outside mwan3 (0x3f00), common PBR fields,
# the independent receiver (0x3f000000), and unrelated low routing marks.
SOCKET_MARK_BASE=0x80000000
SOCKET_MARK_MASK=0x800000ff

def selection_mark(mark):
 value=int(str(mark),0)
 if value & SOCKET_MARK_BASE and not value & ~SOCKET_MARK_MASK:
  return hex(value)+"/"+hex(SOCKET_MARK_MASK)
 # Preserve pre-existing interface marks, ignoring only mwan3's owned field.
 if Path('/etc/config/mwan3').exists():
  result=command(['uci','-q','get','mwan3.@globals[0].mmx_mask'])
  try:foreign=int(result.stdout.strip(),0) if result.returncode==0 else 0x3f00
  except ValueError:raise ValueError('Invalid mwan3 mark mask')
  if not 0<foreign<=0xffffffff:raise ValueError('Invalid mwan3 mark mask')
  stable=0xffffffff ^ foreign
  if not value & stable:raise ValueError('Existing WG mark has no identity outside mwan3 bits')
  return hex(value & stable)+"/"+hex(stable)
 return str(mark)

def mark_for(p,live):
 path=RUN/"interfaces"/(p["interface"]+".json")
 original=readjson(path)
 if not original:
  mark=live.get("mark","off")
  original={"original_mark":mark,"mark":mark if mark not in ("off","0","0x0") else hex(SOCKET_MARK_BASE+int(p["slot"]))}
  atomic(path,original)
 return original["mark"]
def update_guard(states,override=None):
 existing=command(["nft","list","table","inet","wg_uplink"]).returncode==0
 commands=["flush chain inet wg_uplink input","flush chain inet wg_uplink output"]
 for state in states:
  policy_id=state.get("id")
  target=override[1] if override and policy_id==override[0] else state.get("active")
  if not target or (not state.get("initialized") and not (override and policy_id==override[0])):continue
  listen=state.get("listen_port",0)
  if not listen:continue
  for x in state.get("paths",[]):
   for addr in x.get("ips",[]):
    af=ipaddress.ip_address(addr).version;prefix="ip6" if af==6 else "ip"
    base=prefix+" saddr "+addr+" udp sport "+str(x["port"])+" udp dport "+str(listen)
    outbase=prefix+" daddr "+addr+" udp dport "+str(x["port"])+" udp sport "+str(listen)
    if af!=target["af"] or addr not in target["ips"]:
     commands.append("add rule inet wg_uplink input "+base+" counter drop")
     commands.append("add rule inet wg_uplink output "+outbase+" counter drop")
    else:
     commands.append("add rule inet wg_uplink input "+base+" iifname != "+json.dumps(target["device"])+" counter drop")
     commands.append("add rule inet wg_uplink output "+outbase+" oifname != "+json.dumps(target["device"])+" counter drop")
 # All generated guard rules only drop; stable ordering avoids restart-only rewrites.
 commands=commands[:2]+sorted(set(commands[2:]))
 desired=hashlib.sha256("\n".join(commands).encode()).hexdigest()
 cache=RUN/"guard-applied.json";old=readjson(cache)
 current=audit.nft_fingerprint(command,"wg_uplink") if existing else None
 if existing and old.get("desired")==desired and old.get("actual")==current:return False
 if not existing:
  commands=["add table inet wg_uplink","add chain inet wg_uplink input { type filter hook input priority -21; policy accept; }","add chain inet wg_uplink output { type filter hook output priority -21; policy accept; }"]+commands
 command(["nft","-f","-"],stdin="\n".join(commands)+"\n",check=True)
 after={"desired":desired,"actual":audit.nft_fingerprint(command,"wg_uplink")}
 atomic(cache,after)
 atomic(RUN/"guard-change.json",{"before":dict(old,observed=current),"after":after,"rules":commands})
 return True
def select_route(p,target,mark,s):
 pref=300+int(p["slot"]);af=target["af"];addr=target["ips"][0]
 rule(af,pref,["to",addr+("/128" if af==6 else "/32"),"fwmark",selection_mark(mark),"ipproto","udp","dport",target["port"],"lookup",target["table"]],s.get("initialized",False))
 # Remove only the opposite-family selection rule, never management rules.
 other=10-af;cache=RUN/"rules"/(str(other)+"-"+str(pref)+".json")
 if cache.exists():delrule(other,pref);cache.unlink()
def verify_inner(p):
 if not p["verify_targets"]:return True
 jobs=[]
 for target in p["verify_targets"]:
  af=ipaddress.ip_address(target).version
  try:
   route=json.loads(command(["ip","-j","-"+str(af),"route","get",target],check=True).stdout)[0]
   if route.get("dev")!=p["interface"]:continue
   src=route.get("prefsrc") or route.get("src")
   if not src:
    infos=json.loads(command(["ip","-j","-"+str(af),"addr","show","dev",p["interface"]]).stdout)
    src=next(a["local"] for x in infos for a in x["addr_info"] if a.get("scope")=="global")
   jobs.append((target,lambda src=src,target=target,af=af:ping(src,target,af,5)))
  except (ValueError,KeyError,StopIteration):continue
 return any(x.get("ok") for x in parallel(jobs).values()) if jobs else False
def apply_path(p,s,target,all_states,trigger=None):
 mark=s["mark"];old=s.get("active")
 support=audit.evidence(s);old_view=audit.path_view(old or {})
 endpoint=("["+target["ips"][0]+"]" if target["af"]==6 else target["ips"][0])+":"+str(target["port"])
 try:
  update_guard(all_states,(s["id"],target))
  select_route(p,target,mark,s)
  command(["ip","-"+str(target["af"]),"route","flush","cache"],check=True)
  command(["wg","set",p["interface"],"fwmark",mark,"peer",p["peer_key"],"endpoint",endpoint],check=True)
  if not verify_inner(p):raise ValueError("Tunnel verification failed")
  live=peer_runtime(p["interface"],p["peer_key"])
  if live.get("endpoint")!=endpoint:raise ValueError("Endpoint roamed during verification")
  proof=command(["ip","-"+str(target["af"]),"route","get",target["ips"][0],"mark",mark,"ipproto","udp","dport",target["port"]],check=True).stdout.strip()
  if "dev "+target["device"]+" " not in proof+" ":raise ValueError("Sticky route verification failed")
 except Exception as error:
  if old:
   select_route(p,old,mark,s);update_guard(all_states,(s["id"],old))
   ep=("["+old["ips"][0]+"]" if old["af"]==6 else old["ips"][0])+":"+str(old["port"])
   command(["ip","-"+str(old["af"]),"route","flush","cache"])
   command(["wg","set",p["interface"],"fwmark",mark,"peer",p["peer_key"],"endpoint",ep],check=True)
  else:
   for af in (4,6):
    pref=300+int(p["slot"]);cache=RUN/"rules"/(str(af)+"-"+str(pref)+".json")
    if cache.exists():delrule(af,pref);cache.unlink()
   if s.get("original_endpoint"):
    command(["wg","set",p["interface"],"peer",p["peer_key"],"endpoint",s["original_endpoint"]])
   update_guard(all_states)
  audit.emit("uplink",trigger or "check_condition_met",{"type":"rollback_switch","interface":p["interface"],"peer":s["id"]},{"before":old_view,"attempted":audit.path_view(target),"after":old_view,"error":str(error),"support":support})
  raise
 s.update(selected=target["id"],active=target,endpoint=endpoint,route_proof=proof,last_switch=time.time(),initialized=True)
 s.pop("failure_since",None);s.pop("recovery_since",None);s["timer"]=None
 audit.emit("uplink",trigger or ("check_condition_met" if old_view.get("id")!=target["id"] else "interface_detail_update_observed"),{"type":"switch_path" if old_view.get("id")!=target["id"] else "refresh_selected_path","interface":p["interface"],"peer":s["id"]},{"before":old_view,"after":audit.path_view(target),"route_proof":proof,"support":support})
def cleanup_policy(p,s,remaining):
 slot=int(s.get("slot",p.get("slot",0)))
 if not slot:return
 for af in (4,6):
  for pref in [300+slot]+list(range(500+slot*4,504+slot*4)):
   cache=RUN/"rules"/(str(af)+"-"+str(pref)+".json")
   if cache.exists():delrule(af,pref);cache.unlink()
  for table in range(48000+slot*8,48004+slot*8):
   owned=RUN/"tables"/(str(af)+"-"+str(table)+".json")
   if owned.exists():
    command(["ip","-"+str(af),"route","flush","table",table]);owned.unlink()
 if s.get("original_endpoint"):
  command(["wg","set",s["interface"],"peer",s["peer_key"],"endpoint",s["original_endpoint"]])
 if not any(x.get("interface")==s.get("interface") for x in remaining):
  snap=RUN/"interfaces"/(s["interface"]+".json");original=readjson(snap)
  if original:command(["wg","set",s["interface"],"fwmark",original["original_mark"] if original["original_mark"]!="off" else "0"])
  if snap.exists():snap.unlink()
 path=RUN/"peers"/(s["id"]+".json")
 if path.exists():path.unlink()
def initialize_state(p,state,live,paths):
 if "original_endpoint" in state:return state
 current_ip,_=endpoint_tuple(live["endpoint"])
 current=None
 if current_ip:
  af=ipaddress.ip_address(current_ip).version
  route=command(["ip","-"+str(af),"route","get",current_ip,"mark",live["mark"] if live["mark"]!="off" else "0","ipproto","udp","dport",paths[0]["port"]]).stdout
  match=re.search(r"\bdev\s+(\S+)",route)
  current=next((x for x in paths if current_ip in x["ips"] and match and x.get("device")==match[1]),None)
 return dict(state,id=p["id"],slot=int(p["slot"]),interface=p["interface"],peer_key=p["peer_key"],original_endpoint=live["endpoint"],selected=current["id"] if current else None)
def tick(force=False,trigger="check_condition_met"):
 RUN.mkdir(parents=True,exist_ok=True)
 with open(LOCK,"w") as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return {"ok":True,"busy":True}
  d=inventory();ps=policies(d);interval=int(d["settings"].get("interval",10))
  stamp=readjson(RUN/"tick.json")
  if not force and time.monotonic()-stamp.get("started",0)<max(4,interval-1):return {"ok":True,"skipped":True}
  atomic(RUN/"tick.json",{"started":time.monotonic()})
  states={x.stem:readjson(x) for x in (RUN/"peers").glob("*.json")} if (RUN/"peers").exists() else {}
  enabled={id_for(p["interface"],p["peer_key"]):p for p in ps if p["enabled"]=="1" and findpeer(p,d)}
  for key,s in list(states.items()):
   if key not in enabled:
    cleanup_policy({},s,[v for k,v in states.items() if k in enabled and k!=key]);states.pop(key)
    audit.emit("uplink","change_settings",{"type":"remove_peer_policy","interface":s.get("interface"),"peer":key},{"before":audit.path_view(s.get("active") or {}),"after":None})
  if update_guard(list(states.values())):
   audit.emit("uplink",trigger,{"type":"reconcile_firewall"},dict(readjson(RUN/"guard-change.json"),support=[audit.evidence(s) for s in states.values()]))
  for ident,p in enabled.items():
   p["id"]=ident;p["_interval"]=interval
   state=states.get(ident,{})
   digest=hashlib.sha256(json.dumps({k:p.get(k) for k in DEFAULTS},sort_keys=True).encode()).hexdigest()
   if state.get("config_hash")!=digest:
    state.pop("failure_since",None);state.pop("recovery_since",None);state["timer"]=None
   state["config_hash"]=digest
   try:
    # Persisted config can also be changed by SSH, so validate again.
    validate({k:v for k,v in p.items() if k in set(DEFAULTS)|{"id","interface","peer_key"}},d)
    peer=findpeer(p,d)
    if not peer:raise ValueError("Configured endpoint peer is no longer available")
    live=peer_runtime(p["interface"],p["peer_key"])
    if not live:raise ValueError("WireGuard interface is not running")
    paths=paths_for(p,peer,d)
    state=initialize_state(p,state,live,paths)
    before_resources=audit.paths_view(state.get("paths",[]))
    state.update(mark=mark_for(p,live),listen_port=live["listen_port"],paths=paths)
    repaired=install_resources(paths,state)
    after_resources=audit.paths_view(paths)
    if before_resources!=after_resources or repaired:
     audit.emit("uplink",trigger if trigger=="start_service" else "interface_detail_update_observed",{"type":"refresh_routes","interface":p["interface"],"peer":ident},{"before":before_resources,"after":after_resources,"restored_missing_resources":bool(repaired)})
    observed=parallel([(x["id"],lambda x=x:check_path(x,p)) for x in paths])
    results=[observed[x["id"]] for x in paths]
    if any("failed" not in x for x in results):raise ValueError("Health check could not complete")
    state["paths"]=results
    chosen=next((x for x in results if x["id"]==state.get("selected")),None)
    # Adopt the already-working production transport without a cutover.
    if not state.get("active") and chosen and chosen["usable"]:
     state["active"]=chosen
    local={"ok":True}
    if not any(x["group"]=="preferred" and not x["failed"] for x in results):local=general_health(paths)
    state,desired=transition(p,state,results,local["ok"],time.monotonic())
    state.update(id=ident,slot=int(p["slot"]),interface=p["interface"],peer_key=p["peer_key"],paths=results,local_health=local,checked_at=time.time(),error=None)
    states[ident]=state
    target=next((x for x in results if x["id"]==(desired or state.get("selected"))),None)
    if target and target["usable"]:
     same=state.get("active") and state["active"].get("id")==target["id"] and state["active"].get("source")==target.get("source") and state["active"].get("ips")==target["ips"]
     wanted=("["+target["ips"][0]+"]" if target["af"]==6 else target["ips"][0])+":"+str(target["port"])
     # Always pin the selected peer, including initial adoption.
     if not state.get("initialized") or desired or not same or live.get("endpoint")!=wanted or live.get("mark")!=state["mark"]:
      apply_path(p,state,target,list(states.values()),trigger="start_service" if trigger=="start_service" else ("check_condition_met" if desired else "interface_detail_update_observed"))
     else:
      select_route(p,target,state["mark"],state)
      state["active"]=target
    state["live"]=peer_runtime(p["interface"],p["peer_key"])
   except Exception as e:
    state.pop("failure_since",None);state.pop("recovery_since",None);state["timer"]=None
    state.update(id=ident,slot=int(p["slot"]),interface=p["interface"],peer_key=p["peer_key"],error=str(e)[:250],checked_at=time.time())
    states[ident]=state
    print("WG Uplink "+p["interface"]+": "+str(e),file=sys.stderr)
   atomic(RUN/"peers"/(ident+".json"),state)
   # One-minute RAM history, retained for about 48 hours.
   hp=RUN/"history"/(ident+".json");hist=readjson(hp,[])
   if not hist or time.time()-hist[-1].get("time",0)>=55:
    hist.append({"time":time.time(),"selected":state.get("selected"),"reason":state.get("reason"),"paths":[{"id":x.get("id"),"failed":x.get("failed"),"checks":x.get("checks",{})} for x in state.get("paths",[])]})
    atomic(hp,hist[-2880:])
  if update_guard(list(states.values())):
   audit.emit("uplink",trigger,{"type":"reconcile_firewall"},{"interfaces":[s.get("interface") for s in states.values()]})
  return {"ok":True,"policies":len(enabled)}
def status():
 d=inventory();ps=policies(d);by={id_for(p["interface"],p["peer_key"]):p for p in ps}
 cards=[]
 for interface in [x for x in d["interfaces"] if x["proto"]=="wireguard"]:
  rows=[]
  for peer in [x for x in d["peers"] if x["interface"]==interface["name"]]:
   ident=id_for(peer["interface"],peer["key"]);p=by.get(ident)
   policy=cfg(p or {})
   policy.update(id=ident,interface=peer["interface"],peer_key=peer["key"])
   rows.append(dict(peer,id=ident,eligible=bool(peer["endpoint_host"]) and not peer["disabled"],policy=policy,status=readjson(RUN/"peers"/(ident+".json"))))
  cards.append(dict(interface,peers=rows))
 # Include WG devices which exist at runtime without a matching UCI definition.
 runtime_names=command(["wg","show","interfaces"]).stdout.split()
 for name in runtime_names:
  if not any(x["name"]==name for x in cards):cards.append({"name":name,"proto":"wireguard","peers":[],"runtime_only":True})
 runtime={x["interface"]:x for x in d["runtime"]}
 uplinks=[dict(x,device=runtime.get(x["name"],{}).get("l3_device",""),up=runtime.get(x["name"],{}).get("up",False),family_children={str(af):[r["interface"] for r in family_rows(x["name"],af,d)[1] if r["interface"]==x["name"]+"_"+str(af) or (next((c.get("device","") for c in d["interfaces"] if c["name"]==r["interface"]),"")=="@"+x["name"])] for af in (4,6)}) for x in d["interfaces"] if x["proto"]!="wireguard" and x["name"]!="loopback"]
 return {"ok":True,"version":VERSION,"interfaces":cards,"uplinks":uplinks,"receiver":receiver_status(),"settings":{"interval":int(d["settings"].get("interval",10))}}
def daemon():
 first=True
 while True:
  start=time.monotonic()
  try:tick(force=first,trigger="start_service" if first else "check_condition_met");first=False
  except Exception as e:print("WG Uplink: "+str(e),file=sys.stderr)
  try:interval=int(inventory()["settings"].get("interval",10))
  except Exception:interval=10
  time.sleep(max(1,interval-(time.monotonic()-start)))
def main():
 RUN.mkdir(parents=True,exist_ok=True)
 action=sys.argv[1] if len(sys.argv)>1 else "status"
 try:
  if action=="status":out=status()
  elif action=="logs":out=action_logs()
  elif action=="save":
   raw=sys.argv[2] if len(sys.argv)>2 else sys.stdin.read(16385)
   if len(raw)>16384:raise ValueError("Request too large")
   out=save(json.loads(raw))
  elif action=="validate":
   data=json.loads(sys.stdin.read(16385));out={"ok":True,"policy":validate(data,inventory())}
  elif action=="tick":out=tick()
  elif action=="kick":kick();out={"ok":True}
  elif action=="daemon":daemon();return
  else:raise ValueError("Unknown command")
 except Exception as e:out={"ok":False,"error":str(e)[:300]}
 print(json.dumps(out,separators=(",",":")))
 if not out.get("ok"):sys.exit(1)
if __name__=="__main__":main()
