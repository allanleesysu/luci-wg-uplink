"""Persistent, bounded action journal. No logging or third-party dependency."""
import os,json,time,fcntl,hashlib,subprocess
from pathlib import Path
LIMIT=1024*1024
KEEP=3
MAX_RECORD=128*1024
BASE=Path("/etc")
LOCKBASE=Path("/var/lock")
_zone=None
def diff(before,after):
 return {k:{"before":before.get(k),"after":after.get(k)} for k in sorted(set(before)|set(after)) if before.get(k)!=after.get(k)}
def clean(value):
 if isinstance(value,dict):return {k:("[redacted]" if any(s in k.lower() for s in ("private_key","preshared_key","password","token","secret")) else clean(v)) for k,v in value.items()}
 if isinstance(value,list):return [clean(x) for x in value]
 return value
def directory(scope):return BASE/("wg-uplink" if scope=="uplink" else "wg-sticky-receiver")
def emit(scope,trigger,action,data):
 global _zone
 try:
  if _zone is None:
   p=subprocess.run(["uci","-q","get","system.@system[0].zonename"],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=2)
   zone=p.stdout.strip() or time.tzname[time.localtime().tm_isdst>0]
  else:zone=_zone
  if hasattr(time,"tzset"):time.tzset()
  now=time.localtime();offset=time.strftime("%z",now);offset=offset[:3]+":"+offset[3:] if offset else ""
  record={"timestamp":time.strftime("%Y-%m-%dT%H:%M:%S",now)+offset,"epoch":time.time(),
   "date":time.strftime("%Y-%m-%d",now),"time":time.strftime("%H:%M:%S",now),"timezone":zone,"utc_offset":offset,
   "scope":scope,"trigger":trigger,"action":clean(action),"data":clean(data)}
  path=directory(scope);path.mkdir(parents=True,exist_ok=True,mode=0o700)
  LOCKBASE.mkdir(parents=True,exist_ok=True)
  with open(LOCKBASE/("wg-actionlog-"+scope+".lock"),"a") as lock:
   fcntl.flock(lock,fcntl.LOCK_EX)
   target=path/"actions.jsonl";line=(json.dumps(record,ensure_ascii=True,separators=(",",":"))+"\n").encode()
   if len(line)>MAX_RECORD:
    record["data"]={"truncated":True,"original_bytes":len(line),"preview":json.dumps(record["data"],ensure_ascii=True)[:32768]}
    line=(json.dumps(record,ensure_ascii=True,separators=(",",":"))+"\n").encode()
   if target.exists() and target.stat().st_size+len(line)>LIMIT:
    for n in range(KEEP-1,0,-1):
     src=target if n==1 else path/("actions.jsonl."+str(n-1))
     if src.exists():os.replace(src,path/("actions.jsonl."+str(n)))
   fd=os.open(target,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
   try:os.write(fd,line);os.fsync(fd)
   finally:os.close(fd)
  return True
 except Exception as e:
  print("WG action journal unavailable: "+str(e),file=__import__("sys").stderr);return False
def read(scope,limit=100):
 entries=[];path=directory(scope)
 try:
  for name in ["actions.jsonl"]+["actions.jsonl."+str(n) for n in range(1,KEEP)]:
   p=path/name
   if not p.exists():continue
   with p.open("rb") as f:
    f.seek(max(0,p.stat().st_size-512*1024));raw=f.read()
   for line in raw.splitlines():
    try:
     item=json.loads(line)
     if item.get("scope")==scope:entries.append(item)
    except (ValueError,UnicodeError):pass
   if len(entries)>=limit:break
  return sorted(entries,key=lambda x:x.get("epoch",0),reverse=True)[:limit]
 except OSError:return []
def path_view(path):
 return {k:path.get(k) for k in ("id","role","af","logical_interface","available","source","gateway","device","table","pref","port","ips") if k in path}
def paths_view(paths):return [path_view(p) for p in paths]
def evidence(state):
 return {"condition":state.get("reason"),"observation":state.get("timer"),"local_health":state.get("local_health"),
  "candidates":[dict(path_view(p),failed=p.get("failed"),recovered=p.get("recovered"),checks=p.get("checks",{})) for p in state.get("paths",[])]}
def nft_fingerprint(command,table):
 r=command(["nft","-j","list","table","inet",table])
 if r.returncode:return None
 def normalize(x):
  if isinstance(x,dict):return {k:normalize(v) for k,v in x.items() if k not in ("handle","packets","bytes","metainfo")}
  if isinstance(x,list):return [normalize(v) for v in x if not (isinstance(v,dict) and set(v)=={"metainfo"})]
  return x
 try:value=normalize(json.loads(r.stdout))
 except ValueError:value=r.stdout
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
