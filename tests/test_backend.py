#!/usr/bin/env python3
import sys,importlib.util,copy,tempfile,json
from pathlib import Path
spec=importlib.util.spec_from_file_location("wgu",sys.argv[1])
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
count=0
def check(condition,name):
 global count
 assert condition,name
 count+=1;print("PASS",name)
def invalid(data,d,name):
 try:w.validate(data,d)
 except ValueError:check(True,name);return
 raise AssertionError(name)
d={"interfaces":[{"name":"wan1","proto":"dhcp"},{"name":"wan2","proto":"dhcp"},{"name":"wan1_6","proto":"dhcpv6"},{"name":"wg0","proto":"wireguard"}],
 "runtime":[{"interface":"wan1","l3_device":"eth1","up":True,"ipv4-address":[{"address":"192.0.2.2"}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.0.2.1"}]},
 {"interface":"wan2","l3_device":"eth2","up":True,"ipv4-address":[{"address":"198.51.100.2"}],"route":[]},
 {"interface":"wan1_6","l3_device":"eth1","up":True,"ipv6-address":[{"address":"2606:4700::1234","preferred":1}],"route":[{"target":"::","mask":0,"nexthop":"fe80::1"}]}],
 "peers":[{"interface":"wg0","key":"public","endpoint_host":"hub.example.com","endpoint_port":51820,"disabled":False},{"interface":"wg0","key":"inbound","endpoint_host":"","endpoint_port":51820,"disabled":False}],"policies":[]}
p=dict(w.DEFAULTS,interface="wg0",peer_key="public",preferred="wan1",fallback="wan2",enabled="1",slot="1",_interval=10,fo_tcp="1",rec_tcp="1")
valid={k:v for k,v in p.items() if k not in ("slot","_interval")}
check(w.validate(valid,d)["preferred"]=="wan1","valid outbound policy")
invalid(dict(valid,peer_key="inbound"),d,"inbound-only peer cannot be managed")
invalid(dict(valid,fallback="wan1"),d,"same uplink rejected")
invalid(dict(valid,fallback="wan1_6"),d,"same device via alias rejected")
alias=copy.deepcopy(d)
alias["interfaces"][2]["device"]="@wan1"
alias["runtime"][2]["l3_device"]="separate-v6-device"
invalid(dict(valid,fallback="wan1_6"),alias,"same provider through differently named alias devices rejected")
invalid(dict(valid,endpoint4="example.com;bad"),d,"hostname command injection rejected")
invalid(dict(valid,observe_seconds="0"),d,"zero observation window rejected")
invalid(dict(valid,fo_ping_loss="NaN"),d,"NaN threshold rejected")
invalid(dict(valid,fo_ping="0",fo_tcp="0",fo_dns="0"),d,"empty policy rejected")
invalid(dict(valid,preferred_gateway6="192.0.2.1"),d,"wrong gateway family rejected")
invalid(dict(valid,verify_targets=["hub.example.com"]),d,"tunnel target requires IP")
invalid(dict(valid,slot="9"),d,"client cannot choose routing slot")
check(w.resource("wan1",4,"",d)["gateway"]=="192.0.2.1","DHCP gateway discovery")
check(w.resource("wan1",6,"",d)["source"]=="2606:4700::1234","IPv6 sibling discovery")
check(w.resource("wan2",4,"198.51.100.1",d)["gateway"]=="198.51.100.1","static gateway override")
# No kernel calls or real probes in decision tests.
def path(name,failed=False,recovered=True,selectable=True):
 return {"id":name,"group":"preferred" if name.startswith("preferred") else "fallback","failed":failed,"recovered":recovered,"selectable":selectable}
def window(state,paths,now,local=True):return w.transition(p,state,paths,local,now)
good=[path("preferred6"),path("preferred4"),path("fallback4"),path("fallback6",selectable=False)]
state={"selected":"preferred6"}
out,target=window(state,good,100)
check(target is None,"healthy preferred IPv6 retained")
bad=copy.deepcopy(good);bad[0].update(failed=True,recovered=False)
s,t=window(state,bad,100)
check(t is None and s["timer"]["window"]==300,"family failover uses observed window")
s,t=window(s,bad,399)
check(t is None,"no family cutover before 300 seconds")
# Fresh intermediate observations are required; insert two normal intervals.
s,_=window(s,bad,400-60)
s,t=window(s,bad,400)
# The deliberate out-of-order sample above cannot satisfy a fresh uninterrupted window.
# Start a clean five-minute sequence.
s={"selected":"preferred6"}
for now in (100,160,220,280,340,399):s,t=window(s,bad,now)
check(t is None,"299 seconds does not switch")
s,t=window(s,bad,400)
check(t=="preferred4","complete IPv6 failure selects healthy IPv4 at 300 seconds")
both=copy.deepcopy(bad);both[1].update(failed=True,recovered=False)
s={"selected":"preferred6"}
for now in (100,160,220,280,340,400):s,t=window(s,both,now)
check(t=="fallback4","both preferred families failed, observed fallback")
s,t=window({"selected":"preferred6"},both,100,False)
s,t=window(s,both,109,False);check(t is None,"fast branch waits 10 seconds")
s,t=window(s,both,110,False);check(t=="fallback4","corroborated local failure fast-track")
allbad=[path(x["id"],True,False,x["selectable"]) for x in good]
s,t=window({"selected":"preferred6"},allbad,999,False)
check(t is None and "shared" in s["reason"],"shared hub failure blocks failover")
s={"selected":"fallback4"}
for now in (100,160,220,280,340,399):s,t=window(s,good,now)
check(t is None,"working fallback still observes recovery")
s,t=window(s,good,400)
check(t=="preferred6","actively restores preferred while fallback works")
s={"selected":"preferred4"}
for now in (100,160,220,280,340,400):s,t=window(s,good,now)
check(t=="preferred6","IPv4 is not sticky; IPv6 actively recovers")
gap=[path("preferred6",False,False),path("preferred4"),path("fallback4")]
s,t=window({"selected":"fallback4"},gap,100)
check(t is None,"strict recovery does not silently substitute IPv4 for reachable IPv6")
s={"selected":"fallback4"}
s,_=window(s,good,100);s,t=window(s,good,401)
check(t is None and s["timer"]["elapsed"]==0,"monitoring gap restarts timer")
# Ping partial loss must not be interpreted using process return status.
checks={"ping":{"loss":33.3,"received":2},"tcp":{"ok":False}}
check(not w.policy_test(checks,p,"fo"),"partial ping loss plus TCP timeout is not all-check failure")
check(w.policy_test(checks,p,"rec"),"intermittent loss permits recovery")
check(not w.policy_test({"ping":{"loss":100,"received":0}},dict(p,rec_tcp="0",rec_ping_loss="100"),"rec"),"no replies never counts as recovered")
# Route ownership and sticky guard tests.
with tempfile.TemporaryDirectory() as tmp:
 w.RUN=Path(tmp)
 calls=[]
 class R:
  returncode=0;stdout="";stderr=""
 def fake_command(argv,**kw):
  calls.append((argv,kw));r=R()
  if argv[:5]==["nft","list","table","inet","wg_uplink"]:r.returncode=1
  return r
 original=w.command;w.command=fake_command
 route={"available":True,"af":4,"table":48008,"pref":504,"gateway":"192.0.2.1","device":"eth1","source":"192.0.2.2"}
 w.install_resources([route],{})
 check(any("unreachable" in a for a,k in calls),"unavailable route cannot fall through to main WAN")
 check(any("from" in a and "192.0.2.2/32" in a for a,k in calls),"health probes are source-pinned")
 calls.clear()
 target={"af":6,"ips":["2606:4700::1"],"device":"eth1"}
 states=[{"id":"a","initialized":True,"active":target,"listen_port":51822,"paths":[{"af":6,"ips":["2606:4700::1"],"port":51820},{"af":4,"ips":["192.0.2.1"],"port":51820}]}]
 w.update_guard(states)
 batch="\n".join(k.get("stdin","") for a,k in calls)
 check('iifname != "eth1"' in batch,"wrong ingress uplink rejected")
 check('oifname != "eth1"' in batch,"wrong egress uplink rejected")
 check("ip daddr 192.0.2.1 udp dport 51820" in batch,"unselected endpoint family cannot roam")
 check("51821" not in batch,"separate management listener untouched")
 w.command=original


# Transactional cutover: failed inner validation must restore the previous route,
# endpoint and sticky guard, including same-family route-cache invalidation.
old={"id":"preferred6","af":6,"ips":["2606:4700::1"],"device":"eth1","port":51820,"table":48008}
target={"id":"fallback4","af":4,"ips":["192.0.2.9"],"device":"eth2","port":51820,"table":48010}
state={"id":"a","slot":1,"mark":"0x4a01","active":old,"selected":"preferred6","initialized":True}
originals={k:getattr(w,k) for k in ("command","update_guard","select_route","verify_inner")}
events=[]
def cmd(argv,**kw):
 events.append(("command",argv))
 r=type("Result",(),{"stdout":"","stderr":"","returncode":0})()
 return r
w.command=cmd
w.update_guard=lambda states,override=None:events.append(("guard",override[1]["id"] if override else None))
w.select_route=lambda p,t,mark,s:events.append(("route",t["id"]))
w.verify_inner=lambda p:False
try:w.apply_path(p,state,target,[state]);raise AssertionError("Failed verification was accepted")
except ValueError:pass
check([x for x in events if x[0]=="route"][-1][1]=="preferred6","failed switch restores original route")
check([x for x in events if x[0]=="guard"][-1][1]=="preferred6","failed switch restores original ingress/egress guard")
check(state["selected"]=="preferred6","failed switch does not commit selected state")
check(any(x[0]=="command" and x[1]==["ip","-4","route","flush","cache"] for x in events),"cutover invalidates cached outer route")
for k,v in originals.items():setattr(w,k,v)

# Fresh first tick already carries config_hash; it must still snapshot the
# existing endpoint and adopt its route, so later disable can restore it.
with tempfile.TemporaryDirectory() as tmp:
 w.RUN=Path(tmp)
 class R:
  returncode=0;stdout="";stderr=""
 def occupied(argv,**kw):
  r=R()
  if "rule" in argv:r.stdout="301: from all lookup 123"
  elif "route" in argv:r.stdout="192.0.2.9 dev eth1 src 192.0.2.2"
  return r
 original=w.command;w.command=occupied
 fresh=w.initialize_state(dict(p,id="new"),{"config_hash":"present"},
  {"endpoint":"192.0.2.9:51820","mark":"off"},
  [{"id":"preferred4","ips":["192.0.2.9"],"device":"eth1","port":51820}])
 check(fresh["original_endpoint"]=="192.0.2.9:51820","first tick snapshots original endpoint despite config hash")
 check(fresh["selected"]=="preferred4" and fresh["config_hash"]=="present","first tick adopts working route and preserves state")
 try:w.rule(4,301,["lookup",48008],True)
 except ValueError:check(True,"prior state cannot claim an uncached foreign routing rule")
 else:raise AssertionError("Foreign rule was overwritten")
 w.command=original

# Old saved policies inherit five probes; each peer/policy can override the count.
legacy={k:v for k,v in valid.items() if k not in ("fo_ping_count","rec_ping_count")}
check(w.validate(legacy,d)["fo_ping_count"]=="5" and w.cfg(legacy)["rec_ping_count"]=="5","existing policies inherit five pings")
check(w.validate(dict(valid,fo_ping_count=1,rec_ping_count="20"),d)["rec_ping_count"]=="20","independent ping count boundaries accepted")
for key in ("fo_ping_count","rec_ping_count"):
 for bad in ("0","21","2.5",2.5,True,"5;bad"):
  invalid(dict(valid,**{key:bad}),d,key+" rejects "+str(bad))
original_ping=w.ping
calls=[]
def fake_ping(src,host,af,count=5):
 calls.append((host,count))
 return {"ok":True,"sent":count,"received":count-1,"loss":100/count,"rtt":5}
w.ping=fake_ping
probe=dict(p,fo_tcp="0",rec_tcp="0")
candidate={"usable":True,"source":"192.0.2.2","af":4,"ips":["198.51.100.1"]}
try:
 result=w.check_path(candidate,probe)["checks"]
 check(calls==[("198.51.100.1",5)] and result["fo"]["ping"]["sent"]==5,"matching failover/recovery samples share five actual probes")
 check(result["fo"]["ping"]["loss"]==20,"one lost packet in five reports twenty percent")
 calls.clear()
 result=w.check_path(candidate,dict(probe,fo_ping_count="3",rec_ping_count="7"))["checks"]
 check(sorted(n for h,n in calls)==[3,7] and result["rec"]["ping"]["sent"]==7,"different failover/recovery counts run independent samples")
 calls.clear()
 result=w.check_path(candidate,dict(probe,fo_ping_targets=["198.51.100.1","198.51.100.2"],rec_ping_targets=["198.51.100.1","198.51.100.2"]))["checks"]
 check(result["fo"]["ping"]["sent"]==10 and result["fo"]["ping"]["received"]==8 and result["fo"]["ping"]["loss"]==20,"multiple targets aggregate actual sent and received counts")
 calls.clear()
 w.check_path(candidate,dict(probe,fo_ping_count="2",rec_ping_count="2"))
 check(calls==[("198.51.100.1",2)] and probe["fo_ping_count"]=="5","one peer's custom count does not change another policy")
finally:w.ping=original_ping

print("ALL",count,"CHECKS PASSED")
