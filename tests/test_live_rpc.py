import sys,json,time,socket,subprocess,importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location("w","/usr/libexec/wg-uplink.py")
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
def ubus(obj,method,data):
 r=w.command(["ubus","call",obj,method,json.dumps(data)],check=True);return json.loads(r.stdout) if r.stdout.strip() else {}
def http_rpc(sid,method,args):
 body=json.dumps({"jsonrpc":"2.0","id":1,"method":"call","params":[sid,"luci.wg_uplink",method,args]}).encode()
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
  s.settimeout(3);s.connect(("127.0.0.1",80))
  s.sendall(b"POST /ubus HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body)
  raw=b""
  while True:
   part=s.recv(65536)
   if not part:break
   raw+=part
 headers,body=raw.split(b"\r\n\r\n",1)
 if b"transfer-encoding: chunked" in headers.lower():
  decoded=b""
  while body:
   line,body=body.split(b"\r\n",1);size=int(line.split(b";")[0],16)
   if not size:break
   decoded+=body[:size];body=body[size+2:]
  body=decoded
 return json.loads(body)
def main():
 sid=ubus("session","create",{"timeout":120})["ubus_rpc_session"]
 try:
  ubus("session","grant",{"ubus_rpc_session":sid,"objects":[["luci.wg_uplink","status"]]})
  denied=http_rpc("0"*32,"status",{})
  print("AUTH_TEST_RESPONSE",json.dumps(denied))
  assert denied.get("error",{}).get("code")==-32002 or denied.get("result",[0])[0]!=0,"Unauthenticated access was not denied"
  print("PASS unauthenticated RPC denied")
  status=http_rpc(sid,"status",{})
  assert status["result"][0]==0 and status["result"][1]["ok"]
  print("PASS authenticated read-only RPC status")
  denied=http_rpc(sid,"save",{"data":"{}"})
  print("AUTH_TEST_RESPONSE",json.dumps(denied))
  assert denied.get("error",{}).get("code")==-32002 or denied.get("result",[0])[0]!=0
  print("PASS read-only session cannot save")
  ubus("session","grant",{"ubus_rpc_session":sid,"objects":[["luci.wg_uplink","save"]]})
  data=status["result"][1];peer=next(p for i in data["interfaces"] for p in i["peers"] if p["eligible"])
  payload={k:v for k,v in peer["policy"].items() if k in set(w.DEFAULTS)|{"id","interface","peer_key"}}
  before=w.command(["uci","export","wg_uplink"]).stdout
  invalid=dict(payload,endpoint4="host;invalid")
  reply=http_rpc(sid,"save",{"data":json.dumps(invalid)})["result"][1]
  assert reply["ok"] is False
  assert w.command(["uci","export","wg_uplink"]).stdout==before
  print("PASS invalid configuration rejected without modifying UCI")
  reply=http_rpc(sid,"save",{"data":json.dumps(payload)})["result"][1]
  assert reply["ok"],reply
  after=w.inventory()
  assert len(after["policies"])==1 and after["policies"][0]["slot"]=="1"
  print("PASS UI-shaped Save & Apply keeps one stable policy")
  state=w.readjson(w.RUN/"peers"/(peer["id"]+".json"))
  assert state.get("selected")=="preferred6" and state.get("initialized")
  print("PASS migration retained active preferred IPv6")
  rs=w.parallel([(x["id"],lambda x=x:w.dns(x["source"],"2606:4700:4700::1111" if x["af"]==6 else "1.1.1.1",x["af"],"example.com")) for x in state["paths"] if x["available"]])
  print("SOURCE_PINNED_DNS",json.dumps(rs))
  rs=w.parallel([(x["id"],lambda x=x:w.tcp(x["source"],"2606:4700:4700::1111" if x["af"]==6 else "1.1.1.1",x["af"],443,"connect")) for x in state["paths"] if x["available"]])
  print("GENERIC_TCP",json.dumps(rs))

  info=data.get("receiver",{})
  if info.get("installed"):
   before=w.command(["uci","export","wg_sticky"]).stdout
   bad=http_rpc(sid,"save",{"data":json.dumps({"action":"receiver","enabled":"1","uplinks":["not-an-interface"]})})["result"][1]
   assert not bad["ok"] and w.command(["uci","export","wg_sticky"]).stdout==before
   settings=dict(info["settings"],action="receiver")
   reply=http_rpc(sid,"save",{"data":json.dumps(settings)})["result"][1]
   assert reply["ok"],reply
   print("PASS Receiver tab RPC validation and same-settings Save & Apply")
 finally:ubus("session","destroy",{"ubus_rpc_session":sid})
if __name__=='__main__':main()
