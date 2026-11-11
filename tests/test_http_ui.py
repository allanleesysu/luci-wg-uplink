import socket,json,subprocess,os
def ubus(method,data):
 r=subprocess.run(["ubus","call","session",method,json.dumps(data)],stdout=subprocess.PIPE,check=True,text=True)
 return json.loads(r.stdout) if r.stdout.strip() else {}
def get(path,sid=""):
 with socket.socket() as s:
  s.settimeout(5);s.connect(("127.0.0.1",80))
  cookie=("Cookie: sysauth_http="+sid+"; sysauth="+sid+"\r\n") if sid else ""
  s.sendall(("GET "+path+" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"+cookie+"\r\n").encode())
  raw=b""
  while True:
   b=s.recv(65536)
   if not b:break
   raw+=b
 return raw
def main():
 sid=ubus("create",{"timeout":60})["ubus_rpc_session"]
 try:
  ubus("set",{"ubus_rpc_session":sid,"values":{"username":"root","token":os.urandom(16).hex()}})
  ubus("grant",{"ubus_rpc_session":sid,"scope":"access-group","objects":[["luci-base","read"],["luci-base","write"],["luci-wg-uplink","read"],["luci-wg-uplink","write"]]})
  ubus("grant",{"ubus_rpc_session":sid,"objects":[["luci.wg_uplink","status"],["luci.wg_uplink","save"],["luci","getFeatures"],["uci","get"],["session","access"]]})
  raw=get("/luci-static/resources/view/network/wg_uplink.js")
  assert raw.startswith(b"HTTP/1.1 200") and b"Manage this peer" in raw
  print("PASS deployed JavaScript served over HTTP")
  raw=get("/cgi-bin/luci/admin/network/wg_uplink",sid)
  print("PAGE_STATUS",raw.split(b"\r\n",1)[0].decode())
  assert raw.startswith(b"HTTP/1.1 200") and b'luci_password' not in raw
  assert b"wg_uplink" in raw
  print("PASS authenticated LuCI route loads WG Uplink view")
 finally:ubus("destroy",{"ubus_rpc_session":sid})
if __name__=='__main__':main()
