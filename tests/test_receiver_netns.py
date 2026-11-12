"""Isolated two-uplink UDP/conntrack test. No production interfaces/routes changed."""
import subprocess,sys,os,time,importlib.util
from pathlib import Path
base=Path(__file__).resolve().parents[1]/"receiver/root/usr/libexec"
sp=importlib.util.spec_from_file_location("core",base/"wg-sticky-core.py")
core=importlib.util.module_from_spec(sp);sp.loader.exec_module(core)
rx="wgs_test_rx";client="wgs_test_client";created=[]
def run(args,stdin=None):
 p=subprocess.run(args,input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=8)
 if p.returncode:raise RuntimeError(" ".join(args[:4])+": "+p.stderr.strip())
 return p.stdout
def inside(ns,args,stdin=None):return run(["ip","netns","exec",ns]+args,stdin)
def main():
 global created
 names=run(["ip","netns","list"])
 assert rx not in names and client not in names,"Test namespace name in use"
 for dev in ("wgsrt0","wgsct0","wgsrt1","wgsct1"):
  assert subprocess.run(["ip","link","show",dev],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
 try:
  for ns in (rx,client):
   run(["ip","netns","add",ns]);created.append(ns)
   inside(ns,["ip","link","set","lo","up"])
   inside(ns,["sysctl","-q","-w","net.ipv4.conf.all.rp_filter=0","net.ipv4.conf.default.rp_filter=0"])
  for i,(ra,ca) in enumerate((("192.0.2.1","192.0.2.2"),("198.51.100.1","198.51.100.2"))):
   r="wgsrt"+str(i);c="wgsct"+str(i)
   run(["ip","link","add",r,"type","veth","peer","name",c])
   run(["ip","link","set",r,"netns",rx]);run(["ip","link","set",c,"netns",client])
   inside(rx,["ip","addr","add",ra+"/30","dev",r]);inside(client,["ip","addr","add",ca+"/30","dev",c])
   inside(rx,["ip","link","set",r,"up"]);inside(client,["ip","link","set",c,"up"])
  inside(client,["ip","addr","add","203.0.113.9/32","dev","lo"])
  inside(rx,["ip","route","add","default","via","192.0.2.2","dev","wgsrt0"])
  server="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(4);s.bind(('198.51.100.1',51820));d,a=s.recvfrom(64);s.sendto(d,a)"
  probe="import socket,struct;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(4);s.setsockopt(socket.IPPROTO_IP,8,1);s.bind(('203.0.113.9',45000));s.sendto(b'sticky',('198.51.100.1',51820));d,anc,f,a=s.recvmsg(64,128);idx=next(struct.unpack('I4s4s',v)[0] for l,t,v in anc if l==socket.IPPROTO_IP and t==8);print(socket.if_indextoname(idx))"
  def exchange():
   p=subprocess.Popen(["ip","netns","exec",rx,sys.executable,"-c",server],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   time.sleep(.2)
   try:return inside(client,[sys.executable,"-c",probe]).strip()
   finally:p.communicate(timeout=5)
  before=exchange()
  assert before=="wgsct0",before
  uplinks=[]
  for slot,(dev,src,gw) in enumerate((("wgsrt0","192.0.2.1","192.0.2.2"),("wgsrt1","198.51.100.1","198.51.100.2")),1):
   table=49000+slot*2
   inside(rx,["ip","route","add","table",str(table),"default","via",gw,"dev",dev])
   inside(rx,["ip","rule","add","pref",str(200+slot),"fwmark",hex(slot<<24)+"/"+hex(core.MASK),"lookup",str(table)])
   uplinks.append({"slot":slot,"paths":[{"available":True,"af":4,"device":dev}]})
  inside(rx,["nft","-f","-"],"\n".join(core.build_rules(uplinks,[51820],[]))+"\n")
  # A fresh receiver-originated flow must not advertise the wrong local WAN.
  initiating="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.51.100.1',51820));s.sendto(b'rogue',('203.0.113.9',46000))"
  listening="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1);s.bind(('203.0.113.9',46000));\ntry:s.recvfrom(64);print('unexpected')\nexcept TimeoutError:print('blocked')"
  listener=subprocess.Popen(["ip","netns","exec",client,sys.executable,"-c",listening],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  time.sleep(.2)
  inside(rx,[sys.executable,"-c",initiating])
  observed,errors=listener.communicate(timeout=3)
  assert observed.strip()=="blocked",(observed,errors)
  print("PASS passive receiver cannot originate a new flow from a different WAN source")
  after=exchange()
  assert after=="wgsct1",after
  print("PASS baseline reply uses preferred uplink, despite ingress on secondary")
  print("PASS receiver learning moves the existing UDP flow reply to its ingress uplink")
  print("PASS namespace test required no production routing or WG changes")
 finally:
  for ns in reversed(created):subprocess.run(["ip","netns","delete",ns],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if __name__=='__main__':main()
