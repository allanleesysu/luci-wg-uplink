import importlib.util,sys
from pathlib import Path
base=Path(__file__).resolve().parents[1]/"receiver/root/usr/libexec"
spec=importlib.util.spec_from_file_location("core",base/"wg-sticky-core.py")
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
up=[{"slot":1,"paths":[{"available":True,"af":4,"device":"wan-a"},{"available":True,"af":6,"device":"wan-a"}]},
 {"slot":2,"paths":[{"available":True,"af":4,"device":"wan-b"}]}]
states=[{"initialized":True,"listen_port":51820,"paths":[{"ips":["2001:db8::1"],"port":51820}]}]
lines=core.build_rules(up,[51820,51821],states,[1,2,3]);text="\n".join(lines)
assert 'iifname "wan-a"' in text and 'iifname "wan-b"' in text
assert "type route hook output" in text
assert text.index("ip6 saddr 2001:db8::1")<text.index("iifname")
assert "ct direction" not in text  # Existing connections may start in either direction.
assert "ct mark & 0x3f000000 == 0" in text
assert "(meta mark & 0xc0ffffff) | 0x2000000" in text
assert "== 0x3000000" in text  # Retired-slot replies still fail closed.
assert all(" accept" not in x or "policy accept" in x for x in lines)
assert not any("dnat" in x or "snat" in x for x in lines)
assert not any("private" in x for x in lines)
print("PASS receiver port discovery, both address families and ingress marking")
print("PASS configured outbound peer exclusion precedes learning")
print("PASS existing UDP flows in either conntrack direction are supported")
print("PASS socket-mark low bits and retired-slot routing are preserved")
print("PASS receiver neither opens firewall ports nor changes NAT")

# Ownership regressions: a failed initial attempt cannot claim foreign rules or tables.
import tempfile
sp=importlib.util.spec_from_file_location("runner",base/"wg-sticky-receiver.py")
runner=importlib.util.module_from_spec(sp);sp.loader.exec_module(runner)
with tempfile.TemporaryDirectory() as tmp:
 runner.RUN=Path(tmp)
 calls=[]
 def occupied(argv,**kw):
  calls.append(argv)
  return type("R",(),{"returncode":0,"stdout":"201: from all lookup 123","stderr":""})()
 runner.command=occupied
 try:runner.rule(4,201,["lookup",49002],True)
 except ValueError:pass
 else:raise AssertionError("Foreign receiver rule overwritten after retry")
 assert not any("del" in a for a in calls)
 calls.clear()
 core.cleanup(runner,{"slots":[1]})
 assert not any("flush" in a for a in calls),"Unowned receiver table flushed"
 print("PASS failed attempts cannot claim foreign routing rules or cleanup foreign tables")
