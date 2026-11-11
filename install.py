#!/usr/bin/env python3
"""Install WG Uplink; --with-receiver installs its independent receiver addon."""
import os,sys,shutil,subprocess
from pathlib import Path
base=Path(__file__).resolve().parent
if "--install" not in sys.argv:raise SystemExit("Use --install, optionally --activate and --with-receiver.")
installed=[]
for tree,dest in ((base/"root",Path("/")),(base/"htdocs",Path("/www"))):
 for src in tree.rglob("*"):
  if not src.is_file() or "__pycache__" in src.parts:continue
  rel=src.relative_to(tree);target=dest/rel
  if str(rel)=="etc/config/wg_uplink" and target.exists():
   installed.append(str(target));continue
  target.parent.mkdir(parents=True,exist_ok=True)
  tmp=target.with_name(target.name+".new");shutil.copyfile(src,tmp)
  tmp.chmod(0o755 if str(rel).startswith(("usr/sbin/","etc/init.d/","etc/hotplug.d/")) else 0o644)
  os.replace(tmp,target);installed.append(str(target))
preserve=Path("/etc/sysupgrade.conf");text=preserve.read_text() if preserve.exists() else ""
if text and not text.endswith("\n"):text+="\n"
installed.append("/etc/wg-uplink/")
for path in installed:
 if path not in text.splitlines():text+=path+"\n"
preserve.write_text(text)
if "--with-receiver" in sys.argv:
 args=[sys.executable,str(base/"receiver/install.py"),"--install"]
 if "--activate" in sys.argv:args.append("--activate")
 subprocess.run(args,check=True)
if "--activate" in sys.argv:
 for args in [["/etc/init.d/rpcd","restart"],["/etc/init.d/wg-uplink","enable"],["/etc/init.d/wg-uplink","restart"]]:subprocess.run(args,check=True)
print("WG Uplink installed; existing configuration preserved.")
