#!/usr/bin/env python3
"""Install the standalone receiver service, without LuCI or uplink selection."""
import os,sys,shutil,subprocess
from pathlib import Path
base=Path(__file__).resolve().parent
if "--install" not in sys.argv:raise SystemExit("Use --install; optionally --activate (configuration still defaults to disabled).")
installed=[]
for src in (base/"root").rglob("*"):
 if not src.is_file() or "__pycache__" in src.parts:continue
 rel=src.relative_to(base/"root");target=Path("/")/rel
 if str(rel)=="etc/config/wg_sticky" and target.exists():
  installed.append(str(target));continue
 target.parent.mkdir(parents=True,exist_ok=True)
 tmp=target.with_name(target.name+".new");shutil.copyfile(src,tmp)
 tmp.chmod(0o755 if str(rel).startswith(("usr/sbin/","etc/init.d/","etc/hotplug.d/")) else 0o644)
 os.replace(tmp,target);installed.append(str(target))
preserve=Path("/etc/sysupgrade.conf");text=preserve.read_text() if preserve.exists() else ""
if text and not text.endswith("\n"):text+="\n"
for path in installed:
 if path not in text.splitlines():text+=path+"\n"
preserve.write_text(text)
if "--activate" in sys.argv:
 subprocess.run(["/etc/init.d/wg-sticky-receiver","enable"],check=True)
 subprocess.run(["/etc/init.d/wg-sticky-receiver","restart"],check=True)
print("Standalone WG receiver installed. Use wg-sticky-receiver enable to enable learning.")
