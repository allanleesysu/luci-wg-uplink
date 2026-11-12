"""LAN role discovery and delegation to existing mwan3 policy chains."""
import ipaddress,json,shlex

def words(value):return value if isinstance(value,list) else str(value or '').split()
def context(role,d):
 rt={x['interface']:x for x in d.get('runtime',[])}
 dev=rt.get(role,{}).get('l3_device') or rt.get(role,{}).get('device')
 related={role}|{n for n,r in rt.items() if dev and (r.get('l3_device') or r.get('device'))==dev}
 zones=d.get('firewall',{}).get('zones',[])
 sources=[z for z in zones if related.intersection(words(z.get('network')))]
 interfaces={x['name']:x for x in d.get('interfaces',[])}
 for src in sources:
  # NAT on the selected network is evidence of egress, not a downstream LAN.
  if str(src.get('masq','0'))=='1' or str(src.get('masq6','0'))=='1':continue
  for f in d.get('firewall',{}).get('forwardings',[]):
   if str(f.get('enabled','1'))=='0' or f.get('src')!=src.get('name'):continue
   for dest in zones:
    if dest.get('name')!=f.get('dest') or not any(str(dest.get(k,'0'))=='1' for k in ('masq','masq6')):continue
    upstream=[n for n in words(dest.get('network')) if n not in related and interfaces.get(n,{}).get('proto') not in ('wireguard','none','')]
    if upstream:return {'mode':'edge','zone':src['name'],'device':dev,'nat_zone':dest['name']}
 return {'mode':'direct','device':dev}

def inherited_rules(lines,source,device):
 """Evaluate only the source/input selectors as this LAN; retain native targets."""
 out=[]
 for line in lines:
  args=shlex.split(line)
  if args[:2]!=['-A','mwan3_rules']:continue
  args=args[2:];result=[];include=True;i=0
  while i<len(args):
   inverse=args[i]=='!';j=i+1 if inverse else i
   if j<len(args) and args[j] in ('-s','--source','-i','--in-interface'):
    flag=args[j];k=j+1
    if k<len(args) and args[k]=='!':inverse=not inverse;k+=1
    if k>=len(args):raise ValueError('Invalid mwan3 source selector')
    value=args[k]
    try:match=ipaddress.ip_address(source) in ipaddress.ip_network(value,strict=False) if flag in ('-s','--source') else value==device or value.endswith('+') and device.startswith(value[:-1])
    except ValueError:raise ValueError('Unsupported mwan3 source selector')
    include=include and (not match if inverse else match);i=k+1
   else:
    result.append(args[i]);i+=1
  if include:out.append(result)
 return out

def sync(w,states,override=None):
 active=[]
 for s in states:
  target=override[1] if override and override[0]==s.get('id') else s.get('active')
  if target and target.get('routing')=='lan-policy' and (s.get('initialized') or override and override[0]==s.get('id')):
   active.append((s,target))
 cache=w.RUN/'lan-policy.json';old=w.readjson(cache)
 if not active and not old:return False
 try:current=w.command(['iptables','-t','mangle','-S'])
 except FileNotFoundError:
  if old:raise ValueError('Cannot remove owned LAN policy chains: iptables is missing')
  return False
 if current.returncode:
  if active:raise ValueError('Cannot read mwan3 policy chains')
  return False
 lines=current.stdout.splitlines();chains={shlex.split(x)[1] for x in lines if x.startswith('-N ')}
 owned={x for x in chains if x=='WGU_LAN4' or x.startswith('WGU_L_')}
 if owned and not old:raise ValueError('LAN policy chain names are already in use')
 # If mwan3 is absent, delegate to ordinary OpenWrt output routing.
 if active and 'mwan3_rules' not in chains:
  active=[]
 if not active and not owned and not old:return False
 wanted={'WGU_LAN4'} if active else set();rules=[]
 mask=hex(w.mwan3_mark_mask())
 for s,t in active:
  name='WGU_L_'+str(int(s['slot']));wanted.add(name)
  match=['-m','mark','--mark',w.selection_mark(s['mark']),'-p','udp','-d',t['ips'][0],'--dport',str(t['port']),'-j',name]
  rules.append(['-A','WGU_LAN4']+match)
  zero=['-m','mark','--mark','0/'+mask]
  rules.append(['-A',name]+zero+['-j','CONNMARK','--restore-mark','--nfmask',mask,'--ctmask',mask])
  for native in ('mwan3_custom_ipv4','mwan3_connected_ipv4','mwan3_dynamic_ipv4'):
   if native in chains:rules.append(['-A',name]+zero+['-j',native])
  for rule in inherited_rules(lines,t['source'],t['lan_device']):rules.append(['-A',name]+rule)
  rules.append(['-A',name,'-j','CONNMARK','--save-mark','--nfmask',mask,'--ctmask',mask])
 desired=[' '.join(shlex.quote(x) for x in r) for r in rules]
 observed=[x for x in lines if x.startswith('-A WGU_') or x=='-A OUTPUT -j WGU_LAN4']
 if old.get('desired')==desired and old.get('observed')==observed and wanted==owned:return False
 batch=['*mangle']+[':'+x+' - [0:0]' for x in sorted(wanted-owned)]
 batch+=['-F '+x for x in sorted(owned)]
 batch+=desired
 if active and '-A OUTPUT -j WGU_LAN4' not in lines:batch+=['-I OUTPUT 1 -j WGU_LAN4']
 if not active and '-A OUTPUT -j WGU_LAN4' in lines:batch+=['-D OUTPUT -j WGU_LAN4']
 batch+=['-X '+x for x in sorted(owned-wanted)]+['COMMIT']
 w.command(['iptables-restore','--noflush'],stdin='\n'.join(batch)+'\n',check=True)
 after=w.command(['iptables','-t','mangle','-S'],check=True).stdout.splitlines()
 observed=[x for x in after if x.startswith('-A WGU_') or x=='-A OUTPUT -j WGU_LAN4']
 if active:w.atomic(cache,{'desired':desired,'observed':observed})
 elif cache.exists():cache.unlink()
 return True
