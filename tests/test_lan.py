#!/usr/bin/env python3
"""LAN topology, policy reuse, cleanup and installation defaults regressions."""
import copy,importlib.util,sys,tempfile,json
from pathlib import Path
from types import SimpleNamespace
base=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('lan_test_backend',base/'root/usr/libexec/wg-uplink.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
l=w.lan_routes
count=0
def check(ok,label):
 global count
 assert ok,label
 count+=1;print('PASS',label)
d={'interfaces':[{'name':'lan','proto':'static'},{'name':'wan','proto':'dhcp'},{'name':'vpn','proto':'wireguard'}],
 'runtime':[{'interface':'lan','up':True,'l3_device':'br-lan','ipv4-address':[{'address':'10.0.0.1'}]},
 {'interface':'wan','up':True,'l3_device':'eth1','ipv4-address':[{'address':'192.0.2.2'}],'route':[{'target':'0.0.0.0','mask':0,'nexthop':'192.0.2.1'}]}],
 'firewall':{'zones':[{'name':'inside','network':['lan']},{'name':'outside','network':['wan'],'masq':'1'}],
 'forwardings':[{'src':'inside','dest':'outside'}]}}
check(l.context('lan',d)['mode']=='edge','Forwarding from LAN to masqueraded WAN identifies edge LAN')
check(l.context('wan',d)['mode']=='direct','Masqueraded upstream remains a direct uplink')
side=copy.deepcopy(d);side['firewall']['forwardings']=[]
check(l.context('lan',side)['mode']=='direct','Side router without NAT forwarding treats LAN as an uplink')
side['runtime'][0]['route']=[{'target':'0.0.0.0','mask':0,'nexthop':'10.0.0.254'}]
check(w.resource('lan',4,'',side)['gateway']=='10.0.0.254','Side LAN retains its conventional gateway')
vpn=copy.deepcopy(d);vpn['firewall']['zones'][1]['network']=['vpn']
check(l.context('lan',vpn)['mode']=='direct','WireGuard NAT alone does not imply a physical edge WAN')
alias=copy.deepcopy(d);alias['runtime'].append({'interface':'legacy','up':True,'l3_device':'br-lan'})
check(l.context('legacy',alias)['mode']=='edge','LAN aliases inherit topology from shared bridge')
r=w.resource('lan',4,'',d)
check(r['available'] and r['routing']=='lan-policy' and r['source']=='10.0.0.1','Edge IPv4 probes use LAN source and policy delegation')
w.command=lambda *args,**kwargs:SimpleNamespace(returncode=0,stdout='[{"dev":"eth1","prefsrc":"2606:4700::2"}]')
r6=w.resource('lan',6,'',d)
check(r6['available'] and r6['routing']=='router-default' and r6['source']=='2606:4700::2','Edge IPv6 follows normal Core route source')
w.command=lambda *args,**kwargs:SimpleNamespace(returncode=1,stdout='')
missing=w.resource('lan',6,'',d)
check(not missing['available'] and 'default IPv6 route' in missing['error'],'Missing Core IPv6 default stays unavailable; no arbitrary WAN is selected')
lines=['-A mwan3_rules -s 10.0.0.0/24 -m set --match-set CMCC dst -m mark --mark 0/0x3f00 -j mwan3_policy_A',
 '-A mwan3_rules -s 10.1.0.0/24 -j mwan3_policy_other',
 '-A mwan3_rules ! -s 10.0.0.0/24 -j mwan3_policy_other',
 '-A mwan3_rules -i br-lan -d 1.1.1.1/32 -j mwan3_policy_special',
 '-A mwan3_rules -i eth1 -j mwan3_policy_other',
 '-A mwan3_rules -m mark --mark 0/0x3f00 -j mwan3_policy_default']
rules=l.inherited_rules(lines,'10.0.0.1','br-lan')
check(len(rules)==3 and '-s' not in rules[0] and 'CMCC' in rules[0],'Only matching LAN source rules are inherited with destination IPset intact')
check('-i' not in rules[1] and rules[1][-1]=='mwan3_policy_special','Input-interface match is evaluated as selected LAN')
check(rules[-1][-1]=='mwan3_policy_default','Native default policy and order are retained')
# No static selector or probe rule may override a delegated candidate.
with tempfile.TemporaryDirectory() as tmp:
 w.RUN=Path(tmp);calls=[]
 payloads=[]
 def command(argv,**kw):
  calls.append(argv);payloads.append(kw);return SimpleNamespace(returncode=0,stdout='0x3f00')
 w.command=command
 w.install_resources([dict(r,table=48008,pref=504)],{})
 w.select_route({'slot':'1'},dict(r,ips=['1.1.1.1'],port=51820),'0x80000001',{})
 check(not any(x[0]=='ip' for x in calls),'Delegated candidates install no static RPDB/source routes')
 s={'id':'p_test','slot':1,'mark':'0x80000001','initialized':True,'listen_port':51820,
 'active':dict(r,ips=['1.1.1.1'],port=51820),'paths':[dict(r,ips=['1.1.1.1'],port=51820)]}
 w.audit.nft_fingerprint=lambda *a:'hash'
 w.update_guard([s])
 nft='\n'.join(x.get('stdin','') for x in payloads)
 check('iifname !=' not in nft and 'oifname !=' not in nft,'Delegated paths are not constrained to br-lan or one WAN by guards')
 check(l.sync(SimpleNamespace(RUN=w.RUN,readjson=w.readjson),[]) is False,'No configured LAN policies means no policy-chain calls')
# Simulate atomic native chain generation and removal; no host rules changed.
with tempfile.TemporaryDirectory() as tmp:
 holder={'lines':['-N mwan3_rules','-N mwan3_policy_A','-A OUTPUT -j mwan3_hook']+lines,'batch':''}
 def command(argv,**kw):
  if argv[0]=='iptables-restore':holder['batch']=kw['stdin']
  return SimpleNamespace(returncode=0,stdout='\n'.join(holder['lines']))
 fake=SimpleNamespace(RUN=Path(tmp),readjson=w.readjson,atomic=w.atomic,command=command,mwan3_mark_mask=lambda:0x3f00,selection_mark=lambda x:'0x80000001/0x800000ff')
 s['active']['lan_device']='br-lan'
 check(l.sync(fake,[s]),'Native policy chain synchronization succeeds')
 batch=holder['batch']
 check('mwan3_policy_A' in batch and '--match-set CMCC' in batch and '-I OUTPUT 1 -j WGU_LAN4' in batch,'Native policy targets and IPsets are reused from output hook')
 check('--save-mark --nfmask 0x3f00 --ctmask 0x3f00' in batch,'Only mwan3 mark bits are saved; socket identity stays separate')
 holder['lines']=['-N WGU_LAN4','-N WGU_L_1','-A OUTPUT -j WGU_LAN4']
 check(l.sync(fake,[]) and '-D OUTPUT -j WGU_LAN4' in holder['batch'] and '-X WGU_L_1' in holder['batch'],'Disabling last LAN policy removes its hooks and chains')
check('config policy' not in (base/'root/etc/config/wg_uplink').read_text(),'Clean installation contains no peer policies')
check("option enabled '0'" in (base/'receiver/root/etc/config/wg_sticky').read_text(),'Receiver is disabled on clean installation')
check(w.DEFAULTS['enabled']=='0','Discovered peers default to unmanaged')
print('ALL',count,'LAN CHECKS PASSED')
