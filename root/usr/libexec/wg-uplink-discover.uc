'use strict';
import { cursor } from 'uci';
let c=cursor(), interfaces=[], peers=[], policies=[];
c.foreach('network','interface',s=>{
 push(interfaces,{name:s['.name'],proto:s.proto||'',device:s.device||s.ifname||'',description:s.description||s.alias||'',gateway:s.gateway||'',ip6gw:s.ip6gw||''});
 if(s.proto=='wireguard') c.foreach('network','wireguard_'+s['.name'],p=>{
  push(peers,{interface:s['.name'],section:p['.name'],key:p.public_key||'',description:p.description||p['.name'],
   endpoint_host:p.endpoint_host||'',endpoint_port:+(p.endpoint_port||51820),disabled:p.disabled=='1',keepalive:+(p.persistent_keepalive||0)});
 });
});
c.foreach('wg_uplink','policy',s=>{push(policies,s);});
let settings=c.get_all('wg_uplink','main')||{};
print(sprintf('%J',{interfaces,peers,policies,settings}));
