'use strict';
import { cursor } from 'uci';
let c=cursor(),interfaces=[],peers=[];
c.foreach('network','interface',s=>{
 push(interfaces,{name:s['.name'],proto:s.proto||'',gateway:s.gateway||'',ip6gw:s.ip6gw||''});
 if(s.proto=='wireguard')c.foreach('network','wireguard_'+s['.name'],p=>{
  if(p.public_key)push(peers,{interface:s['.name'],key:p.public_key,description:p.description||p['.name'],
   endpoint_host:p.endpoint_host||'',endpoint_port:+(p.endpoint_port||51820)});
 });
});
let s=c.get_all('wg_sticky','main')||{};
print(sprintf('%J',{interfaces,peers,settings:{
 receiver_enabled:s.enabled||'0',receiver_uplinks:s.uplinks||[],receiver_gateways:s.gateways||[],interval:+(s.interval||10)
}}));
