'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

var getStatus=rpc.declare({object:'luci.wg_uplink',method:'status',expect:{'':{}}});
var savePolicy=rpc.declare({object:'luci.wg_uplink',method:'save',params:['data'],expect:{'':{}}});
var checkNow=rpc.declare({object:'luci.wg_uplink',method:'check',expect:{'':{}}});
var fields=['enabled','label','preferred','preferred_family','fallback','fallback_family',
 'preferred_other','fallback_other','observe_seconds','recovery_seconds','fast_seconds',
 'preferred_gateway4','preferred_gateway6','fallback_gateway4','fallback_gateway6','endpoint4','endpoint6','verify_targets',
 'fo_ping','fo_ping_loss','fo_ping_targets','fo_tcp','fo_tcp_host','fo_tcp_port','fo_tcp_mode','fo_dns','fo_dns_name','fo_dns_servers','fo_combine',
 'rec_ping','rec_ping_loss','rec_ping_targets','rec_tcp','rec_tcp_host','rec_tcp_port','rec_tcp_mode','rec_dns','rec_dns_name','rec_dns_servers','rec_combine'];
var lists=['verify_targets','fo_ping_targets','rec_ping_targets','fo_dns_servers','rec_dns_servers'];
var flags=['enabled','preferred_other','fallback_other','fo_ping','fo_tcp','fo_dns','rec_ping','rec_tcp','rec_dns'];
function notify(e){ui.addNotification(null,E('p',{},e.message||String(e)));}
function success(result){if(!result.ok)throw new Error(result.error||_('Request failed'));return result;}
function lines(v){return (Array.isArray(v)?v.join('\n'):String(v||'')).trim().split(/\s+/).filter(Boolean);}
function value(v){return v==null?'—':String(v);}
function fmt(v,n){return v==null?'—':Number(v).toFixed(n||0);}
function row(label,control,help){
 return E('div',{'class':'cbi-value'},[
  E('label',{'class':'cbi-value-title'},label),
  E('div',{'class':'cbi-value-field'},[control,help?E('div',{'class':'cbi-value-description'},help):''])
 ]);
}
function input(v,type){return E('input',{'class':'cbi-input-text',type:type||'text',value:v==null?'':String(v)});}
function select(v,options){
 var node=E('select',{'class':'cbi-input-select'},options.map(function(x){return E('option',{value:x[0]},x[1]);}));
 node.value=String(v);return node;
}
function checkbox(v){var n=E('input',{type:'checkbox'});n.checked=String(v)==='1';return n;}
function textarea(v){return E('textarea',{'class':'cbi-input-textarea',rows:2,style:'width:100%'},Array.isArray(v)?v.join('\n'):String(v||''));}
function editPeer(peer,data,refresh){
 var p=Object.assign({},peer.policy),controls={},panels=[],buttons=[];
 var tabs=E('div',{'class':'cbi-tabmenu',style:'display:flex;gap:.5em;flex-wrap:wrap;margin-bottom:1em'});
 var body=E('div',{},[tabs]);
 function tab(label){
  var idx=panels.length, panel=E('div',{style:idx?'display:none':''});
  var b=E('button',{type:'button','class':'btn '+(idx?'':'cbi-button-positive'),click:function(){
   panels.forEach(function(x,i){x.style.display=i===idx?'':'none';buttons[i].className='btn '+(i===idx?'cbi-button-positive':'');});
  }},label);
  panels.push(panel);buttons.push(b);tabs.appendChild(b);body.appendChild(panel);return panel;
 }
 function add(panel,key,label,type,help,options){
  var n=type==='flag'?checkbox(p[key]):type==='list'?textarea(p[key]):type==='select'?select(p[key],options):input(p[key],type==='number'?'number':'text');
  controls[key]=n;panel.appendChild(row(label,n,help));return n;
 }
 var uplinks=data.uplinks.map(function(x){return [x.name,x.name+(x.description?' — '+x.description:'')+(x.device?' · '+x.device:'')+(x.up?'':' · '+_('down'))];});
 var general=tab(_('Connection'));
 general.appendChild(E('p',{},_('WG packets are pinned to the selected uplink in both directions. The remote peer is assumed to use one uplink or already maintain a sticky return path. A change is applied after the configured observation window.')));
 add(general,'enabled',_('Manage this peer'),'flag');
 add(general,'label',_('Name'),'text');
 add(general,'preferred',_('Preferred uplink'),'select',null,uplinks);
 add(general,'preferred_family',_('Preferred protocol'),'select',_('The endpoint must have an address in this family.'),[['6','IPv6'],['4','IPv4']]);
 add(general,'preferred_other',_('Allow the other IP family on this uplink'),'flag',_('Only when the preferred family fails the failover policy. Recovery returns to the preferred family automatically.'));
 add(general,'fallback',_('Fallback uplink'),'select',null,uplinks);
 add(general,'fallback_family',_('Fallback protocol'),'select',null,[['4','IPv4'],['6','IPv6']]);
 add(general,'fallback_other',_('Allow the other IP family on the fallback uplink'),'flag');
 function policyTab(pre,title){
  var pane=tab(title),fail=pre==='fo';
  pane.appendChild(E('p',{},fail?_('Default: fail only when all enabled checks fail. Partial ping loss alone keeps the current path.'):_('Recovery is monitored while the fallback works. Default: any successful check can qualify the preferred path.')));
  add(pane,pre+'_combine',_('Combine enabled checks'),'select',null,
   fail?[['all',_('All checks must fail')],['any',_('Any check may fail')]]:[['any',_('Any check may recover')],['all',_('All checks must recover')]]);
  add(pane,fail?'observe_seconds':'recovery_seconds',_('Observation window (seconds)'),'number',_('Default 300 seconds (5 minutes). A monitoring gap restarts the window.'));
  if(fail)add(pane,'fast_seconds',_('Fast-track window (seconds)'),'number',_('Default 10 seconds. Used for corroborated local Internet/uplink failure, not a hub-only failure.'));
  pane.appendChild(E('h4',{},_('Ping')));
  add(pane,pre+'_ping',_('Enable ping check'),'flag');
  add(pane,pre+'_ping_loss',fail?_('Fail at or above loss (%)'):_('Recover at or below loss (%)'),'number',
   fail?_('100 means complete loss; smaller values intentionally allow partial-loss failover.'):_('99.9 accepts intermittent loss, but still requires a reply.'));
  add(pane,pre+'_ping_targets',_('Ping targets'),'list',_('Optional IPs or hostnames, one per line. Blank uses the peer endpoint. Every check is sent through its candidate uplink.'));
  pane.appendChild(E('h4',{},_('TCP service')));
  add(pane,pre+'_tcp',_('Enable TCP check'),'flag');
  var mode=add(pane,pre+'_tcp_mode',_('Check type'),'select',null,[['connect',_('TCP connection accepted')],['iperf3',_('iperf3 protocol response')]]);
  add(pane,pre+'_tcp_host',_('TCP host'),'text',_('Blank uses the peer endpoint.'));
  var port=add(pane,pre+'_tcp_port',_('TCP port'),'number',_('The iperf3 check exchanges only its initial protocol message; it does not run a bandwidth test. A busy server still counts as reachable.'));
  mode.addEventListener('change',function(){if(mode.value==='iperf3'&&port.value==='443')port.value='5201';else if(mode.value==='connect'&&port.value==='5201')port.value='443';});
  pane.appendChild(E('h4',{},_('DNS')));
  add(pane,pre+'_dns',_('Enable DNS resolution check'),'flag');
  add(pane,pre+'_dns_name',_('Name to resolve'),'text');
  add(pane,pre+'_dns_servers',_('DNS servers'),'list',_('Blank uses Cloudflare and Google in the candidate IP family. Queries are source-pinned; TCP is tried if UDP does not answer.'));
 }
 policyTab('fo',_('Failover'));
 policyTab('rec',_('Recovery'));
 var advanced=tab(_('Advanced'));
 add(advanced,'endpoint4',_('IPv4 endpoint name'),'text',_('Optional alias when the peer uses separate IPv4 and IPv6 DNS names.'));
 add(advanced,'endpoint6',_('IPv6 endpoint name'),'text',_('Blank uses the endpoint configured in Network → Interfaces.'));
 ['preferred','fallback'].forEach(function(role){
  add(advanced,role+'_gateway4',(role==='preferred'?_('Preferred'):_('Fallback'))+' '+_('IPv4 gateway override'),'text',_('Only needed when this uplink has no gateway in its network configuration.'));
  add(advanced,role+'_gateway6',(role==='preferred'?_('Preferred'):_('Fallback'))+' '+_('IPv6 gateway override'),'text');
 });
 add(advanced,'verify_targets',_('Tunnel verification addresses'),'list',_('Optional IPs reachable through this WG interface. After a switch, at least one must reply or the old path is restored.'));
 var save=E('button',{type:'button','class':'btn cbi-button-positive',click:function(){
  var out={id:p.id,interface:peer.interface,peer_key:peer.key};
  fields.forEach(function(k){out[k]=flags.indexOf(k)>=0?(controls[k].checked?'1':'0'):lists.indexOf(k)>=0?lines(controls[k].value):controls[k].value.trim();});
  save.disabled=true;
  savePolicy(JSON.stringify(out)).then(success).then(function(){ui.hideModal();return refresh();}).catch(notify).finally(function(){save.disabled=false;});
 }},_('Save & Apply'));
 ui.showModal(_('WG Uplink')+' — '+peer.interface+' / '+peer.description,[
  E('p',{},peer.endpoint_host+':'+peer.endpoint_port),body,
  E('div',{'class':'right',style:'margin-top:1em'},[
   E('button',{type:'button','class':'btn',click:ui.hideModal},_('Cancel')),' ',save])
 ]);
}
function pathTable(state){
 var headers=[_('Candidate'),_('Device / source'),_('Ping loss'),_('RTT'),_('TCP'),_('DNS')];
 return E('table',{'class':'table'},[
  E('tr',{'class':'tr table-titles'},headers.map(function(x){return E('th',{'class':'th'},x);})),
 ].concat((state.paths||[]).map(function(p){
  var c=(p.checks||{}).fo||{},r=(p.checks||{}).rec||{},ping=c.ping||r.ping||{},tcp=c.tcp||r.tcp,dns=c.dns||r.dns;
  var selected=state.selected===p.id;
  return E('tr',{'class':'tr'},[
   E('td',{'class':'td'},(selected?'● ':'')+p.role+' · IPv'+p.af+(p.selectable===false?' · '+_('probe only'):'')),
   E('td',{'class':'td'},[E('span',{},p.device||'—'),E('br'),E('small',{},p.source||p.error||'—')]),
   E('td',{'class':'td'},ping.loss==null?'—':fmt(ping.loss,1)+'% ('+ping.received+'/'+ping.sent+')'),
   E('td',{'class':'td'},ping.rtt==null?'—':fmt(ping.rtt,1)+' ms'),
   E('td',{'class':'td'},tcp?(tcp.ok?_('Reachable'):_('No response')):'—'),
   E('td',{'class':'td'},dns?(dns.ok?_('Resolved'):_('No answer')):'—')
  ]);
 })));
}
function renderCards(data,refresh){
 return E('div',{},(data.interfaces||[]).map(function(wg){
  return E('div',{'class':'cbi-section'},[
   E('h3',{},wg.name),
   wg.runtime_only?E('p',{},_('Runtime interface without a saved network definition.')):'',
   !(wg.peers||[]).length?E('p',{},_('No saved peers.')):'',
   E('div',{},(wg.peers||[]).map(function(peer){
    var p=peer.policy||{},s=peer.status||{},a=s.active;
    var title=p.label||peer.description||peer.section;
    var selected=a?(a.role+' · IPv'+a.af+' · '+a.device):_('No active selection yet');
    var timer=s.timer?E('p',{},_('Observation')+': '+Math.floor(s.timer.elapsed)+' / '+s.timer.window+' s'):'';
    return E('div',{style:'border-top:1px solid #ddd;padding:1em 0'},[
     E('div',{style:'display:flex;justify-content:space-between;gap:1em;align-items:center'},[
      E('strong',{},title),
      peer.eligible?E('button',{'class':'btn cbi-button-action',click:function(){editPeer(peer,data,refresh);}},_('Configure')):E('span',{'class':'label'},peer.disabled?_('Peer disabled'):_('Inbound-only'))
     ]),
     E('p',{},peer.endpoint_host?peer.endpoint_host+':'+peer.endpoint_port:_('No configured endpoint. Existing incoming-path handling is retained.')),
     peer.eligible&&p.enabled==='1'?E('div',{},[
      E('p',{},[E('strong',{},_('Selected')+': '),selected]),
      s.error?E('p',{style:'color:#b00'},s.error):E('p',{},s.reason||_('Waiting for the controller')),
      s.live&&s.live.endpoint?E('p',{},_('Actual WG endpoint')+': '+s.live.endpoint):'',
      s.live?E('p',{},_('Last WG handshake')+': '+(s.live.handshake?new Date(s.live.handshake*1000).toLocaleString():_('None yet'))):'',
      timer,
      E('h4',{},_('Uplink checks (outside WG)')),
      s.checked_at?E('small',{},_('Last check')+': '+new Date(s.checked_at*1000).toLocaleString()):'',
      pathTable(s)
     ]):peer.eligible?E('p',{},_('Automatic uplink selection is disabled for this peer.')):''
    ]);
   }))
  ]);
 }));
}

function editReceiver(data,refresh){
 var info=data.receiver||{},settings=info.settings||{};
 var enabled=checkbox(settings.enabled||'0'),uplinks=textarea(settings.uplinks||[]),
  gateways=textarea(settings.gateways||[]),interval=input(settings.interval||10,'number');
 var save=E('button',{'class':'btn cbi-button-positive',click:function(){
  save.disabled=true;
  savePolicy(JSON.stringify({action:'receiver',enabled:enabled.checked?'1':'0',uplinks:lines(uplinks.value),gateways:lines(gateways.value),interval:interval.value}))
   .then(success).then(function(){ui.hideModal();return refresh();}).catch(notify).finally(function(){save.disabled=false;});
 }},_('Save & Apply'));
 ui.showModal(_('Receiver sticky replies'),[
  E('p',{},_('Independent receiver service. It learns the uplink of incoming WG traffic and pins replies to it. It does not select preferred uplinks for outbound peers.')),
  row(_('Enable receiver learning'),enabled),
  row(_('Upstream interfaces'),uplinks,_('Blank auto-detects upstream interfaces with a native address and gateway. Available: ')+(data.uplinks||[]).map(function(x){return x.name;}).join(', ')),
  row(_('Gateway overrides'),gateways,_('Optional interface=IP entries, one per line, for static uplinks without a default gateway.')),
  row(_('Discovery refresh (seconds)'),interval,_('Learning happens in the kernel per packet; this interval refreshes interfaces and WG listen ports.')),
  E('div',{'class':'right'},[E('button',{'class':'btn',click:ui.hideModal},_('Cancel')),' ',save])
 ]);
}
function renderReceiver(data,refresh){
 var info=data.receiver||{};
 if(!info.installed)return E('div',{'class':'cbi-section'},[
  E('h3',{},_('Receiver sticky replies')),
  E('p',{},_('Optional standalone receiver service is not installed. It can run without LuCI or this uplink-selection app.'))
 ]);
 var runtime=info.runtime||{},active=!!runtime.active;
 return E('div',{'class':'cbi-section'},[
  E('h3',{},_('Receiver sticky replies')),
  E('p',{},_('For incoming WG connections only. Outbound selection can remain disabled on this router.')),
  E('button',{'class':'btn',click:function(){editReceiver(data,refresh);}},_('Configure receiver')),
  E('p',{},active?_('Receiver enabled'):_('Receiver inactive')),
  runtime.error||info.error?E('p',{style:'color:#b00'},runtime.error||info.error):'',
  E('p',{},_('Discovered uplinks')+': '+(runtime.uplinks||[]).map(function(x){return x.interface+' / '+x.device;}).join(', ')),
  E('div',{},(info.interfaces||[]).map(function(wg){
   return E('div',{},[
    E('h4',{},wg.interface+' · UDP '+wg.listen_port),
    E('table',{'class':'table'},[
     E('tr',{'class':'tr table-titles'},[_('Peer'),_('Learned endpoint'),_('Return uplink'),_('Pin status')].map(function(x){return E('th',{'class':'th'},x);}))
    ].concat((wg.peers||[]).map(function(p){
     var state=!p.inbound?_('Excluded: locally initiated'):p.pinned?_('Actively pinned'):p.pin_enabled?_('Enabled; waiting for inbound traffic'):_('Disabled');
     return E('tr',{'class':'tr'},[
      E('td',{'class':'td'},p.description),
      E('td',{'class':'td'},p.endpoint||'—'),
      E('td',{'class':'td'},p.pinned?p.uplink+' / '+p.device+' · IPv'+p.family:'—'),
      E('td',{'class':'td'},state)
     ]);
    })))
   ]);
  }))
 ]);
}

return view.extend({
 load:function(){return getStatus();},
 render:function(data){
  success(data);
  var cards=E('div'),receiver=E('div',{style:'display:none'}),self=this,latest=data;
  function display(d){latest=d;while(cards.firstChild)cards.removeChild(cards.firstChild);cards.appendChild(renderCards(d,refresh));while(receiver.firstChild)receiver.removeChild(receiver.firstChild);receiver.appendChild(renderReceiver(d,refresh));}
  function refresh(){return getStatus().then(success).then(display);}
  display(data);
  poll.add(function(){return refresh().catch(function(e){console.warn('WG Uplink status:',e);});},5);
  var interval=input(data.settings.interval,'number');
  var controls=E('div',{'class':'cbi-section'},[
   E('h3',{},_('Monitoring')),
   row(_('Probe interval (seconds)'),interval,_('5–60 seconds. A fast-track decision cannot happen sooner than a completed observation.')),
   E('button',{'class':'btn',click:function(){return savePolicy(JSON.stringify({action:'settings',interval:interval.value})).then(success).then(refresh).catch(notify);}},_('Save interval')),
   ' ',
   E('button',{'class':'btn',click:function(){return checkNow().then(success).then(function(){ui.addNotification(null,E('p',{},_('A check was queued. Live results update automatically.')));});}},_('Check now'))
  ]);
  var outbound=E('div',{},[cards,controls]);
  var tabs=E('div',{'class':'cbi-tabmenu',style:'display:flex;gap:.5em;margin-bottom:1em'},[
   E('button',{'class':'btn',click:function(){outbound.style.display='';receiver.style.display='none';}},_('Uplink selection')),
   E('button',{'class':'btn',click:function(){outbound.style.display='none';receiver.style.display='';}},_('Receiver'))
  ]);
  return E('div',{},[
   E('h2',{},_('WG Uplink')),
   E('p',{},_('Choose preferred and fallback uplinks for outbound WireGuard peers. Sticky routing is enforced in both directions. Peers without a configured endpoint are listed for reference and are not changed.')),
   tabs,outbound,receiver
  ]);
 },
 handleSaveApply:null,
 handleSave:null,
 handleReset:null
});
