'use strict';
// A small DOM fixture exercises the LuCI view without a browser or router.
async function run(source,data) {
 class Node {
  constructor(tag,attrs,children) {
   this.tag=tag;this.attrs=attrs||{};this.children=[];this.style={};this.value=this.attrs.value||'';this.checked=false;
   if(tag==='textarea'&&typeof children==='string')this.value=children;
   this.appendChild(children);
  }
  appendChild(child) {
   if(child==null)return child;
   if(Array.isArray(child))child.forEach(x=>this.appendChild(x));else this.children.push(child);
   return child;
  }
  get firstChild(){return this.children[0];}
  removeChild(x){this.children.splice(this.children.indexOf(x),1);}
  addEventListener(name,fn){this.attrs[name]=fn;}
 }
 const E=(tag,attrs,children)=>new Node(tag,attrs,children);
 const walk=n=>n instanceof Node?[n].concat(n.children.flatMap(walk)):[];
 const text=n=>n instanceof Node?n.children.map(text).join(''):String(n||'');
 function assert(condition,message){if(!condition)throw Error(message);}
 let modal,request;
 const rpc={declare:spec=>(arg)=>{
  if(spec.method==='save'){request=JSON.parse(arg);return Promise.resolve({ok:true});}
  return Promise.resolve(data);
 }};
 const ui={showModal:(title,items)=>{modal=E('modal',{},items);},hideModal:()=>{},addNotification:()=>{}};
 const v=new Function('view','rpc','ui','poll','E','_',source)(
  {extend:x=>x},rpc,ui,{add:()=>{}},E,x=>x);
 const root=v.render(data);
 function button(tree,label){return walk(tree).find(x=>x.tag==='button'&&text(x)===label);}
 assert(button(root,'Receiver'),'Receiver tab missing');
 const config=walk(root).filter(x=>x.tag==='button'&&text(x)==='Configure');
 const eligible=data.interfaces.reduce((n,i)=>n+i.peers.filter(p=>p.eligible).length,0);
 assert(config.length===eligible,'Configure shown for an ineligible peer');
 assert(!/private_key|preshared_key/.test(JSON.stringify(data)),'Secret field in status');
 if(config.length) {
  config[0].attrs.click();
  const samples=walk(modal).filter(x=>x.tag==='div'&&x.attrs.class==='cbi-value'&&text(x.children[0])==='Pings per check')
   .map(x=>walk(x).find(n=>n.tag==='input'));
  assert(samples.length===2,'Ping sample fields missing from Failover/Recovery');
  const policy=data.interfaces.flatMap(i=>i.peers).find(p=>p.eligible).policy;
  assert(samples[0].value===String(policy.fo_ping_count||5)&&samples[1].value===String(policy.rec_ping_count||5),'Configured ping counts not rendered');
  samples[0].value='7';samples[1].value='9';
  button(modal,'Save & Apply').attrs.click();
  await new Promise(r=>setTimeout(r,0));
  assert(request&&request.interface&&request.peer_key,'Outbound policy save not serialized');
  assert(request.fo_ping_count==='7'&&request.rec_ping_count==='9','Separate ping counts not serialized');
 }
 if(data.receiver&&data.receiver.installed) {
  assert(button(root,'Configure receiver'),'Receiver configuration missing');
  const peers=data.receiver.interfaces.flatMap(i=>i.peers);
  assert(!peers.some(p=>p.pinned)||text(root).includes('Actively pinned'),'Active pin status missing');
  assert(!peers.some(p=>!p.inbound)||text(root).includes('Excluded: locally initiated'),'Outbound exclusion missing');
  button(root,'Configure receiver').attrs.click();
  button(modal,'Save & Apply').attrs.click();
  await new Promise(r=>setTimeout(r,0));
  assert(request.action==='receiver'&&Array.isArray(request.uplinks),'Receiver save not serialized');
 }
 return {interfaces:data.interfaces.length,configurable:config.length,receiver:!!(data.receiver&&data.receiver.installed)};
}
if(typeof module!=='undefined')module.exports=run;
if(typeof require!=='undefined'&&require.main===module) {
 const fs=require('fs');
 run(fs.readFileSync(process.argv[2],'utf8'),JSON.parse(fs.readFileSync(process.argv[3],'utf8')))
  .then(x=>console.log('PASS LuCI render and save',x)).catch(e=>{console.error(e);process.exitCode=1;});
}
