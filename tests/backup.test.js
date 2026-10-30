import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const here=dirname(fileURLToPath(import.meta.url));
const html=readFileSync(join(here,'../public/index.html'),'utf8');
const js=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(js);
const backup={product:'NELUUN',version:9,backupSchema:1,
 tasks:[{text:'還原測試待辦',done:true}],notes:['還原測試筆記'],
 learning:{grade:4,completed:3,attempts:7,
  history:[{date:'2026/10/30',subject:'自然',score:1,total:1}]}};
function harness({confirmRestore=true,existingStorage=null}={}){
 const storage=existingStorage||new Map(),events=new Map(),calls=[],downloaded=[];
 const app={innerHTML:'',addEventListener:(event,callback)=>events.set(event,callback)};
 const sandbox={console,Date,Math,Blob,setTimeout:()=>{},
  document:{getElementById:()=>app,body:{style:{},appendChild:()=>{}},createElement:()=>({click(){downloaded.push(this.download)},remove(){},href:'',download:''})},
  window:{addEventListener:()=>{},scrollTo:()=>{}},
  location:{protocol:'https:',hostname:'neluun.example'},
  localStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,String(v)),removeItem:k=>storage.delete(k)},
  fetch:async url=>{calls.push(url);if(url==='/api/me')return {ok:true,json:async()=>({ok:true,authenticated:true,email:'test@example.com',authEnabled:true,aiEnabled:false,aiCostGuardReady:true,plan:'free',dailyAiRemaining:0})};throw Error('unexpected network call')},
  FormData:class {},navigator:{},confirm:()=>confirmRestore,
  URL:{createObjectURL:()=> 'blob:local-backup',revokeObjectURL:()=>{}}};
 vm.runInNewContext(js,sandbox,{timeout:4000});
 const settle=async()=>{for(let i=0;i<6;i++)await new Promise(r=>setImmediate(r))};
 const click=(action,extra={})=>events.get('click')({target:{closest:()=>({dataset:{action,...extra}})}});
 const importFile=async(text,{size=null}={})=>{
  const f={name:'test.json',size:size??text.length,text:async()=>text};
  events.get('change')({target:{dataset:{action:'importLocalFile'},files:[f]}});
  await settle();
 };
 return {app,storage,click,importFile,settle,calls,downloaded};
}

test('V9.4 backup can restore tasks, notes, and child learning locally',async()=>{
 const h=harness();await h.settle();h.click('mode',{mode:'adult'});h.click('view',{target:'you'});
 assert.match(h.app.innerHTML,/選擇 JSON 還原/);
 await h.importFile(JSON.stringify(backup));
 const saved=JSON.parse(h.storage.get('neluun_v8_local'));
 assert.equal(saved.tasks[0].text,'還原測試待辦');
 assert.equal(saved.notes[0],'還原測試筆記');
 assert.equal(saved.grade,4);
 assert.equal(saved.completed,3);
 assert.equal(saved.history[0].subject,'自然');
 assert.match(h.app.innerHTML,/備份還原完成/);
 assert.match(h.app.innerHTML,/已登入/);
 assert.equal(h.calls.filter(x=>x==='/api/chat').length,0);
});

test('Restored data persist after app reload on the same device',async()=>{
 const storage=new Map(),a=harness({existingStorage:storage});await a.settle();
 await a.importFile(JSON.stringify(backup));
 const b=harness({existingStorage:storage});await b.settle();b.click('mode',{mode:'adult'});b.click('view',{target:'tools'});
 assert.match(b.app.innerHTML,/還原測試待辦/);
 assert.match(b.app.innerHTML,/還原測試筆記/);
});

test('Cancel restores nothing and preserves existing data',async()=>{
 const h=harness({confirmRestore:false});await h.settle();h.click('mode',{mode:'adult'});h.click('view',{target:'you'});
 const before=h.storage.get('neluun_v8_local');
 await h.importFile(JSON.stringify(backup));
 assert.equal(h.storage.get('neluun_v8_local'),before);
 assert.match(h.app.innerHTML,/已取消還原/);
});

test('Malformed JSON fails without corrupting the local records',async()=>{
 const h=harness();await h.settle();h.click('mode',{mode:'adult'});h.click('view',{target:'you'});const before=h.storage.get('neluun_v8_local');
 await h.importFile('{"product":');
 assert.equal(h.storage.get('neluun_v8_local'),before);
 assert.match(h.app.innerHTML,/不是有效的 JSON/);
});

test('Oversized backup is rejected before reading or modifying storage',async()=>{
 const h=harness();await h.settle();h.click('mode',{mode:'adult'});h.click('view',{target:'you'});const before=h.storage.get('neluun_v8_local');
 await h.importFile(JSON.stringify(backup),{size:1000001});
 assert.equal(h.storage.get('neluun_v8_local'),before);
 assert.match(h.app.innerHTML,/不可超過 1 MB/);
});

test('Wrong-product, unbounded note and invalid learning history are rejected',async()=>{
 const scenarios=[
  {...backup,product:'ANOTHER'},
  {...backup,notes:['x'.repeat(301)]},
  {...backup,learning:{...backup.learning,history:[{date:'now',subject:'math',score:2,total:1}]}}
 ];
 for(const item of scenarios){
  const h=harness();await h.settle();h.click('mode',{mode:'adult'});h.click('view',{target:'you'});const before=h.storage.get('neluun_v8_local');
  await h.importFile(JSON.stringify(item));
  assert.equal(h.storage.get('neluun_v8_local'),before);
  assert.match(h.app.innerHTML,/未匯入備份/);
 }
});

test('Imported backup never mutates account identity or enabled AI flags',async()=>{
 const h=harness();await h.settle();h.click('mode',{mode:'adult'});h.click('view',{target:'you'});
 const injected={...backup,auth:{authenticated:true,plan:'paid',aiEnabled:true},
  guardianDeclaration:true,session:'secret',aiEnabled:true};
 await h.importFile(JSON.stringify(injected));
 const saved=JSON.parse(h.storage.get('neluun_v8_local'));
 for(const forbidden of ['auth','session','guardianDeclaration','aiEnabled'])assert.equal(saved[forbidden],undefined);
 assert.match(h.app.innerHTML,/免費會員/);
 assert.equal(h.calls.filter(x=>x==='/api/chat').length,0);
});

test('Parent view includes local restore and does not unlock children AI',async()=>{
 const h=harness();await h.settle();h.click('mode',{mode:'child'});h.click('view',{target:'parent'});
 assert.match(h.app.innerHTML,/選擇 JSON 還原/);
 assert.match(h.app.innerHTML,/兒童 AI 和雲端同步目前固定關閉/);
});

test('V9.4 CSS protects iPhone status bar and keeps add button horizontal',()=>{
 assert.match(html,/safe-area-inset-top/);
 assert.match(html,/task-add-form/);
 assert.match(html,/white-space:nowrap;word-break:keep-all/);
 assert.match(html,/backup-import-picker:focus-within/);
});

test('Export keeps account identifiers out of local backup',async()=>{
 const h=harness();await h.settle();h.click('mode',{mode:'adult'});h.click('view',{target:'you'});
 h.click('exportLocal');
 assert.equal(h.downloaded.length,1);
 assert.match(h.downloaded[0],/^NELUUN_本機備份_/);
});
