import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here=dirname(fileURLToPath(import.meta.url));
const html=readFileSync(join(here,'../public/index.html'),'utf8');
const matched=html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(matched,'Front-end inline script must exist');
const js=matched[1];

function harness({authenticated=false,aiEnabled=false,remaining=0,chatFailure=null}={}){
 const events=new Map(), calls=[], storage=new Map();
 const app={innerHTML:'',addEventListener:(type,fn)=>events.set(type,fn)};
 const me={ok:true,authenticated,email:authenticated?'adult@example.com':null,authEnabled:true,
  aiEnabled,aiCostGuardReady:true,guardianDeclaration:false,plan:authenticated?'free':'guest',
  dailyAiLimit:aiEnabled?5:0,dailyAiUsed:aiEnabled?5-remaining:0,dailyAiRemaining:aiEnabled?remaining:0};
 const fetch=async (url,opts={})=>{
  calls.push({url,opts});
  if(url==='/api/me')return {ok:true,json:async()=>me};
  if(url==='/api/chat'){
   if(chatFailure)return {ok:false,json:async()=>({ok:false,error:chatFailure,
    message:'後端拒絕本次請求'})};
   return {ok:true,json:async()=>({ok:true,answer:'測試 AI 回覆',quotaUsed:1})};
  }
  throw Error('unexpected request '+url);
 };
 const sandbox={console,
  document:{getElementById:()=>app,body:{style:{}}},
  window:{addEventListener:()=>{},scrollTo:()=>{}},
  location:{protocol:'https:',hostname:'neluun.example'},
  localStorage:{getItem:(k)=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,String(v)),removeItem:(k)=>storage.delete(k)},
  fetch,FormData:class {},navigator:{},URL,Date,Math};
 vm.runInNewContext(js,sandbox,{timeout:3000});
 const click=(action,extra={})=>{
  const target={dataset:{action,...extra}};
  events.get('click')({target:{closest:()=>target}});
 };
 const change=(action,checked)=>events.get('change')({target:{dataset:{action},checked}});
 const settle=async()=>{for(let i=0;i<5;i++)await new Promise(resolve=>setImmediate(resolve));};
 const chatCalls=()=>calls.filter(c=>c.url==='/api/chat');
 return {app,calls,click,change,settle,chatCalls};
}

test('Guest stays in local demonstration; no request to /api/chat',async()=>{
 const h=harness();await h.settle();h.click('mode',{mode:'adult'});
 assert.match(h.app.innerHTML,/訪客 · 本機示範/);
 h.click('adultPrompt',{prompt:'幫我整理想法'});await h.settle();
 assert.equal(h.chatCalls().length,0);
 assert.match(h.app.innerHTML,/NELUUN · 本機規則示範/);
});

test('Signed-in adult with AI disabled stays in local mode, even after artificial checkbox event',async()=>{
 const h=harness({authenticated:true,aiEnabled:false});await h.settle();h.click('mode',{mode:'adult'});
 assert.match(h.app.innerHTML,/AI 尚未開放 · 本機示範/);
 h.change('adultAiConsent',true);
 h.click('adultPrompt',{prompt:'幫我規劃今天'});await h.settle();
 assert.equal(h.chatCalls().length,0);
 assert.match(h.app.innerHTML,/本機規則示範/);
});

test('Adult AI requires explicit session consent; revocation restores local-only mode',async()=>{
 const h=harness({authenticated:true,aiEnabled:true,remaining:5});await h.settle();h.click('mode',{mode:'adult'});
 assert.match(h.app.innerHTML,/需要先同意 · 本機示範/);
 h.click('adultPrompt',{prompt:'測試同意前'});await h.settle();
 assert.equal(h.chatCalls().length,0);
 h.change('adultAiConsent',true);
 assert.match(h.app.innerHTML,/成人 AI · 已同意傳送/);
 h.click('adultPrompt',{prompt:'測試同意後'});await h.settle();
 assert.equal(h.chatCalls().length,1);
 assert.match(h.app.innerHTML,/NELUUN · AI 回覆/);
 h.click('revokeAiConsent');
 h.click('adultPrompt',{prompt:'測試撤回後'});await h.settle();
 assert.equal(h.chatCalls().length,1);
 assert.match(h.app.innerHTML,/本機規則示範/);
});

test('No personal quota does not send to AI even after consent event',async()=>{
 const h=harness({authenticated:true,aiEnabled:true,remaining:0});await h.settle();h.click('mode',{mode:'adult'});
 assert.match(h.app.innerHTML,/今日額度不足 · 本機示範/);
 h.change('adultAiConsent',true);
 h.click('adultPrompt',{prompt:'不能扣款'});await h.settle();
 assert.equal(h.chatCalls().length,0);
});

test('Upstream quota rejection is shown as failure, never as a successful AI answer',async()=>{
 const h=harness({authenticated:true,aiEnabled:true,remaining:2,chatFailure:'platform_monthly_cap'});
 await h.settle();h.click('mode',{mode:'adult'});h.change('adultAiConsent',true);
 h.click('adultPrompt',{prompt:'月額度測試'});await h.settle();
 assert.equal(h.chatCalls().length,1);
 assert.match(h.app.innerHTML,/全站本月安全額度已用完/);
 assert.match(h.app.innerHTML,/NELUUN · 傳送失敗/);
});
