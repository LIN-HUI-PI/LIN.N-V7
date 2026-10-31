import test from 'node:test';
import assert from 'node:assert/strict';
import {ParentStepUpClient} from '../public/v95_parent_client.js';
const reply=(body,status=200)=>({ok:status>=200&&status<300,status,
  json:async()=>body});
test('logged-in alone never unlocks adult area',async()=>{
 const client=new ParentStepUpClient({request:async()=>reply({ok:true,adultAccess:false,expiresIn:0})});
 assert.equal(await client.status(),false);assert.equal(client.unlocked,false);
});
test('OTP verified by server, then expiry status re-locks',async()=>{
 const calls=[];
 const client=new ParentStepUpClient({request:async(path,options)=>{
   calls.push({path,options});
   if(path.endsWith('/verify'))return reply({ok:true,adultAccess:true,expiresIn:600});
   return reply({ok:true,adultAccess:false,expiresIn:0});
 }});
 assert.equal(await client.verify('123456'),true);
 assert.equal(client.unlocked,true);
 assert.equal(await client.status(),false);
 assert.equal(calls[0].options.credentials,'same-origin');
 assert.equal(calls[0].options.cache,'no-store');
 assert.equal(calls[0].options.body,'{"code":"123456"}');
});
test('malformed code never sends a request',async()=>{
 let count=0;
 const c=new ParentStepUpClient({request:async()=>{count++;return reply({ok:true})}});
 await assert.rejects(()=>c.verify('12a456'),/六位數/);assert.equal(count,0);
});
test('network failures, bad JSON, and non-200 server responses fail closed',async()=>{
 const c=new ParentStepUpClient({request:async()=>reply({ok:true,adultAccess:true,expiresIn:600})});
 await c.verify('000123');assert.equal(c.unlocked,true);
 c.request=async()=>{throw Error('offline')};
 await assert.rejects(()=>c.status(),/保持鎖定/);assert.equal(c.unlocked,false);
 c.request=async()=>reply({ok:true,adultAccess:true,expiresIn:600});
 await c.verify('000123');
 c.request=async()=>reply({ok:false,error:'sign_in'},401);
 await assert.rejects(()=>c.status(),/登入/);assert.equal(c.unlocked,false);
 c.request=async()=>({ok:true,json:async()=>{throw Error('bad json')}});
 await assert.rejects(()=>c.status(),/回應異常/);assert.equal(c.unlocked,false);
});
test('lock hides immediately and posts to same-origin API',async()=>{
 let resolveNetwork;
 const c=new ParentStepUpClient({request:async(path,opts)=> {
   assert.equal(path,'/api/parent/lock');
   assert.equal(opts.credentials,'same-origin');
   return new Promise(resolve=>resolveNetwork=resolve);
 }});
 c.unlocked=true;
 const pending=c.lock();
 assert.equal(c.unlocked,false);
 resolveNetwork(reply({ok:true,adultAccess:false}));
 assert.equal(await pending,true);
});
test('revoke failure still locks UI and does not claim successful server revocation',async()=>{
 const c=new ParentStepUpClient({request:async()=>{throw Error('offline')}});
 c.unlocked=true;
 await assert.rejects(()=>c.lock(),/登出/);assert.equal(c.unlocked,false);
});
