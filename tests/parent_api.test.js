import test from 'node:test';
import assert from 'node:assert/strict';
import api from '../src/v95_parent_api.js';

const origin = 'https://neluun-test.example';
const sidA = 'a'.repeat(64), sidB = 'b'.repeat(64);
const now = () => Math.floor(Date.now()/1000);
const sha = async s => Array.from(new Uint8Array(await crypto.subtle.digest(
  'SHA-256', new TextEncoder().encode(s)
)), x => x.toString(16).padStart(2,'0')).join('');

class FakeD1 {
  constructor() { this.sessions=new Map();this.rate=new Map();this.challenges=new Map();
    this.grants=new Map();this.guardian=new Map(); }
  prepare(sql) {
    const db=this;
    return {bind(...args) {
      return {
        async first() {
          if(sql.includes('FROM sessions s JOIN users u ON u.id=s.user_id') ||
             sql.includes('FROM sessions s JOIN users u ON s.user_id=u.id')) {
            const [key,t]=args, r=db.sessions.get(key);
            return r && r.expires_at>t ? {id:r.id,email:r.email,
              expires_at:r.expires_at,token_hash:key}:null;
          }
          if(sql.startsWith('SELECT declared_at,withdrawn_at FROM guardian_declarations'))
            return db.guardian.get(args[0])||null;
          if(sql.startsWith('SELECT id,email FROM users')) return null;
          if(sql.startsWith('SELECT used FROM daily_ai_usage')) return {used:0};
          if(sql.includes('FROM subscription_entitlements')) return null;
          if(sql.startsWith('INSERT INTO rate_limits')) {
            const [key,expiry,limit]=args, n=db.rate.get(key)||0;
            if(n>=limit)return null;db.rate.set(key,n+1);return {hits:n+1};
          }
          if(sql.startsWith('INSERT INTO parent_challenges')) {
            const [key,codeHash,expiry,issued,cooldown]=args;
            const prev=db.challenges.get(key);
            if(prev && prev.sent_at>cooldown)return null;
            db.challenges.set(key,{codeHash,expiry,attempts:0,sent_at:issued});
            return {session_hash:key};
          }
          if(sql.startsWith('DELETE FROM parent_challenges')&&sql.includes('RETURNING')) {
            const [key,codeHash,t]=args,r=db.challenges.get(key);
            if(!r||r.codeHash!==codeHash||r.expiry<=t||r.attempts>=5)return null;
            db.challenges.delete(key);return {session_hash:key};
          }
          if(sql.startsWith('SELECT expires_at FROM parent_grants')) {
            const [key,t]=args,r=db.grants.get(key);
            return r && r.expires_at>t ? r : null;
          }
          throw Error('Unhandled D1 first: '+sql);
        },
        async run() {
          if(sql.startsWith('DELETE FROM parent_grants')) {
            db.grants.delete(args[0]);return {success:true};
          }
          if(sql.startsWith('DELETE FROM parent_challenges')) {
            const [key,codeHash]=args;
            if(args.length===1 || db.challenges.get(key)?.codeHash===codeHash)
              db.challenges.delete(key);
            return {success:true};
          }
          if(sql.startsWith('UPDATE parent_challenges')) {
            const [key,t]=args,r=db.challenges.get(key);
            if(r&&r.expiry>t&&r.attempts<5)r.attempts++;
            return {success:true};
          }
          if(sql.startsWith('INSERT INTO parent_grants')) {
            const [key,expiry,created]=args;
            db.grants.set(key,{expires_at:expiry,created_at:created});
            return {success:true};
          }
          if(sql.startsWith('DELETE FROM sessions')) {
            db.sessions.delete(args[0]);return {success:true};
          }
          if(sql.startsWith('INSERT INTO guardian_declarations')) {
            db.guardian.set(args[0],{declared_at:args[1],withdrawn_at:null});
            return {success:true};
          }
          if(sql.startsWith('UPDATE guardian_declarations')) {
            const entry=db.guardian.get(args[1]);if(entry)entry.withdrawn_at=args[0];
            return {success:true};
          }
          throw Error('Unhandled D1 run: '+sql);
        }
      };
    }};
  }
}
const envFor = db => ({DB:db, SESSION_PEPPER:'local-test-session-pepper',
  OTP_PEPPER:'local-test-otp-pepper',RESEND_API_KEY:'fake-resend-only',
  EMAIL_FROM:'NELUUN <noreply@example.org>',
  PARENT_STEP_UP_ENABLED:'true', AI_ENABLED:'false'});
async function setup() {
  const db=new FakeD1(),env=envFor(db);
  const hashA=await sha(env.SESSION_PEPPER+':'+sidA);
  const hashB=await sha(env.SESSION_PEPPER+':'+sidB);
  db.sessions.set(hashA,{id:'adult-a',email:'adult-a@example.org',expires_at:now()+3600});
  db.sessions.set(hashB,{id:'adult-b',email:'adult-b@example.org',expires_at:now()+3600});
  return {db,env,hashA,hashB};
}
function request(path,{method='GET',sid=sidA,body={},requestOrigin=origin,
   type='application/json'}={}) {
  return new Request(origin+path,{
    method,headers:{
      ...(sid?{Cookie:'neluun_sid='+sid}:{}),
      ...(method==='POST'?{Origin:requestOrigin,'Content-Type':type}:{})
    },
    ...(method==='POST'?{body:JSON.stringify(body)}:{})
  });
}
async function call(env,path,options={}) {
  const r=await api.fetch(request(path,options),env);
  return {status:r.status,body:await r.json(),headers:r.headers};
}
async function withEmail(fn) {
  const original=globalThis.fetch;let sent=null,requests=0;
  globalThis.fetch=async (url,opts)=>{
    assert.equal(url,'https://api.resend.com/emails');
    sent=JSON.parse(opts.body);requests++;
    return new Response(JSON.stringify({id:'fake'}),{status:200});
  };
  try {
    await fn({code:()=>sent?.text.match(/：([0-9]{6})/)[1],
      mail:()=>sent,count:()=>requests});
  } finally {globalThis.fetch=original;}
}

test('Guest cannot request unlock or open protected adult route',async()=>{
  const {env}=await setup();
  assert.equal((await call(env,'/api/parent/challenge',{method:'POST',sid:null})).status,401);
  assert.equal((await call(env,'/api/adult/private/status',{sid:null})).status,401);
});
test('Feature disabled by default: deny adult step-up',async()=>{
  const {env}=await setup();delete env.PARENT_STEP_UP_ENABLED;
  assert.equal((await call(env,'/api/parent/challenge',{method:'POST'})).status,503);
  assert.equal((await call(env,'/api/parent/status')).status,503);
  assert.equal((await call(env,'/api/chat',{method:'POST',body:{mode:'personal'}})).status,503);
});
test('CSRF defense rejects cross-origin and non-JSON POST requests',async()=>{
  const {env}=await setup();
  assert.equal((await call(env,'/api/parent/challenge',{method:'POST',requestOrigin:'https://attacker.example'})).status,403);
  assert.equal((await call(env,'/api/parent/challenge',{method:'POST',type:'text/plain'})).status,403);
});
test('Step-up required even when member already signed in',async()=>{
  const {env}=await setup();
  assert.equal((await call(env,'/api/parent/status')).body.adultAccess,false);
  assert.equal((await call(env,'/api/adult/private/status')).status,403);
  assert.equal((await call(env,'/api/chat',{method:'POST',body:{mode:'personal',message:'hi'}})).status,403);
  assert.equal((await call(env,'/api/guardian/declare',{method:'POST',body:{agree:true,confirmGuardian:true}})).status,403);
});
test('OTP binds to verified email and single session, and cannot be replayed',async()=>{
  await withEmail(async({code,mail,count})=>{
    const {env,db,hashA}=await setup();
    const c=await call(env,'/api/parent/challenge',{method:'POST',body:{email:'attacker@malicious.example'}});
    assert.equal(c.status,200);
    assert.deepEqual(mail().to,['adult-a@example.org']);
    assert.equal(count(),1);
    const v=await call(env,'/api/parent/verify',{method:'POST',body:{code:code()}});
    assert.equal(v.status,200);assert.equal(v.body.adultAccess,true);
    assert.ok(v.body.expiresIn<=600);
    assert.equal((await call(env,'/api/adult/private/status')).status,200);
    assert.equal((await call(env,'/api/adult/private/status',{sid:sidB})).status,403);
    assert.equal((await call(env,'/api/parent/verify',{method:'POST',body:{code:code()}})).status,401);
    assert.equal((await call(env,'/api/parent/challenge',{method:'POST'})).status,429);
    assert.ok(db.grants.has(hashA));
    assert.equal((await call(env,'/api/chat',{method:'POST',body:{mode:'personal',message:'hi'}})).status,503);
    assert.equal((await call(env,'/api/parent/lock',{method:'POST'})).status,200);
    assert.equal((await call(env,'/api/adult/private/status')).status,403);
    assert.equal((await call(env,'/api/parent/status')).body.adultAccess,false);
  });
});
test('Five wrong verification attempts invalidate even the correct code',async()=>{
  await withEmail(async({code})=>{
    const {env}=await setup();
    assert.equal((await call(env,'/api/parent/challenge',{method:'POST'})).status,200);
    const wrong=code()==='000000'?'999999':'000000';
    for(let i=0;i<5;i++)
      assert.equal((await call(env,'/api/parent/verify',{method:'POST',body:{code:wrong}})).status,401);
    assert.equal((await call(env,'/api/parent/verify',{method:'POST',body:{code:code()}})).status,401);
    assert.equal((await call(env,'/api/adult/private/status')).status,403);
  });
});
test('Expired grant does not refresh automatically',async()=>{
  await withEmail(async({code})=>{
    const {env,db,hashA}=await setup();
    await call(env,'/api/parent/challenge',{method:'POST'});
    await call(env,'/api/parent/verify',{method:'POST',body:{code:code()}});
    db.grants.get(hashA).expires_at=now()-1;
    assert.equal((await call(env,'/api/parent/status')).body.adultAccess,false);
    assert.equal((await call(env,'/api/adult/private/status')).status,403);
  });
});
test('Unsupported route and method denied',async()=>{
  const {env}=await setup();
  assert.equal((await call(env,'/api/parent/something')).status,404);
  assert.equal((await call(env,'/api/parent/challenge')).status,405);
  assert.equal((await call(env,'/api/adult/private/status',{method:'POST'})).status,405);
});
test('Logout clears grant and base session, including when step-up flag disabled',async()=>{
  await withEmail(async({code})=>{
    const {env,db,hashA}=await setup();
    await call(env,'/api/parent/challenge',{method:'POST'});
    await call(env,'/api/parent/verify',{method:'POST',body:{code:code()}});
    assert.equal((await call(env,'/api/auth/logout',{method:'POST'})).status,200);
    assert.equal(db.grants.has(hashA),false);
    assert.equal(db.sessions.has(hashA),false);
    assert.equal((await call(env,'/api/parent/status')).status,401);
  });
  const {env}=await setup();env.PARENT_STEP_UP_ENABLED='false';
  assert.equal((await call(env,'/api/auth/logout',{method:'POST'})).status,200);
});
