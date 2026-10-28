import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';

const origin = 'https://neluun.example';
const now = () => Math.floor(Date.now() / 1000);
const request = (path, method = 'GET', data, cookie = '', reqOrigin = origin) => new Request(origin + path, {
  method,
  headers: {
    ...(method === 'POST' ? { 'content-type': 'application/json', origin: reqOrigin } : {}),
    ...(cookie ? { cookie } : {}),
  },
  ...(method === 'POST' ? { body: JSON.stringify(data ?? {}) } : {}),
});
const ask = async (path, env, method='GET', data, cookie='', reqOrigin=origin) => {
  const resp = await worker.fetch(request(path,method,data,cookie,reqOrigin),env);
  return { response:resp, status:resp.status, data:await resp.json() };
};
class MemoryD1 {
  constructor() { this.users=new Map();this.codes=new Map();this.sessions=new Map();this.rate=new Map();this.guardian=new Map();this.entitlements=new Map();this.usage=new Map(); }
  prepare(sql) {
    const db=this;
    return { bind(...args) {
      return {
        async first(){
          if (sql.includes('INSERT INTO rate_limits')) {
            const [bucket, expires, limit]=args;const rec=db.rate.get(bucket)||{hits:0,expires};
            if(rec.hits>=limit)return null;
            rec.hits++;db.rate.set(bucket,rec);return {hits:rec.hits};
          }
          if(sql.includes('DELETE FROM login_codes')&&sql.includes('RETURNING')){
            const [email, hash, current, maxAttempts]=args;const c=db.codes.get(email);
            if(!c||c.hash!==hash||c.expires<=current||c.attempts>=maxAttempts)return null;
            db.codes.delete(email);return {email};
          }
          if(sql.startsWith('SELECT id,email FROM users'))return db.users.get(args[0])||null;
          if(sql.includes('FROM sessions s JOIN users')) {
            const [tokenHash,current]=args;const sess=db.sessions.get(tokenHash);
            if(!sess||sess.expires<=current)return null;
            const user=[...db.users.values()].find(u=>u.id===sess.userId);
            return user?{id:user.id,email:user.email,token_hash:tokenHash,expires_at:sess.expires}:null;
          }
          if(sql.includes('FROM guardian_declarations WHERE'))return db.guardian.get(args[0])||null;
          if(sql.includes('FROM subscription_entitlements WHERE'))return db.entitlements.get(args[0])||null;
          if(sql.includes('SELECT used FROM daily_ai_usage')) {
            const [userId,day]=args;return {used:db.usage.get(userId+day)||0};
          }
          if(sql.includes('INSERT INTO daily_ai_usage')) {
            const [userId,day,limit]=args;const key=userId+day, used=db.usage.get(key)||0;
            if(used>=limit)return null;db.usage.set(key,used+1);return {used:used+1};
          }
          throw Error('Unhandled FIRST SQL: '+sql);
        },
        async run(){
          if(sql.includes('INSERT INTO login_codes')){const [email,hash,expires,issued]=args;db.codes.set(email,{hash,expires,issued,attempts:0});return {success:true};}
          if(sql.startsWith('DELETE FROM login_codes WHERE email=')){const [email,hash]=args;if(db.codes.get(email)?.hash===hash)db.codes.delete(email);return {success:true};}
          if(sql.startsWith('UPDATE login_codes SET')){const [email,current,maxAttempts]=args;let v=db.codes.get(email);if(v&&v.expires>current&&v.attempts<maxAttempts)v.attempts++;return {success:true};}
          if(sql.includes('INSERT INTO users')){const [id,email,created]=args;if(!db.users.has(email))db.users.set(email,{id,email,created});return {success:true};}
          if(sql.includes('INSERT INTO sessions')){const [hash,userId,expires,created]=args;db.sessions.set(hash,{userId,expires,created});return {success:true};}
          if(sql.startsWith('DELETE FROM sessions')){db.sessions.delete(args[0]);return {success:true};}
          if(sql.includes('INSERT INTO guardian_declarations')){const [userId,declared]=args;db.guardian.set(userId,{declared_at:declared,withdrawn_at:null});return {success:true};}
          if(sql.startsWith('UPDATE guardian_declarations SET withdrawn_at')){const [withdrawn,userId]=args;const v=db.guardian.get(userId);if(v)v.withdrawn_at=withdrawn;return {success:true};}
          throw Error('Unhandled RUN SQL: '+sql);
        },
      };
    }};
  }
}
const envFor = db => ({ DB:db, RESEND_API_KEY:'test_resend_secret',EMAIL_FROM:'NELUUN <onboarding@resend.dev>',OTP_PEPPER:'test_only_otp_40_random_characters_1234',SESSION_PEPPER:'test_only_session_40_random_characters_4567',AI_ENABLED:'false' });
const cookieFrom = r => r.response.headers.get('set-cookie')?.split(';')[0]||'';

async function withFakeEmail(fn){
  const original=globalThis.fetch;let lastCode='';let calls=0;let lastAiPayload=null;
  globalThis.fetch=async (url, options) => {
    if(url==='https://api.resend.com/emails'){
      calls++;
      const body=JSON.parse(options.body);
      lastCode=body.text.match(/：([0-9]{6})/)[1];
      return new Response(JSON.stringify({id:'test_mail'}),{status:200});
    }
    if(url==='https://api.openai.com/v1/responses'){
      calls++;lastAiPayload=JSON.parse(options.body);
      return new Response(JSON.stringify({output:[{content:[{type:'output_text',text:'測試完成'}]}]}),{status:200});
    }
    throw Error('Unexpected fetch URL '+url);
  };
  try { await fn({code:()=>lastCode,calls:()=>calls,lastAi:()=>lastAiPayload}); } finally {globalThis.fetch=original;}
}
async function login(env,codeAccessor,rememberDevice=false,email='adult@example.com'){
  const codeRequest=await ask('/api/auth/request',env,'POST',{email});
  assert.equal(codeRequest.status,200);
  const res=await ask('/api/auth/verify',env,'POST',{email,code:codeAccessor(),rememberDevice});
  assert.equal(res.status,200);return res;
}

test('Guest /api/me is safe: no paid tier, no child AI and no billing',async()=>{
  const r=await ask('/api/me',{});
  assert.equal(r.status,200);assert.equal(r.data.plan,'guest');assert.equal(r.data.authenticated,false);
  assert.equal(r.data.aiEnabled,false);assert.equal(r.data.childAIEnabled,false);assert.equal(r.data.billingEnabled,false);
});
test('Cross-site POST is denied',async()=>{
  const r=await ask('/api/auth/request',{},'POST',{email:'adult@example.com'},'','https://untrusted.example');
  assert.equal(r.status,403);
});
test('Sign-in with unchecked keep-signed-in uses a session cookie, 24h DB expiry',async()=>{
  await withFakeEmail(async ({code})=>{
    const db=new MemoryD1(),env=envFor(db);
    const r=await login(env,code,false),header=r.response.headers.get('set-cookie');
    assert.equal(r.data.sessionMode,'session');assert.match(header,/HttpOnly; Secure; SameSite=Strict/);
    assert.ok(!header.includes('Max-Age='));
    const row=[...db.sessions.values()][0];assert.ok(row.expires-now()<=24*3600&&row.expires-now()>=24*3600-5);
    const me=await ask('/api/me',env,'GET',null,cookieFrom(r));
    assert.equal(me.data.authenticated,true);assert.equal(me.data.plan,'free');assert.equal(me.data.dailyAiLimit,0);
    const logout=await ask('/api/auth/logout',env,'POST',{},cookieFrom(r));
    assert.equal(logout.status,200);assert.match(logout.response.headers.get('set-cookie'),/Max-Age=0/);
    const after=await ask('/api/me',env,'GET',null,cookieFrom(r));assert.equal(after.data.authenticated,false);
  });
});
test('Opt-in 30-day persistent login is only enabled by explicit true',async()=>{
  await withFakeEmail(async ({code})=>{
    const db=new MemoryD1(),env=envFor(db);
    const r=await login(env,code,true);
    assert.equal(r.data.sessionMode,'remembered');assert.match(r.response.headers.get('set-cookie'),/Max-Age=2592000/);
    const row=[...db.sessions.values()][0];assert.ok(row.expires-now()<=2592000&&row.expires-now()>=2591995);
    assert.equal((await ask('/api/me',env,'GET',null,cookieFrom(r))).data.authenticated,true);
    row.expires=now()-1;
    assert.equal((await ask('/api/me',env,'GET',null,cookieFrom(r))).data.authenticated,false);
  });
});
test('Adult/guardian statement does not unlock child AI or verify guardianship identity',async()=>{
  await withFakeEmail(async ({code})=>{
    const db=new MemoryD1(),env=envFor(db),r=await login(env,code);
    const cookie=cookieFrom(r);
    const consent=await ask('/api/guardian/declare',env,'POST',{agree:true,confirmGuardian:true},cookie);
    assert.equal(consent.status,200);
    const me=await ask('/api/me',env,'GET',null,cookie);
    assert.equal(me.data.guardianDeclaration,true);assert.equal(me.data.guardianIdentityVerified,false);
    assert.equal(me.data.childAIEnabled,false);
    const child=await ask('/api/chat',env,'POST',{mode:'child',message:'你好'},cookie);
    assert.equal(child.status,403);assert.equal(child.data.error,'child_ai_disabled');
  });
});
test('User cannot self-upgrade through fake tier fields or billing endpoints',async()=>{
  await withFakeEmail(async ({code})=>{
    const db=new MemoryD1(),env=envFor(db);
    await ask('/api/auth/request',env,'POST',{email:'adult@example.com',plan:'paid',billingEnabled:true});
    const r=await ask('/api/auth/verify',env,'POST',{email:'adult@example.com',code:code(),plan:'paid'});
    const cookie=cookieFrom(r);
    assert.equal((await ask('/api/me',env,'GET',null,cookie)).data.plan,'free');
    const billing=await ask('/api/billing/subscribe',env,'POST',{plan:'paid'},cookie);
    assert.equal(billing.status,404);
  });
});
test('AI remains OFF even if an API key exists, until explicit quotas are configured',async()=>{
  await withFakeEmail(async ({code})=>{
    const db=new MemoryD1(),env={...envFor(db),AI_ENABLED:'true',OPENAI_API_KEY:'test_ai_key'},r=await login(env,code);
    const cookie=cookieFrom(r),me=await ask('/api/me',env,'GET',null,cookie);
    assert.equal(me.data.aiEnabled,false);assert.equal(me.data.dailyAiLimit,0);
    const chat=await ask('/api/chat',env,'POST',{mode:'personal',message:'你好'},cookie);
    assert.equal(chat.status,503);assert.equal(chat.data.error,'ai_disabled');
  });
});
test('Entitlements and AI quota are only granted by verified backend values',async()=>{
  await withFakeEmail(async ({code})=>{
    const db=new MemoryD1(),env={...envFor(db),AI_ENABLED:'true',OPENAI_API_KEY:'test_ai_key',FREE_AI_DAILY_LIMIT:'2',PAID_AI_DAILY_LIMIT:'20',GLOBAL_AI_DAILY_LIMIT:'10',GLOBAL_AI_MONTHLY_LIMIT:'30'};
    const r=await login(env,code),cookie=cookieFrom(r);
    const me1=await ask('/api/me',env,'GET',null,cookie);
    assert.equal(me1.data.plan,'free');assert.equal(me1.data.dailyAiLimit,2);assert.equal(me1.data.dailyAiUsed,0);assert.equal(me1.data.aiCostGuardReady,true);
    const ch1=await ask('/api/chat',env,'POST',{mode:'personal',message:'你好'},cookie);
    assert.equal(ch1.status,200);assert.equal(ch1.data.quotaLimit,2);assert.equal((await ask('/api/me',env,'GET',null,cookie)).data.dailyAiUsed,1);
    const ch2=await ask('/api/chat',env,'POST',{mode:'personal',message:'你好'},cookie);
    assert.equal(ch2.status,200);
    const ch3=await ask('/api/chat',env,'POST',{mode:'personal',message:'你好'},cookie);
    assert.equal(ch3.status,429);
    const user=db.users.get('adult@example.com');
    db.entitlements.set(user.id,{plan:'paid',status:'active',current_period_end:now()+6000});
    const me2=await ask('/api/me',env,'GET',null,cookie);
    assert.equal(me2.data.plan,'paid');assert.equal(me2.data.dailyAiLimit,20);
    db.entitlements.set(user.id,{plan:'paid',status:'canceled',current_period_end:now()+6000});
    assert.equal((await ask('/api/me',env,'GET',null,cookie)).data.plan,'free');
  });
});

test('Shared daily cap stops requests across accounts before upstream API call',async()=>{
  await withFakeEmail(async ({code,calls})=>{
    const db=new MemoryD1(),env={...envFor(db),AI_ENABLED:'true',OPENAI_API_KEY:'fake',
      FREE_AI_DAILY_LIMIT:'5',GLOBAL_AI_DAILY_LIMIT:'1',GLOBAL_AI_MONTHLY_LIMIT:'6'};
    const r=await login(env,code),cookie=cookieFrom(r);
    const r2=await login(env,code,false,'another-adult@example.com'),cookie2=cookieFrom(r2);
    const before=calls();
    assert.equal((await ask('/api/chat',env,'POST',{mode:'personal',message:'一'},cookie)).status,200);
    const second=await ask('/api/chat',env,'POST',{mode:'personal',message:'二'},cookie2);
    assert.equal(second.status,429);assert.equal(second.data.error,'platform_daily_cap');
    assert.equal(calls()-before,1);
    assert.equal((await ask('/api/me',env,'GET',null,cookie)).data.dailyAiUsed,1);
    assert.equal((await ask('/api/me',env,'GET',null,cookie2)).data.dailyAiUsed,1);
  });
});
test('Shared calendar-month cap independently blocks additional chargeable calls',async()=>{
  await withFakeEmail(async ({code,calls})=>{
    const db=new MemoryD1(),env={...envFor(db),AI_ENABLED:'true',OPENAI_API_KEY:'fake',
      FREE_AI_DAILY_LIMIT:'5',GLOBAL_AI_DAILY_LIMIT:'8',GLOBAL_AI_MONTHLY_LIMIT:'1'};
    const r=await login(env,code),cookie=cookieFrom(r),before=calls();
    assert.equal((await ask('/api/chat',env,'POST',{mode:'personal',message:'一'},cookie)).status,200);
    const second=await ask('/api/chat',env,'POST',{mode:'personal',message:'二'},cookie);
    assert.equal(second.status,429);assert.equal(second.data.error,'platform_monthly_cap');
    assert.equal(calls()-before,1);
  });
});
test('No global ceiling or unsupported AI model means no upstream calls at all',async()=>{
  await withFakeEmail(async ({code,calls})=>{
    const db=new MemoryD1(),env={...envFor(db),AI_ENABLED:'true',OPENAI_API_KEY:'fake',
      FREE_AI_DAILY_LIMIT:'5',GLOBAL_AI_DAILY_LIMIT:'8',GLOBAL_AI_MONTHLY_LIMIT:'20',AI_MODEL:'gpt-6-astra'};
    const r=await login(env,code),cookie=cookieFrom(r),before=calls();
    assert.equal((await ask('/api/me',env,'GET',null,cookie)).data.aiEnabled,false);
    const blocked=await ask('/api/chat',env,'POST',{mode:'personal',message:'文字'},cookie);
    assert.equal(blocked.status,503);assert.equal(blocked.data.error,'ai_disabled');
    assert.equal(calls(),before);
    delete env.AI_MODEL;
    delete env.GLOBAL_AI_MONTHLY_LIMIT;
    assert.equal((await ask('/api/me',env,'GET',null,cookie)).data.aiCostGuardReady,false);
    assert.equal((await ask('/api/chat',env,'POST',{mode:'personal',message:'文字'},cookie)).status,503);
    assert.equal(calls(),before);
  });
});
test('Disabled child AI and client-supplied payment fields cannot bypass budgets',async()=>{
  await withFakeEmail(async ({code,calls})=>{
    const db=new MemoryD1(),env={...envFor(db),AI_ENABLED:'true',OPENAI_API_KEY:'fake',
      FREE_AI_DAILY_LIMIT:'1',GLOBAL_AI_DAILY_LIMIT:'1',GLOBAL_AI_MONTHLY_LIMIT:'1'};
    const r=await login(env,code),cookie=cookieFrom(r),before=calls();
    const denied=await ask('/api/chat',env,'POST',{mode:'child',message:'你好',plan:'paid',paid:true},cookie);
    assert.equal(denied.status,403);assert.equal(denied.data.error,'child_ai_disabled');
    assert.equal(calls(),before);
    assert.equal((await ask('/api/me',env,'GET',null,cookie)).data.plan,'free');
  });
});

test('Upstream requests are limited to a fixed low-cost model, no tools, and capped output',async()=>{
  await withFakeEmail(async ({code,lastAi})=>{
    const db=new MemoryD1(),env={...envFor(db),AI_ENABLED:'true',OPENAI_API_KEY:'fake',
      FREE_AI_DAILY_LIMIT:'1',GLOBAL_AI_DAILY_LIMIT:'1',GLOBAL_AI_MONTHLY_LIMIT:'1'};
    const r=await login(env,code),cookie=cookieFrom(r);
    assert.equal((await ask('/api/chat',env,'POST',{mode:'personal',message:'整理今天'},cookie)).status,200);
    const data=lastAi();assert.equal(data.model,'gpt-6-luna');
    assert.equal(data.reasoning.effort,'none');assert.equal(data.max_output_tokens,320);
    assert.equal(data.store,false);assert.equal(data.tools,undefined);
    assert.equal(data.input[1].content,'整理今天');
  });
});
