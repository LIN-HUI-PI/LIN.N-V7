/** NELUUN V9 Worker. No child AI endpoint. AI is OFF by default. */
const SESSION_SECONDS = 14 * 24 * 3600;
const CODE_SECONDS = 10 * 60;
const CONSENT_VERSION = 'guardian-declaration-v1-2026-10';
const json = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', ...headers },
});
const fail = (status, code, message) => json({ ok: false, error: code, message }, status);
const epoch = () => Math.floor(Date.now() / 1000);
const cleanEmail = x => String(x || '').trim().toLowerCase();
const validEmail = s => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,30}$/.test(s) && s.length <= 254;
const randomHex = n => Array.from(crypto.getRandomValues(new Uint8Array(n)), b=>b.toString(16).padStart(2,'0')).join('');
const digest = async s => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))),b=>b.toString(16).padStart(2,'0')).join('');
const hasDb = env => !!(env.DB && typeof env.DB.prepare === 'function');
const authReady = env => hasDb(env) && !!(env.RESEND_API_KEY && env.EMAIL_FROM && env.SESSION_PEPPER && env.OTP_PEPPER);
const aiReady = env => authReady(env) && env.AI_ENABLED === 'true' && !!env.OPENAI_API_KEY;
const cookieName = 'neluun_sid';
const cookieHeader = (token, maxAge) => `${cookieName}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
function getToken(req){const m=(req.headers.get('cookie')||'').match(/(?:^|;\s*)neluun_sid=([a-f0-9]{64})(?:;|$)/);return m?.[1]||null;}
async function session(req,env){const token=getToken(req);if(!token || !hasDb(env) || !env.SESSION_PEPPER)return null;
 const hash=await digest(env.SESSION_PEPPER+':'+token);
 return env.DB.prepare(`SELECT u.id,u.email,s.token_hash FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?`).bind(hash,epoch()).first();}
async function bodyJSON(req){const contentLength=Number(req.headers.get('content-length')||0);if(contentLength>4096)throw Error('too_large');const raw=await req.text();if(raw.length>4096)throw Error('too_large');try{return JSON.parse(raw);}catch{throw Error('bad_json');}}
function onlySameOrigin(req){const origin=req.headers.get('origin');return !!origin && origin===new URL(req.url).origin && req.headers.get('content-type')?.toLowerCase().startsWith('application/json');}
async function rate(env,key,limit,seconds){const now=epoch(),window=Math.floor(now/seconds),bucket=await digest(env.OTP_PEPPER+':'+key+':'+window);
 const result=await env.DB.prepare(`INSERT INTO rate_limits (bucket,hits,expires_at) VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET hits=hits+1 WHERE hits<? RETURNING hits`).bind(bucket,(window+1)*seconds,limit).first();return !!result;}
async function sendLoginEmail(env,email,code){const msg={from:env.EMAIL_FROM,to:[email],subject:'NELUUN 登入驗證碼',text:`你的 NELUUN 登入驗證碼：${code}\n10 分鐘內有效。若不是你本人操作，可忽略此郵件。\n請勿轉寄驗證碼。`};
 const res=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(msg)});
 if(!res.ok)throw new Error('Email delivery failed');}
async function requestCode(req,env){if(!authReady(env))return fail(503,'not_configured','登入服務尚未啟用。');
 const body=await bodyJSON(req),email=cleanEmail(body.email);if(!validEmail(email))return fail(400,'invalid_email','請輸入正確的電子郵件。');
 const ip=req.headers.get('cf-connecting-ip')||'unknown';
 if(!await rate(env,`otp-ip:${ip}`,12,3600)||!await rate(env,`otp-mail:${email}`,4,3600))return fail(429,'try_later','驗證碼要求次數較多，請稍後再試。');
 const digits=crypto.getRandomValues(new Uint32Array(1))[0];const code=String(digits%1000000).padStart(6,'0');
 const hash=await digest(`${env.OTP_PEPPER}:${email}:${code}`);const now=epoch();
 await env.DB.prepare(`INSERT INTO login_codes(email,code_hash,expires_at,attempts,issued_at) VALUES(?,?,?,0,?) ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,issued_at=excluded.issued_at`).bind(email,hash,now+CODE_SECONDS,now).run();
 try{await sendLoginEmail(env,email,code);}catch {await env.DB.prepare('DELETE FROM login_codes WHERE email=? AND code_hash=?').bind(email,hash).run();return fail(502,'email_unavailable','郵件暫時無法寄送，請稍後再試。');}
 return json({ok:true,message:'驗證碼已寄出，請查看信箱。'});
}
async function verifyCode(req,env){if(!authReady(env))return fail(503,'not_configured','登入服務尚未啟用。');
 const body=await bodyJSON(req),email=cleanEmail(body.email),code=String(body.code||'');
 if(!validEmail(email)||!/^[0-9]{6}$/.test(code))return fail(400,'invalid_code','電子郵件或驗證碼格式不正確。');
 const ip=req.headers.get('cf-connecting-ip')||'unknown';if(!await rate(env,`verify-ip:${ip}`,25,3600))return fail(429,'try_later','驗證次數較多，請稍後再試。');
 const hash=await digest(`${env.OTP_PEPPER}:${email}:${code}`);
 const match=await env.DB.prepare('DELETE FROM login_codes WHERE email=? AND code_hash=? AND expires_at>? AND attempts<5 RETURNING email').bind(email,hash,epoch()).first();
 if(!match){await env.DB.prepare('UPDATE login_codes SET attempts=attempts+1 WHERE email=? AND expires_at>? AND attempts<5').bind(email,epoch()).run();return fail(401,'invalid_code','驗證碼錯誤或已過期。');}
 const now=epoch(),newId=crypto.randomUUID();
 await env.DB.prepare('INSERT INTO users(id,email,created_at) VALUES(?,?,?) ON CONFLICT(email) DO NOTHING').bind(newId,email,now).run();
 const user=await env.DB.prepare('SELECT id,email FROM users WHERE email=?').bind(email).first();
 const token=randomHex(32),tokenHash=await digest(env.SESSION_PEPPER+':'+token);
 await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').bind(tokenHash,user.id,now+SESSION_SECONDS,now).run();
 return json({ok:true,email:user.email},200,{'set-cookie':cookieHeader(token,SESSION_SECONDS)});
}
async function currentUser(req,env){const u=await session(req,env);let consent=false;
 if(u){const rec=await env.DB.prepare('SELECT declared_at,withdrawn_at FROM guardian_declarations WHERE user_id=?').bind(u.id).first();consent=!!rec?.declared_at&&!rec.withdrawn_at;}
 return json({ok:true,authenticated:!!u,email:u?.email||null,authEnabled:authReady(env),aiEnabled:aiReady(env),guardianDeclaration:consent,
  childAIEnabled:false, dailyAiLimit:5});}
async function logout(req,env){const u=await session(req,env);if(u)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(u.token_hash).run();
 return json({ok:true},200,{'set-cookie':cookieHeader('',0)});}
async function setDeclaration(req,env,withdraw){const u=await session(req,env);if(!u)return fail(401,'sign_in','請先登入。');
 const now=epoch();if(withdraw){await env.DB.prepare('UPDATE guardian_declarations SET withdrawn_at=? WHERE user_id=?').bind(now,u.id).run();return json({ok:true,guardianDeclaration:false});}
 const body=await bodyJSON(req);if(body.agree!==true||body.confirmGuardian!==true)return fail(400,'explicit_consent_required','需要主動勾選聲明。');
 await env.DB.prepare(`INSERT INTO guardian_declarations(user_id,declared_at,withdrawn_at,policy_version) VALUES(?,?,NULL,?) ON CONFLICT(user_id) DO UPDATE SET declared_at=excluded.declared_at,withdrawn_at=NULL,policy_version=excluded.policy_version`).bind(u.id,now,CONSENT_VERSION).run();
 return json({ok:true,guardianDeclaration:true,notice:'這是自行聲明，不等於已驗證法定代理人身分。'});
}
async function aiChat(req,env){if(!aiReady(env))return fail(503,'ai_disabled','AI 尚未啟用；不會產生付費請求。');
 const u=await session(req,env);if(!u)return fail(401,'sign_in','請先登入個人助理。');
 const body=await bodyJSON(req);if(body.mode!=='personal')return fail(403,'child_ai_disabled','學習助理的 AI 連線尚未開放。');
 const prompt=String(body.message||'').trim();if(!prompt || prompt.length>800)return fail(400,'invalid_message','訊息不可空白或超過 800 字。');
 const day=new Date().toISOString().slice(0,10);const allowed=await env.DB.prepare(`INSERT INTO daily_ai_usage(user_id,day,used) VALUES(?,?,1) ON CONFLICT(user_id,day) DO UPDATE SET used=used+1 WHERE used<5 RETURNING used`).bind(u.id,day).first();
 if(!allowed)return fail(429,'quota_exceeded','今天已達 5 次個人助理 AI 上限。');
 let answer;try{
 const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),18000);
 let response;try{response=await fetch('https://api.openai.com/v1/responses',{method:'POST',headers:{Authorization:`Bearer ${env.OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({model:env.AI_MODEL||'gpt-4.1-mini',input:[{role:'system',content:'你是 NELUUN 個人助理。使用繁體中文，以清楚、尊重自主權、簡潔的語氣回答。不假裝知道未提供的個人資料。若被要求處理兒童私密資料，提醒避免分享。'},{role:'user',content:prompt}],max_output_tokens:350,store:false}),signal:controller.signal});}finally{clearTimeout(timeout);}
 if(!response.ok)return fail(502,'upstream_error','AI 服務暫時無法回應。此筆請求已占用當日額度。');
 const data=await response.json();answer=(data.output||[]).flatMap(x=>x.content||[]).filter(x=>x.type==='output_text').map(x=>x.text).join('\n').trim()||data.output_text;
 }catch{return fail(502,'upstream_error','AI 服務連線逾時或失敗。此筆請求已占用當日額度。');}
 return json({ok:true,answer:answer||'目前沒有取得可顯示的回覆。',quotaUsed:allowed.used,quotaLimit:5});
}
export default {
 async fetch(req,env){const url=new URL(req.url);if(!url.pathname.startsWith('/api/')){
  if(env.ASSETS)return env.ASSETS.fetch(req);return fail(404,'assets_missing','靜態資源尚未設定。');}
  if(req.method==='OPTIONS')return fail(405,'method_not_allowed','不接受跨站 API 請求。');
  if(url.pathname==='/api/me'&&req.method==='GET')return currentUser(req,env);
  if(req.method!=='POST')return fail(405,'method_not_allowed','不支援此方法。');
  if(!onlySameOrigin(req))return fail(403,'origin_required','安全檢查失敗。請從正式 HTTPS 網站操作。');
  try{
   if(url.pathname==='/api/auth/request')return await requestCode(req,env);
   if(url.pathname==='/api/auth/verify')return await verifyCode(req,env);
   if(url.pathname==='/api/auth/logout')return await logout(req,env);
   if(url.pathname==='/api/guardian/declare')return await setDeclaration(req,env,false);
   if(url.pathname==='/api/guardian/withdraw')return await setDeclaration(req,env,true);
   if(url.pathname==='/api/chat')return await aiChat(req,env);
   return fail(404,'unknown_endpoint','沒有這個 API。');
  }catch(err){if(err.message==='too_large'||err.message==='bad_json')return fail(400,'bad_request','請求內容格式不正確。');
   return fail(503,'service_unavailable','伺服器暫時無法完成要求。');}
 }
};
