/**
 * NELUUN V9 — shared adult/guardian sign-in, free local learning, and fail-closed entitlements.
 * No public billing endpoint. No child AI endpoint. AI disabled unless expressly configured.
 */
const SESSION_SHORT_SECONDS = 24 * 3600;
const SESSION_REMEMBER_SECONDS = 30 * 24 * 3600;
const CODE_SECONDS = 10 * 60;
const CONSENT_VERSION = 'guardian-declaration-v1-2026-10';
const COOKIE_NAME = 'neluun_sid';

const json = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), {
  status, headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    ...headers,
  },
});
const fail = (status, code, message) => json({ ok: false, error: code, message }, status);
const epoch = () => Math.floor(Date.now() / 1000);
const cleanEmail = value => String(value || '').trim().toLowerCase();
const validEmail = value => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,30}$/.test(value) && value.length <= 254;
const randomHex = n => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => b.toString(16).padStart(2, '0')).join('');
const digest = async value => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))), b => b.toString(16).padStart(2, '0')).join('');
const hasDb = env => !!(env.DB && typeof env.DB.prepare === 'function');
const authReady = env => hasDb(env) && !!(env.RESEND_API_KEY && env.EMAIL_FROM && env.SESSION_PEPPER && env.OTP_PEPPER);
const clampLimit = (value, maximum) => {
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 ? Math.min(n, maximum) : 0;
};
// By default, even configured OpenAI credentials do not grant usable AI quota.
// A separate explicit Cloudflare quota variable is required.
const freeLimit = env => clampLimit(env.FREE_AI_DAILY_LIMIT, 5);
const paidLimit = env => clampLimit(env.PAID_AI_DAILY_LIMIT, 25);
// These are shared ceilings across every adult account. Both default to zero (fail closed).
// Per-user caps alone do NOT control the platform's total API bill.
const globalDailyLimit = env => clampLimit(env.GLOBAL_AI_DAILY_LIMIT, 100);
const globalMonthlyLimit = env => clampLimit(env.GLOBAL_AI_MONTHLY_LIMIT, 1000);
const aiModel = env => env.AI_MODEL || 'gpt-6-luna';
const allowedModel = env => aiModel(env) === 'gpt-6-luna';
const costGuardsReady = env => globalDailyLimit(env) > 0 && globalMonthlyLimit(env) > 0 && allowedModel(env);
const aiConfigured = env => authReady(env) && env.AI_ENABLED === 'true' &&
  !!env.OPENAI_API_KEY && costGuardsReady(env);

function cookieHeader(token, durationSeconds = null) {
  const parts = [`${COOKIE_NAME}=${token}`, 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Strict'];
  if (durationSeconds !== null) parts.push(`Max-Age=${durationSeconds}`);
  return parts.join('; ');
}
function getToken(req) {
  const match = (req.headers.get('cookie') || '').match(/(?:^|;\s*)neluun_sid=([a-f0-9]{64})(?:;|$)/);
  return match?.[1] || null;
}
async function session(req, env) {
  const token = getToken(req);
  if (!token || !hasDb(env) || !env.SESSION_PEPPER) return null;
  const hash = await digest(env.SESSION_PEPPER + ':' + token);
  return env.DB.prepare(`SELECT u.id,u.email,s.token_hash,s.expires_at
    FROM sessions s JOIN users u ON s.user_id=u.id
    WHERE s.token_hash=? AND s.expires_at>?`).bind(hash, epoch()).first();
}
async function bodyJSON(req) {
  const len = Number(req.headers.get('content-length') || 0);
  if (len > 4096) throw Error('too_large');
  const raw = await req.text();
  if (raw.length > 4096) throw Error('too_large');
  try { return JSON.parse(raw); } catch { throw Error('bad_json'); }
}
function onlySameOrigin(req) {
  const origin = req.headers.get('origin');
  return !!origin && origin === new URL(req.url).origin &&
    req.headers.get('content-type')?.toLowerCase().startsWith('application/json');
}
async function rate(env, key, limit, windowSeconds) {
  const now = epoch();
  const window = Math.floor(now / windowSeconds);
  const bucket = await digest(env.OTP_PEPPER + ':' + key + ':' + window);
  const r = await env.DB.prepare(`INSERT INTO rate_limits(bucket,hits,expires_at) VALUES(?,1,?)
     ON CONFLICT(bucket) DO UPDATE SET hits=hits+1 WHERE hits<? RETURNING hits`)
    .bind(bucket, (window + 1) * windowSeconds, limit).first();
  return !!r;
}
// An atomic shared counter in D1: one reservation per attempted upstream request.
// Calendar UTC day/month names are part of the key to avoid mid-month rollovers.
async function reserveGlobalAiCall(env, scope, windowName, limit, expiresAt) {
  const bucket = await digest(`${env.OTP_PEPPER}:ai-budget:${scope}:${windowName}`);
  const row = await env.DB.prepare(`INSERT INTO rate_limits(bucket,hits,expires_at) VALUES(?,1,?)
    ON CONFLICT(bucket) DO UPDATE SET hits=hits+1 WHERE hits<? RETURNING hits`)
    .bind(bucket, expiresAt, limit).first();
  return !!row;
}
async function sendLoginEmail(env, email, code) {
  const msg = {
    from: env.EMAIL_FROM, to: [email], subject: 'NELUUN 登入驗證碼',
    text: `你的 NELUUN 登入驗證碼：${code}\n10 分鐘內有效。若不是你本人操作，可忽略此郵件。\n請勿轉寄驗證碼。`,
  };
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json',
    }, body: JSON.stringify(msg),
  });
  if (!res.ok) throw Error('Email delivery failed');
}
async function requestCode(req, env) {
  if (!authReady(env)) return fail(503, 'not_configured', '登入服務尚未啟用。');
  const body = await bodyJSON(req), email = cleanEmail(body.email);
  if (!validEmail(email)) return fail(400, 'invalid_email', '請輸入正確的電子郵件。');
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await rate(env, `otp-ip:${ip}`, 12, 3600) ||
      !await rate(env, `otp-mail:${email}`, 4, 3600)) {
    return fail(429, 'try_later', '驗證碼要求次數較多，請稍後再試。');
  }
  const digits = crypto.getRandomValues(new Uint32Array(1))[0];
  const code = String(digits % 1000000).padStart(6, '0');
  const hash = await digest(`${env.OTP_PEPPER}:${email}:${code}`), now = epoch();
  await env.DB.prepare(`INSERT INTO login_codes(email,code_hash,expires_at,attempts,issued_at)
    VALUES(?,?,?,0,?) ON CONFLICT(email) DO UPDATE SET
    code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,issued_at=excluded.issued_at`)
    .bind(email, hash, now + CODE_SECONDS, now).run();
  try { await sendLoginEmail(env, email, code); }
  catch {
    await env.DB.prepare('DELETE FROM login_codes WHERE email=? AND code_hash=?').bind(email, hash).run();
    return fail(502, 'email_unavailable', '郵件暫時無法寄送，請稍後再試。');
  }
  return json({ ok: true, message: '驗證碼已寄出，請查看信箱。' });
}
async function verifyCode(req, env) {
  if (!authReady(env)) return fail(503, 'not_configured', '登入服務尚未啟用。');
  const body = await bodyJSON(req);
  const email = cleanEmail(body.email), code = String(body.code || '');
  if (!validEmail(email) || !/^[0-9]{6}$/.test(code)) {
    return fail(400, 'invalid_code', '電子郵件或驗證碼格式不正確。');
  }
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await rate(env, `verify-ip:${ip}`, 25, 3600)) return fail(429, 'try_later', '驗證次數較多，請稍後再試。');
  const hash = await digest(`${env.OTP_PEPPER}:${email}:${code}`);
  const matched = await env.DB.prepare(`DELETE FROM login_codes
    WHERE email=? AND code_hash=? AND expires_at>? AND attempts<5 RETURNING email`)
    .bind(email, hash, epoch()).first();
  if (!matched) {
    await env.DB.prepare('UPDATE login_codes SET attempts=attempts+1 WHERE email=? AND expires_at>? AND attempts<5')
      .bind(email, epoch()).run();
    return fail(401, 'invalid_code', '驗證碼錯誤或已過期。');
  }
  const now = epoch();
  await env.DB.prepare('INSERT INTO users(id,email,created_at) VALUES(?,?,?) ON CONFLICT(email) DO NOTHING')
    .bind(crypto.randomUUID(), email, now).run();
  const user = await env.DB.prepare('SELECT id,email FROM users WHERE email=?').bind(email).first();
  const keepSignedIn = body.rememberDevice === true;
  const duration = keepSignedIn ? SESSION_REMEMBER_SECONDS : SESSION_SHORT_SECONDS;
  const token = randomHex(32), tokenHash = await digest(env.SESSION_PEPPER + ':' + token);
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)')
    .bind(tokenHash, user.id, now + duration, now).run();
  // A session cookie without Max-Age is used when the user did not opt into 30-day persistence.
  return json({ ok: true, email: user.email, sessionMode: keepSignedIn ? 'remembered' : 'session' }, 200,
    { 'set-cookie': cookieHeader(token, keepSignedIn ? duration : null) });
}

// A paid entitlement can ONLY be established by a separate, trusted administrative or
// payment-verification workflow. No client-visible endpoint can create or upgrade it.
async function userPlan(user, env) {
  if (!user || !hasDb(env)) return 'guest';
  try {
    const paid = await env.DB.prepare(`SELECT plan, status, current_period_end
      FROM subscription_entitlements WHERE user_id=?`).bind(user.id).first();
    if (paid?.plan === 'paid' && paid.status === 'active' && paid.current_period_end > epoch()) return 'paid';
  } catch { /* Legacy D1 before the optional migration: fail closed to free tier. */ }
  return 'free';
}
async function currentUser(req, env) {
  const user = await session(req, env);
  let guardianDeclaration = false;
  if (user) {
    const rec = await env.DB.prepare('SELECT declared_at,withdrawn_at FROM guardian_declarations WHERE user_id=?')
      .bind(user.id).first();
    guardianDeclaration = !!rec?.declared_at && !rec.withdrawn_at;
  }
  const plan = await userPlan(user, env);
  const limit = !user || !aiConfigured(env) ? 0 : plan === 'paid' ? paidLimit(env) : freeLimit(env);
  let used = 0;
  if (user && limit > 0) {
    const day = new Date().toISOString().slice(0, 10);
    const row = await env.DB.prepare('SELECT used FROM daily_ai_usage WHERE user_id=? AND day=?')
      .bind(user.id, day).first();
    used = Math.min(limit, Math.max(0, Number(row?.used) || 0));
  }
  return json({
    ok: true, authenticated: !!user, email: user?.email || null,
    authEnabled: authReady(env), plan, aiEnabled: limit > 0,
    guardianDeclaration, guardianIdentityVerified: false, childAIEnabled: false,
    dailyAiLimit: limit, dailyAiUsed: used, dailyAiRemaining: Math.max(0, limit - used),
    aiCostGuardReady: costGuardsReady(env), billingEnabled: false, cloudLearningSyncEnabled: false,
    rememberLoginOption: true,
  });
}
async function logout(req, env) {
  const user = await session(req, env);
  if (user) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(user.token_hash).run();
  return json({ ok: true }, 200, { 'set-cookie': cookieHeader('', 0) });
}
async function setDeclaration(req, env, withdraw) {
  const user = await session(req, env);
  if (!user) return fail(401, 'sign_in', '請先登入。');
  const now = epoch();
  if (withdraw) {
    await env.DB.prepare('UPDATE guardian_declarations SET withdrawn_at=? WHERE user_id=?').bind(now, user.id).run();
    return json({ ok: true, guardianDeclaration: false });
  }
  const body = await bodyJSON(req);
  if (body.agree !== true || body.confirmGuardian !== true)
    return fail(400, 'explicit_consent_required', '需要主動勾選聲明。');
  await env.DB.prepare(`INSERT INTO guardian_declarations(user_id,declared_at,withdrawn_at,policy_version)
    VALUES(?,?,NULL,?) ON CONFLICT(user_id) DO UPDATE SET
    declared_at=excluded.declared_at,withdrawn_at=NULL,policy_version=excluded.policy_version`)
    .bind(user.id, now, CONSENT_VERSION).run();
  return json({ ok: true, guardianDeclaration: true,
    notice: '這是家長自行聲明，不等於已驗證法定代理人身分。兒童 AI 仍然關閉。' });
}
async function aiChat(req, env) {
  // Check authentication and user plan before even considering an upstream AI request.
  const user = await session(req, env);
  if (!user) return fail(401, 'sign_in', '請先登入個人助理。');
  const body = await bodyJSON(req);
  if (body.mode !== 'personal') return fail(403, 'child_ai_disabled', '學習助理 AI 尚未開放。');
  if (!aiConfigured(env)) return fail(503, 'ai_disabled', 'AI 尚未啟用；不會產生付費請求。');
  const plan = await userPlan(user, env);
  const limit = plan === 'paid' ? paidLimit(env) : freeLimit(env);
  if (limit === 0) return fail(403, 'tier_not_enabled', '此方案目前未開放 AI 使用。');
  const prompt = String(body.message || '').trim();
  if (!prompt || prompt.length > 800) return fail(400, 'invalid_message', '訊息不可空白或超過 800 字。');
  const day = new Date().toISOString().slice(0, 10);
  const allowed = await env.DB.prepare(`INSERT INTO daily_ai_usage(user_id,day,used)
    VALUES(?,?,1) ON CONFLICT(user_id,day) DO UPDATE SET
    used=used+1 WHERE used<? RETURNING used`).bind(user.id, day, limit).first();
  if (!allowed) return fail(429, 'quota_exceeded', `今天已達 ${limit} 次個人助理 AI 上限。`);
  // Per-user reservation goes first so accounts already over quota cannot exhaust
  // the shared platform budget. A blocked global-budget request may still consume
  // a per-user slot; this favors fail-closed cost control, not exact billing.
  const date = new Date();
  const utcDay = date.toISOString().slice(0, 10);
  const utcMonth = utcDay.slice(0, 7);
  const nextDay = Math.floor(Date.parse(utcDay + 'T00:00:00Z') / 1000) + 86400;
  const nextMonth = Math.floor(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1) / 1000);
  if (!await reserveGlobalAiCall(env, 'month', utcMonth, globalMonthlyLimit(env), nextMonth))
    return fail(429, 'platform_monthly_cap', 'NELUUN 本月 AI 安全額度已達上限，未發送新請求。');
  if (!await reserveGlobalAiCall(env, 'day', utcDay, globalDailyLimit(env), nextDay))
    return fail(429, 'platform_daily_cap', 'NELUUN 今日 AI 安全額度已達上限，未發送新請求。');
  let answer;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 18000);
    let response;
    try {
      response = await fetch('https://api.openai.com/v1/responses', {
        method: 'POST', headers: { Authorization: `Bearer ${env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: aiModel(env), reasoning: { effort: 'none' },
          input: [
            { role: 'system', content: '你是 NELUUN 成人個人助理。使用繁體中文，尊重使用者自主權，清楚、簡潔回答。切勿推斷未提供的敏感個人資訊；若涉及兒童私密資訊，請提醒避免提供。' },
            { role: 'user', content: prompt },
          ],
          max_output_tokens: 320, store: false,
        }), signal: controller.signal,
      });
    } finally { clearTimeout(timeout); }
    if (!response.ok) return fail(502, 'upstream_error', 'AI 服務暫時無法回應。此筆請求已占用當日額度。');
    const data = await response.json();
    answer = (data.output || []).flatMap(x => x.content || [])
      .filter(x => x.type === 'output_text').map(x => x.text).join('\n').trim() || data.output_text;
  } catch {
    return fail(502, 'upstream_error', 'AI 服務連線逾時或失敗。此筆請求已占用當日額度。');
  }
  return json({ ok: true, answer: answer || '目前沒有取得可顯示的回覆。',
    quotaUsed: allowed.used, quotaLimit: limit, plan });
}
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) {
      if (env.ASSETS) return env.ASSETS.fetch(req);
      return fail(404, 'assets_missing', '靜態資源尚未設定。');
    }
    if (req.method === 'OPTIONS') return fail(405, 'method_not_allowed', '不接受跨站 API 請求。');
    if (url.pathname === '/api/me' && req.method === 'GET') {
      try { return await currentUser(req, env); }
      catch { return fail(503, 'service_unavailable', '登入狀態目前無法查詢。'); }
    }
    if (req.method !== 'POST') return fail(405, 'method_not_allowed', '不支援此方法。');
    if (!onlySameOrigin(req)) return fail(403, 'origin_required', '安全檢查失敗。請從正式 HTTPS 網站操作。');
    try {
      if (url.pathname === '/api/auth/request') return await requestCode(req, env);
      if (url.pathname === '/api/auth/verify') return await verifyCode(req, env);
      if (url.pathname === '/api/auth/logout') return await logout(req, env);
      if (url.pathname === '/api/guardian/declare') return await setDeclaration(req, env, false);
      if (url.pathname === '/api/guardian/withdraw') return await setDeclaration(req, env, true);
      if (url.pathname === '/api/chat') return await aiChat(req, env);
      return fail(404, 'unknown_endpoint', '沒有這個 API。');
    } catch (err) {
      if (err.message === 'too_large' || err.message === 'bad_json')
        return fail(400, 'bad_request', '請求內容格式不正確。');
      return fail(503, 'service_unavailable', '伺服器暫時無法完成要求。');
    }
  },
};
