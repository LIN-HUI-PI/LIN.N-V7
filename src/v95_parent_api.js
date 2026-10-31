/**
 * NELUUN V9.5: server-enforced adult step-up.
 * Email verification proves mailbox access only, not legal guardianship or age.
 * This is an isolated candidate; no child AI, billing or cloud child data API.
 */
import base from './index.js';

const COOKIE = 'neluun_sid';
const OTP_TTL = 600;
const GRANT_TTL = 600;
const now = () => Math.floor(Date.now() / 1000);
const headers = {
  'cache-control': 'no-store', 'pragma': 'no-cache',
  'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY', 'vary': 'Cookie'
};
const respond = (body, status = 200, other = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers, ...other }
});
const deny = (status, error, message) => respond({ ok: false, error, message }, status);
const sha = async value => Array.from(new Uint8Array(await crypto.subtle.digest(
  'SHA-256', new TextEncoder().encode(value)
)), b => b.toString(16).padStart(2, '0')).join('');
function otp() {
  // Unbiased uniform six-digit code.
  const ceiling = Math.floor(4294967296 / 1000000) * 1000000;
  let n;
  do { n = crypto.getRandomValues(new Uint32Array(1))[0]; } while (n >= ceiling);
  return String(n % 1000000).padStart(6, '0');
}
function token(req) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)neluun_sid=([a-f0-9]{64})(?:;|$)/);
  return m ? m[1] : null;
}
function sameOrigin(req) {
  const origin = req.headers.get('origin');
  const type = (req.headers.get('content-type') || '').toLowerCase();
  return !!origin && origin === new URL(req.url).origin && type.startsWith('application/json');
}
function ready(env) {
  return env.PARENT_STEP_UP_ENABLED === 'true' && !!(
    env.DB && typeof env.DB.prepare === 'function' &&
    env.RESEND_API_KEY && env.EMAIL_FROM && env.OTP_PEPPER && env.SESSION_PEPPER
  );
}
async function identity(req, env) {
  const sid = token(req);
  if (!sid || !env.DB || !env.SESSION_PEPPER) return null;
  const key = await sha(env.SESSION_PEPPER + ':' + sid);
  const row = await env.DB.prepare(
    'SELECT u.id,u.email,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id ' +
    'WHERE s.token_hash=? AND s.expires_at>?'
  ).bind(key, now()).first();
  return row ? { ...row, sessionHash: key } : null;
}
async function limit(env, label, max, seconds) {
  const window = Math.floor(now() / seconds);
  const key = await sha(env.OTP_PEPPER + ':parent:' + label + ':' + window);
  const value = await env.DB.prepare(
    'INSERT INTO rate_limits(bucket,hits,expires_at) VALUES(?,1,?) ' +
    'ON CONFLICT(bucket) DO UPDATE SET hits=hits+1 WHERE hits<? RETURNING hits'
  ).bind(key, (window + 1) * seconds, max).first();
  return !!value;
}
async function sendEmail(env, email, code) {
  const mail = {
    from: env.EMAIL_FROM, to: [email], subject: 'NELUUN 成人區安全驗證',
    text: 'NELUUN 成人區安全驗證碼：' + code +
      '\n10 分鐘內有效。若不是你操作，請忽略此郵件。此驗證只確認信箱控制權。'
  };
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(mail)
  });
  if (!response.ok) throw Error('email_failed');
}
async function access(env, user) {
  const row = await env.DB.prepare(
    'SELECT expires_at FROM parent_grants WHERE session_hash=? AND expires_at>?'
  ).bind(user.sessionHash, now()).first();
  return row ? { ok: true, adultAccess: true, expiresIn: Math.max(0, row.expires_at - now()) } :
    { ok: true, adultAccess: false, expiresIn: 0 };
}
async function challenge(req, env, user) {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!(await limit(env, 'challenge-ip:' + ip, 12, 3600)) ||
      !(await limit(env, 'challenge-session:' + user.sessionHash, 5, 3600)) ||
      !(await limit(env, 'challenge-minute:' + user.sessionHash, 1, 60))) {
    return deny(429, 'try_later', '驗證要求過於頻繁，請稍後再試。');
  }
  const code = otp(), issued = now();
  const codeHash = await sha(env.OTP_PEPPER + ':parent-code:' + user.sessionHash + ':' + code);
  // A new challenge invalidates any prior step-up authorization.
  await env.DB.prepare('DELETE FROM parent_grants WHERE session_hash=?').bind(user.sessionHash).run();
  const reserved = await env.DB.prepare(
    'INSERT INTO parent_challenges(session_hash,code_hash,expires_at,attempts,sent_at) ' +
    'VALUES(?,?,?,0,?) ON CONFLICT(session_hash) DO UPDATE SET ' +
    'code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,sent_at=excluded.sent_at ' +
    'WHERE parent_challenges.sent_at<=? RETURNING session_hash'
  ).bind(user.sessionHash, codeHash, issued + OTP_TTL, issued, issued - 60).first();
  if (!reserved) return deny(429, 'cooldown', '新驗證碼要求過於頻繁，請稍後再試。');
  try { await sendEmail(env, user.email, code); }
  catch {
    await env.DB.prepare(
      'DELETE FROM parent_challenges WHERE session_hash=? AND code_hash=?'
    ).bind(user.sessionHash, codeHash).run();
    return deny(502, 'email_unavailable', '安全驗證郵件暫時無法寄送。');
  }
  return respond({ ok: true, message: '已寄出成人區驗證碼。', expiresIn: OTP_TTL });
}
async function verify(req, env, user) {
  const len = Number(req.headers.get('content-length') || 0);
  if (len > 512) return deny(400, 'bad_request', '驗證資料過大。');
  const raw = await req.text();
  if (raw.length > 512) return deny(400, 'bad_request', '驗證資料過大。');
  let body;
  try { body = JSON.parse(raw); } catch { return deny(400, 'bad_request', '驗證碼格式錯誤。'); }
  if (!body || typeof body !== 'object' || Array.isArray(body) ||
      typeof body.code !== 'string' || !/^[0-9]{6}$/.test(body.code)) {
    return deny(400, 'bad_request', '請輸入六位數驗證碼。');
  }
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!(await limit(env, 'verify-ip:' + ip, 30, 3600)))
    return deny(429, 'try_later', '驗證過於頻繁，請稍後再試。');
  const codeHash = await sha(env.OTP_PEPPER + ':parent-code:' + user.sessionHash + ':' + body.code);
  const consumed = await env.DB.prepare(
    'DELETE FROM parent_challenges WHERE session_hash=? AND code_hash=? ' +
    'AND expires_at>? AND attempts<5 RETURNING session_hash'
  ).bind(user.sessionHash, codeHash, now()).first();
  if (!consumed) {
    await env.DB.prepare(
      'UPDATE parent_challenges SET attempts=attempts+1 ' +
      'WHERE session_hash=? AND expires_at>? AND attempts<5'
    ).bind(user.sessionHash, now()).run();
    return deny(401, 'invalid_code', '驗證碼錯誤、已失效或嘗試次數已達上限。');
  }
  const issued = now(), until = Math.min(issued + GRANT_TTL, Number(user.expires_at));
  await env.DB.prepare(
    'INSERT INTO parent_grants(session_hash,expires_at,created_at) VALUES(?,?,?) ' +
    'ON CONFLICT(session_hash) DO UPDATE SET expires_at=excluded.expires_at,created_at=excluded.created_at'
  ).bind(user.sessionHash, until, issued).run();
  return respond({
    ok: true, adultAccess: true, expiresIn: Math.max(0, until - issued),
    notice: '信箱驗證不等於法定監護人身分驗證。'
  });
}
export async function requireAdultStepUp(req, env) {
  if (!ready(env)) return { ok: false, status: 503, error: 'not_configured' };
  const user = await identity(req, env);
  if (!user) return { ok: false, status: 401, error: 'sign_in' };
  const grant = await access(env, user);
  return grant.adultAccess ?
    { ok: true, user, expiresIn: grant.expiresIn } :
    { ok: false, status: 403, error: 'adult_locked' };
}
const paths = new Set(['/api/parent/status', '/api/parent/challenge',
  '/api/parent/verify', '/api/parent/lock']);
export default {
  async fetch(req, env) {
    const pathname = new URL(req.url).pathname;
    const parent = pathname.startsWith('/api/parent/');
    const privateStatus = pathname === '/api/adult/private/status';
    const logout = pathname === '/api/auth/logout';
    const sensitiveOld = pathname === '/api/chat' ||
      pathname === '/api/guardian/declare' || pathname === '/api/guardian/withdraw';
    if (!parent && !privateStatus && !logout && !sensitiveOld) return base.fetch(req, env);
    if (parent && !paths.has(pathname)) return deny(404, 'unknown_endpoint', '安全驗證路徑不存在。');
    const isGet = pathname === '/api/parent/status' || privateStatus;
    if (req.method !== (isGet ? 'GET' : 'POST')) return deny(405, 'method_not_allowed', '方法不支援。');
    if (req.method === 'POST' && !sameOrigin(req)) return deny(403, 'origin_required', '來源驗證失敗。');
    // Logout must remain operational even when step-up is unconfigured.
    if (logout) {
      if (ready(env)) {
        try {
          const user = await identity(req, env);
          if (user) {
            await env.DB.prepare('DELETE FROM parent_challenges WHERE session_hash=?').bind(user.sessionHash).run();
            await env.DB.prepare('DELETE FROM parent_grants WHERE session_hash=?').bind(user.sessionHash).run();
          }
        } catch { /* The base logout still revokes the original session. */ }
      }
      return base.fetch(req, env);
    }
    if (!ready(env)) return deny(503, 'not_configured', '家長二次驗證尚未啟用。');
    try {
      const user = await identity(req, env);
      if (!user) return deny(401, 'sign_in', '請先登入會員。');
      if (sensitiveOld) {
        if (!(await access(env, user)).adultAccess)
          return deny(403, 'adult_locked', '需要家長二次驗證。');
        return base.fetch(req, env);
      }
      if (pathname === '/api/parent/status') return respond(await access(env, user));
      if (pathname === '/api/parent/challenge') return challenge(req, env, user);
      if (pathname === '/api/parent/verify') return verify(req, env, user);
      if (pathname === '/api/parent/lock') {
        await env.DB.prepare('DELETE FROM parent_grants WHERE session_hash=?').bind(user.sessionHash).run();
        await env.DB.prepare('DELETE FROM parent_challenges WHERE session_hash=?').bind(user.sessionHash).run();
        return respond({ ok: true, adultAccess: false });
      }
      if (privateStatus) {
        const grant = await access(env, user);
        return grant.adultAccess ? respond(grant) : deny(403, 'adult_locked', '成人區已鎖定。');
      }
      return deny(404, 'unknown_endpoint', '找不到 API。');
    } catch {
      return deny(503, 'service_unavailable', '家長驗證服務暫時無法完成要求。');
    }
  }
};
