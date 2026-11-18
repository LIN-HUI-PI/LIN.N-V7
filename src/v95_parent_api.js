/**
 * NELUUN V9.5: server-enforced adult step-up.
 * Email verification proves mailbox access only, not legal guardianship or age.
 * This is an isolated candidate; no child AI, billing or cloud child data API.
 */
import base from './index.js';
import { FAMILY_ROUTES, handleFamily, revokeChildAccess } from './v95_family_api.js';
import { newSecret, base32, matchStep, sealSecret, openSecret, otpauthUri,
  recoveryCode, RECOVERY_RE } from './v95_totp.js';

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
async function needsStepUp(env, user) {
  // Step-up is only meaningful once the account has declared itself a guardian.
  const row = await env.DB.prepare(
    'SELECT declared_at,withdrawn_at FROM guardian_declarations WHERE user_id=?'
  ).bind(user.id).first();
  return !!(row && row.declared_at != null && row.withdrawn_at == null);
}
async function accessOrOpen(env, user) {
  // Accounts without a guardian declaration have no children to protect: no step-up.
  if (!(await needsStepUp(env, user)))
    return { ok: true, adultAccess: true, expiresIn: 600, stepUpRequired: false };
  return { ...(await access(env, user)), stepUpRequired: true };
}
async function issueGrant(env, user) {
  const issued = now(), until = Math.min(issued + GRANT_TTL, Number(user.expires_at));
  await env.DB.prepare(
    'INSERT INTO parent_grants(session_hash,expires_at,created_at) VALUES(?,?,?) ' +
    'ON CONFLICT(session_hash) DO UPDATE SET expires_at=excluded.expires_at,created_at=excluded.created_at'
  ).bind(user.sessionHash, until, issued).run();
  return Math.max(0, until - issued);
}
async function totpRow(env, userId) {
  return env.DB.prepare('SELECT * FROM parent_totp WHERE user_id=?').bind(userId).first();
}
async function totpEnrolled(env, userId) {
  const row = await totpRow(env, userId);
  return !!(row && row.confirmed_at);
}
async function readCode(req, pattern) {
  const raw = await req.text();
  if (raw.length > 512) return null;
  let body; try { body = JSON.parse(raw); } catch { return null; }
  if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.code !== 'string') return null;
  const code = body.code.trim().toUpperCase();
  return pattern.test(code) ? code : null;
}
async function totpLimits(req, env, user) {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  return (await limit(env, 'totp-ip:' + ip, 30, 3600)) && (await limit(env, 'totp-user:' + user.id, 10, 3600));
}
async function totpBegin(env, user) {
  if (!(await access(env, user)).adultAccess) return deny(403, 'adult_locked', '需要家長二次驗證。');
  if (await totpEnrolled(env, user.id)) return deny(409, 'already_enrolled', '已設定驗證器；要更換請先移除。');
  const secret = newSecret(), sealed = await sealSecret(env.OTP_PEPPER, user.id, secret);
  await env.DB.prepare(
    'INSERT INTO parent_totp(user_id,secret_enc,confirmed_at,last_step,created_at) VALUES(?,?,NULL,0,?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET secret_enc=excluded.secret_enc,confirmed_at=NULL,last_step=0,created_at=excluded.created_at'
  ).bind(user.id, sealed, now()).run();
  const text = base32(secret);
  return respond({ ok: true, secret: text, uri: otpauthUri(user.email, text) });
}
async function totpConfirm(req, env, user) {
  if (!(await access(env, user)).adultAccess) return deny(403, 'adult_locked', '需要家長二次驗證。');
  const code = await readCode(req, /^[0-9]{6}$/);
  if (!code) return deny(400, 'bad_request', '請輸入驗證器上的六位數。');
  if (!(await totpLimits(req, env, user))) return deny(429, 'try_later', '嘗試過於頻繁，請稍後再試。');
  const row = await env.DB.prepare('SELECT * FROM parent_totp WHERE user_id=? AND confirmed_at IS NULL').bind(user.id).first();
  if (!row) return deny(409, 'no_pending', '請先開始設定驗證器。');
  const step = await matchStep(await openSecret(env.OTP_PEPPER, user.id, row.secret_enc), code, now(), 0);
  if (step === null) return deny(401, 'invalid_code', '驗證碼錯誤，請確認手機時間正確後再試。');
  const t = now();
  await env.DB.prepare('UPDATE parent_totp SET confirmed_at=?,last_step=? WHERE user_id=? AND confirmed_at IS NULL')
    .bind(t, step, user.id).run();
  await env.DB.prepare('DELETE FROM parent_totp_recovery WHERE user_id=?').bind(user.id).run();
  const codes = [];
  for (let i = 0; i < 8; i++) {
    const c = recoveryCode(); codes.push(c);
    await env.DB.prepare('INSERT INTO parent_totp_recovery(code_hash,user_id,created_at) VALUES(?,?,?)')
      .bind(await sha(env.OTP_PEPPER + ':totp-recovery:' + user.id + ':' + c), user.id, t).run();
  }
  return respond({ ok: true, enrolled: true, recoveryCodes: codes,
    notice: '備用碼只會顯示這一次，請抄寫或截圖保存。' });
}
async function totpVerify(req, env, user) {
  const code = await readCode(req, new RegExp('^(?:[0-9]{6}|' + RECOVERY_RE.source.slice(1, -1) + ')$'));
  if (!code) return deny(400, 'bad_request', '請輸入六位數驗證碼或備用碼。');
  if (!(await totpLimits(req, env, user))) return deny(429, 'try_later', '驗證過於頻繁，請稍後再試。');
  const row = await totpRow(env, user.id);
  if (!row || !row.confirmed_at) return deny(409, 'not_enrolled', '尚未設定驗證器。');
  if (/^[0-9]{6}$/.test(code)) {
    const step = await matchStep(await openSecret(env.OTP_PEPPER, user.id, row.secret_enc), code, now(), Number(row.last_step));
    // Compare-and-set the step so a captured code cannot be replayed.
    const claimed = step === null ? null : await env.DB.prepare(
      'UPDATE parent_totp SET last_step=? WHERE user_id=? AND last_step<? RETURNING user_id'
    ).bind(step, user.id, step).first();
    if (!claimed) return deny(401, 'invalid_code', '驗證碼錯誤或已使用過。');
  } else {
    const used = await env.DB.prepare(
      'DELETE FROM parent_totp_recovery WHERE code_hash=? AND user_id=? RETURNING code_hash'
    ).bind(await sha(env.OTP_PEPPER + ':totp-recovery:' + user.id + ':' + code), user.id).first();
    if (!used) return deny(401, 'invalid_code', '備用碼錯誤或已使用過。');
  }
  const expiresIn = await issueGrant(env, user);
  const left = await env.DB.prepare('SELECT COUNT(*) AS n FROM parent_totp_recovery WHERE user_id=?').bind(user.id).first();
  return respond({ ok: true, adultAccess: true, expiresIn, recoveryLeft: left?.n ?? 0,
    notice: '驗證器驗證不等於法定監護人身分驗證。' });
}
async function totpRemove(env, user) {
  if (!(await access(env, user)).adultAccess) return deny(403, 'adult_locked', '需要家長二次驗證。');
  await env.DB.prepare('DELETE FROM parent_totp WHERE user_id=?').bind(user.id).run();
  await env.DB.prepare('DELETE FROM parent_totp_recovery WHERE user_id=?').bind(user.id).run();
  return respond({ ok: true, enrolled: false });
}
async function challenge(req, env, user) {
  if (await totpEnrolled(env, user.id)) return deny(409, 'use_totp', '已啟用驗證器，請用驗證器 App 的六位數驗證。');
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
  if (await totpEnrolled(env, user.id)) return deny(409, 'use_totp', '已啟用驗證器，請用驗證器 App 的六位數驗證。');
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
  const expiresIn = await issueGrant(env, user);
  return respond({
    ok: true, adultAccess: true, expiresIn,
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
  '/api/parent/verify', '/api/parent/lock', '/api/parent/totp/status',
  '/api/parent/totp/begin', '/api/parent/totp/confirm', '/api/parent/totp/verify',
  '/api/parent/totp/remove']);
export default {
  async fetch(req, env) {
    const pathname = new URL(req.url).pathname;
    const parent = pathname.startsWith('/api/parent/');
    const privateStatus = pathname === '/api/adult/private/status';
    const logout = pathname === '/api/auth/logout';
    const sensitiveOld = pathname === '/api/chat' ||
      pathname === '/api/guardian/declare' || pathname === '/api/guardian/withdraw';
    const family = pathname.startsWith('/api/family/');
    // The adult site never serves the child API: children use their own site.
    if (pathname.startsWith('/api/kids/')) return deny(404, 'unknown_endpoint', '這裡沒有孩童入口。');
    if (!parent && !privateStatus && !logout && !sensitiveOld && !family) return base.fetch(req, env);
    if (parent && !paths.has(pathname)) return deny(404, 'unknown_endpoint', '安全驗證路徑不存在。');
    if (family && !Object.hasOwn(FAMILY_ROUTES, pathname)) return deny(404, 'unknown_endpoint', '找不到 API。');
    const isGet = family ? FAMILY_ROUTES[pathname] === 'GET' : (pathname === '/api/parent/status' || pathname === '/api/parent/totp/status' || privateStatus);
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
      if (family) {
        if (!(await access(env, user)).adultAccess)
          return deny(403, 'adult_locked', '需要家長二次驗證。');
        return await handleFamily(req, env, user, pathname);
      }
      if (sensitiveOld) {
        const strict = pathname !== '/api/chat';
        const allowed = strict ? await access(env, user) : await accessOrOpen(env, user);
        if (!allowed.adultAccess)
          return deny(403, 'adult_locked', '需要家長二次驗證。');
        const result = await base.fetch(req, env);
        // Withdrawing the guardian declaration ends every child session at once.
        if (pathname === '/api/guardian/withdraw' && result.ok)
          await revokeChildAccess(env, { guardianId: user.id });
        return result;
      }
      if (pathname === '/api/parent/status') {
        // The family page always needs the real grant; legacy callers get the guardian-aware answer.
        const strict = new URL(req.url).searchParams.get('strict') === '1';
        return respond(strict ? { ...(await access(env, user)), stepUpRequired: true } : await accessOrOpen(env, user));
      }
      if (pathname === '/api/parent/totp/status') return respond({ ok: true, enrolled: await totpEnrolled(env, user.id) });
      if (pathname === '/api/parent/totp/begin') return totpBegin(env, user);
      if (pathname === '/api/parent/totp/confirm') return totpConfirm(req, env, user);
      if (pathname === '/api/parent/totp/verify') return totpVerify(req, env, user);
      if (pathname === '/api/parent/totp/remove') return totpRemove(env, user);
      if (pathname === '/api/parent/challenge') return challenge(req, env, user);
      if (pathname === '/api/parent/verify') return verify(req, env, user);
      if (pathname === '/api/parent/lock') {
        await env.DB.prepare('DELETE FROM parent_grants WHERE session_hash=?').bind(user.sessionHash).run();
        await env.DB.prepare('DELETE FROM parent_challenges WHERE session_hash=?').bind(user.sessionHash).run();
        return respond({ ok: true, adultAccess: false });
      }
      if (privateStatus) {
        const grant = await accessOrOpen(env, user);
        return grant.adultAccess ? respond(grant) : deny(403, 'adult_locked', '成人區已鎖定。');
      }
      return deny(404, 'unknown_endpoint', '找不到 API。');
    } catch {
      return deny(503, 'service_unavailable', '家長驗證服務暫時無法完成要求。');
    }
  }
};
