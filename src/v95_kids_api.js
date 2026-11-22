/**
 * NELUUN V9.5: CHILD Worker (separate origin from the adult Worker).
 * - A child enters only with a one-time code that a verified adult generated.
 * - Access is time-limited (set by the adult, 60 minutes at most) and revocable.
 * - This Worker has no adult session logic, no email, no AI and no payment.
 * - Child AI stays OFF until an AI vendor, consent flow and filters are approved.
 * Secrets needed: OTP_PEPPER (must equal the adult Worker's value) and SESSION_PEPPER.
 */
import {
  ACTIVE_DECLARATION, KID_COOKIE, childTokenHash, deny, entryCodeHash, limit, now,
  pepperFingerprint, randomHex, readJson, respond, sameOrigin
} from './v95_family_shared.js';

const ready = env => !!(env.DB && typeof env.DB.prepare === 'function' &&
  env.OTP_PEPPER && env.SESSION_PEPPER);

const cookie = (token, maxAge) => [
  `${KID_COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Strict', `Max-Age=${maxAge}`
].join('; ');

function readToken(req) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)neluun_kid=([a-f0-9]{64})(?:;|$)/);
  return m ? m[1] : null;
}

/** Returns the live child session, or null. Revoked child / withdrawn declaration => null. */
export async function childSession(req, env) {
  const token = readToken(req);
  if (!token || !ready(env)) return null;
  const hash = await childTokenHash(env, token);
  return env.DB.prepare(
    'SELECT s.token_hash,s.child_id,s.expires_at,c.nickname,c.avatar ' +
    'FROM child_sessions s JOIN children c ON c.id=s.child_id ' +
    'JOIN guardian_declarations g ON g.user_id=c.guardian_user_id ' +
    `WHERE s.token_hash=? AND s.expires_at>? AND c.revoked_at IS NULL AND ${ACTIVE_DECLARATION}`
  ).bind(hash, now()).first();
}

async function me(req, env) {
  const s = await childSession(req, env);
  return respond(s ? {
    ok: true, authenticated: true, nickname: s.nickname, avatar: s.avatar,
    expiresIn: Math.max(0, s.expires_at - now()), childAIEnabled: false
  } : { ok: true, authenticated: false, childAIEnabled: false });
}

async function enter(req, env) {
  if (!sameOrigin(req)) return deny(403, 'origin_required', '來源驗證失敗。');
  const body = await readJson(req, 256);
  const code = String(body?.code ?? '').replace(/[\s-]/g, '');
  if (!/^[0-9]{8}$/.test(code)) return deny(400, 'invalid_code', '請輸入 8 位數代碼。');
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await limit(env, 'enter-ip:' + ip, 20, 3600) || !await limit(env, 'enter-all', 600, 3600))
    return deny(429, 'try_later', '嘗試次數過多，請請爸爸媽媽稍後再試。');
  const t = now();
  const consumed = await env.DB.prepare(
    'DELETE FROM child_entry_codes WHERE code_hash=? AND expires_at>? ' +
    'RETURNING child_id,session_minutes'
  ).bind(await entryCodeHash(env, code), t).first();
  const refused = deny(401, 'invalid_code', '代碼錯誤或已過期，請爸爸媽媽重新產生。');
  if (!consumed) return refused;
  const child = await env.DB.prepare(
    'SELECT c.id,c.guardian_user_id,c.nickname,c.avatar FROM children c ' +
    'JOIN guardian_declarations g ON g.user_id=c.guardian_user_id ' +
    `WHERE c.id=? AND c.revoked_at IS NULL AND ${ACTIVE_DECLARATION}`
  ).bind(consumed.child_id).first();
  if (!child) return refused;
  const minutes = Math.min(60, Math.max(1, Number(consumed.session_minutes) || 0));
  const token = randomHex(32), expires = t + minutes * 60;
  // One device per child at a time.
  await env.DB.prepare('DELETE FROM child_sessions WHERE child_id=?').bind(child.id).run();
  await env.DB.prepare(
    'INSERT INTO child_sessions(token_hash,child_id,guardian_user_id,expires_at,created_at) VALUES(?,?,?,?,?)'
  ).bind(await childTokenHash(env, token), child.id, child.guardian_user_id, expires, t).run();
  return respond(
    { ok: true, nickname: child.nickname, avatar: child.avatar, expiresIn: minutes * 60 },
    200, { 'set-cookie': cookie(token, minutes * 60) }
  );
}

async function logout(req, env) {
  if (!sameOrigin(req)) return deny(403, 'origin_required', '來源驗證失敗。');
  const s = await childSession(req, env);
  if (s) await env.DB.prepare('DELETE FROM child_sessions WHERE token_hash=?').bind(s.token_hash).run();
  return respond({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
}

async function assets(req, env, extra = {}) {
  if (!env.ASSETS) return deny(404, 'assets_missing', '靜態資源尚未設定。');
  const res = await env.ASSETS.fetch(req);
  const out = new Response(res.body, res);
  out.headers.set('x-content-type-options', 'nosniff');
  out.headers.set('referrer-policy', 'no-referrer');
  out.headers.set('x-frame-options', 'DENY');
  for (const [k, v] of Object.entries(extra)) out.headers.set(k, v);
  return out;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      if (path.startsWith('/api/')) {
        if (!ready(env)) return deny(503, 'not_configured', '孩童入口尚未啟用。');
        if (path === '/api/kids/me' && req.method === 'GET') return await me(req, env);
        if (path === '/api/kids/health' && req.method === 'GET') {
          // Fingerprint only (never the secret). Readable cross-origin by the adult site's check page only.
          const origin = req.headers.get('origin') || '';
          const adultOk = origin && (origin === String(env.ADULT_ORIGIN || '').trim() ||
            /^https:\/\/neluun-v95-auth-test\.[a-z0-9-]+\.workers\.dev$/.test(origin));
          return respond({ ok: true, pepper: await pepperFingerprint(env) }, 200,
            adultOk ? { 'access-control-allow-origin': origin } : {});
        }
        if (path === '/api/kids/enter' && req.method === 'POST') return await enter(req, env);
        if (path === '/api/kids/logout' && req.method === 'POST') return await logout(req, env);
        if (path === '/api/kids/chat')
          return deny(403, 'child_ai_disabled', '學習助理 AI 尚未開放。');
        // No adult API of any kind exists on this origin.
        return deny(404, 'unknown_endpoint', '沒有這個 API。');
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') return deny(405, 'method_not_allowed', '方法不支援。');
      // The learning space is only served to a live, parent-approved child session.
      if (path === '/learn.html' || path === '/learn') {
        const s = await childSession(req, env);
        if (!s) return new Response(null, {
          status: 302, headers: { location: '/', 'cache-control': 'no-store' }
        });
        // Asset path without ".html": default html_handling rewrites it to learn.html (no redirect).
        const learn = new Request(new URL('/learn', url), req);
        return await assets(learn, env, { 'cache-control': 'no-store' });
      }
      return await assets(req, env, { 'cache-control': 'no-cache' });
    } catch {
      return deny(503, 'service_unavailable', '伺服器暫時無法完成要求。');
    }
  }
};
