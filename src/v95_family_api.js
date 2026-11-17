/**
 * NELUUN V9.5: ADULT-side family routes (child profiles + parent-approved sessions).
 * Called only from v95_parent_api.js AFTER the adult session is verified and the
 * parent step-up grant is active. A child session is never accepted here.
 * Legal note: mailbox control is not proof of legal guardianship; the guardian
 * declaration remains a self-declaration.
 */
import {
  AVATARS, CODE_TTL, MAX_CHILDREN, cleanMinutes, cleanNickname,
  deny, entryCodeHash, limit, now, randomDigits, readJson, respond
} from './v95_family_shared.js';

export const FAMILY_ROUTES = {
  '/api/family/children': 'GET',
  '/api/family/children/create': 'POST',
  '/api/family/children/remove': 'POST',
  '/api/family/companion/start': 'POST',
  '/api/family/companion/end': 'POST'
};

const hasDeclaration = async (env, userId) => {
  const row = await env.DB.prepare(
    'SELECT declared_at,withdrawn_at FROM guardian_declarations g WHERE g.user_id=?'
  ).bind(userId).first();
  return !!row?.declared_at && !row.withdrawn_at;
};

const ownChild = (env, userId, childId) => env.DB.prepare(
  'SELECT id,nickname,avatar FROM children WHERE id=? AND guardian_user_id=? AND revoked_at IS NULL'
).bind(String(childId || ''), userId).first();

/** Remove every code and session of one child (or of every child of a guardian). */
export async function revokeChildAccess(env, { childId = null, guardianId = null }) {
  if (childId) {
    await env.DB.prepare('DELETE FROM child_sessions WHERE child_id=?').bind(childId).run();
    await env.DB.prepare('DELETE FROM child_entry_codes WHERE child_id=?').bind(childId).run();
  } else if (guardianId) {
    await env.DB.prepare('DELETE FROM child_sessions WHERE guardian_user_id=?').bind(guardianId).run();
    await env.DB.prepare('DELETE FROM child_entry_codes WHERE guardian_user_id=?').bind(guardianId).run();
  }
}

async function listChildren(env, user) {
  const t = now();
  const rows = await env.DB.prepare(
    'SELECT c.id,c.nickname,c.avatar,' +
    '(SELECT MAX(s.expires_at) FROM child_sessions s WHERE s.child_id=c.id AND s.expires_at>?) AS active_until ' +
    'FROM children c WHERE c.guardian_user_id=? AND c.revoked_at IS NULL ORDER BY c.created_at'
  ).bind(t, user.id).all();
  return respond({
    ok: true,
    declaration: await hasDeclaration(env, user.id),
    maxChildren: MAX_CHILDREN,
    children: (rows.results || []).map(r => ({
      id: r.id, nickname: r.nickname, avatar: r.avatar,
      activeFor: r.active_until ? Math.max(0, r.active_until - t) : 0
    }))
  });
}

async function createChild(req, env, user) {
  const body = await readJson(req);
  if (!body) return deny(400, 'bad_request', '資料格式不正確。');
  const nickname = cleanNickname(body.nickname);
  if (!nickname) return deny(400, 'invalid_nickname', '暱稱請用 1 到 12 個字，不要放真實姓名或信箱。');
  if (!AVATARS.includes(body.avatar)) return deny(400, 'invalid_avatar', '請選擇頭像。');
  if (!await hasDeclaration(env, user.id))
    return deny(403, 'declaration_required', '請先勾選監護人聲明，才能建立孩子檔案。');
  if (!await limit(env, 'create:' + user.id, 10, 3600))
    return deny(429, 'try_later', '建立次數過多，請稍後再試。');
  const count = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM children WHERE guardian_user_id=? AND revoked_at IS NULL'
  ).bind(user.id).first();
  if ((count?.n || 0) >= MAX_CHILDREN) return deny(409, 'too_many_children', '孩子檔案已達上限。');
  const id = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO children(id,guardian_user_id,nickname,avatar,created_at) VALUES(?,?,?,?,?)'
  ).bind(id, user.id, nickname, body.avatar, now()).run();
  return respond({ ok: true, child: { id, nickname, avatar: body.avatar, activeFor: 0 } });
}

async function removeChild(req, env, user) {
  const body = await readJson(req);
  const child = body && await ownChild(env, user.id, body.childId);
  if (!child) return deny(404, 'child_not_found', '找不到這個孩子檔案。');
  await revokeChildAccess(env, { childId: child.id });
  await env.DB.prepare('UPDATE children SET revoked_at=? WHERE id=? AND guardian_user_id=?')
    .bind(now(), child.id, user.id).run();
  return respond({ ok: true });
}

async function startCompanion(req, env, user) {
  const body = await readJson(req);
  const child = body && await ownChild(env, user.id, body.childId);
  if (!child) return deny(404, 'child_not_found', '找不到這個孩子檔案。');
  const minutes = cleanMinutes(body.minutes);
  if (!minutes) return deny(400, 'invalid_minutes', '陪同時間只能選 30、45 或 60 分鐘。');
  if (!await hasDeclaration(env, user.id))
    return deny(403, 'declaration_required', '請先勾選監護人聲明。');
  if (!await limit(env, 'start:' + user.id, 10, 3600))
    return deny(429, 'try_later', '產生代碼次數過多，請稍後再試。');
  const t = now();
  // Housekeeping, then at most one live code per child.
  await env.DB.prepare('DELETE FROM child_entry_codes WHERE expires_at<=?').bind(t).run();
  await env.DB.prepare('DELETE FROM child_sessions WHERE expires_at<=?').bind(t).run();
  await env.DB.prepare('DELETE FROM child_entry_codes WHERE child_id=?').bind(child.id).run();
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = randomDigits(8);
    const hash = await entryCodeHash(env, code);
    try {
      await env.DB.prepare(
        'INSERT INTO child_entry_codes(code_hash,child_id,guardian_user_id,session_minutes,expires_at,created_at) ' +
        'VALUES(?,?,?,?,?,?)'
      ).bind(hash, child.id, user.id, minutes, t + CODE_TTL, t).run();
      return respond({
        ok: true, code, codeExpiresIn: CODE_TTL, sessionMinutes: minutes,
        notice: '請陪在孩子身旁，把這組代碼輸入孩子入口。代碼只能用一次。'
      });
    } catch { /* hash collision with another live code: draw again */ }
  }
  return deny(503, 'service_unavailable', '暫時無法產生代碼，請再試一次。');
}

async function endCompanion(req, env, user) {
  const body = await readJson(req);
  const child = body && await ownChild(env, user.id, body.childId);
  if (!child) return deny(404, 'child_not_found', '找不到這個孩子檔案。');
  await revokeChildAccess(env, { childId: child.id });
  return respond({ ok: true });
}

export async function handleFamily(req, env, user, pathname) {
  if (pathname === '/api/family/children') return listChildren(env, user);
  if (pathname === '/api/family/children/create') return createChild(req, env, user);
  if (pathname === '/api/family/children/remove') return removeChild(req, env, user);
  if (pathname === '/api/family/companion/start') return startCompanion(req, env, user);
  if (pathname === '/api/family/companion/end') return endCompanion(req, env, user);
  return deny(404, 'unknown_endpoint', '找不到 API。');
}

