// Real SQLite (node:sqlite) runs the real migrations and the real SQL of both Workers.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import adult from '../src/v95_parent_api.js';
import kids from '../src/v95_kids_api.js';

const ADULT_ORIGIN = 'https://neluun-v95-auth-test.example.workers.dev';
const KIDS_ORIGIN = 'https://neluun-v95-kids-test.example.workers.dev';
const sidA = 'a'.repeat(64), sidB = 'b'.repeat(64);
const now = () => Math.floor(Date.now() / 1000);
const sha = async s => Array.from(new Uint8Array(await crypto.subtle.digest(
  'SHA-256', new TextEncoder().encode(s))), x => x.toString(16).padStart(2, '0')).join('');

function d1(db) {
  return { prepare(sql) {
    const st = db.prepare(sql);
    return { bind: (...a) => ({
      first: async () => st.get(...a) ?? null,
      run: async () => { st.run(...a); return { success: true }; },
      all: async () => ({ results: st.all(...a) })
    }) };
  } };
}
const ENV = { SESSION_PEPPER: 'test-session-pepper', OTP_PEPPER: 'test-otp-pepper',
  RESEND_API_KEY: 'fake', EMAIL_FROM: 'NELUUN <noreply@example.org>',
  PARENT_STEP_UP_ENABLED: 'true', AI_ENABLED: 'false' };

async function setup({ declare = true } = {}) {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const f of ['0001_init', '0002_parent_access', '0003_family_children', '0004_parent_totp'])
    db.exec(readFileSync(new URL(`../migrations/${f}.sql`, import.meta.url), 'utf8'));
  const assetsSeen = [];
  const env = { ...ENV, DB: d1(db), ASSETS: { fetch: async req => {
    const p = new URL(req.url).pathname; assetsSeen.push(p);
    return new Response('ASSET:' + p, { status: 200 });
  } } };
  const t = now();
  for (const [id, email, sid] of [['user-a', 'a@example.org', sidA], ['user-b', 'b@example.org', sidB]]) {
    db.prepare('INSERT INTO users(id,email,created_at) VALUES(?,?,?)').run(id, email, t);
    const hash = await sha(ENV.SESSION_PEPPER + ':' + sid);
    db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').run(hash, id, t + 3600, t);
  }
  if (declare) db.prepare('INSERT INTO guardian_declarations(user_id,declared_at,withdrawn_at,policy_version) VALUES(?,?,NULL,?)').run('user-a', t, 'v1');
  return { db, env, assetsSeen };
}
async function unlock(db, sid = sidA) {
  const hash = await sha(ENV.SESSION_PEPPER + ':' + sid);
  db.prepare('INSERT OR REPLACE INTO parent_grants(session_hash,expires_at,created_at) VALUES(?,?,?)').run(hash, now() + 600, now());
}
function req(origin, path, { method = 'GET', cookie, body, reqOrigin = origin, type = 'application/json', ip = '203.0.113.5' } = {}) {
  return new Request(origin + path, { method,
    headers: { ...(cookie ? { cookie } : {}), 'cf-connecting-ip': ip,
      ...(method === 'POST' ? { origin: reqOrigin, 'content-type': type } : {}) },
    ...(method === 'POST' ? { body: JSON.stringify(body ?? {}) } : {}) });
}
const A = (env, path, o = {}) => adult.fetch(req(ADULT_ORIGIN, path, { cookie: 'neluun_sid=' + sidA, ...o }), env);
const K = (env, path, o = {}) => kids.fetch(req(KIDS_ORIGIN, path, o), env);
const json = async r => ({ status: r.status, body: await r.json().catch(() => null), headers: r.headers });

async function makeChild(env, nickname = 'Mimi') {
  const r = await json(await A(env, '/api/family/children/create', { method: 'POST', body: { nickname, avatar: 'cat' } }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body.child.id;
}
async function enterWithCode(env, childId, minutes = 45, ip) {
  const s = await json(await A(env, '/api/family/companion/start', { method: 'POST', body: { childId, minutes } }));
  assert.equal(s.status, 200, JSON.stringify(s.body));
  const e = await K(env, '/api/kids/enter', { method: 'POST', body: { code: s.body.code }, ip });
  const out = await json(e);
  const cookie = (e.headers.get('set-cookie') || '').split(';')[0];
  return { start: s.body, enter: out, cookie, setCookie: e.headers.get('set-cookie') };
}

test('Family routes need a session, step-up and the feature flag', async () => {
  const { env, db } = await setup();
  assert.equal((await A(env, '/api/family/children', { cookie: undefined })).status, 401);
  assert.equal((await A(env, '/api/family/children')).status, 403);          // signed in, not unlocked
  await unlock(db);
  assert.equal((await A(env, '/api/family/children')).status, 200);
  assert.equal((await A(env, '/api/family/children', { cookie: 'neluun_sid=' + sidB })).status, 403);
  delete env.PARENT_STEP_UP_ENABLED;
  assert.equal((await A(env, '/api/family/children')).status, 503);
});

test('CSRF: cross-origin and non-JSON family writes are refused', async () => {
  const { env, db } = await setup(); await unlock(db);
  const bad = { method: 'POST', body: { nickname: 'x', avatar: 'cat' } };
  assert.equal((await A(env, '/api/family/children/create', { ...bad, reqOrigin: 'https://evil.example' })).status, 403);
  assert.equal((await A(env, '/api/family/children/create', { ...bad, type: 'text/plain' })).status, 403);
  assert.equal((await A(env, '/api/family/nope', { method: 'POST' })).status, 404);
  assert.equal((await A(env, '/api/family/children', { method: 'POST' })).status, 405);
});

test('Child profile needs a guardian declaration and minimal, safe data', async () => {
  const { env, db } = await setup({ declare: false }); await unlock(db);
  const create = async body => json(await A(env, '/api/family/children/create', { method: 'POST', body }));
  assert.equal((await create({ nickname: 'Mimi', avatar: 'cat' })).body.error, 'declaration_required');
  db.prepare('INSERT INTO guardian_declarations(user_id,declared_at,withdrawn_at,policy_version) VALUES(?,?,NULL,?)').run('user-a', now(), 'v1');
  for (const nickname of ['mom@example.org', '', 'x'.repeat(13), '<b>hi</b>', 'a\nb', 123456789012345])
    assert.equal((await create({ nickname, avatar: 'cat' })).status, 400, String(nickname));
  assert.equal((await create({ nickname: 'Mimi', avatar: 'dragon' })).status, 400);
  assert.equal((await create({ nickname: '小米 2', avatar: 'owl' })).status, 200);
  const cols = db.prepare('PRAGMA table_info(children)').all().map(c => c.name).sort();
  assert.deepEqual(cols, ['avatar', 'created_at', 'guardian_user_id', 'id', 'nickname', 'revoked_at']);
});

test('At most six children per guardian', async () => {
  const { env, db } = await setup(); await unlock(db);
  for (let i = 0; i < 6; i++) await makeChild(env, 'kid' + i);
  const r = await json(await A(env, '/api/family/children/create', { method: 'POST', body: { nickname: 'seven', avatar: 'cat' } }));
  assert.equal(r.status, 409);
});

test('Entry code: 8 digits, stored hashed, one-time, expires, wrong code refused', async () => {
  const { env, db } = await setup(); await unlock(db);
  const child = await makeChild(env);
  const s = await json(await A(env, '/api/family/companion/start', { method: 'POST', body: { childId: child, minutes: 45 } }));
  assert.match(s.body.code, /^[0-9]{8}$/);
  const stored = JSON.stringify(db.prepare('SELECT * FROM child_entry_codes').all());
  assert.ok(!stored.includes(s.body.code), 'plain code must never be stored');
  assert.equal((await json(await K(env, '/api/kids/enter', { method: 'POST', body: { code: '00000000' } }))).status, 401);
  assert.equal((await json(await K(env, '/api/kids/enter', { method: 'POST', body: { code: '12ab' } }))).status, 400);
  const ok = await K(env, '/api/kids/enter', { method: 'POST', body: { code: s.body.code.slice(0, 4) + ' ' + s.body.code.slice(4) } });
  assert.equal(ok.status, 200);
  assert.equal((await json(await K(env, '/api/kids/enter', { method: 'POST', body: { code: s.body.code } }))).status, 401);
  // expiry
  const s2 = await json(await A(env, '/api/family/companion/start', { method: 'POST', body: { childId: child, minutes: 30 } }));
  db.prepare('UPDATE child_entry_codes SET expires_at=?').run(now() - 1);
  assert.equal((await json(await K(env, '/api/kids/enter', { method: 'POST', body: { code: s2.body.code } }))).status, 401);
});

test('Session time is chosen by the parent and capped at 60 minutes', async () => {
  const { env, db } = await setup(); await unlock(db);
  const child = await makeChild(env);
  for (const minutes of [0, 15, 90, 61, 'abc', null])
    assert.equal((await A(env, '/api/family/companion/start', { method: 'POST', body: { childId: child, minutes } })).status, 400, String(minutes));
  const r = await enterWithCode(env, child, 60);
  assert.equal(r.enter.status, 200);
  assert.ok(r.enter.body.expiresIn <= 3600);
  const row = db.prepare('SELECT expires_at-created_at AS span FROM child_sessions').get();
  assert.ok(row.span <= 3600 && row.span > 3500);
  for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Max-Age=3600']) assert.ok(r.setCookie.includes(flag), flag);
});

test('Child and adult sites cannot be crossed in either direction', async () => {
  const { env, db, assetsSeen } = await setup(); await unlock(db);
  const child = await makeChild(env);
  const { cookie, enter } = await enterWithCode(env, child);
  assert.equal(enter.status, 200); assert.match(cookie, /^neluun_kid=[a-f0-9]{64}$/);
  const token = cookie.split('=')[1];
  // child token presented to the adult site under the adult cookie name: no session
  const me = await json(await adult.fetch(req(ADULT_ORIGIN, '/api/me', { cookie: 'neluun_sid=' + token }), env));
  assert.equal(me.body.authenticated, false);
  assert.equal((await adult.fetch(req(ADULT_ORIGIN, '/api/family/children', { cookie: 'neluun_sid=' + token }), env)).status, 401);
  assert.equal((await adult.fetch(req(ADULT_ORIGIN, '/api/parent/status', { cookie: 'neluun_sid=' + token }), env)).status, 401);
  // adult cookie on the child site: nothing
  assert.equal((await json(await K(env, '/api/kids/me', { cookie: 'neluun_kid=' + sidA }))).body.authenticated, false);
  assert.equal((await K(env, '/learn', { cookie: 'neluun_sid=' + sidA })).status, 302);
  // adult site has no child API; child site has no adult API
  assert.equal((await A(env, '/api/kids/enter', { method: 'POST', body: { code: '12345678' } })).status, 404);
  for (const p of ['/api/me', '/api/parent/status', '/api/family/children', '/api/auth/request', '/api/chat', '/api/guardian/declare', '/api/adult/private/status'])
    assert.equal((await K(env, p, { cookie })).status, 404, p);
  assert.equal((await json(await K(env, '/api/kids/chat', { method: 'POST', cookie, body: { message: 'hi' } }))).body.error, 'child_ai_disabled');
  // learning page only with a live child session
  assert.equal((await K(env, '/learn')).status, 302);
  assert.equal((await K(env, '/learn.html')).status, 302);
  const page = await K(env, '/learn', { cookie });
  assert.equal(page.status, 200); assert.equal(await page.text(), 'ASSET:/learn');
  assert.equal(page.headers.get('cache-control'), 'no-store');
  assert.deepEqual(assetsSeen.filter(p => p !== '/learn'), []);
  // child cannot call adult-only routes even by sending an adult-looking origin
  assert.equal((await K(env, '/api/kids/enter', { method: 'POST', reqOrigin: 'https://evil.example', body: { code: '12345678' } })).status, 403);
});

test('Adult can end a session, delete a child, and cannot touch another family', async () => {
  const { env, db } = await setup(); await unlock(db);
  const child = await makeChild(env);
  let r = await enterWithCode(env, child);
  assert.equal((await json(await K(env, '/api/kids/me', { cookie: r.cookie }))).body.authenticated, true);
  const listed = (await json(await A(env, '/api/family/children'))).body;
  assert.equal(listed.declaration, true);
  assert.equal(listed.children.length, 1);
  assert.ok(listed.children[0].activeFor > 0 && listed.children[0].activeFor <= 2700);
  assert.ok(!JSON.stringify(listed).includes('guardian'), 'list must not leak guardian ids');
  // another guardian cannot start or end for this child
  await unlock(db, sidB);
  const other = o => adult.fetch(req(ADULT_ORIGIN, o.path, { method: 'POST', cookie: 'neluun_sid=' + sidB, body: o.body }), env);
  assert.equal((await other({ path: '/api/family/companion/start', body: { childId: child, minutes: 30 } })).status, 404);
  assert.equal((await other({ path: '/api/family/companion/end', body: { childId: child } })).status, 404);
  assert.equal((await other({ path: '/api/family/children/remove', body: { childId: child } })).status, 404);
  assert.equal((await json(await K(env, '/api/kids/me', { cookie: r.cookie }))).body.authenticated, true);
  // end companion
  assert.equal((await A(env, '/api/family/companion/end', { method: 'POST', body: { childId: child } })).status, 200);
  assert.equal((await json(await K(env, '/api/kids/me', { cookie: r.cookie }))).body.authenticated, false);
  // delete child: session and codes gone, code unusable
  const s = await json(await A(env, '/api/family/companion/start', { method: 'POST', body: { childId: child, minutes: 30 } }));
  assert.equal((await A(env, '/api/family/children/remove', { method: 'POST', body: { childId: child } })).status, 200);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM child_entry_codes').get().n, 0);
  assert.equal((await json(await K(env, '/api/kids/enter', { method: 'POST', body: { code: s.body.code } }))).status, 401);
  const list = await json(await A(env, '/api/family/children'));
  assert.deepEqual(list.body.children, []);
});

test('Withdrawing the guardian declaration ends every child session at once', async () => {
  const { env, db } = await setup(); await unlock(db);
  const c1 = await makeChild(env, 'one'), c2 = await makeChild(env, 'two');
  const a = await enterWithCode(env, c1), b = await enterWithCode(env, c2);
  const spare = await json(await A(env, '/api/family/companion/start', { method: 'POST', body: { childId: c1, minutes: 30 } }));
  const w = await A(env, '/api/guardian/withdraw', { method: 'POST' });
  assert.equal(w.status, 200);
  for (const r of [a, b]) assert.equal((await json(await K(env, '/api/kids/me', { cookie: r.cookie }))).body.authenticated, false);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM child_sessions').get().n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM child_entry_codes').get().n, 0);
  assert.equal((await json(await K(env, '/api/kids/enter', { method: 'POST', body: { code: spare.body.code } }))).status, 401);
});

test('Even without the cleanup, a withdrawn declaration blocks the child session', async () => {
  const { env, db } = await setup(); await unlock(db);
  const child = await makeChild(env);
  const r = await enterWithCode(env, child);
  db.prepare('UPDATE guardian_declarations SET withdrawn_at=? WHERE user_id=?').run(now(), 'user-a');
  assert.equal((await K(env, '/learn', { cookie: r.cookie })).status, 302);
});

test('Expired child session is refused; a new entry replaces the old device', async () => {
  const { env, db } = await setup(); await unlock(db);
  const child = await makeChild(env);
  const first = await enterWithCode(env, child);
  const second = await enterWithCode(env, child);
  assert.equal((await json(await K(env, '/api/kids/me', { cookie: first.cookie }))).body.authenticated, false);
  assert.equal((await json(await K(env, '/api/kids/me', { cookie: second.cookie }))).body.authenticated, true);
  db.prepare('UPDATE child_sessions SET expires_at=?').run(now() - 1);
  assert.equal((await json(await K(env, '/api/kids/me', { cookie: second.cookie }))).body.authenticated, false);
  assert.equal((await K(env, '/learn', { cookie: second.cookie })).status, 302);
});

test('Brute force on the child entry is rate limited per IP', async () => {
  const { env, db } = await setup(); await unlock(db);
  let last = 0;
  for (let i = 0; i < 21; i++)
    last = (await K(env, '/api/kids/enter', { method: 'POST', body: { code: String(10000000 + i) }, ip: '198.51.100.9' })).status;
  assert.equal(last, 429);
  assert.equal((await K(env, '/api/kids/enter', { method: 'POST', body: { code: '10000099' }, ip: '198.51.100.10' })).status, 401);
});

test('Child Worker is closed when secrets are missing, logout clears the session', async () => {
  const { env, db } = await setup(); await unlock(db);
  const child = await makeChild(env);
  const r = await enterWithCode(env, child);
  const out = await K(env, '/api/kids/logout', { method: 'POST', cookie: r.cookie });
  assert.equal(out.status, 200); assert.ok(out.headers.get('set-cookie').includes('Max-Age=0'));
  assert.equal((await json(await K(env, '/api/kids/me', { cookie: r.cookie }))).body.authenticated, false);
  delete env.SESSION_PEPPER;
  assert.equal((await K(env, '/api/kids/me')).status, 503);
});

// ---- Authenticator app (TOTP) -------------------------------------------------
import { hotp, STEP } from '../src/v95_totp.js';
const b32decode = s => { let bits = 0, v = 0; const out = [];
  for (const ch of s) { v = (v << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(ch); bits += 5;
    if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out); };
const P = async (env, path, body, o = {}) => json(await adult.fetch(req(ADULT_ORIGIN, path,
  { method: body === undefined ? 'GET' : 'POST', body, cookie: 'neluun_sid=' + sidA, ...o }), env));
async function codeAt(secretB32, offsetSteps = 0) {
  return hotp(b32decode(secretB32), Math.floor(Date.now() / 1000 / STEP) + offsetSteps);
}
async function enroll(env, db) {
  await unlock(db);
  const begin = await P(env, '/api/parent/totp/begin', {});
  assert.equal(begin.status, 200, JSON.stringify(begin.body));
  const done = await P(env, '/api/parent/totp/confirm', { code: await codeAt(begin.body.secret) });
  assert.equal(done.status, 200, JSON.stringify(done.body));
  return { secret: begin.body.secret, recovery: done.body.recoveryCodes, begin: begin.body };
}
async function lockAll(db) { db.prepare('DELETE FROM parent_grants').run(); }

test('TOTP: setup needs step-up, secret is encrypted at rest, uri is standard', async () => {
  const { env, db } = await setup();
  assert.equal((await P(env, '/api/parent/totp/begin', {})).status, 403);   // not unlocked
  const e = await enroll(env, db);
  assert.match(e.begin.uri, /^otpauth:\/\/totp\/NELUUN%3Aa%40example\.org\?secret=[A-Z2-7]{32}&issuer=NELUUN/);
  assert.equal(e.recovery.length, 8);
  const row = db.prepare('SELECT * FROM parent_totp WHERE user_id=?').get('user-a');
  assert.ok(row.confirmed_at);
  assert.ok(!row.secret_enc.includes(e.secret), 'secret must not be stored in plaintext');
  const rec = db.prepare('SELECT code_hash FROM parent_totp_recovery').all();
  assert.equal(rec.length, 8);
  for (const c of e.recovery) assert.ok(!rec.some(r => r.code_hash.includes(c)), 'recovery codes stored hashed only');
  assert.equal((await P(env, '/api/parent/totp/begin', {})).status, 409);   // already enrolled
});

test('TOTP: confirm rejects wrong code and does not enrol', async () => {
  const { env, db } = await setup(); await unlock(db);
  const b = await P(env, '/api/parent/totp/begin', {});
  const good = await codeAt(b.body.secret), bad = good === '000000' ? '111111' : '000000';
  assert.equal((await P(env, '/api/parent/totp/confirm', { code: bad })).status, 401);
  assert.equal((await P(env, '/api/parent/totp/status')).body.enrolled, false);
  assert.equal((await P(env, '/api/parent/totp/confirm', { code: 'abcdef' })).status, 400);
});

test('TOTP: once enrolled the grant comes only from the authenticator, not email', async () => {
  const { env, db } = await setup(); const e = await enroll(env, db); await lockAll(db);
  assert.equal((await P(env, '/api/parent/challenge', {})).body.error, 'use_totp');
  assert.equal((await P(env, '/api/parent/verify', { code: '123456' })).body.error, 'use_totp');
  assert.equal((await A(env, '/api/family/children')).status, 403);
  const ok = await P(env, '/api/parent/totp/verify', { code: await codeAt(e.secret, 1) });   // next step still accepted
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(ok.body.adultAccess, true); assert.ok(ok.body.expiresIn <= 600);
  assert.equal((await A(env, '/api/family/children')).status, 200);
});

test('TOTP: a used code cannot be replayed, older steps are rejected', async () => {
  const { env, db } = await setup(); const e = await enroll(env, db); await lockAll(db);
  const c = await codeAt(e.secret, 1);
  assert.equal((await P(env, '/api/parent/totp/verify', { code: c })).status, 200);
  await lockAll(db);
  assert.equal((await P(env, '/api/parent/totp/verify', { code: c })).status, 401);                 // replay
  assert.equal((await P(env, '/api/parent/totp/verify', { code: await codeAt(e.secret, 0) })).status, 401); // older than last_step
  assert.equal((await A(env, '/api/family/children')).status, 403);
});

test('TOTP: wrong codes are rate limited per user, then even the right code waits', async () => {
  const { env, db } = await setup(); const e = await enroll(env, db); await lockAll(db);
  const good = await codeAt(e.secret, 1), bad = good === '000000' ? '111111' : '000000';
  let last;
  for (let i = 0; i < 12; i++) last = await P(env, '/api/parent/totp/verify', { code: bad }, { ip: '198.51.100.' + i });
  assert.equal(last.status, 429);
  assert.equal((await P(env, '/api/parent/totp/verify', { code: good }, { ip: '198.51.100.99' })).status, 429);
});

test('TOTP: recovery code works once, unlocks, and is consumed', async () => {
  const { env, db } = await setup(); const e = await enroll(env, db); await lockAll(db);
  const r = await P(env, '/api/parent/totp/verify', { code: e.recovery[0] });
  assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.recoveryLeft, 7);
  await lockAll(db);
  assert.equal((await P(env, '/api/parent/totp/verify', { code: e.recovery[0] })).status, 401);
  assert.equal((await P(env, '/api/parent/totp/verify', { code: 'AAAAA-AAAAA' })).status, 401);
  assert.equal((await P(env, '/api/parent/totp/verify', { code: e.recovery[0].toLowerCase() + 'x' })).status, 400);
});

test('TOTP: another account cannot use this account\'s code or recovery codes', async () => {
  const { env, db } = await setup(); const e = await enroll(env, db); await lockAll(db);
  const asB = { cookie: 'neluun_sid=' + sidB };
  assert.equal((await P(env, '/api/parent/totp/verify', { code: await codeAt(e.secret, 1) }, asB)).status, 409); // B not enrolled
  db.prepare("INSERT INTO parent_totp(user_id,secret_enc,confirmed_at,last_step,created_at) VALUES('user-b','x',1,0,1)").run();
  assert.equal((await P(env, '/api/parent/totp/verify', { code: e.recovery[1] }, asB)).status, 401);
});

test('TOTP: removal needs an unlock; afterwards email step-up works again', async () => {
  const { env, db } = await setup(); await enroll(env, db); await lockAll(db);
  assert.equal((await P(env, '/api/parent/totp/remove', {})).status, 403);
  await unlock(db);
  assert.equal((await P(env, '/api/parent/totp/remove', {})).status, 200);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM parent_totp').get().n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM parent_totp_recovery').get().n, 0);
  const c = await P(env, '/api/parent/challenge', {});
  assert.notEqual(c.body.error, 'use_totp');
});

test('TOTP: CSRF and bad input are refused', async () => {
  const { env, db } = await setup(); await unlock(db);
  assert.equal((await P(env, '/api/parent/totp/begin', {}, { reqOrigin: 'https://evil.example' })).status, 403);
  assert.equal((await P(env, '/api/parent/totp/begin', {}, { type: 'text/plain' })).status, 403);
  assert.equal((await P(env, '/api/parent/totp/begin')).status, 405);
  assert.equal((await P(env, '/api/parent/totp/status', {})).status, 405);
  assert.equal((await P(env, '/api/parent/totp/verify', { code: 123456 })).status, 400);
  assert.equal((await P(env, '/api/parent/totp/verify', { code: 'x'.repeat(600) })).status, 400);
  assert.equal((await P(env, '/api/parent/totp/begin', {}, { cookie: undefined })).status, 401);
});

test('No step-up for a signed-in account without a guardian declaration, but family stays locked', async () => {
  const { env } = await setup({ declare: false });
  const s = await P(env, '/api/parent/status');
  assert.equal(s.body.adultAccess, true); assert.equal(s.body.stepUpRequired, false);
  assert.equal((await P(env, '/api/parent/status?strict=1')).body.adultAccess, false);
  assert.equal((await A(env, '/api/family/children')).status, 403);
});

test('Pepper fingerprint: same secret matches across Workers, whitespace is ignored, secret never exposed', async () => {
  const { env } = await setup();
  const a = await json(await A(env, '/api/parent/pepper-fp'));
  const k = await json(await K(env, '/api/kids/health'));
  assert.equal(a.status, 200); assert.equal(k.status, 200);
  assert.equal(a.body.pepper, k.body.pepper); assert.match(a.body.pepper, /^[0-9a-f]{6}$/);
  assert.ok(!JSON.stringify(a.body).includes(ENV.OTP_PEPPER));
  const padded = { ...env, OTP_PEPPER: ' \n' + ENV.OTP_PEPPER + '\n ' };
  assert.equal((await json(await K(padded, '/api/kids/health'))).body.pepper, a.body.pepper);
  const other = { ...env, OTP_PEPPER: 'a-different-secret' };
  assert.notEqual((await json(await K(other, '/api/kids/health'))).body.pepper, a.body.pepper);
  assert.equal((await A(env, '/api/parent/pepper-fp', { cookie: undefined })).status, 401);
});

test('Child entry code still works when one Worker has a padded OTP_PEPPER', async () => {
  const { env, db } = await setup(); await unlock(db);
  const id = await makeChild(env);
  const s = await json(await A(env, '/api/family/companion/start', { method: 'POST', body: { childId: id, minutes: 30 } }));
  const kidsEnv = { ...env, OTP_PEPPER: env.OTP_PEPPER + '\n' };
  const r = await json(await K(kidsEnv, '/api/kids/enter', { method: 'POST', body: { code: s.body.code } }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
});

test('Kids health is cross-origin readable only from the adult site, and exposes the fingerprint only', async () => {
  const { env } = await setup();
  const ask = origin => kids.fetch(new Request(KIDS_ORIGIN + '/api/kids/health', {
    headers: origin ? { origin } : {} }), env);
  const ok = await ask(ADULT_ORIGIN);
  assert.equal(ok.headers.get('access-control-allow-origin'), ADULT_ORIGIN);
  const body = await ok.json(); assert.match(body.pepper, /^[0-9a-f]{6}$/);
  assert.ok(!JSON.stringify(body).includes(ENV.OTP_PEPPER));
  assert.equal((await ask('https://evil.example')).headers.get('access-control-allow-origin'), null);
  assert.equal((await ask(null)).headers.get('access-control-allow-origin'), null);
});
