/**
 * NELUUN V9.5: helpers shared by the ADULT family routes and the CHILD Worker.
 * Keep this file free of any adult-session logic: the child Worker bundles it too.
 */
export const KID_COOKIE = 'neluun_kid';
export const CODE_TTL = 600;                 // an entry code is valid for 10 minutes
export const SESSION_CHOICES = [30, 45, 60]; // minutes a parent may grant, hard maximum 60
export const MAX_CHILDREN = 6;
export const AVATARS = ['cat', 'rabbit', 'bear', 'fox', 'panda', 'owl'];
export const now = () => Math.floor(Date.now() / 1000);

const baseHeaders = {
  'cache-control': 'no-store', 'pragma': 'no-cache',
  'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY', 'vary': 'Cookie'
};
export const respond = (body, status = 200, other = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', ...baseHeaders, ...other }
});
export const deny = (status, error, message) => respond({ ok: false, error, message }, status);

export const sha = async value => Array.from(new Uint8Array(await crypto.subtle.digest(
  'SHA-256', new TextEncoder().encode(value)
)), b => b.toString(16).padStart(2, '0')).join('');

export const randomHex = n => Array.from(crypto.getRandomValues(new Uint8Array(n)),
  b => b.toString(16).padStart(2, '0')).join('');

/** Uniform decimal code of `length` digits (rejection sampling, no modulo bias). */
export function randomDigits(length = 8) {
  const space = 10 ** length;
  const ceiling = Math.floor(4294967296 / space) * space;
  if (ceiling === 0) throw Error('code too long');
  let n;
  do { n = crypto.getRandomValues(new Uint32Array(1))[0]; } while (n >= ceiling);
  return String(n % space).padStart(length, '0');
}

export function sameOrigin(req) {
  const origin = req.headers.get('origin');
  const type = (req.headers.get('content-type') || '').toLowerCase();
  return !!origin && origin === new URL(req.url).origin && type.startsWith('application/json');
}

/** Small JSON body reader with a hard size cap. Returns null on any malformed body. */
export async function readJson(req, max = 1024) {
  const len = Number(req.headers.get('content-length') || 0);
  if (len > max) return null;
  const raw = await req.text();
  if (raw.length > max) return null;
  try {
    const value = JSON.parse(raw);
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch { return null; }
}

/** Fixed-window counter in D1 (same table the adult Worker already uses). */
export async function limit(env, label, max, seconds) {
  const window = Math.floor(now() / seconds);
  const key = await sha(env.OTP_PEPPER + ':family:' + label + ':' + window);
  const row = await env.DB.prepare(
    'INSERT INTO rate_limits(bucket,hits,expires_at) VALUES(?,1,?) ' +
    'ON CONFLICT(bucket) DO UPDATE SET hits=hits+1 WHERE hits<? RETURNING hits'
  ).bind(key, (window + 1) * seconds, max).first();
  return !!row;
}

export const entryCodeHash = (env, code) => sha(env.OTP_PEPPER + ':child-entry:' + code);
export const childTokenHash = (env, token) => sha(env.SESSION_PEPPER + ':child-session:' + token);

/** Nickname: 1-12 letters/digits/space/_/-, no '@' so it can never be an email address. */
export function cleanNickname(value) {
  const raw = String(value ?? '');
  if (/\p{C}/u.test(raw)) return null; // control / invisible characters are refused, not rewritten
  const text = raw.normalize('NFKC').trim().replace(/ +/g, ' ');
  return /^[\p{L}\p{N} _-]{1,12}$/u.test(text) ? text : null;
}

/** Minutes of child access a parent can grant; anything else is refused. */
export function cleanMinutes(value) {
  const n = Number(value);
  return SESSION_CHOICES.includes(n) ? n : null;
}

/** A guardian declaration must be active before any child access is possible. */
export const ACTIVE_DECLARATION =
  'g.declared_at IS NOT NULL AND g.withdrawn_at IS NULL';
