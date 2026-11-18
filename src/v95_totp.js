/**
 * RFC 6238 TOTP (SHA-1, 6 digits, 30 s) with WebCrypto only. No dependencies.
 * Secrets are AES-GCM encrypted at rest with a key derived from OTP_PEPPER.
 */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // 31 chars, no 0/O/1/I/L
const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...b));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export const STEP = 30;
export const newSecret = () => crypto.getRandomValues(new Uint8Array(20));
export function base32(bytes) {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
export async function hotp(secret, counter) {
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const msg = new ArrayBuffer(8), view = new DataView(msg);
  view.setUint32(0, Math.floor(counter / 4294967296));
  view.setUint32(4, counter >>> 0);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const o = h[19] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}
/** Returns the matching time step (number) within +-1 step, or null. Constant-ish time per candidate. */
export async function matchStep(secret, code, nowSeconds, lastStep = 0) {
  const current = Math.floor(nowSeconds / STEP);
  let hit = null;
  for (const step of [current - 1, current, current + 1]) {
    const expected = await hotp(secret, step);
    let diff = 0;
    for (let i = 0; i < 6; i++) diff |= expected.charCodeAt(i) ^ code.charCodeAt(i);
    if (diff === 0 && step > lastStep) hit = hit === null ? step : Math.max(hit, step);
  }
  return hit;
}
async function aesKey(pepper) {
  const raw = await crypto.subtle.digest('SHA-256', enc.encode(pepper + ':totp-secret-key'));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function sealSecret(pepper, userId, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(userId) }, await aesKey(pepper), secret));
  return b64(iv) + '.' + b64(ct);
}
export async function openSecret(pepper, userId, sealed) {
  const [iv, ct] = String(sealed).split('.');
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(iv), additionalData: enc.encode(userId) }, await aesKey(pepper), unb64(ct)));
}
export function otpauthUri(email, secretBase32) {
  const label = encodeURIComponent('NELUUN:' + email);
  return 'otpauth://totp/' + label + '?secret=' + secretBase32 +
    '&issuer=NELUUN&algorithm=SHA1&digits=6&period=30';
}
export function recoveryCode() {
  let out = '';
  while (out.length < 10) {
    const b = crypto.getRandomValues(new Uint8Array(16));
    for (const x of b) { if (x < 248 && out.length < 10) out += RECOVERY_ALPHABET[x % 31]; }
  }
  return out.slice(0, 5) + '-' + out.slice(5);
}
export const RECOVERY_RE = /^[A-HJ-KM-NP-Z2-9]{5}-[A-HJ-KM-NP-Z2-9]{5}$/;
