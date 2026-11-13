// Hashes, HMAC, random tokens and constant-time comparison.
// Copied from perchlight-hooks src/lib/crypto.js (itself from perchlight-status):
// hex / sha256Hex / hmacHex / safeEqual / randomId / randomToken / sortableId / hash32.

const enc = new TextEncoder();

export function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function toBase64(bytes) {
  let bin = "";
  const u = new Uint8Array(bytes);
  for (let i = 0; i < u.length; i += 0x8000) bin += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(bin);
}

export async function sha256Hex(data) {
  return hex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
}

export async function hmacHex(key, message) {
  const k = await crypto.subtle.importKey("raw", enc.encode(String(key)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode(String(message))));
}

/** Constant-time comparison of two strings (hashes both first, so lengths don't leak either). */
export async function safeEqual(a, b) {
  const [x, y] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(String(a))), crypto.subtle.digest("SHA-256", enc.encode(String(b)))]);
  return crypto.subtle.timingSafeEqual(x, y);
}

const ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"; // 32 symbols: no 0/o, 1/l

/** "<prefix>_" + 16 random characters (80 bits): an id, not a secret. */
export function randomId(prefix) {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let s = "";
  for (const b of bytes) s += ALPHABET[b & 31];
  return `${prefix}_${s}`;
}

/** 128 random bits, 22 base64url characters (verification tokens, share tokens). */
export function randomToken() {
  return toBase64(crypto.getRandomValues(new Uint8Array(16))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const isToken = (s) => typeof s === "string" && /^[A-Za-z0-9_-]{22}$/.test(s);

let lastMs = 0;
let seq = 0;
/** A time-sortable id: 9 base-36 characters of milliseconds, a per-isolate sequence, then 6 random. */
export function sortableId(prefix, now = Date.now()) {
  const ms = Math.floor(now);
  seq = ms === lastMs ? seq + 1 : 0;
  lastMs = ms;
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  let r = "";
  for (const b of bytes) r += ALPHABET[b & 31];
  return `${prefix}${ms.toString(36).padStart(9, "0")}${Math.min(seq, 46655).toString(36).padStart(3, "0")}${r}`;
}

/** FNV-1a, for the config hash. */
export function hash32(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}
