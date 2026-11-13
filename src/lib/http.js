// Small HTTP helpers. From perchlight-hooks src/lib/http.js (itself from
// perchlight-status), plus the report page's security headers.

export const BASE_HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

export function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...BASE_HEADERS, ...extraHeaders } });
}

/** An API error: { ok: false, error }. */
export function fail(status, error, extra = {}) {
  return json({ ok: false, error, ...extra }, status);
}

export function text(body, status = 200, extraHeaders = {}) {
  return new Response(body, { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...BASE_HEADERS, ...extraHeaders } });
}

/**
 * Headers for every HTML page this Worker serves (docs/SDD.md, "API"). They
 * pass this tool's own header checks: HSTS 1 year, Referrer-Policy,
 * Permissions-Policy, a CSP with no unsafe-* and frame-ancestors, nosniff.
 */
export const PAGE_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Strict-Transport-Security": "max-age=31536000",
  "X-Frame-Options": "DENY",
  ...BASE_HEADERS,
};

export function html(body, status = 200, extraHeaders = {}) {
  return new Response(body, { status, headers: { ...PAGE_HEADERS, ...extraHeaders } });
}

/** @param {unknown} s */
export function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

/** Reads a JSON object of at most maxBytes, or null. */
export async function readJson(request, maxBytes = 16 * 1024) {
  const len = Number(request.headers.get("Content-Length") ?? "0");
  if (len > maxBytes) return null;
  if (!request.body) return {};
  const r = await readCapped(request.body, maxBytes);
  if (r.over) return null;
  try {
    const v = JSON.parse(new TextDecoder().decode(r.bytes) || "{}");
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/**
 * Reads a stream up to `max` bytes. Stops (and cancels) beyond it.
 * `deadline` (ms since epoch) cuts a slow stream short.
 * @returns {Promise<{ bytes: Uint8Array, size: number, over: boolean }>}
 */
export async function readCapped(stream, max, deadline = Infinity) {
  if (!stream) return { bytes: new Uint8Array(0), size: 0, over: false };
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  let over = false;
  for (;;) {
    if (Date.now() > deadline) {
      await reader.cancel().catch(() => {});
      throw Object.assign(new Error("response body took too long"), { name: "TimeoutError" });
    }
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > max) {
      chunks.push(value.subarray(0, max - size));
      size = max;
      over = true;
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return { bytes: all, size, over };
}

/** "YYYY-MM-DD HH:MM:SS" (UTC), the format D1's datetime('now') uses. */
export function sqlTime(ms = Date.now()) {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19);
}

export function utcDay(ms = Date.now()) {
  return new Date(ms).toISOString().slice(0, 10);
}

export const parseJson = (s, d) => {
  try {
    return s == null ? d : JSON.parse(s);
  } catch {
    return d;
  }
};

export const errText = (err) => (err instanceof Error ? err.message : String(err));
