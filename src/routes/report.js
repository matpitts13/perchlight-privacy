// GET /r/:site: the HTML report (decision 4: admin only by default, or a
// per-site share link). Access: the admin token as a Bearer header, a
// session cookie set by the login form (an HMAC of the admin token, never
// the token itself), or ?s=<share token> (stored hashed, compared in
// constant time, revocable). No JavaScript; everything is escaped text.
import { html, text, readCapped } from "../lib/http.js";
import { safeEqual, sha256Hex, hmacHex } from "../lib/crypto.js";
import { buildReport, renderReport, renderLogin, STYLE } from "../lib/report.js";
import { isAdmin } from "./api.js";

export const SESSION_COOKIE = "pp_session";
const SESSION_MAX_AGE = 8 * 3600;

async function sessionValue(env) {
  return hmacHex(env.ADMIN_TOKEN, "perchlight-privacy report session v1");
}

function cookie(request, name) {
  for (const part of (request.headers.get("Cookie") ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

async function hasSession(request, env) {
  const c = cookie(request, SESSION_COOKIE);
  if (!c || String(env.ADMIN_TOKEN ?? "").length < 16) return false;
  return safeEqual(c, await sessionValue(env));
}

export async function handleReport(request, app, path) {
  const { env } = app;
  if (path === "/r/style.css") return new Response(STYLE, { headers: { "Content-Type": "text/css; charset=utf-8", "Cache-Control": "public, max-age=3600", "X-Content-Type-Options": "nosniff" } });
  if (path === "/r/login") {
    if (request.method !== "POST") return text("method not allowed\n", 405);
    if (String(env.ADMIN_TOKEN ?? "").length < 16) return text("Set the ADMIN_TOKEN secret first.\n", 503);
    const r = await readCapped(request.body, 4096);
    if (r.over) return text("too large\n", 413);
    const form = new URLSearchParams(new TextDecoder().decode(r.bytes));
    const site = (form.get("site") ?? "").slice(0, 64);
    const ok = await safeEqual(form.get("token") ?? "", env.ADMIN_TOKEN);
    if (!ok) return html(renderLogin(site, "That isn't the admin token."), 401);
    const target = /^[a-z0-9][a-z0-9-]{0,63}$/.test(site) ? `/r/${site}` : "/r/";
    return new Response(null, {
      status: 303,
      headers: {
        Location: target,
        "Set-Cookie": `${SESSION_COOKIE}=${await sessionValue(env)}; Path=/r/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`,
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }
  const m = /^\/r\/([a-z0-9][a-z0-9-]{0,31})$/.exec(path);
  if (!m || request.method !== "GET") return html(renderLogin("", ""), 404);
  const siteId = m[1];
  const url = new URL(request.url);
  let allowed = (await isAdmin(request, env)) || (await hasSession(request, env));
  if (!allowed) {
    const s = url.searchParams.get("s");
    if (s && s.length <= 64) {
      const row = await env.DB.prepare("SELECT share_token_hash FROM sites WHERE id = ?").bind(siteId).first();
      // Hash, then compare in constant time; a missing site or link compares against a dummy.
      allowed = await safeEqual(await sha256Hex(s), row?.share_token_hash ?? "no share link");
      allowed = allowed && Boolean(row?.share_token_hash);
    }
  }
  if (!allowed) return html(renderLogin(siteId), 401);
  const report = await buildReport(env.DB, siteId);
  if (!report) return html(renderLogin(siteId, "No such site."), 404);
  return html(renderReport(report));
}
