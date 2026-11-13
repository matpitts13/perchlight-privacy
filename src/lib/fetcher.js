// safeFetch: the ONE function every request to your site goes through
// (docs/SDD.md, "Security (SSRF)"). Per hop:
//   1. static URL rules (https only; http only for the redirect check; no
//      user info; port 443/80; no IP literals; no local or reserved names),
//   2. the host must be inside the site's verified scope (a redirect to an
//      unverified host is NOT followed and reported as "offsite"),
//   3. the first time a host is fetched in a scan, its A/AAAA answers are
//      re-resolved over DoH and any private address refuses it,
//   4. one subrequest is reserved from the budget,
//   5. fetch with redirect: "manual", no cookies, a time cap for the whole
//      chain including the body, and the body read to at most `maxBytes`.
// Redirects are followed by hand, at most 5 hops, each checked from step 1.
import { net } from "./net.js";
import { spend, COST } from "./budget.js";
import { readCapped, errText } from "./http.js";
import { checkUrl, inScope, normHost } from "./ssrf.js";
import { checkResolves } from "./dns.js";

export const MAX_HOPS = COST.maxHops;
export const PAGE_BYTES = 2 * 1024 * 1024;
export const FETCH_TIMEOUT_MS = 15_000;

/**
 * Browser-like by default (decision 7), with a header the owner can allow in
 * WAF rules; or an honest User-Agent.
 */
export function requestHeaders(site, tokenTag) {
  const ua =
    site.userAgent === "honest"
      ? "perchlight-privacy/0.1 (+https://github.com/matpitts13/perchlight-privacy)"
      : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
  return {
    "User-Agent": ua,
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en",
    "X-Perchlight-Privacy": tokenTag,
  };
}

/**
 * @param {string} raw
 * @param {{ scope: {kind:string,name:string}, budget: object, dnsOk: Record<string, true>, headers: Record<string,string>, stats?: { fetches: number } }} ctx
 * @param {{ follow?: number, allowHttp?: boolean, maxBytes?: number, timeoutMs?: number, readBody?: boolean }} opts
 * @returns {Promise<
 *   { ok: true, status: number, headers: Headers, url: string, hops: number, body: Uint8Array, truncated: boolean, redirected?: string } |
 *   { ok: false, kind: "refused"|"offsite"|"dns"|"network"|"timeout"|"budget", error: string, host?: string, url?: string, hops: number }
 * >}
 */
export async function safeFetch(raw, ctx, { follow = MAX_HOPS, allowHttp = false, maxBytes = PAGE_BYTES, timeoutMs = FETCH_TIMEOUT_MS, readBody = true } = {}) {
  const deadline = Date.now() + timeoutMs;
  const signal = AbortSignal.timeout(timeoutMs);
  let cur = String(raw);
  const hopsMax = Math.min(follow, MAX_HOPS);
  for (let hop = 0; ; hop++) {
    const t = checkUrl(cur, { allowHttp: allowHttp && hop === 0 });
    if (!t.ok) return { ok: false, kind: "refused", error: hop ? `redirect not followed: Location ${t.error}` : `URL ${t.error}`, url: cur, hops: hop };
    if (!inScope(t.host, ctx.scope)) {
      if (hop === 0) return { ok: false, kind: "refused", error: `host ${t.host} isn't verified for this site`, host: t.host, url: cur, hops: hop };
      return { ok: false, kind: "offsite", error: `redirected to ${t.host}, which isn't verified for this site; not followed`, host: t.host, url: cur, hops: hop };
    }
    const host = normHost(t.host);
    if (!ctx.dnsOk[host]) {
      const d = await checkResolves(host, ctx.budget);
      if (!d.ok) {
        if (d.private) return { ok: false, kind: "refused", error: d.error, host, url: cur, hops: hop };
        return { ok: false, kind: /subrequests/.test(d.error) ? "budget" : "dns", error: d.error, host, url: cur, hops: hop };
      }
      ctx.dnsOk[host] = true;
    }
    if (!spend(ctx.budget, 1)) return { ok: false, kind: "budget", error: "no subrequests left in this run", url: cur, hops: hop };
    if (ctx.stats) ctx.stats.fetches++;
    let res;
    try {
      // No Cookie header, ever: every page is a first visit.
      res = await net.fetch(t.url.toString(), { method: "GET", headers: ctx.headers, redirect: "manual", signal });
    } catch (err) {
      const timeout = err && typeof err === "object" && (err.name === "TimeoutError" || err.name === "AbortError");
      return { ok: false, kind: timeout ? "timeout" : "network", error: timeout ? `timed out after ${Math.round(timeoutMs / 1000)} s` : `couldn't connect: ${errText(err).slice(0, 120)}`, url: cur, hops: hop };
    }
    const loc = res.headers.get("Location");
    if (res.status >= 300 && res.status < 400 && loc && hop < hopsMax) {
      res.body?.cancel().catch(() => {});
      let next;
      try {
        next = new URL(loc, cur).toString();
      } catch {
        return { ok: false, kind: "refused", error: "redirect not followed: Location isn't a valid URL", url: cur, hops: hop };
      }
      cur = next;
      continue;
    }
    let body = new Uint8Array(0);
    let truncated = false;
    if (readBody && res.status !== 204 && res.status !== 304) {
      try {
        const r = await readCapped(res.body, maxBytes, deadline);
        body = r.bytes;
        truncated = r.over;
      } catch (err) {
        const timeout = err && typeof err === "object" && (err.name === "TimeoutError" || err.name === "AbortError");
        return { ok: false, kind: timeout ? "timeout" : "network", error: timeout ? "the response took too long" : `reading the response failed: ${errText(err).slice(0, 120)}`, url: cur, hops: hop };
      }
    } else res.body?.cancel().catch(() => {});
    return { ok: true, status: res.status, headers: res.headers, url: cur, hops: hop, body, truncated };
  }
}

/** Set-Cookie values, one per cookie (Workers' Headers.getAll / getSetCookie). */
export function setCookies(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  if (typeof headers.getAll === "function") return headers.getAll("Set-Cookie");
  const v = headers.get("Set-Cookie");
  return v ? [v] : [];
}
