import { env, createExecutionContext, waitOnExecutionContext, runInDurableObject } from "cloudflare:test";
import { makeWorker, resetWatchdog } from "../src/app.js";
import { clock, testHooks, scannerStub } from "../src/lib/appctx.js";
import { net } from "../src/lib/net.js";
import { resetCounters } from "../src/lib/counters.js";
import { DOH_URL } from "../src/lib/dns.js";
import { TEST_CONFIG } from "./config.js";

export const ORIGIN = "https://privacy.example.net";
export const TOKEN = "test-admin-token-0123456789";
export const MIN = 60_000;
export const HOUR = 3_600_000;
export const DAY = 86_400_000;
// Monday 2 March 2026, 08:00:00 UTC.
export const NOW = Date.UTC(2026, 2, 2, 8, 0);

export const worker = makeWorker(TEST_CONFIG);
const realFetch = net.fetch;

export function setNow(ms) {
  clock.now = () => ms;
}

/**
 * Fake network: NO request in the tests reaches a real host.
 * routes: "=<url>" (exact) or "<url prefix>" -> { status, body, headers } | "down" | "timeout" | (url, init) => same | Response.
 * Exact keys win, then the longest prefix. Every call is recorded.
 */
export function fakeNet(routes = {}) {
  const calls = [];
  const defaults = { "https://discord.com/": { status: 204 }, "https://alerts.example.org/": { status: 200 }, [DOH_URL]: dohJson([]) };
  const pick = (table, url) => {
    if (Object.prototype.hasOwnProperty.call(table, `=${url}`)) return `=${url}`;
    return Object.keys(table).filter((k) => !k.startsWith("=") && url.startsWith(k)).sort((a, b) => b.length - a.length)[0];
  };
  net.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    const headers = new Headers(init.headers ?? {});
    calls.push({ url, method: init.method ?? "GET", headers, body: typeof init.body === "string" ? init.body : null, redirect: init.redirect });
    const own = pick(routes, url);
    const def = own === undefined ? pick(defaults, url) : undefined;
    let r = own !== undefined ? routes[own] : def !== undefined ? defaults[def] : undefined;
    if (typeof r === "function") r = await r(url, init, calls.length);
    if (r === undefined) throw new Error(`unexpected fetch in test: ${url}`);
    if (r instanceof Response) return r;
    if (r === "down") throw new TypeError("Network connection lost.");
    if (r === "timeout") {
      const e = new Error("The operation was aborted due to timeout");
      e.name = "TimeoutError";
      throw e;
    }
    const h = new Headers();
    for (const [k, v] of Object.entries(r.headers ?? {})) {
      if (Array.isArray(v)) for (const x of v) h.append(k, x);
      else h.set(k, v);
    }
    return new Response(r.status === 204 || r.status === 304 ? null : (r.body ?? ""), { status: r.status ?? 200, headers: h });
  };
  return calls;
}

export function restoreNet() {
  net.fetch = realFetch;
}

/** A DoH JSON answer. */
export function dohJson(answers, status = 0) {
  return { status: 200, headers: { "Content-Type": "application/dns-json" }, body: JSON.stringify({ Status: status, Answer: answers }) };
}

export const dohUrl = (name, type) => `=${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`;

/** Routes for a TXT record and A records. */
export function dns({ txt = {}, a = {}, aaaa = {} } = {}) {
  const r = {};
  for (const [name, values] of Object.entries(txt)) r[dohUrl(name, "TXT")] = dohJson(values.map((v) => ({ name, type: 16, TTL: 300, data: v.startsWith('"') ? v : `"${v}"` })));
  for (const [name, ips] of Object.entries(a)) r[dohUrl(name, "A")] = dohJson(ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })));
  for (const [name, ips] of Object.entries(aaaa)) r[dohUrl(name, "AAAA")] = dohJson(ips.map((ip) => ({ name, type: 28, TTL: 300, data: ip })));
  return r;
}

export const GOOD_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=()",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
};

export const FILLER = "<p>" + "We make honest things for honest people. ".repeat(8) + "</p>";

export function htmlPage(body, head = "") {
  return `<!doctype html><html><head><title>t</title>${head}</head><body>${body}${FILLER}</body></html>`;
}

/** A clean home page: privacy link, good headers. */
export const CLEAN_HOME = htmlPage('<nav><a href="/privacy">Privacy policy</a></nav>');

/**
 * Routes for a well-behaved site: http -> https redirect, robots/sitemap 404,
 * security.txt, a privacy page, A record, and the given pages (path -> body string | route).
 */
export function siteRoutes(host, pages = {}, { ip = "93.184.216.34", headers = GOOD_HEADERS } = {}) {
  const r = {
    ...dns({ a: { [host]: [ip] } }),
    [`=http://${host}/`]: { status: 301, headers: { Location: `https://${host}/` } },
    [`=https://${host}/robots.txt`]: { status: 404 },
    [`=https://${host}/sitemap.xml`]: { status: 404 },
    [`=https://${host}/.well-known/security.txt`]: { status: 200, body: "Contact: mailto:security@example.com\n", headers: { "Content-Type": "text/plain" } },
    [`=https://${host}/privacy`]: { status: 200, body: htmlPage("<h1>Privacy</h1>"), headers },
    [`=https://${host}/`]: { status: 200, body: CLEAN_HOME, headers },
  };
  for (const [p, v] of Object.entries(pages)) r[`=https://${host}${p}`] = typeof v === "string" ? { status: 200, body: v, headers } : v;
  return r;
}

/** A fake send_email binding that records messages (or fails). */
export function fakeEmail({ fail = false } = {}) {
  const sent = [];
  return {
    sent,
    binding: {
      async send(message) {
        if (fail) throw new Error(typeof fail === "string" ? fail : "send failed");
        sent.push(message);
      },
    },
  };
}

/** A D1 stand-in where every call fails. */
export function brokenDb() {
  const boom = async () => {
    throw new Error("D1_ERROR: writes are blocked until 00:00 UTC");
  };
  const stmt = { bind: () => stmt, first: boom, run: boom, all: boom, raw: boom };
  return { prepare: () => stmt, batch: boom, exec: boom };
}

export const scanner = () => scannerStub(env);

export function runAt(at) {
  setNow(at);
  return runInDurableObject(scanner(), (inst) => inst.run(at));
}

export function inDo(fn) {
  return runInDurableObject(scanner(), fn);
}

/** Runs the Scanner until no scan is in progress (or n runs), each a second apart. Returns how many runs it took. */
export async function runScan(at, max = 12) {
  let t = at;
  for (let i = 1; i <= max; i++) {
    const r = await runAt(t);
    const busy = await inDo((inst) => Boolean(inst.getCursor()));
    if (!busy) return { runs: i, at: t, last: r };
    t += 1000;
  }
  throw new Error("scan didn't finish");
}

export async function call(path, init = {}, envOverrides = {}) {
  resetWatchdog();
  const ctx = createExecutionContext();
  const e = { ...env, ...envOverrides };
  const res = await worker.fetch(new Request(`${ORIGIN}${path}`, init), e, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

export async function api(method, path, body, envOverrides = {}, token = TOKEN) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await call(`/api/${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }, envOverrides);
  const t = await res.text();
  let data;
  try {
    data = JSON.parse(t);
  } catch {
    data = t;
  }
  return { status: res.status, data, res };
}

export async function rows(sql, ...params) {
  return (await env.DB.prepare(sql).bind(...params).all()).results;
}

const TABLES = ["findings", "scans", "mutes", "deliveries", "footprint", "state", "sites"];
export async function resetAll() {
  restoreNet();
  testHooks.env = null;
  resetWatchdog();
  resetCounters();
  setNow(NOW);
  await env.DB.batch(TABLES.map((t) => env.DB.prepare(`DELETE FROM ${t}`)));
  await inDo(async (inst) => {
    for (const t of ["kv", "claims", "cursor", "tracked", "sitestate", "queue"]) inst.sql.exec(`DELETE FROM ${t}`);
    inst.hot = null;
    inst.running = false;
    await inst.ctx.storage.deleteAlarm();
  });
}

/**
 * Adds a site through the API and verifies it by TXT on `txtName` (default: the host).
 * Leaves fakeNet unset; returns { id, token }.
 */
export async function addVerifiedSite(settings, { txtName = settings.host, extraRoutes = {} } = {}) {
  fakeNet();
  const r = await api("POST", "sites", settings);
  if (r.status !== 201) throw new Error(`add site: ${JSON.stringify(r.data)}`);
  const id = r.data.site.id;
  const token = r.data.verify.token;
  fakeNet({ ...dns({ txt: { [`_perchlight-privacy.${txtName}`]: [`perchlight-privacy-verify=${token}`] }, a: { [settings.host]: ["93.184.216.34"] } }), ...extraRoutes });
  const v = await api("POST", `sites/${id}/verify`);
  if (v.status !== 200) throw new Error(`verify: ${JSON.stringify(v.data)}`);
  return { id, token };
}

/** TXT routes proving ownership for a token. */
export const txtFor = (name, token) => dns({ txt: { [`_perchlight-privacy.${name}`]: [`perchlight-privacy-verify=${token}`] } });

/** Alert webhook calls a fake network saw. */
export function alertCalls(calls) {
  return calls.filter((c) => /discord\.com|alerts\.example\.org/.test(c.url));
}

/** The parsed body of the signed JSON webhook among alert calls. */
export function jsonAlert(calls) {
  const c = calls.find((x) => x.url.startsWith("https://alerts.example.org/"));
  return c ? JSON.parse(c.body) : null;
}
