import { describe, it, expect, beforeEach } from "vitest";
import { env } from "cloudflare:test";
import { resetAll, setNow, fakeNet, api, call, rows, runScan, runAt, inDo, siteRoutes, txtFor, addVerifiedSite, htmlPage, GOOD_HEADERS, NOW, TOKEN } from "./helpers.js";
import { headerFindings } from "../src/lib/checks.js";
import wranglerText from "../wrangler.jsonc?raw";

async function scannedSite(homeHtml) {
  const { id, token } = await addVerifiedSite({ id: "main", host: "example.com" });
  const r = { ...siteRoutes("example.com"), ...txtFor("example.com", token) };
  if (homeHtml) r["=https://example.com/"] = { status: 200, body: homeHtml, headers: GOOD_HEADERS };
  fakeNet(r);
  await runScan(NOW);
  return id;
}

describe("admin auth", () => {
  beforeEach(resetAll);
  it("401 without or with a wrong token; 503 when ADMIN_TOKEN is unset or short; constant-time compare", async () => {
    expect((await api("GET", "sites", undefined, {}, null)).status).toBe(401);
    expect((await api("GET", "sites", undefined, {}, "wrong-token-wrong-token")).status).toBe(401);
    expect((await api("GET", "sites", undefined, {}, `${TOKEN}x`)).status).toBe(401);
    expect((await api("GET", "sites")).status).toBe(200);
    expect((await api("GET", "sites", undefined, { ADMIN_TOKEN: "short" }, "short")).status).toBe(503);
    expect((await api("GET", "sites", undefined, { ADMIN_TOKEN: undefined }, "")).status).toBe(503);
  });
  it("bodies over 16 KB and non-objects are refused", async () => {
    expect((await api("POST", "sites", { host: "example.com", pages: ["/" + "a".repeat(17000)] })).status).toBe(400);
    const res = await call("/api/sites", { method: "POST", headers: { Authorization: `Bearer ${TOKEN}` }, body: "[1,2]" });
    expect(res.status).toBe(400);
  });
});

describe("sites API", () => {
  beforeEach(resetAll);
  it("create, list, patch, delete; at most 10 sites; config sites can be paused, not deleted", async () => {
    fakeNet();
    // The config site is synced into D1 by the Scanner's first run.
    await runAt(NOW);
    let list = await api("GET", "sites");
    expect(list.data.sites.map((s) => [s.id, s.source, s.state])).toEqual([["cfg", "config", "unverified"]]);
    expect(list.data.sites[0].verify.txt.name).toBe("_perchlight-privacy.config-site.com");
    expect((await api("DELETE", "sites/cfg")).status).toBe(409);
    expect((await api("PATCH", "sites/cfg", { pages: ["/x"] })).status).toBe(409);
    expect((await api("PATCH", "sites/cfg", { paused: true })).data.site.paused).toBe(true);

    for (let i = 0; i < 9; i++) expect((await api("POST", "sites", { id: `s${i}`, host: `s${i}.example.com` })).status).toBe(201);
    const over = await api("POST", "sites", { id: "s10", host: "s10.example.com" });
    expect(over.status).toBe(409);
    expect((await api("POST", "sites", { id: "s0", host: "dup.example.com" })).status).toBe(409);
    expect((await api("POST", "sites", { host: "http://10.0.0.5" })).status).toBe(400);

    const p = await api("PATCH", "sites/s1", { pages: ["/pricing"], imprint: true });
    expect(p.data.site.pages).toEqual(["/", "/pricing"]);
    expect(p.data.site.settings.imprint).toBe(true);
    expect((await api("PATCH", "sites/s1", { pages: ["https://127.0.0.1/"] })).status).toBe(400);
    expect((await api("DELETE", "sites/s1")).status).toBe(200);
    list = await api("GET", "sites");
    expect(list.data.sites).toHaveLength(9);
  });

  it("changing a verified site's host resets verification", async () => {
    await addVerifiedSite({ id: "main", host: "example.com" });
    const p = await api("PATCH", "sites/main", { host: "other-example.com" });
    expect(p.data.site.state).toBe("unverified");
    expect(p.data.site.verifiedBy).toBeNull();
  });

  it("report.json: stable shape, schema 1, disclaimer, findings by severity, changes", async () => {
    const id = await scannedSite(htmlPage('<a href="/privacy">p</a><script src="https://connect.facebook.net/x.js"></script>'));
    const r = await api("GET", `sites/${id}/report.json`);
    expect(r.data.schema).toBe(1);
    expect(r.data.disclaimer).toMatch(/not legal advice/i);
    expect(r.data.site).toMatchObject({ id, host: "example.com", state: "active", verifiedBy: "txt", verifiedScope: "domain:example.com" });
    expect(r.data.scan).toMatchObject({ status: "done", pagesOk: 1, pagesFailed: 0 });
    expect(r.data.findings.high).toHaveLength(1);
    expect(r.data.findings.high[0]).toMatchObject({ check: "third-party.tracker", subject: "connect.facebook.net", source: "static", muted: false });
    expect(r.data.findings.high[0].why).toBeTruthy();
    expect(r.data.changes.new).toHaveLength(1);
    expect(Object.keys(r.data.findings)).toEqual(["high", "medium", "low", "info"]);
    const scans = await api("GET", `scans?site=${id}`);
    expect(scans.data.scans).toHaveLength(1);
    const one = await api("GET", `scans/${scans.data.scans[0].id}`);
    expect(one.data.findings).toHaveLength(1);
  });

  it("mutes: by key (site inferred), with a note; unmute", async () => {
    const id = await scannedSite(htmlPage('<a href="/privacy">p</a><script src="https://connect.facebook.net/x.js"></script>'));
    const key = (await rows("SELECT key FROM findings"))[0].key;
    expect((await api("POST", "findings/zzz/mute", {})).status).toBe(400);
    expect((await api("POST", `findings/${key}/mute`, { note: "consent-gated on click" })).data.muted).toEqual({ site: id, key, note: "consent-gated on click" });
    expect(await rows("SELECT site_id, key, note FROM mutes")).toEqual([{ site_id: id, key, note: "consent-gated on click" }]);
    expect((await api("DELETE", `findings/${key}/mute?site=${id}`)).status).toBe(200);
    expect(await rows("SELECT * FROM mutes")).toEqual([]);
  });

  it("test alert, deliveries, footprint and config", async () => {
    const calls = fakeNet();
    setNow(NOW);
    const t = await api("POST", "test-alert");
    expect(t.data.results.map((x) => x.status).sort()).toEqual(["sent", "sent", "sent"]);
    expect(calls.filter((c) => c.url.startsWith("https://alerts.example.org/"))[0].headers.get("X-Perchlight-Signature")).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect((await api("GET", "deliveries")).data.deliveries).toHaveLength(3);
    expect((await api("GET", "footprint")).data.scanner[0]).toHaveProperty("d1RowsWritten");
    expect((await api("GET", "config")).data.errors).toEqual([]);
  });
});

describe("the report page", () => {
  beforeEach(resetAll);

  it("needs the admin token, a session cookie from the login form, or a share link", async () => {
    const id = await scannedSite();
    expect((await call(`/r/${id}`)).status).toBe(401);
    expect((await call(`/r/${id}`, { headers: { Authorization: `Bearer ${TOKEN}` } })).status).toBe(200);
    // Login form -> cookie (an HMAC, not the token).
    const bad = await call("/r/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `site=${id}&token=nope` });
    expect(bad.status).toBe(401);
    const login = await call("/r/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `site=${id}&token=${TOKEN}` });
    expect(login.status).toBe(303);
    const setCookie = login.headers.get("Set-Cookie");
    expect(setCookie).toMatch(/HttpOnly; Secure; SameSite=Strict/);
    expect(setCookie).not.toContain(TOKEN);
    const cookie = setCookie.split(";")[0];
    expect((await call(`/r/${id}`, { headers: { Cookie: cookie } })).status).toBe(200);
    expect((await call(`/r/${id}`, { headers: { Cookie: "pp_session=forged" } })).status).toBe(401);
  });

  it("share links: created once, stored hashed, revocable; wrong or other-site tokens refused", async () => {
    const id = await scannedSite();
    const s = await api("POST", `sites/${id}/share`);
    const url = new URL(s.data.url);
    const token = url.searchParams.get("s");
    const stored = (await rows("SELECT share_token_hash FROM sites WHERE id = ?", id))[0].share_token_hash;
    expect(stored).toMatch(/^[0-9a-f]{64}$/);
    expect(stored).not.toContain(token);
    expect((await call(`/r/${id}?s=${token}`)).status).toBe(200);
    expect((await call(`/r/${id}?s=${token}x`)).status).toBe(401);
    expect((await call(`/r/cfg?s=${token}`)).status).toBe(401);
    expect((await call(`/r/nosuch?s=${token}`)).status).toBe(401);
    await api("DELETE", `sites/${id}/share`);
    expect((await call(`/r/${id}?s=${token}`)).status).toBe(401);
  });

  it("passes its own header checks, has no JavaScript, renders <script> in evidence as text", async () => {
    const id = await scannedSite(htmlPage('<a href="/privacy">p</a><script>gtag("config","</script><script>alert(1)//")</script><a href="/x">x</a>'));
    // Evidence with markup, straight into D1 to be sure escaping is what protects the page.
    const scanId = (await rows("SELECT last_scan_id FROM sites"))[0].last_scan_id;
    await env.DB.prepare("INSERT INTO findings (scan_id, site_id, key, check_id, severity, page, subject, evidence, first_seen_at) VALUES (?, ?, 'aaaaaaaaaaaaaaaaaaaa', 'third-party.other', 'info', '/<b>', '<img src=x onerror=alert(1)>', '<script>alert(1)</script>', '2026-03-02 08:00:00')").bind(scanId, id).run();
    const res = await call(`/r/${id}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    const body = await res.text();
    expect(headerFindings(res.headers)).toEqual([]);
    expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Set-Cookie")).toBeNull();
    expect(body).not.toMatch(/<script/i);
    expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(body).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(body).toMatch(/not legal advice/i);
    const css = await call("/r/style.css");
    expect(css.headers.get("Content-Type")).toMatch(/text\/css/);
  });
});

describe("no cron trigger; the alarm is re-armed", () => {
  beforeEach(resetAll);
  it("wrangler.jsonc has no triggers", () => {
    const noComments = wranglerText.replace(/^\s*\/\/.*$/gm, "");
    expect(noComments).not.toMatch(/"triggers"|"crons"/);
  });
  it("a stopped alarm is re-armed by /tick or any API request", async () => {
    fakeNet();
    expect(await inDo((inst) => inst.ctx.storage.getAlarm())).toBeNull();
    expect((await call("/tick")).status).toBe(200);
    expect(await inDo((inst) => inst.ctx.storage.getAlarm())).not.toBeNull();
    await inDo((inst) => inst.ctx.storage.deleteAlarm());
    await api("GET", "sites");
    expect(await inDo((inst) => inst.ctx.storage.getAlarm())).not.toBeNull();
  });
  it("GET / is the name; unknown paths 404", async () => {
    expect(await (await call("/")).text()).toBe("perchlight-privacy\n");
    expect((await call("/nope")).status).toBe(404);
  });
});
