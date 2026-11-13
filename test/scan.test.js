import { describe, it, expect, beforeEach } from "vitest";
import { resetAll, setNow, fakeNet, api, rows, runScan, runAt, inDo, siteRoutes, txtFor, addVerifiedSite, alertCalls, jsonAlert, htmlPage, CLEAN_HOME, GOOD_HEADERS, brokenDb, NOW, MIN, HOUR, DAY } from "./helpers.js";
import { ACCEPTANCE_HTML } from "./fixtures.js";
import { testHooks } from "../src/lib/appctx.js";
import { SUBREQUEST_BUDGET } from "../src/lib/budget.js";

const HOST = "example.com";

async function setup(settings = {}, pages = {}, opts = {}) {
  const { id, token } = await addVerifiedSite({ id: "main", host: HOST, ...settings });
  const routes = () => ({ ...siteRoutes(HOST, pages, opts), ...txtFor(HOST, token) });
  return { id, token, routes };
}

const latest = async () => rows("SELECT f.check_id, f.subject, f.severity, f.page, f.carried FROM findings f JOIN sites s ON s.last_scan_id = f.scan_id ORDER BY f.check_id, f.subject");
const triples = (fs) => fs.map((f) => `${f.check_id}|${f.subject}|${f.severity}`);

/** Runs the Scanner until the scan in progress is done, recording each run's subrequests. */
async function scanRuns(at) {
  const used = [];
  let t = at;
  for (let i = 0; i < 15; i++) {
    const r = await runAt(t);
    used.push(r.used);
    if (!(await inDo((inst) => Boolean(inst.getCursor())))) return used;
    t += 1000;
  }
  throw new Error("didn't finish");
}

describe("scanning", () => {
  beforeEach(resetAll);

  it("a 20-page scan completes in at most 5 alarm invocations, none over 45 subrequests", async () => {
    const pages = Object.fromEntries(Array.from({ length: 19 }, (_, i) => [`/p${i}`, htmlPage(`<p>page ${i}</p>`)]));
    const { routes } = await setup({ pages: Object.keys(pages) }, pages);
    // Every page redirects once, to show redirects are budgeted too.
    const r = routes();
    for (const p of Object.keys(pages)) {
      r[`=https://${HOST}${p}/`] = r[`=https://${HOST}${p}`];
      r[`=https://${HOST}${p}`] = { status: 301, headers: { Location: `${p}/` } };
    }
    fakeNet(r);
    const used = await scanRuns(NOW);
    expect(used.length).toBeLessThanOrEqual(5);
    for (const u of used) expect(u).toBeLessThanOrEqual(SUBREQUEST_BUDGET);
    const scan = (await rows("SELECT status, pages_ok, pages_failed, subrequests FROM scans"))[0];
    expect(scan).toMatchObject({ status: "done", pages_ok: 20, pages_failed: 0 });
    expect(scan.subrequests).toBeGreaterThan(40);
  });

  it("the acceptance fixture: exact findings stored, evidence masked, one alert, report", async () => {
    const { routes } = await setup({}, {}, {});
    const r = routes();
    r[`=https://${HOST}/`] = { status: 200, body: ACCEPTANCE_HTML, headers: { ...GOOD_HEADERS, "Set-Cookie": "_ga=GA1.1.1.2; Path=/; Max-Age=31536000; Secure; SameSite=Lax" } };
    const calls = fakeNet(r);
    await runScan(NOW);
    expect(triples(await latest())).toEqual(
      [
        "cookie.pre-consent|_ga|high",
        "email.exposed|jane.doe@example.com|low",
        "form.insecure|example.com/subscribe|high",
        "mixed-content|example.com/logo.png|medium",
        "third-party.ip-leak|fonts.googleapis.com|medium",
        "third-party.tag-manager|googletagmanager.com|high",
        "third-party.tracker|connect.facebook.net|high",
        "third-party.tracker|google-analytics.com|high",
      ].sort(),
    );
    const ev = await rows("SELECT evidence FROM findings WHERE check_id = 'email.exposed'");
    expect(ev[0].evidence).toContain("j***@example.com");
    expect(ev[0].evidence).not.toContain("jane.doe");
    // One alert per channel, naming the trackers; never evidence.
    const a = alertCalls(calls);
    expect(a).toHaveLength(2);
    const body = jsonAlert(a);
    expect(body.title).toBe("perchlight-privacy: example.com, 7 new");
    expect(body.text).toContain("NEW (high): connect.facebook.net on / (loaded)");
    expect(body.text).not.toContain("jane");
    expect(body.text).toContain("Automated check, not legal advice.");
    // No page HTML is stored anywhere.
    const all = JSON.stringify(await rows("SELECT * FROM findings")) + JSON.stringify(await rows("SELECT * FROM scans"));
    expect(all).not.toContain("Write to");
    for (const f of await rows("SELECT evidence FROM findings")) expect(f.evidence.length).toBeLessThanOrEqual(200);
  });

  it("privacy link: missing reported; a 'Datenschutz' footer link to a 200 page clears it on the next scan", async () => {
    const { routes } = await setup();
    const r = routes();
    r[`=https://${HOST}/`] = { status: 200, body: htmlPage("<p>no links</p>"), headers: GOOD_HEADERS };
    fakeNet(r);
    await runScan(NOW);
    expect(triples(await latest())).toEqual(["policy.privacy-missing|privacy|high"]);
    r[`=https://${HOST}/`] = { status: 200, body: htmlPage('<footer><a href="/datenschutz">Datenschutz</a></footer>'), headers: GOOD_HEADERS };
    r[`=https://${HOST}/datenschutz`] = { status: 200, body: htmlPage("x"), headers: GOOD_HEADERS };
    fakeNet(r);
    await runScan(NOW + DAY);
    expect(triples(await latest())).toEqual([]);
  });

  it("a privacy link that 404s is reported; the imprint is checked only with imprint: true", async () => {
    const { routes } = await setup({ imprint: true });
    const r = routes();
    r[`=https://${HOST}/privacy`] = { status: 404 };
    fakeNet(r);
    await runScan(NOW);
    const f = await rows("SELECT check_id, evidence FROM findings ORDER BY check_id");
    expect(f.map((x) => x.check_id)).toEqual(["policy.imprint-missing", "policy.privacy-missing"]);
    expect(f[1].evidence).toMatch(/\/privacy answered HTTP 404/);
  });

  it("missing HSTS, Referrer-Policy and Permissions-Policy are each reported; setting them clears them", async () => {
    const bare = { "Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff" };
    const { routes } = await setup();
    const r = routes();
    r[`=https://${HOST}/`] = { status: 200, body: CLEAN_HOME, headers: bare };
    fakeNet(r);
    await runScan(NOW);
    expect(triples(await latest())).toEqual(["header.hsts|Strict-Transport-Security|medium", "header.permissions-policy|Permissions-Policy|low", "header.referrer-policy|Referrer-Policy|low"]);
    fakeNet(routes());
    await runScan(NOW + DAY);
    expect(await latest()).toEqual([]);
  });

  it("change alerts: a new script alerts once; removal alerts 'resolved' only after 2 completed scans; muted never alerts", async () => {
    const { id, routes } = await setup({ pages: ["/pricing"] }, { "/pricing": htmlPage("<p>prices</p>") });
    let calls = fakeNet(routes());
    await runScan(NOW);
    expect(alertCalls(calls)).toHaveLength(0); // a clean site: nothing to alert

    const withPixel = routes();
    withPixel[`=https://${HOST}/pricing`] = { status: 200, body: htmlPage('<script src="https://connect.facebook.net/en_US/fbevents.js"></script>'), headers: GOOD_HEADERS };
    calls = fakeNet(withPixel);
    await runScan(NOW + DAY);
    let a = alertCalls(calls);
    expect(a).toHaveLength(2);
    expect(jsonAlert(a).text).toContain("NEW (high): connect.facebook.net on /pricing (loaded)");

    // Still there: no alert.
    calls = fakeNet(withPixel);
    await runScan(NOW + 2 * DAY);
    expect(alertCalls(calls)).toHaveLength(0);

    // Removed: no alert after one scan, "resolved" after the second.
    calls = fakeNet(routes());
    await runScan(NOW + 3 * DAY);
    expect(alertCalls(calls)).toHaveLength(0);
    calls = fakeNet(routes());
    await runScan(NOW + 4 * DAY);
    a = alertCalls(calls);
    expect(a).toHaveLength(2);
    expect(jsonAlert(a).title).toBe("perchlight-privacy: example.com, 1 resolved");

    // A muted key never alerts: add the pixel back after muting its key.
    const key = (await rows("SELECT key FROM findings WHERE subject = 'connect.facebook.net' LIMIT 1"))[0].key;
    setNow(NOW + 4 * DAY);
    expect((await api("POST", `findings/${key}/mute`, { note: "reviewed" })).status).toBe(200);
    calls = fakeNet(withPixel);
    await runScan(NOW + 5 * DAY);
    expect(alertCalls(calls)).toHaveLength(0);
    const report = await api("GET", `sites/${id}/report.json`);
    expect(report.data.findings.high[0]).toMatchObject({ subject: "connect.facebook.net", muted: true, muteNote: "reviewed" });
  });

  it("alert level: low findings alert only when alertLevel is low; info never", async () => {
    const { routes } = await setup({ alertLevel: "low" });
    const r = routes();
    r[`=https://${HOST}/`] = { status: 200, body: htmlPage('<a href="/privacy">Privacy</a><p>mail a.b@example.com</p><a href="mailto:x@example.com">x</a>'), headers: GOOD_HEADERS };
    const calls = fakeNet(r);
    await runScan(NOW);
    const t = jsonAlert(alertCalls(calls)).text;
    expect(t).toContain("NEW (low): a***@example.com");
    expect(t).not.toContain("mailto");
  });

  it("a scan where 3 pages time out is partial: their findings are carried forward, nothing 'resolved'", async () => {
    const pages = { "/a": htmlPage('<script src="https://connect.facebook.net/x.js"></script>'), "/b": htmlPage('<img src="https://cdn.tracker-free.net/x.png">'), "/c": htmlPage("<p>c</p>"), "/d": htmlPage("<p>d</p>") };
    const { routes } = await setup({ pages: Object.keys(pages) }, pages);
    fakeNet(routes());
    await runScan(NOW);
    const before = triples(await latest());
    expect(before).toEqual(["third-party.other|cdn.tracker-free.net|info", "third-party.tracker|connect.facebook.net|high"]);

    const r = routes();
    for (const p of ["/a", "/b", "/c"]) r[`=https://${HOST}${p}`] = "timeout";
    const calls = fakeNet(r);
    await runScan(NOW + DAY);
    const scan = (await rows("SELECT status, pages_ok, pages_failed, resolved_count FROM scans ORDER BY id DESC LIMIT 1"))[0];
    expect(scan).toEqual({ status: "partial", pages_ok: 2, pages_failed: 3, resolved_count: 0 });
    expect(triples(await latest())).toEqual(before);
    expect((await latest()).every((f) => f.carried === 1)).toBe(true);
    expect(alertCalls(calls)).toHaveLength(0);

    // Two more partial scans with the same pages failing never resolve them either.
    fakeNet(r);
    await runScan(NOW + 2 * DAY);
    fakeNet(r);
    await runScan(NOW + 3 * DAY);
    expect(triples(await latest())).toEqual(before);
  });

  it("a page 404 or 5xx is recorded as failed, its findings carried; the scan is partial", async () => {
    const { routes } = await setup({ pages: ["/gone"] }, { "/gone": htmlPage('<script src="https://connect.facebook.net/x.js"></script>') });
    fakeNet(routes());
    await runScan(NOW);
    const r = routes();
    r[`=https://${HOST}/gone`] = { status: 503 };
    fakeNet(r);
    await runScan(NOW + DAY);
    const s = (await rows("SELECT status, notes FROM scans ORDER BY id DESC LIMIT 1"))[0];
    expect(s.status).toBe("partial");
    expect(JSON.parse(s.notes).pages["/gone"]).toMatchObject({ ok: false, status: 503, error: "HTTP 503" });
    expect(triples(await latest())).toEqual(["third-party.tracker|connect.facebook.net|high"]);
  });

  it("an eviction mid-scan resumes the same scan from its cursor", async () => {
    const pages = Object.fromEntries(Array.from({ length: 15 }, (_, i) => [`/p${i}`, htmlPage(`<p>${i}</p>`)]));
    const { routes } = await setup({ pages: Object.keys(pages) }, pages);
    const calls = fakeNet(routes());
    await runAt(NOW); // prepare
    await runAt(NOW + 1000); // first 10 pages
    const mid = await inDo((inst) => inst.getCursor());
    expect(mid.stage).toBe("pages");
    expect(mid.pageIdx).toBe(10);
    // Evicted: in-memory state is gone.
    await inDo((inst) => {
      inst.hot = null;
    });
    const fetchedBefore = calls.filter((c) => /\/p\d+$/.test(c.url)).length;
    await runScan(NOW + 2000);
    expect(calls.filter((c) => /\/p\d+$/.test(c.url)).length - fetchedBefore).toBe(6);
    expect(await rows("SELECT id, status, pages_ok FROM scans")).toEqual([{ id: mid.scanId, status: "done", pages_ok: 16 }]);
  });

  it("an alarm that runs twice never alerts twice", async () => {
    const { routes } = await setup();
    const r = routes();
    r[`=https://${HOST}/`] = { status: 200, body: htmlPage('<a href="/privacy">p</a><script src="https://connect.facebook.net/x.js"></script>'), headers: GOOD_HEADERS };
    const calls = fakeNet(r);
    const { at } = await runScan(NOW);
    await runAt(at);
    await runAt(at + 1000);
    expect(alertCalls(calls)).toHaveLength(2);
    // email + discord + json, each sent once
    expect(await rows("SELECT channel, status, attempts FROM deliveries ORDER BY channel")).toEqual([
      { channel: "email:ops@example.com", status: "sent", attempts: 1 },
      { channel: "webhook:discord", status: "sent", attempts: 1 },
      { channel: "webhook:json", status: "sent", attempts: 1 },
    ]);
  });

  it("manual scans: at most one per site every 5 minutes", async () => {
    const { id, routes } = await setup();
    fakeNet(routes());
    await runScan(NOW);
    setNow(NOW + 2 * MIN);
    const r = await api("POST", `sites/${id}/scan`);
    expect(r.status).toBe(429);
    expect(r.data.retryAfterSeconds).toBe(180);
    setNow(NOW + 5 * MIN);
    expect((await api("POST", `sites/${id}/scan`)).status).toBe(202);
    await runScan(NOW + 5 * MIN);
    expect((await rows("SELECT trigger FROM scans ORDER BY id")).map((x) => x.trigger)).toEqual(["schedule", "manual"]);
  });

  it("the schedule: every (min 6h) from the last start; paused sites aren't scanned", async () => {
    const { id, routes } = await setup({ every: "6h" });
    fakeNet(routes());
    await runScan(NOW);
    await runScan(NOW + 5 * HOUR);
    expect(await rows("SELECT id FROM scans")).toHaveLength(1);
    await runScan(NOW + 6 * HOUR);
    expect(await rows("SELECT id FROM scans")).toHaveLength(2);
    setNow(NOW + 6 * HOUR);
    await api("PATCH", `sites/${id}`, { paused: true });
    await runScan(NOW + 13 * HOUR);
    expect(await rows("SELECT id FROM scans")).toHaveLength(2);
    expect((await api("PATCH", `sites/${id}`, { every: "1h" })).status).toBe(400);
  });

  it("D1 failing: no alarm hot loop; the scan resumes after backoff, nothing lost", async () => {
    const { routes } = await setup();
    fakeNet(routes());
    await runAt(NOW); // prepare
    await runAt(NOW + 1000); // pages
    testHooks.env = { DB: brokenDb() };
    let t = NOW + 2000;
    const gaps = [];
    for (let i = 0; i < 4; i++) {
      const r = await runAt(t);
      gaps.push(r.next - t);
      t = r.next;
    }
    // Backoff doubles: 30 s, 60 s, 120 s, 240 s, never once a second.
    expect(gaps).toEqual([30_000, 60_000, 120_000, 240_000]);
    testHooks.env = null;
    await runScan(t);
    expect((await rows("SELECT status FROM scans"))[0].status).toBe("done");
  });

  it("a run that throws backs off instead of re-running at once", async () => {
    await setup();
    const r = await inDo(async (inst) => {
      inst.work = async () => {
        throw new Error("boom");
      };
      try {
        const a = await inst.run(NOW);
        const b = await inst.run(a.next);
        return [a.next - NOW, b.next - a.next];
      } finally {
        delete inst.work;
      }
    });
    expect(r).toEqual([30_000, 60_000]);
  });

  it("a scan not finished within 30 minutes is closed as failed; the previous findings stay current", async () => {
    const { routes } = await setup({ pages: ["/x"] }, { "/x": htmlPage('<script src="https://connect.facebook.net/x.js"></script>') });
    fakeNet(routes());
    await runScan(NOW);
    const before = await latest();
    fakeNet(routes());
    await runAt(NOW + DAY); // prepare
    await runAt(NOW + DAY + 31 * MIN);
    const s = await rows("SELECT status, error FROM scans ORDER BY id DESC LIMIT 1");
    expect(s[0]).toMatchObject({ status: "failed" });
    expect(s[0].error).toMatch(/timed out/);
    expect(await latest()).toEqual(before);
    expect(await inDo((inst) => inst.getCursor())).toBeNull();
  });

  it("deleting a site mid-scan drops the scan without an alert", async () => {
    const { id, routes } = await setup();
    const calls = fakeNet(routes());
    await runAt(NOW);
    setNow(NOW);
    expect((await api("DELETE", `sites/${id}`)).status).toBe(200);
    await runScan(NOW + 1000);
    expect(await rows("SELECT * FROM scans")).toEqual([]);
    expect(alertCalls(calls)).toHaveLength(0);
  });

  it("bot protection on your zone is reported as scan.blocked", async () => {
    const { routes } = await setup();
    const r = routes();
    r[`=https://${HOST}/`] = { status: 403, body: "<html><title>Just a moment...</title></html>", headers: { "cf-mitigated": "challenge" } };
    fakeNet(r);
    await runScan(NOW);
    expect(triples(await latest())).toEqual(["scan.blocked|bot-protection|medium"]);
  });

  it("robots.txt, sitemap discovery (capped) and same-host CSS", async () => {
    const { routes } = await setup({ discover: 2 });
    const r = routes();
    r[`=https://${HOST}/robots.txt`] = { status: 200, body: "User-agent: *\nDisallow: /admin/\nSitemap: https://example.com/sm.xml\n" };
    r[`=https://${HOST}/sm.xml`] = { status: 200, body: "<urlset><url><loc>https://example.com/one</loc></url><url><loc>https://example.com/two</loc></url><url><loc>https://example.com/three</loc></url><url><loc>https://staging.other.org/</loc></url></urlset>" };
    r[`=https://${HOST}/one`] = htmlPage("<p>1</p>") && { status: 200, body: htmlPage("<p>1</p>"), headers: GOOD_HEADERS };
    r[`=https://${HOST}/two`] = { status: 200, body: htmlPage('<link rel="stylesheet" href="/theme.css">'), headers: GOOD_HEADERS };
    r[`=https://${HOST}/theme.css`] = { status: 200, body: "@import url('https://fonts.googleapis.com/css2?family=Lato');", headers: { "Content-Type": "text/css" } };
    const calls = fakeNet(r);
    await runScan(NOW);
    expect(calls.some((c) => c.url === "https://example.com/three")).toBe(false);
    expect(triples(await latest())).toEqual(["robots.sensitive|/admin/|low", "sitemap.sensitive|staging.other.org|medium", "third-party.ip-leak|fonts.googleapis.com|medium"]);
    expect((await rows("SELECT pages_ok FROM scans"))[0].pages_ok).toBe(3);
  });

  it("footprint: a day of the example (3 sites, 20 pages, daily) writes under 1,000 D1 rows", async () => {
    const pages = Object.fromEntries(Array.from({ length: 19 }, (_, i) => [`/p${i}`, htmlPage(`<a href="/privacy">p</a><script src="https://connect.facebook.net/x.js"></script><img src="https://cdn${i}.images-x.net/a.png">`)]));
    const all = {};
    for (const host of ["a-site.com", "b-site.com", "c-site.com"]) {
      const { token } = await addVerifiedSite({ id: host.slice(0, 1), host, pages: Object.keys(pages) });
      Object.assign(all, siteRoutes(host, pages), txtFor(host, token));
    }
    fakeNet(all);
    setNow(NOW);
    let t = NOW;
    for (let i = 0; i < 3; i++) t = (await runScan(t)).at + 1000;
    expect(await rows("SELECT status FROM scans")).toEqual([{ status: "done" }, { status: "done" }, { status: "done" }]);
    const fp = await api("GET", "footprint");
    const today = fp.data.scanner[0];
    expect(today.scans).toBe(3);
    expect(today.d1RowsWritten).toBeGreaterThan(0);
    expect(today.d1RowsWritten).toBeLessThan(1000);
    expect(today.doRowsWritten).toBeLessThan(1000);
    expect(today.pages).toBe(60);
  });
});
