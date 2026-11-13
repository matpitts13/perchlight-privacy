import { describe, it, expect, beforeEach } from "vitest";
import { resetAll, setNow, jsonAlert, fakeNet, api, rows, runScan,  dns, siteRoutes, txtFor, addVerifiedSite, alertCalls, NOW, HOUR, DAY, MIN } from "./helpers.js";

const pageCalls = (calls, host) => calls.filter((c) => c.url.includes(`//${host}/`));

describe("ownership verification", () => {
  beforeEach(resetAll);

  it("an unverified site can't be scanned: 409 unverified and no request reaches the host", async () => {
    const calls = fakeNet();
    const r = await api("POST", "sites", { id: "shop", host: "example.com" });
    expect(r.status).toBe(201);
    expect(r.data.verify.txt).toMatchObject({ name: "_perchlight-privacy.example.com", value: `perchlight-privacy-verify=${r.data.verify.token}` });
    expect(r.data.verify.file.url).toBe("https://example.com/.well-known/perchlight-privacy.txt");
    expect(r.data.verify.token).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const s = await api("POST", "sites/shop/scan");
    expect(s.status).toBe(409);
    expect(s.data.error).toBe("unverified");
    await runScan(NOW);
    expect(calls).toHaveLength(0);
    expect(await rows("SELECT * FROM scans")).toEqual([]);
  });

  it("TXT on the parent domain verifies a subdomain site and covers its other subdomains", async () => {
    const { id } = await addVerifiedSite({ id: "www", host: "www.example.com", ownHosts: ["example.com"] }, { txtName: "example.com" });
    const site = (await rows("SELECT * FROM sites WHERE id = ?", id))[0];
    expect(site).toMatchObject({ state: "active", verify_method: "txt", verified_scope: "domain", verified_name: "example.com" });
  });

  it("split TXT strings and other records alongside are fine; a wrong token isn't", async () => {
    fakeNet();
    const r = await api("POST", "sites", { id: "a", host: "example.com" });
    const token = r.data.verify.token;
    fakeNet(dns({ txt: { "_perchlight-privacy.example.com": ["v=spf1 -all", `"perchlight-privacy-" "verify=${token}"`] } }));
    expect((await api("POST", "sites/a/verify")).data).toMatchObject({ ok: true, method: "txt" });

    fakeNet();
    const b = await api("POST", "sites", { id: "b", host: "other.com" });
    void b;
    fakeNet({ ...dns({ txt: { "_perchlight-privacy.other.com": ["perchlight-privacy-verify=WRONGTOKEN"] }, a: { "other.com": ["93.184.216.34"] } }), "=https://other.com/.well-known/perchlight-privacy.txt": { status: 404 } });
    const v = await api("POST", "sites/b/verify");
    expect(v.status).toBe(422);
    expect(v.data.result).toBe("failed");
    expect(v.data.found.join(" ")).toMatch(/different token/);
  });

  it("file verification covers that host only: a redirect to shop.example.com isn't fetched and is reported", async () => {
    fakeNet();
    const r = await api("POST", "sites", { id: "www", host: "www.example.com" });
    const token = r.data.verify.token;
    const routes = {
      ...siteRoutes("www.example.com"),
      "=https://www.example.com/.well-known/perchlight-privacy.txt": { status: 200, body: `${token}\n` },
      "=https://www.example.com/": { status: 302, headers: { Location: "https://shop.example.com/" } },
    };
    fakeNet(routes);
    const v = await api("POST", "sites/www/verify");
    expect(v.data).toMatchObject({ ok: true, method: "file", scope: { kind: "host", name: "www.example.com" } });
    const calls = fakeNet(routes);
    await runScan(NOW);
    expect(pageCalls(calls, "shop.example.com")).toHaveLength(0);
    const f = await rows("SELECT check_id, subject, severity FROM findings WHERE check_id = 'redirect.offsite'");
    expect(f).toEqual([{ check_id: "redirect.offsite", subject: "shop.example.com", severity: "info" }]);
    const scan = (await rows("SELECT status, pages_failed FROM scans"))[0];
    expect(scan).toEqual({ status: "partial", pages_failed: 1 });
  });

  it("a file verification doesn't follow redirects", async () => {
    fakeNet();
    await api("POST", "sites", { id: "x", host: "example.com" });
    fakeNet({ ...dns({ a: { "example.com": ["93.184.216.34"] } }), "=https://example.com/.well-known/perchlight-privacy.txt": { status: 301, headers: { Location: "https://evil.example.org/token" } } });
    const v = await api("POST", "sites/x/verify");
    expect(v.data.result).toBe("failed");
    expect(v.data.found.join(" ")).toMatch(/HTTP 301.*redirects aren't followed/);
  });

  it("ownership is re-checked before every scan; lost after two failures 24 hours apart, with one alert", async () => {
    const { id, token } = await addVerifiedSite({ id: "main", host: "example.com" });
    const good = { ...siteRoutes("example.com"), ...txtFor("example.com", token) };
    let calls = fakeNet(good);
    await runScan(NOW);
    expect(calls.some((c) => c.url.includes("name=_perchlight-privacy.example.com&type=TXT"))).toBe(true);
    expect((await rows("SELECT status FROM scans"))[0].status).toBe("done");

    // The token is removed.
    const gone = { ...siteRoutes("example.com"), "=https://example.com/.well-known/perchlight-privacy.txt": { status: 404 } };
    calls = fakeNet(gone);
    await runScan(NOW + DAY);
    let site = (await rows("SELECT state, verify_failures FROM sites WHERE id = ?", id))[0];
    expect(site).toEqual({ state: "active", verify_failures: 1 });
    // No page was fetched without ownership.
    expect(calls.filter((c) => c.url === "https://example.com/")).toHaveLength(0);
    const failed = await rows("SELECT status, error FROM scans ORDER BY id DESC LIMIT 1");
    expect(failed[0].status).toBe("failed");
    expect(failed[0].error).toMatch(/ownership check failed/);

    // A manual scan 6 hours later: still not lost (less than 24 h apart).
    setNow(NOW + DAY + 6 * HOUR);
    expect((await api("POST", `sites/${id}/scan`)).status).toBe(202);
    await runScan(NOW + DAY + 6 * HOUR);
    expect((await rows("SELECT state FROM sites"))[0].state).toBe("active");

    // At least 24 hours after the first failure: lost, one alert.
    calls = fakeNet(gone);
    await runScan(NOW + 2 * DAY + 7 * HOUR); // the next scan is 1 day after the manual one started
    site = (await rows("SELECT state FROM sites WHERE id = ?", id))[0];
    expect(site.state).toBe("verification_lost");
    const alerts = alertCalls(calls);
    expect(alerts).toHaveLength(2); // one per channel (discord, json)
    expect(jsonAlert(alerts).title).toBe("VERIFICATION LOST: example.com");

    // Scans stop: nothing more is fetched, nothing more alerts.
    calls = fakeNet(gone);
    await runScan(NOW + 4 * DAY);
    expect(calls.filter((c) => !c.url.includes("discord") && !c.url.includes("alerts.example"))).toHaveLength(0);
    expect(alertCalls(calls)).toHaveLength(0);
    expect((await api("POST", `sites/${id}/scan`)).data.error).toBe("verification_lost");

    // Restored by POST /verify.
    fakeNet(good);
    expect((await api("POST", `sites/${id}/verify`)).data.ok).toBe(true);
    expect((await rows("SELECT state, verify_failures FROM sites"))[0]).toEqual({ state: "active", verify_failures: 0 });
  });

  it("DoH unreachable: verification unknown, not counted as lost; two such scans alert scan_failing once", async () => {
    const { id } = await addVerifiedSite({ id: "main", host: "example.com" });
    const down = { "https://cloudflare-dns.com/": "down", "=https://example.com/.well-known/perchlight-privacy.txt": "down" };
    let calls = fakeNet(down);
    await runScan(NOW);
    expect((await rows("SELECT state, verify_failures FROM sites WHERE id = ?", id))[0]).toEqual({ state: "active", verify_failures: 0 });
    expect((await rows("SELECT error FROM scans"))[0].error).toMatch(/couldn't check ownership/);
    expect(alertCalls(calls)).toHaveLength(0);
    setNow(NOW + 10 * MIN);
    expect((await api("POST", `sites/${id}/scan`)).status).toBe(202);
    calls = fakeNet(down);
    await runScan(NOW + 10 * MIN);
    const a = alertCalls(calls);
    expect(a).toHaveLength(2);
    expect(jsonAlert(a).title).toBe("SCANS FAILING: example.com");
    setNow(NOW + 20 * MIN);
    await api("POST", `sites/${id}/scan`);
    calls = fakeNet(down);
    await runScan(NOW + 20 * MIN);
    expect(alertCalls(calls)).toHaveLength(0);
  });

  it("a verified host now resolving to a private address isn't fetched", async () => {
    const { token } = await addVerifiedSite({ id: "main", host: "example.com" });
    const calls = fakeNet({ ...siteRoutes("example.com"), ...txtFor("example.com", token), ...dns({ a: { "example.com": ["10.0.0.7"] } }) });
    await runScan(NOW);
    expect(calls.filter((c) => c.url.startsWith("https://example.com/") || c.url.startsWith("http://example.com/"))).toHaveLength(0);
    expect((await rows("SELECT status, error FROM scans"))[0]).toMatchObject({ status: "failed" });
    expect((await rows("SELECT error FROM scans"))[0].error).toMatch(/private address \(10\.0\.0\.7\)/);
  });
});
