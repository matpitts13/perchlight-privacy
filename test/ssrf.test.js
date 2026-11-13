import { describe, it, expect, beforeEach } from "vitest";
import { checkUrl, inScope, blockedIp, blockedV6, checkHostName } from "../src/lib/ssrf.js";
import { safeFetch } from "../src/lib/fetcher.js";
import { newBudget } from "../src/lib/budget.js";
import { parseTxt } from "../src/lib/dns.js";
import { txtCandidates, registrableDomain, isPublicSuffix } from "../src/lib/psl.js";
import { fakeNet, dns, resetAll, restoreNet } from "./helpers.js";

describe("SSRF URL rules (every rule from perchlight-hooks, stricter)", () => {
  it.each([
    ["http://127.0.0.1/", /http:/],
    ["https://127.0.0.1/", /IP address/],
    ["https://10.0.0.5/", /IP address/],
    ["https://[::1]/", /IP address/],
    ["https://[::ffff:169.254.169.254]/", /IP address/],
    ["https://169.254.169.254/latest/meta-data", /IP address/],
    ["https://2130706433/", /IP address/],
    ["https://0x7f.1/", /IP address/],
    ["https://8.8.8.8/", /IP address/],
    ["https://localhost/", /local or reserved/],
    ["https://LOCALHOST./", /local or reserved/],
    ["https://printer.local/", /local or reserved/],
    ["https://db.internal/", /local or reserved/],
    ["https://nas.home.arpa/", /local or reserved/],
    ["https://intranet/", /valid host name/],
    ["https://user:pw@example.com/", /user name/],
    ["https://example.com:8443/", /port 8443/],
    ["ftp://example.com/", /scheme/],
    ["file:///etc/passwd", /scheme/],
    ["javascript:alert(1)", /scheme/],
    ["not a url", /valid URL/],
  ])("refuses %s", (url, why) => {
    const r = checkUrl(url);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(why);
  });

  it("allows https on a public name, port 443 normalised; http only when asked", () => {
    expect(checkUrl("https://www.example.com:443/a?b=1").ok).toBe(true);
    expect(checkUrl("http://example.com/").ok).toBe(false);
    expect(checkUrl("http://example.com/", { allowHttp: true }).ok).toBe(true);
    expect(checkUrl("http://example.com:8080/", { allowHttp: true }).ok).toBe(false);
  });

  it("scope: TXT covers the domain and subdomains, a file only the host", () => {
    const domain = { kind: "domain", name: "example.com" };
    const host = { kind: "host", name: "www.example.com" };
    expect(inScope("www.example.com", domain)).toBe(true);
    expect(inScope("shop.example.com", domain)).toBe(true);
    expect(inScope("example.com", domain)).toBe(true);
    expect(inScope("badexample.com", domain)).toBe(false);
    expect(inScope("example.com.evil.net", domain)).toBe(false);
    expect(inScope("www.example.com", host)).toBe(true);
    expect(inScope("shop.example.com", host)).toBe(false);
    expect(inScope("example.com", host)).toBe(false);
    expect(inScope("example.com", null)).toBe(false);
  });

  it("DNS answers: private, loopback, link-local, mapped, 6to4 and Teredo are refused", () => {
    for (const ip of ["10.1.2.3", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.5.4", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:0a00:0001::", "2001:0:4136:e378:8000:63bf:f5ff:fffe"]) {
      expect(blockedIp(ip), ip).toBeTruthy();
    }
    for (const ip of ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "1.1.1.1"]) expect(blockedIp(ip), ip).toBeNull();
    expect(blockedV6("2001:0:4136:e378:8000:63bf:f7f7:f7f7")).toBeNull(); // Teredo for a public address
  });

  it("host names for sites", () => {
    expect(checkHostName("example.com")).toBeNull();
    expect(checkHostName("shop.example.co.uk")).toBeNull();
    expect(checkHostName("10.0.0.5")).toMatch(/IP address/);
    expect(checkHostName("example.com/path")).toMatch(/valid host/);
    expect(checkHostName("x.localhost")).toMatch(/local/);
  });
});

describe("TXT parsing and the public-suffix walk", () => {
  it("joins quoted and split strings, undoes escapes", () => {
    expect(parseTxt('"perchlight-privacy-verify=abc"')).toBe("perchlight-privacy-verify=abc");
    expect(parseTxt('"perchlight-privacy-" "verify=abc"')).toBe("perchlight-privacy-verify=abc");
    expect(parseTxt('"a\\"b" "c\\065"')).toBe('a"bcA');
    expect(parseTxt("unquoted")).toBe("unquoted");
  });
  it("walks host then parents up to the registrable domain, at most 3", () => {
    expect(txtCandidates("example.com")).toEqual(["example.com"]);
    expect(txtCandidates("www.example.com")).toEqual(["www.example.com", "example.com"]);
    expect(txtCandidates("a.b.shop.example.com")).toEqual(["a.b.shop.example.com", "b.shop.example.com", "shop.example.com"]);
    expect(txtCandidates("shop.example.co.uk")).toEqual(["shop.example.co.uk", "example.co.uk"]);
    expect(registrableDomain("x.you.workers.dev")).toBe("you.workers.dev");
    expect(isPublicSuffix("co.uk")).toBe(true);
    expect(isPublicSuffix("example.co.uk")).toBe(false);
  });
});

describe("safeFetch", () => {
  beforeEach(resetAll);
  const ctx = (scope, extra = {}) => ({ scope, budget: newBudget(), dnsOk: {}, headers: { "User-Agent": "t" }, ...extra });
  const domain = { kind: "domain", name: "example.com" };

  it("refuses a host outside the verified scope without any request", async () => {
    const calls = fakeNet();
    const r = await safeFetch("https://other.org/", ctx(domain));
    expect(r).toMatchObject({ ok: false, kind: "refused" });
    expect(r.error).toMatch(/isn't verified/);
    expect(calls).toHaveLength(0);
  });

  it("refuses a subdomain when only the host was verified by file", async () => {
    const calls = fakeNet();
    const r = await safeFetch("https://shop.example.com/", ctx({ kind: "host", name: "www.example.com" }));
    expect(r.kind).toBe("refused");
    expect(calls).toHaveLength(0);
  });

  it("re-resolves the host and refuses a private address", async () => {
    const calls = fakeNet({ ...dns({ a: { "example.com": ["10.0.0.7"] } }) });
    const r = await safeFetch("https://example.com/", ctx(domain));
    expect(r.kind).toBe("refused");
    expect(r.error).toMatch(/private address/);
    expect(calls.every((c) => c.url.startsWith("https://cloudflare-dns.com/"))).toBe(true);
  });

  it("follows redirects by hand, checking every hop; an IP-literal Location isn't followed", async () => {
    const calls = fakeNet({
      ...dns({ a: { "example.com": ["93.184.216.34"] } }),
      "=https://example.com/a": { status: 302, headers: { Location: "https://169.254.169.254/latest/meta-data" } },
    });
    const r = await safeFetch("https://example.com/a", ctx(domain));
    expect(r.kind).toBe("refused");
    expect(r.error).toMatch(/redirect not followed.*IP address/);
    expect(calls.filter((c) => !c.url.includes("dns-query")).map((c) => c.url)).toEqual(["https://example.com/a"]);
    expect(calls.every((c) => c.redirect === "manual" || c.url.includes("dns-query"))).toBe(true);
  });

  it("a redirect to an unverified host is 'offsite' and not followed", async () => {
    const calls = fakeNet({ ...dns({ a: { "www.example.com": ["93.184.216.34"] } }), "=https://www.example.com/": { status: 301, headers: { Location: "https://shop.example.com/" } } });
    const r = await safeFetch("https://www.example.com/", ctx({ kind: "host", name: "www.example.com" }));
    expect(r).toMatchObject({ ok: false, kind: "offsite", host: "shop.example.com" });
    expect(calls.some((c) => c.url.includes("shop.example.com") && !c.url.includes("dns-query"))).toBe(false);
  });

  it("stops after 5 hops, sends no cookies, caps the body", async () => {
    const routes = { ...dns({ a: { "example.com": ["93.184.216.34"] } }) };
    for (let i = 0; i < 8; i++) routes[`=https://example.com/r${i}`] = { status: 302, headers: { Location: `/r${i + 1}` } };
    const calls = fakeNet(routes);
    const r = await safeFetch("https://example.com/r0", ctx(domain));
    expect(r.ok).toBe(true);
    expect(r.status).toBe(302);
    expect(r.hops).toBe(5);
    expect(calls.filter((c) => !c.url.includes("dns-query"))).toHaveLength(6);
    expect(calls.every((c) => !c.headers.has("Cookie"))).toBe(true);

    fakeNet({ ...dns({ a: { "example.com": ["93.184.216.34"] } }), "=https://example.com/big": { status: 200, body: "x".repeat(5000) } });
    const big = await safeFetch("https://example.com/big", ctx(domain), { maxBytes: 1000 });
    expect(big.body.length).toBe(1000);
    expect(big.truncated).toBe(true);
  });

  it("spends one subrequest per hop plus DNS, and stops when the budget runs out", async () => {
    fakeNet({ ...dns({ a: { "example.com": ["93.184.216.34"] } }), "=https://example.com/": { status: 200, body: "ok" } });
    const b = newBudget(3);
    const r = await safeFetch("https://example.com/", { scope: domain, budget: b, dnsOk: {}, headers: {} });
    expect(r.ok).toBe(true);
    expect(b.used).toBe(3);
    const r2 = await safeFetch("https://example.com/", { scope: domain, budget: b, dnsOk: { "example.com": true }, headers: {} });
    expect(r2.kind).toBe("budget");
  });

  it("times out", async () => {
    fakeNet({ ...dns({ a: { "example.com": ["93.184.216.34"] } }), "=https://example.com/": "timeout" });
    const r = await safeFetch("https://example.com/", ctx(domain));
    expect(r.kind).toBe("timeout");
    restoreNet();
  });
});
