import { describe, it, expect } from "vitest";
import { diffScan } from "../src/lib/diff.js";
import { checkConfig, checkSite, parseEvery, everySeconds } from "../src/lib/config.js";
import { backoff } from "../src/scanner.js";
import { alertMessage, describeFinding } from "../src/lib/notify.js";
import shipped from "../privacy.json";

const f = (key, extra = {}) => ({ key, check: "third-party.tracker", severity: "high", page: "/", subject: key, evidence: "e", ...extra });
const tracked = (...rows) => new Map(rows.map((r) => [r.key, { ...r, first_seen_at: 1, missing: r.missing ?? 0 }]));

describe("diff: two clean scans to resolve; partial scans never count as missing", () => {
  it("new, unchanged, then resolved only after 2 done scans without it", () => {
    let t = new Map();
    let d = diffScan(t, [f("a"), f("b")], "done", 10);
    expect(d.added.map((x) => x.key)).toEqual(["a", "b"]);
    t = tracked(...d.upserts);
    d = diffScan(t, [f("a")], "done", 20);
    expect(d.added).toEqual([]);
    expect(d.resolved).toEqual([]);
    expect(d.upserts.find((u) => u.key === "b").missing).toBe(1);
    t = tracked(...d.upserts);
    d = diffScan(t, [f("a")], "done", 30);
    expect(d.resolved.map((x) => x.key)).toEqual(["b"]);
    expect(d.deletes).toEqual(["b"]);
  });
  it("a flapping finding (absent once, back) is neither resolved nor new", () => {
    let t = tracked(f("a"));
    let d = diffScan(t, [], "done", 1);
    t = tracked(...d.upserts);
    d = diffScan(t, [f("a")], "done", 2);
    expect(d.added).toEqual([]);
    expect(d.resolved).toEqual([]);
    expect(d.upserts[0].missing).toBe(0);
    expect(d.upserts[0].first_seen_at).toBe(1);
  });
  it("partial: new keys added, absent keys untouched", () => {
    const t = tracked(f("a"), f("b", { missing: 1 }));
    const d = diffScan(t, [f("c")], "partial", 5);
    expect(d.added.map((x) => x.key)).toEqual(["c"]);
    expect(d.resolved).toEqual([]);
    expect(d.deletes).toEqual([]);
    expect(d.upserts.map((u) => u.key)).toEqual(["c"]);
  });
});

describe("config", () => {
  it("the shipped privacy.json is valid", () => {
    expect(checkConfig(shipped).errors).toEqual([]);
  });
  it("durations and the 6-hour minimum", () => {
    expect(parseEvery("6h")).toBe(21600);
    expect(parseEvery("1d12h")).toBe(129600);
    expect(parseEvery("soon")).toBeNull();
    expect(checkSite("a", { host: "example.com", every: "1h" }).error).toMatch(/at least 6h/);
    expect(everySeconds("1h")).toBe(21600);
    expect(everySeconds("bad")).toBe(86400);
  });
  it("pages: paths, https URLs; IP literals, localhost and http refused with a clear message", () => {
    for (const p of ["http://127.0.0.1", "https://10.0.0.5", "https://[::1]", "https://localhost", "http://example.com/x"]) {
      const r = checkSite("a", { host: "example.com", pages: [p] });
      expect(r.error, p).toMatch(/page .*(IP address|local or reserved|http:)/);
    }
    const ok = checkSite("a", { host: "example.com", pages: ["/pricing", "https://www.example.com/shop"] });
    expect(ok.site.pages).toEqual(["/", "/pricing", "https://www.example.com/shop"]);
    expect(checkSite("a", { host: "example.com", pages: Array.from({ length: 20 }, (_, i) => `/p${i}`) }).error).toMatch(/at most 20/);
  });
  it("hosts: IP literals, local names, public suffixes refused; limits", () => {
    expect(checkSite("a", { host: "10.0.0.5" }).error).toMatch(/IP address/);
    expect(checkSite("a", { host: "co.uk" }).error).toMatch(/public suffix/);
    expect(checkSite("a", { host: "nas.local" }).error).toMatch(/local/);
    expect(checkSite("A B", { host: "example.com" }).error).toMatch(/site id/);
    expect(checkSite("a", { host: "example.com", alertLevel: "info" }).error).toMatch(/alertLevel/);
    expect(checkSite("a", { host: "example.com", surprise: 1 }).error).toMatch(/unknown setting/);
    const many = Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`s${i}`, { host: `s${i}.example.com` }]));
    const c = checkConfig({ sites: many });
    expect(c.sites).toHaveLength(10);
    expect(c.errors[0]).toMatch(/at most 10/);
  });
  it("userAgent: browser-like by default, honest as a setting", () => {
    expect(checkSite("a", { host: "example.com" }).site.settings.userAgent).toBe("browser");
    expect(checkSite("a", { host: "example.com", userAgent: "honest" }).site.settings.userAgent).toBe("honest");
  });
});

describe("backoff and alert wording", () => {
  it("doubles from 30 s to at most 30 minutes", () => {
    expect(backoff(1)).toBe(30_000);
    expect(backoff(2)).toBe(60_000);
    expect(backoff(20)).toBe(30 * 60_000);
  });
  it("change alerts name hosts and pages, never evidence, and end with the disclaimer", () => {
    const m = alertMessage(
      {
        kind: "changes",
        subject: "changes:main:sc1",
        site: "main",
        host: "example.com",
        at: 0,
        added: [{ ...f("k1"), subject: "connect.facebook.net", page: "/pricing", evidence: "SECRET-EVIDENCE" }, { ...f("k2"), check: "email.exposed", severity: "low", subject: "jane@example.com" }],
        resolved: [{ ...f("k3"), check: "header.referrer-policy", subject: "Referrer-Policy", severity: "low" }],
      },
      "https://p.example.net/r/main",
    );
    expect(m.title).toBe("perchlight-privacy: example.com, 2 new, 1 resolved");
    expect(m.lines[0]).toBe("NEW (high): connect.facebook.net on /pricing (loaded)");
    expect(m.lines.join("\n")).not.toContain("SECRET-EVIDENCE");
    expect(m.lines.join("\n")).not.toContain("jane@");
    expect(m.lines.at(-2)).toBe("Report: https://p.example.net/r/main");
    expect(m.lines.at(-1)).toBe("Automated check, not legal advice.");
    expect(describeFinding({ subject: "a@b.com", page: "/", check: "email.mailto" })).toBe("a***@b.com on / (mailto: link)");
  });
});
