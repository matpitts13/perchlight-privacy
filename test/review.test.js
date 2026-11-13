// Regressions for the v0.1 review findings.
import { describe, it, expect, beforeEach } from "vitest";
import { resetAll, fakeNet, rows, runScan, runAt, inDo, siteRoutes, txtFor, addVerifiedSite, alertCalls, htmlPage, GOOD_HEADERS, NOW, DAY } from "./helpers.js";
import { scannerClass } from "../src/scanner.js";

describe("review regressions", () => {
  beforeEach(resetAll);

  it("M1: a storage error while persisting never leaves later runs skipped", async () => {
    fakeNet();
    const r = await inDo(async (inst) => {
      const orig = inst.persist;
      let once = true;
      inst.persist = function () {
        if (once) {
          once = false;
          throw new Error("SQLITE_FULL");
        }
        return orig.call(this);
      };
      try {
        await inst.run(NOW).catch(() => {});
        return { running: inst.running, second: await inst.run(NOW + 1000) };
      } finally {
        delete inst.persist;
      }
    });
    expect(r.running).toBe(false);
    expect(r.second.skipped).toBeUndefined();
    expect(r.second.ok).toBe(true);
  });

  it("M2: a config site removed from privacy.json and added back is no longer paused", async () => {
    fakeNet();
    await runAt(NOW); // syncs "cfg"
    // Simulate a deploy without it, then one with it again.
    await inDo(async (inst) => {
      const without = new (scannerClass({ sites: {}, alerts: { email: [], webhooks: [] } }))(inst.ctx, inst.env);
      await without.d1(without.app(NOW), null, without.syncStatements(without.app(NOW)), null);
    });
    expect((await rows("SELECT paused, config_error FROM sites WHERE id = 'cfg'"))[0]).toEqual({ paused: 1, config_error: "removed from privacy.json" });
    await inDo(async (inst) => {
      await inst.d1(inst.app(NOW), null, inst.syncStatements(inst.app(NOW)), null);
    });
    expect((await rows("SELECT paused, config_error FROM sites WHERE id = 'cfg'"))[0]).toEqual({ paused: 0, config_error: null });
  });

  it("L4: a stylesheet that can't be read keeps its findings (no false 'resolved')", async () => {
    const { token } = await addVerifiedSite({ id: "main", host: "example.com" });
    const r = { ...siteRoutes("example.com"), ...txtFor("example.com", token) };
    r["=https://example.com/"] = { status: 200, body: htmlPage('<a href="/privacy">p</a><link rel="stylesheet" href="/t.css">'), headers: GOOD_HEADERS };
    r["=https://example.com/t.css"] = { status: 200, body: "@import url(https://fonts.googleapis.com/css2?family=A);", headers: { "Content-Type": "text/css" } };
    fakeNet(r);
    await runScan(NOW);
    r["=https://example.com/t.css"] = "down";
    let calls = fakeNet(r);
    await runScan(NOW + DAY);
    calls = calls.concat(fakeNet(r));
    await runScan(NOW + 2 * DAY);
    const f = await rows("SELECT f.subject, f.carried FROM findings f JOIN sites s ON s.last_scan_id = f.scan_id");
    expect(f).toEqual([{ subject: "fonts.googleapis.com", carried: 1 }]);
    expect(alertCalls(calls)).toHaveLength(0);
  });

  it("L3: the next alarm after starting a single site's scan includes that site's next due time", async () => {
    const { token } = await addVerifiedSite({ id: "main", host: "example.com", every: "6h" });
    fakeNet({ ...siteRoutes("example.com"), ...txtFor("example.com", token) });
    const { at } = await runScan(NOW);
    const next = await inDo((inst) => inst.hot.nextScanAt);
    expect(next).toBe(NOW + 6 * 3_600_000);
    expect(at).toBeGreaterThan(NOW);
  });
});
