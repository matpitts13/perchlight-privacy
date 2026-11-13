// The Scanner: one Durable Object instance ("scanner") and the only thing
// that fetches your sites, decides findings and sends alerts. One alarm =
// the next due thing: the next chunk of a scan in progress, the next due
// scan, an alert retry, housekeeping, or at most an hour. No cron trigger.
//
// Each run (docs/SDD.md, "Scanning"; the pattern is perchlight-hooks'
// Scheduler / perchlight-status' Checker):
// 1. SETS THE NEXT ALARM FIRST (a minute out while a scan is in progress, an
//    hour otherwise), before anything that can fail.
// 2. Works one chunk of the scan in progress (prepare / pages / finalize), or
//    starts the next due scan. Each fetch reserves its worst case from a
//    45-subrequest budget (4 kept back for D1 and an alert).
// 3. Sends due alerts (claimed in this object's SQLite first).
// 4. Saves the WHOLE hot state (one row) and the scan cursor every run, so
//    an eviction resumes a scan rather than restarting it.
// 5. Never spins: a chunk or D1 call that fails waits with exponential
//    backoff (30 s doubling to 30 min), a run that throws waits the same way,
//    and a scan not finished within 30 minutes is closed as failed.
import { DurableObject } from "cloudflare:workers";
import { makeApp, testHooks, clock } from "./lib/appctx.js";
import { newBudget, spend, refund, left, COST } from "./lib/budget.js";
import { CLAIMS_SQL, channels, claim, sendDue, nextClaimAt, syncStatement, markSynced, retryById, pruneClaims } from "./lib/alerts.js";
import { alertMessage } from "./lib/notify.js";
import { safeFetch, requestHeaders, setCookies } from "./lib/fetcher.js";
import { checkResolves } from "./lib/dns.js";
import { verifyOwnership } from "./lib/verify.js";
import { parseHtml } from "./lib/parse.js";
import { pageFindings, headerFindings, cookieFindings, robotsFindings, sitemapFindings, cssFindings, isBlocked } from "./lib/checks.js";
import { finding, withKeys, countBySeverity, atOrAbove } from "./lib/findings.js";
import { diffScan } from "./lib/diff.js";
import { everySeconds } from "./lib/config.js";
import { inScope, checkUrl, normHost } from "./lib/ssrf.js";
import { sha256Hex, sortableId, hash32, randomToken } from "./lib/crypto.js";
import { sqlTime, utcDay, parseJson, errText } from "./lib/http.js";
import { net } from "./lib/net.js";

export const MIN = 60_000;
export const HOUR = 60 * MIN;
export const IDLE_MS = HOUR;
export const CHUNK_PAGES = 10;
export const CONCURRENCY = 6;
export const SCAN_TIMEOUT_MS = 30 * MIN;
export const HOUSEKEEPING_MS = 6 * HOUR;
export const VERIFY_LOST_GAP_MS = 24 * HOUR;
export const MANUAL_MIN_MS = 5 * MIN;
export const PREPARE_NEEDS = 36;
export const MAX_FINDINGS_PAGE = 100;
export const MAX_FINDINGS_SCAN = 1500;
const HK_DELETES = 2000;
const errStack = (err) => (err instanceof Error ? (err.stack ?? err.message) : String(err));

/** 30 s, 1 min, 2 min ... at most 30 min. */
export function backoff(n) {
  return Math.min(30_000 * 2 ** Math.max(0, n - 1), 30 * MIN);
}

function emptyFootprint(day) {
  return { day, runs: 0, subrequests: 0, d1Statements: 0, d1RowsWritten: 0, d1RowsRead: 0, d1Failures: 0, doRowsWritten: 0, pages: 0, scans: 0, alerts: 0 };
}

function defaultHot(now) {
  return { cfgHash: null, lastRunAt: null, lastError: null, runErrors: 0, d1Fails: 0, d1RetryAt: 0, nextScanAt: null, housekeepingAt: 0, heartbeatAt: 0, fp: emptyFootprint(utcDay(now)), fpPrev: [] };
}

const J = (v) => JSON.stringify(v);

export function scannerClass(rawConfig) {
  return class Scanner extends DurableObject {
    constructor(ctx, env) {
      super(ctx, env);
      Object.defineProperty(this, "env", { get: () => (testHooks.env ? { ...env, ...testHooks.env } : env) });
      this.sql = ctx.storage.sql;
      this.sql.exec("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
      this.sql.exec(CLAIMS_SQL);
      this.sql.exec("CREATE TABLE IF NOT EXISTS cursor (site_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data TEXT NOT NULL)");
      this.sql.exec("CREATE TABLE IF NOT EXISTS tracked (site_id TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL, missing INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (site_id, key))");
      this.sql.exec("CREATE TABLE IF NOT EXISTS sitestate (site_id TEXT PRIMARY KEY, fail_streak INTEGER NOT NULL DEFAULT 0, failing_since INTEGER, failing_open INTEGER NOT NULL DEFAULT 0)");
      this.sql.exec("CREATE TABLE IF NOT EXISTS queue (site_id TEXT PRIMARY KEY, next_run_at INTEGER NOT NULL, trigger TEXT NOT NULL)");
      this.hot = null;
      this.running = false;
    }

    app(now) {
      return makeApp(rawConfig, this.env, { now: () => now });
    }

    // ---- hot state -------------------------------------------------------

    load(now) {
      if (!this.hot) {
        const r = this.sql.exec("SELECT v FROM kv WHERE k = 'hot'").toArray()[0];
        const saved = r ? JSON.parse(r.v) : {};
        this.hot = { ...defaultHot(now), ...saved };
      }
      return this.hot;
    }

    /** The whole hot state, one row. Every run. */
    persist() {
      const cur = this.sql.exec("INSERT INTO kv (k, v) VALUES ('hot', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v", J(this.hot));
      this.hot.fp.doRowsWritten += cur.rowsWritten;
    }

    rollFootprint(h, now) {
      const day = utcDay(now);
      if (h.fp.day !== day) {
        h.fpPrev = [h.fp, ...(h.fpPrev ?? [])].slice(0, 7);
        h.fp = emptyFootprint(day);
      }
    }

    async setAlarmAt(t) {
      await this.ctx.storage.setAlarm(t);
      this.alarmAt = t;
      if (this.hot) this.hot.fp.doRowsWritten++;
    }

    getCursor() {
      const r = this.sql.exec("SELECT data FROM cursor LIMIT 1").toArray()[0];
      return r ? JSON.parse(r.data) : null;
    }

    saveCursor(cur) {
      const w = this.sql.exec("INSERT INTO cursor (site_id, scan_id, data) VALUES (?, ?, ?) ON CONFLICT (site_id) DO UPDATE SET scan_id = excluded.scan_id, data = excluded.data", cur.site.id, cur.scanId, J(cur));
      if (this.hot) this.hot.fp.doRowsWritten += w.rowsWritten;
    }

    dropCursor(siteId) {
      this.sql.exec("DELETE FROM cursor WHERE site_id = ?", siteId);
    }

    /** When the next run is due. Nothing D1-dependent is earlier than the D1 backoff. */
    nextDue(h, now) {
      const times = [now + IDLE_MS];
      const d1 = (t) => Math.max(t, h.d1RetryAt ?? 0);
      const cur = this.getCursor();
      if (cur) times.push(cur.nextAt ?? now + 1000);
      else {
        const q = this.sql.exec("SELECT MIN(next_run_at) AS t FROM queue").toArray()[0]?.t;
        if (q !== null && q !== undefined) times.push(d1(q));
        if (h.nextScanAt !== null && h.nextScanAt !== undefined) times.push(d1(h.nextScanAt));
      }
      const c = nextClaimAt(this.sql);
      if (c !== null && c !== undefined) times.push(c);
      times.push(d1((h.housekeepingAt ?? 0) + HOUSEKEEPING_MS));
      return Math.max(Math.min(...times), now + 1000);
    }

    // ---- RPC from the Worker ----------------------------------------------

    /** Re-arms the alarm if it's missing or stuck. Called lazily (throttled) by API requests and /tick. */
    async ensureAlarm(nowArg) {
      const now = nowArg ?? clock.now();
      const h = this.load(now);
      const cur = await this.ctx.storage.getAlarm();
      if (cur === null || cur < now - MIN) {
        await this.setAlarmAt(now + 1000);
        this.persist();
        return { rearmed: true, at: now + 1000 };
      }
      void h;
      return { rearmed: false, at: cur };
    }

    /** Asks for a run soon, if the alarm is later. */
    async wake(nowArg) {
      const now = nowArg ?? clock.now();
      const t = now + 1000;
      this.wakeAt = Math.min(this.wakeAt ?? Infinity, t);
      const cur = await this.ctx.storage.getAlarm();
      if (cur === null || cur > t + 1000) {
        await this.ctx.storage.setAlarm(t);
        this.alarmAt = t;
      }
      return true;
    }

    /** Checks ownership now (POST /api/sites/:id/verify). */
    async verifySite(id, nowArg) {
      const now = nowArg ?? clock.now();
      const app = this.app(now);
      this.load(now);
      const row = await app.env.DB.prepare("SELECT * FROM sites WHERE id = ?").bind(id).first();
      if (!row) return { ok: false, error: "not found" };
      const settings = parseJson(row.settings, {});
      const budget = newBudget();
      const v = await verifyOwnership(row, { budget, dnsOk: {}, headers: requestHeaders(settings, await tokenTag(row.verify_token)) });
      this.hot.fp.subrequests += budget.used;
      if (v.result === "ok") {
        await app.env.DB.prepare(
          `UPDATE sites SET verify_method = ?2, verified_scope = ?3, verified_name = ?4, verified_at = ?5, verify_failures = 0, verify_failed_ms = NULL,
             next_scan_ms = CASE WHEN state != 'active' OR next_scan_ms IS NULL THEN ?6 ELSE next_scan_ms END,
             next_scan_at = CASE WHEN state != 'active' OR next_scan_ms IS NULL THEN ?7 ELSE next_scan_at END,
             state = 'active' WHERE id = ?1`,
        )
          .bind(id, v.method, v.scope.kind, v.scope.name, sqlTime(now), now, sqlTime(now))
          .run();
        this.hot.nextScanAt = Math.min(this.hot.nextScanAt ?? Infinity, now);
        await this.wake(now);
      }
      this.persist();
      return { ok: v.result === "ok", result: v.result, method: v.method ?? null, scope: v.scope ?? null, detail: v.detail, found: v.found ?? [] };
    }

    /** Queues a manual scan (the Worker has already checked the site is active and the 5-minute limit). */
    async requestScan(id, nowArg) {
      const now = nowArg ?? clock.now();
      this.load(now);
      this.sql.exec("INSERT INTO queue (site_id, next_run_at, trigger) VALUES (?, ?, 'manual') ON CONFLICT (site_id) DO NOTHING", id, now);
      await this.wake(now);
      this.persist();
      return { queued: true };
    }

    /** A deleted site: its tracked findings, state, queue entry and any scan in progress go (no alert). */
    async forgetSite(id) {
      this.sql.exec("DELETE FROM tracked WHERE site_id = ?", id);
      this.sql.exec("DELETE FROM sitestate WHERE site_id = ?", id);
      this.sql.exec("DELETE FROM queue WHERE site_id = ?", id);
      this.dropCursor(id);
      return true;
    }

    async status(nowArg) {
      const now = nowArg ?? clock.now();
      const h = this.load(now);
      const cur = this.getCursor();
      return {
        nextAlarm: await this.ctx.storage.getAlarm(),
        lastRunAt: h.lastRunAt,
        lastError: h.lastError,
        d1Failing: (h.d1RetryAt ?? 0) > now,
        scanInProgress: cur ? { site: cur.site.id, scan: cur.scanId, stage: cur.stage, page: cur.pageIdx, pages: cur.pages.length, startedAt: cur.startedAt } : null,
        footprint: [h.fp, ...(h.fpPrev ?? [])],
      };
    }

    async retryDelivery(id) {
      this.load(clock.now());
      const ok = retryById(this.sql, id);
      if (ok) await this.wake(clock.now());
      return ok;
    }

    /** A sample alert to every channel, sent at once. */
    async testAlert(nowArg) {
      const now = nowArg ?? clock.now();
      const app = this.app(now);
      const h = this.load(now);
      const chans = channels(app.cfg);
      if (!chans.length) return { error: "No alert channels: add addresses to alerts.email or names to alerts.webhooks in privacy.json." };
      const msg = alertMessage({ kind: "test", subject: `test:${now}:${crypto.randomUUID().slice(0, 8)}`, at: now });
      claim(this.sql, msg, chans, now);
      await sendDue(this.sql, this.env, now, chans.length + 5);
      const s = syncStatement(this.sql);
      if (s.stmt && (await this.d1(app, h, [s.stmt], null))) markSynced(this.sql, s.keys);
      const rows = this.sql.exec("SELECT channel, status, error FROM claims WHERE subject = ? AND kind = 'test'", msg.subject).toArray();
      this.persist();
      return { results: rows };
    }

    async housekeepingNow(nowArg) {
      const now = nowArg ?? clock.now();
      const app = this.app(now);
      const h = this.load(now);
      const r = await this.housekeeping(app, h, now, newBudget());
      this.persist();
      return r;
    }

    async alarm() {
      if (this.env.PAUSE_ALARMS === "1") return; // tests drive runs directly
      await this.run(Date.now());
    }

    // ---- D1 ----------------------------------------------------------------

    /** One D1 batch of { sql, params }. Returns the results, or null (and backs off) on failure. */
    async d1(app, h, stmts, budget) {
      if (!stmts.length) return [];
      if (!spend(budget, 1)) return null;
      const db = app.env.DB;
      try {
        const res = await db.batch(stmts.map((s) => db.prepare(s.sql).bind(...s.params)));
        if (h) {
          h.fp.d1Statements += stmts.length;
          for (const r of res) {
            h.fp.d1RowsWritten += r.meta?.rows_written ?? 0;
            h.fp.d1RowsRead += r.meta?.rows_read ?? 0;
          }
          h.d1Fails = 0;
          h.d1RetryAt = 0;
        }
        return res;
      } catch (err) {
        if (h) {
          h.d1Fails = (h.d1Fails ?? 0) + 1;
          h.d1RetryAt = app.now() + backoff(h.d1Fails);
          h.fp.d1Failures++;
          h.lastError = { at: app.now(), error: `D1: ${errText(err).slice(0, 300)}` };
        }
        return null;
      }
    }

    syncStatements(app) {
      const v = (k) => `(j.value ->> '${k}')`;
      const sites = app.cfg.sites.map((s) => ({ id: s.id, host: s.host, own: J(s.ownHosts), pages: J(s.pages), settings: J(s.settings), every: s.every, token: randomToken() }));
      return [
        {
          sql: `INSERT INTO sites (id, host, source, own_hosts, pages, settings, every, verify_token, state)
                SELECT ${v("id")}, ${v("host")}, 'config', ${v("own")}, ${v("pages")}, ${v("settings")}, ${v("every")}, ${v("token")}, 'unverified' FROM json_each(?1) AS j WHERE true
                ON CONFLICT (id) DO UPDATE SET source = 'config', own_hosts = excluded.own_hosts, pages = excluded.pages, settings = excluded.settings,
                  every = excluded.every, config_error = NULL,
                  state = CASE WHEN sites.host != excluded.host THEN 'unverified' ELSE sites.state END,
                  verify_method = CASE WHEN sites.host != excluded.host THEN NULL ELSE sites.verify_method END,
                  verified_scope = CASE WHEN sites.host != excluded.host THEN NULL ELSE sites.verified_scope END,
                  verified_name = CASE WHEN sites.host != excluded.host THEN NULL ELSE sites.verified_name END,
                  verified_at = CASE WHEN sites.host != excluded.host THEN NULL ELSE sites.verified_at END,
                  host = excluded.host`,
          params: [J(sites)],
        },
        { sql: "UPDATE sites SET config_error = 'removed from privacy.json', paused = 1 WHERE source = 'config' AND id NOT IN (SELECT value FROM json_each(?1))", params: [J(sites.map((s) => s.id))] },
      ];
    }

    // ---- one alarm run -------------------------------------------------------

    async run(now = Date.now()) {
      if (this.running) return { skipped: true };
      this.running = true;
      const app = this.app(now);
      const h = this.load(now);
      this.rollFootprint(h, now);
      h.fp.runs++;
      const budget = newBudget();
      this.wakeAt = null;
      let ok = true;
      try {
        // 1. The next alarm, before anything that might fail: soon while a scan is in progress, else idle.
        await this.setAlarmAt(this.getCursor() ? now + MIN : now + IDLE_MS);
        await this.work(app, h, now, budget);
        h.runErrors = 0;
      } catch (err) {
        ok = false;
        h.runErrors = (h.runErrors ?? 0) + 1;
        h.lastError = { at: now, error: errStack(err).slice(0, 500) };
        console.error(`scanner run: ${errStack(err)}`);
      } finally {
        h.lastRunAt = now;
        let next = this.nextDue(h, now);
        // A run that threw never re-runs sooner than its backoff.
        if (!ok) next = Math.max(next, now + backoff(h.runErrors));
        if (this.wakeAt) next = Math.min(next, Math.max(this.wakeAt, now + 1000));
        this.wakeAt = null;
        try {
          if (next !== this.alarmAt) await this.setAlarmAt(next);
          if (ok) await this.heartbeat(app, h, now, budget);
        } finally {
          h.fp.subrequests += budget.used;
          this.persist();
          this.running = false;
        }
      }
      return { ok, next: this.alarmAt, used: budget.used };
    }

    async work(app, h, now, budget) {
      const d1ok = () => !((h.d1RetryAt ?? 0) > now);
      // Config into D1 (only when privacy.json changed).
      const hash = String(hash32(J(rawConfig)));
      if (h.cfgHash !== hash && d1ok()) {
        if (await this.d1(app, h, this.syncStatements(app), budget)) h.cfgHash = hash;
      }
      let cur = this.getCursor();
      if (cur && now - cur.startedAt > SCAN_TIMEOUT_MS && cur.stage !== "closing") {
        cur.close = { error: `timed out: not finished within ${SCAN_TIMEOUT_MS / MIN} minutes`, countFail: true };
        cur.stage = "closing";
        cur.nextAt = now;
      }
      if (!cur && d1ok()) cur = await this.startDue(app, h, now, budget);
      if (cur && (cur.nextAt ?? 0) <= now) await this.chunk(app, h, cur, now, budget);
      await this.sendAlerts(app, h, now, budget);
      if (d1ok() && now - (h.housekeepingAt ?? 0) >= HOUSEKEEPING_MS && left(budget) >= 3) {
        h.housekeepingAt = now;
        await this.housekeeping(app, h, now, budget);
      }
    }

    /** Reads sites from D1 and starts the next due scan (manual requests first). */
    async startDue(app, h, now, budget) {
      const rr = await this.d1(
        app,
        h,
        [
          { sql: "SELECT * FROM sites WHERE state = 'active' AND paused = 0 AND config_error IS NULL", params: [] },
          { sql: "SELECT id FROM deliveries WHERE status = 'retry_requested' LIMIT 20", params: [] },
        ],
        budget,
      );
      if (!rr) return null;
      const sites = rr[0].results ?? [];
      for (const d of rr[1].results ?? []) retryById(this.sql, d.id);
      const byId = new Map(sites.map((s) => [s.id, s]));
      // Queue entries for sites that aren't active any more are dropped.
      const queue = this.sql.exec("SELECT site_id, trigger FROM queue ORDER BY next_run_at").toArray();
      for (const q of queue) if (!byId.has(q.site_id)) this.sql.exec("DELETE FROM queue WHERE site_id = ?", q.site_id);
      const manual = queue.find((q) => byId.has(q.site_id));
      const due = sites.filter((s) => (s.next_scan_ms ?? 0) <= now).sort((a, b) => (a.next_scan_ms ?? 0) - (b.next_scan_ms ?? 0));
      const pick = manual ? byId.get(manual.site_id) : due[0];
      const future = sites.filter((s) => s !== pick).map((s) => s.next_scan_ms ?? now);
      h.nextScanAt = future.length ? Math.min(...future) : null;
      if (!pick) return null;
      const trigger = manual ? "manual" : "schedule";
      const scanId = sortableId("sc_", now);
      const everyMs = everySeconds(pick.every) * 1000;
      // The next scan is computed from this start (so a failing scan never re-runs at once).
      const res = await this.d1(
        app,
        h,
        [
          { sql: "INSERT INTO scans (id, site_id, trigger, started_at, started_ms, status) VALUES (?1, ?2, ?3, ?4, ?5, 'running')", params: [scanId, pick.id, trigger, sqlTime(now), now] },
          { sql: "UPDATE sites SET next_scan_ms = ?2, next_scan_at = ?3 WHERE id = ?1", params: [pick.id, now + everyMs, sqlTime(now + everyMs)] },
        ],
        budget,
      );
      if (!res) return null;
      this.sql.exec("DELETE FROM queue WHERE site_id = ?", pick.id);
      const cur = {
        scanId,
        trigger,
        startedAt: now,
        stage: "prepare",
        nextAt: now,
        fails: 0,
        site: {
          id: pick.id,
          host: pick.host,
          ownHosts: parseJson(pick.own_hosts, []),
          pages: parseJson(pick.pages, ["/"]),
          settings: parseJson(pick.settings, {}),
          verify_token: pick.verify_token,
          verify_failures: pick.verify_failures ?? 0,
          verify_failed_ms: pick.verify_failed_ms ?? null,
        },
        pages: [],
        pageIdx: 0,
        results: {},
        findings: [],
        carryPages: [],
        carryChecks: [],
        consent: [],
        policy: null,
        stylesheets: [],
        dnsOk: {},
        notes: {},
        subrequests: 0,
      };
      this.saveCursor(cur);
      return cur;
    }

    /** One chunk of the scan in progress. A chunk that throws backs off; 5 throws close the scan. */
    async chunk(app, h, cur, now, budget) {
      const used0 = budget.used;
      try {
        if (cur.stage === "prepare") {
          if (left(budget) < PREPARE_NEEDS) {
            cur.nextAt = now + 1000;
          } else await this.prepare(app, h, cur, now, budget);
        } else if (cur.stage === "pages") await this.pagesChunk(app, h, cur, now, budget);
        else if (cur.stage === "final") await this.finalize(app, h, cur, now, budget);
        if (cur.stage === "closing") await this.close(app, h, cur, now, budget);
      } catch (err) {
        cur.fails = (cur.fails ?? 0) + 1;
        cur.nextAt = now + backoff(cur.fails);
        h.lastError = { at: now, error: `scan ${cur.scanId} (${cur.stage}): ${errStack(err).slice(0, 400)}` };
        console.error(`scanner chunk: ${errStack(err)}`);
        if (cur.fails >= 5 && cur.stage !== "closing") {
          cur.stage = "closing";
          cur.close = { error: `the scan failed 5 times in a row: ${errText(err).slice(0, 200)}`, countFail: true };
        } else if (cur.fails >= 10) {
          // Closing itself keeps throwing: give up on the record (housekeeping marks the scan row failed).
          this.dropCursor(cur.site.id);
          return;
        }
      }
      cur.subrequests += budget.used - used0;
      if (cur.done) return;
      this.saveCursor(cur);
    }

    // ---- chunk 1: prepare ---------------------------------------------------

    async prepare(app, h, cur, now, budget) {
      const site = cur.site;
      cur.headers = requestHeaders(site.settings, await tokenTag(site.verify_token));
      // Ownership is re-checked at the start of every scan.
      const v = await verifyOwnership(site, { budget, dnsOk: cur.dnsOk, headers: cur.headers });
      if (v.result === "failed") {
        const first = site.verify_failed_ms ?? now;
        const lost = (site.verify_failures ?? 0) >= 1 && now - first >= VERIFY_LOST_GAP_MS;
        cur.stage = "closing";
        cur.close = {
          error: `ownership check failed: ${v.detail}${v.found?.length ? ` (${v.found.join("; ")})` : ""}`,
          countFail: false,
          siteSql: { sql: "UPDATE sites SET verify_failures = verify_failures + 1, verify_failed_ms = COALESCE(verify_failed_ms, ?2), state = CASE WHEN ?3 = 1 THEN 'verification_lost' ELSE state END WHERE id = ?1", params: [site.id, first, lost ? 1 : 0] },
          alert: lost ? { kind: "verification_lost", subject: `verification_lost:${site.id}:${first}`, reason: v.detail } : null,
        };
        return;
      }
      if (v.result === "unknown") {
        cur.stage = "closing";
        cur.close = { error: `couldn't check ownership: ${v.detail}`, countFail: true };
        return;
      }
      cur.scope = v.scope;
      cur.verify = { method: v.method, scope: v.scope.kind, name: v.scope.name };
      const ctx = { scope: cur.scope, budget, dnsOk: cur.dnsOk, headers: cur.headers };
      const host = normHost(site.host);
      // The site host's addresses are re-resolved every scan and refused if private.
      if (!cur.dnsOk[host]) {
        const d = await checkResolves(host, budget);
        if (!d.ok) {
          cur.stage = "closing";
          cur.close = { error: d.private ? d.error : `couldn't resolve ${host}: ${d.error}`, countFail: true };
          return;
        }
        cur.dnsOk[host] = true;
      }
      // Does http:// redirect to https://? (the one http: request; not followed)
      const hr = await safeFetch(`http://${host}/`, ctx, { follow: 0, allowHttp: true, readBody: false, timeoutMs: 10_000 });
      cur.httpCheck = hr.ok ? { checked: true, status: hr.status, toHttps: hr.status >= 300 && hr.status < 400 && /^https:\/\//i.test(hr.headers.get("Location") ?? ""), hsts: Boolean(hr.headers.get("Strict-Transport-Security")) } : { checked: false };
      const own = ownSet(site);
      // robots.txt (first 512 KB)
      let sitemapUrl = null;
      const rb = await safeFetch(`https://${host}/robots.txt`, ctx, { maxBytes: 512 * 1024 });
      if (rb.ok && rb.status >= 200 && rb.status < 300) {
        const r = robotsFindings(new TextDecoder().decode(rb.body));
        cur.findings.push(...r.findings);
        sitemapUrl = r.sitemaps[0] ?? null;
      } else if (!rb.ok && rb.kind !== "offsite" && rb.kind !== "refused") cur.carryPages.push("/robots.txt");
      // The first sitemap only, first 1 MB.
      let discovered = [];
      const smUrl = sitemapUrl ?? `https://${host}/sitemap.xml`;
      const smCheck = checkUrl(smUrl);
      if (smCheck.ok && !inScope(smCheck.host, cur.scope)) {
        cur.findings.push(finding("sitemap.sensitive", "medium", "/sitemap", smCheck.host, `robots.txt points to a sitemap on another host: ${smCheck.host}`));
      } else if (smCheck.ok) {
        const sm = await safeFetch(smUrl, ctx, { maxBytes: 1024 * 1024 });
        if (sm.ok && sm.status >= 200 && sm.status < 300) {
          const r = sitemapFindings(new TextDecoder().decode(sm.body), { host, own, page: "/sitemap" });
          cur.findings.push(...r.findings);
          discovered = r.paths;
        } else if (!sm.ok && sm.kind !== "offsite" && sm.kind !== "refused") cur.carryPages.push("/sitemap");
      }
      // security.txt (Should; info)
      const st = await safeFetch(`https://${host}/.well-known/security.txt`, ctx, { maxBytes: 32 * 1024 });
      if (st.ok) {
        const text = new TextDecoder().decode(st.body);
        if (!(st.status >= 200 && st.status < 300 && /^\s*contact\s*:/im.test(text))) cur.findings.push(finding("security-txt.missing", "info", "/.well-known/security.txt", "security.txt", `/.well-known/security.txt answered HTTP ${st.status}${st.status === 200 ? " without a Contact: line" : ""}`));
      } else if (st.kind !== "offsite" && st.kind !== "refused") cur.carryPages.push("/.well-known/security.txt");
      // The page list: the home page, your listed pages, then up to `discover` from the sitemap; 20 at most.
      const list = [];
      const seen = new Set();
      const addPage = (p) => {
        let url;
        let label;
        if (p.startsWith("/")) {
          url = `https://${host}${p}`;
          label = p;
        } else {
          url = p;
          try {
            const u = new URL(p);
            label = normHost(u.hostname) === host ? `${u.pathname}${u.search}` : `${u.host}${u.pathname}${u.search}`;
          } catch {
            label = p;
          }
        }
        if (seen.has(label) || list.length >= 20) return;
        seen.add(label);
        list.push({ page: label, url });
      };
      for (const p of site.pages) addPage(p);
      const n = Math.min(site.settings.discover ?? 0, 20);
      for (const p of discovered) {
        if (list.length >= 20 || n <= 0 || list.length - site.pages.length >= n) break;
        addPage(p);
      }
      cur.pages = list;
      cur.stage = "pages";
      cur.nextAt = now + 1000;
    }

    // ---- chunks 2..n: pages -----------------------------------------------

    async pagesChunk(app, h, cur, now, budget) {
      const end = Math.min(cur.pages.length, cur.pageIdx + CHUNK_PAGES);
      let i = cur.pageIdx;
      // Waves of pages, each reserving its worst case (1 fetch + 5 redirects + 2 DNS); what a page
      // didn't use goes back before the next wave. 4 subrequests are always kept back.
      while (i < end) {
        const room = Math.floor((left(budget) - COST.reserve) / COST.page);
        if (room <= 0) break;
        const wave = cur.pages.slice(i, Math.min(end, i + Math.min(room, CONCURRENCY)));
        const results = await Promise.all(
          wave.map(async (p) => {
            spend(budget, COST.page);
            const sub = { left: COST.page, used: 0 };
            try {
              return await this.scanPage(cur, p, sub, now);
            } finally {
              refund(budget, sub.left);
            }
          }),
        );
        let stop = false;
        for (let k = 0; k < wave.length; k++) {
          const r = results[k];
          if (r.deferred) {
            stop = true;
            break;
          }
          this.recordPage(cur, wave[k], r);
          i++;
        }
        if (stop) break;
      }
      cur.pageIdx = i;
      if (cur.pageIdx >= cur.pages.length) cur.stage = "final";
      cur.nextAt = now + 1000;
    }

    recordPage(cur, p, r) {
      this.hot.fp.pages = (this.hot.fp.pages ?? 0) + 1;
      // "responded": the host answered (an error status, a challenge, an unverified redirect), as opposed to no answer at all.
      cur.results[p.page] = { ok: r.ok, responded: Boolean(r.ok || r.responded || r.status), status: r.status ?? null, error: r.error ?? null, truncated: Boolean(r.truncated) };
      if (!r.ok) cur.carryPages.push(p.page);
      const room = MAX_FINDINGS_SCAN - cur.findings.length;
      if (room > 0) cur.findings.push(...(r.findings ?? []).slice(0, Math.min(room, MAX_FINDINGS_PAGE)));
      for (const c of r.consent ?? []) if (!cur.consent.includes(c)) cur.consent.push(c);
      if (r.policy) cur.policy = r.policy;
      if (r.littleHtml) cur.notes.littleHtml = true;
      for (const s of r.stylesheets ?? []) if (!cur.stylesheets.some((x) => x.url === s) && cur.stylesheets.length < 20) cur.stylesheets.push({ url: s, page: p.page });
    }

    async scanPage(cur, p, budget, now) {
      const ctx = { scope: cur.scope, budget, dnsOk: cur.dnsOk, headers: cur.headers };
      const r = await safeFetch(p.url, ctx);
      if (!r.ok) {
        if (r.kind === "budget") return { deferred: true };
        if (r.kind === "offsite") return { ok: false, responded: true, error: r.error, findings: [finding("redirect.offsite", "info", p.page, r.host, `redirected to ${r.host} (not verified for this site), not followed`)] };
        return { ok: false, error: r.error };
      }
      const head = new TextDecoder().decode(r.body.subarray(0, 4096));
      if (isBlocked(r.status, r.headers, head)) return { ok: false, status: r.status, error: `blocked by bot protection (HTTP ${r.status})`, findings: [finding("scan.blocked", "medium", p.page, "bot-protection", `HTTP ${r.status}${r.headers.get("cf-mitigated") ? `, cf-mitigated: ${r.headers.get("cf-mitigated")}` : ""}: a challenge page instead of the page`)] };
      if (r.status < 200 || r.status >= 300) return { ok: false, status: r.status, error: `HTTP ${r.status}` };
      const site = cur.site;
      const isHome = p.page === "/";
      const out = cookieFindings(setCookies(r.headers), { page: p.page, https: r.url.startsWith("https:"), necessary: site.settings.necessaryCookies ?? [], now });
      const ct = (r.headers.get("Content-Type") ?? "").toLowerCase();
      let pf = { findings: [], consent: [], policy: null, stylesheets: [], littleHtml: false };
      let metaReferrer = null;
      if (!ct || ct.includes("html")) {
        const obs = await parseHtml(r.body);
        metaReferrer = obs.metaReferrer;
        pf = pageFindings(obs, { pageUrl: r.url, page: p.page, own: ownSet(site), isHome });
      }
      out.push(...pf.findings);
      if (isHome) out.push(...headerFindings(r.headers, { page: "/", metaReferrer, httpCheck: cur.httpCheck }));
      return { ok: true, status: r.status, truncated: r.truncated, findings: out, consent: pf.consent, policy: isHome ? pf.policy : null, stylesheets: pf.stylesheets, littleHtml: isHome && pf.littleHtml };
    }

    // ---- last chunk: links, CSS, diff, alerts ------------------------------

    async finalize(app, h, cur, now, budget) {
      const site = cur.site;
      const ctx = { scope: cur.scope, budget, dnsOk: cur.dnsOk, headers: cur.headers };
      const home = cur.results["/"];
      if (cur.policyDone !== true) {
        if (home?.ok) {
          const kinds = [["privacy", "policy.privacy-missing", "high"]];
          if (site.settings.imprint) kinds.push(["imprint", "policy.imprint-missing", "medium"]);
          for (const [kind, check, sev] of kinds) {
            const cand = cur.policy?.[kind]?.[0];
            if (!cand) {
              cur.findings.push(finding(check, sev, "/", kind, `no link to ${kind === "privacy" ? "a privacy policy" : "an imprint"} found on the home page`));
              continue;
            }
            const c = checkUrl(cand);
            // A policy hosted elsewhere (a policy generator's site) can't be fetched: it counts as linked.
            if (!c.ok || !inScope(c.host, cur.scope)) continue;
            if (left(budget) < COST.page + COST.reserve) {
              cur.carryChecks.push(check);
              continue;
            }
            const r = await safeFetch(cand, ctx, { maxBytes: 64 * 1024 });
            if (r.ok && !(r.status >= 200 && r.status < 300)) cur.findings.push(finding(check, sev, "/", kind, `the ${kind} link ${new URL(cand).pathname} answered HTTP ${r.status}`));
            else if (!r.ok && r.kind !== "offsite") cur.carryChecks.push(check);
          }
        }
        // Same-host stylesheets (up to 5): @import and @font-face on third-party hosts.
        for (const css of cur.stylesheets.slice(0, 5)) {
          const c = checkUrl(css.url);
          if (!c.ok || !inScope(c.host, cur.scope) || left(budget) < 1 + COST.dns + COST.reserve) continue;
          const r = await safeFetch(css.url, ctx, { follow: 0, maxBytes: 512 * 1024 });
          if (r.ok && r.status >= 200 && r.status < 300) cur.findings.push(...cssFindings(new TextDecoder().decode(r.body), css.url, { page: css.page, own: ownSet(site) }));
        }
        cur.policyDone = true;
        this.saveCursor(cur);
      }

      const results = Object.values(cur.results);
      const pagesOk = results.filter((r) => r.ok).length;
      const pagesFailed = results.length - pagesOk;
      const first = Object.entries(cur.results).find(([, r]) => !r.ok);
      const why = `no page could be checked${first ? ` (${first[0]}: ${first[1].error})` : ""}`;
      // No answer from any page at all: a failed scan. Some answered (an error status, a challenge,
      // an unverified redirect): partial, with those findings, but it still counts as a failing scan.
      if (!results.some((r) => r.ok || r.responded)) {
        cur.stage = "closing";
        cur.close = { error: why, countFail: true };
        return;
      }
      const status = pagesFailed > 0 ? "partial" : "done";
      const countFail = pagesOk === 0;

      // D1: mutes, and whether the site still exists (deleted mid-scan: dropped, no alert).
      const rr = await this.d1(
        app,
        h,
        [
          { sql: "SELECT key FROM mutes WHERE site_id = ?", params: [site.id] },
          { sql: "SELECT id, settings FROM sites WHERE id = ?", params: [site.id] },
        ],
        budget,
      );
      if (!rr) {
        cur.nextAt = Math.max(now + 1000, h.d1RetryAt);
        return;
      }
      if (!(rr[1].results ?? []).length) {
        this.dropCursor(site.id);
        cur.done = true;
        return;
      }
      const settings = parseJson(rr[1].results[0].settings, site.settings);
      const muted = new Set((rr[0].results ?? []).map((r) => r.key));

      let list = await withKeys(cur.findings);
      // Carry forward: a page (or check) that couldn't be read keeps its previous findings, unchanged.
      const tracked = this.trackedFor(site.id);
      const have = new Set(list.map((f) => f.key));
      const carryPages = new Set(cur.carryPages);
      const carryChecks = new Set(cur.carryChecks);
      for (const t of tracked.values()) {
        if (have.has(t.key) || (t.missing ?? 0) > 0) continue;
        if (carryPages.has(t.page) || carryChecks.has(t.check)) list.push({ ...t, carried: true });
      }
      list = list.slice(0, MAX_FINDINGS_SCAN);
      const d = diffScan(tracked, list, status, now);
      const firstSeen = new Map(d.upserts.map((u) => [u.key, u.first_seen_at]));
      const level = settings.alertLevel ?? "medium";
      const alertable = (f) => !muted.has(f.key) && atOrAbove(f.severity, level) && f.severity !== "info";
      const added = d.added.filter(alertable);
      const resolved = d.resolved.filter(alertable);
      const counts = countBySeverity(list);
      const brief = (f) => ({ key: f.key, check: f.check, severity: f.severity, page: f.page, subject: f.subject });
      const notes = { pages: cur.results, consentManagers: cur.consent, littleHtml: Boolean(cur.notes.littleHtml), carried: [...carryPages, ...carryChecks] };
      const rows = list.map((f) => ({ k: f.key, c: f.check, s: f.severity, p: f.page, sub: f.subject, e: f.evidence, fs: sqlTime(firstSeen.get(f.key) ?? now), cr: f.carried ? 1 : 0 }));
      const v = (k) => `(j.value ->> '${k}')`;
      const stmts = [
        {
          sql: `INSERT INTO findings (scan_id, site_id, key, check_id, severity, page, subject, evidence, source, first_seen_at, carried)
                SELECT ?1, ?2, ${v("k")}, ${v("c")}, ${v("s")}, ${v("p")}, ${v("sub")}, ${v("e")}, 'static', ${v("fs")}, ${v("cr")} FROM json_each(?3) AS j WHERE true
                ON CONFLICT (scan_id, key) DO NOTHING`,
          params: [cur.scanId, site.id, J(rows)],
        },
        {
          sql: `UPDATE scans SET status = ?2, finished_at = ?3, pages_ok = ?4, pages_failed = ?5, subrequests = ?6, high = ?7, medium = ?8, low = ?9, info = ?10,
                  new_count = ?11, resolved_count = ?12, notes = ?13, changes = ?14, error = NULL WHERE id = ?1`,
          params: [cur.scanId, status, sqlTime(now), pagesOk, pagesFailed, cur.subrequests + budget.used, counts.high, counts.medium, counts.low, counts.info, d.added.length, d.resolved.length, J(notes), J({ new: d.added.map(brief), resolved: d.resolved.map(brief) })],
        },
        {
          sql: `UPDATE sites SET last_scan_id = ?2, last_scan_at = ?3, last_status = ?4, high = ?5, medium = ?6,
                  verify_method = ?7, verified_scope = ?8, verified_name = ?9, verified_at = ?3, verify_failures = 0, verify_failed_ms = NULL WHERE id = ?1`,
          params: [site.id, cur.scanId, sqlTime(now), status, counts.high, counts.medium, cur.verify.method, cur.verify.scope, cur.verify.name],
        },
      ];
      if (!(await this.d1(app, h, stmts, budget))) {
        cur.nextAt = Math.max(now + 1000, h.d1RetryAt);
        return;
      }
      // D1 has the scan; the diff, the alert claim and the cursor's end commit together, so a
      // repeated alarm can't alert twice or lose the change.
      const host = site.host;
      const reportUrl = reportLink(app, site.id);
      this.ctx.storage.transactionSync(() => {
        for (const k of d.deletes) this.sql.exec("DELETE FROM tracked WHERE site_id = ? AND key = ?", site.id, k);
        for (const u of d.upserts) {
          const { carried: _c, ...rest } = u;
          this.sql.exec("INSERT INTO tracked (site_id, key, data, missing) VALUES (?, ?, ?, ?) ON CONFLICT (site_id, key) DO UPDATE SET data = excluded.data, missing = excluded.missing", site.id, u.key, J(rest), u.missing ?? 0);
        }
        const chans = channels(app.cfg);
        this.applyStreak(app, h, site, cur.scanId, countFail ? why : null, chans, now, reportUrl);
        if (added.length || resolved.length) {
          h.fp.alerts += claim(this.sql, alertMessage({ kind: "changes", subject: `changes:${site.id}:${cur.scanId}`, site: site.id, host, at: now, scan: cur.scanId, added, resolved }, reportUrl), chans, now);
        }
        this.dropCursor(site.id);
      });
      cur.done = true;
      h.fp.scans++;
    }

    /** Closes a scan that couldn't complete: D1 first, then the streak and any alert, together. */
    async close(app, h, cur, now, budget) {
      const site = cur.site;
      const c = cur.close ?? { error: "failed", countFail: true };
      const stmts = [
        {
          sql: "UPDATE scans SET status = 'failed', finished_at = ?2, error = ?3, subrequests = ?4, notes = ?5, pages_ok = ?6, pages_failed = ?7 WHERE id = ?1",
          params: [cur.scanId, sqlTime(now), String(c.error).slice(0, 500), cur.subrequests + budget.used, J({ pages: cur.results, consentManagers: cur.consent }), Object.values(cur.results).filter((r) => r.ok).length, Object.values(cur.results).filter((r) => !r.ok).length],
        },
        { sql: "UPDATE sites SET last_status = 'failed' WHERE id = ?1", params: [site.id] },
      ];
      if (c.siteSql) stmts.push(c.siteSql);
      if (!(await this.d1(app, h, stmts, budget))) {
        cur.nextAt = Math.max(now + 1000, h.d1RetryAt);
        return;
      }
      const reportUrl = reportLink(app, site.id);
      this.ctx.storage.transactionSync(() => {
        const chans = channels(app.cfg);
        if (c.countFail) this.applyStreak(app, h, site, cur.scanId, c.error, chans, now, reportUrl);
        if (c.alert) h.fp.alerts += claim(this.sql, alertMessage({ ...c.alert, site: site.id, host: site.host, at: now, scan: cur.scanId }, reportUrl), chans, now);
        this.dropCursor(site.id);
      });
      cur.done = true;
      h.fp.scans++;
    }

    /**
     * The failing-scans streak (call inside a storage transaction). `failure` is the reason, or null
     * for a scan that checked pages. Two failures in a row alert once; the next good scan alerts recovery.
     */
    applyStreak(app, h, site, scanId, failure, chans, now, reportUrl) {
      const ss = this.siteState(site.id);
      if (failure) {
        const streak = ss.fail_streak + 1;
        const since = ss.failing_since ?? now;
        const open = ss.failing_open || streak >= 2 ? 1 : 0;
        if (streak >= 2 && !ss.failing_open) {
          h.fp.alerts += claim(this.sql, alertMessage({ kind: "scan_failing", subject: `scan_failing:${site.id}:${since}`, site: site.id, host: site.host, at: now, failures: streak, since, reason: failure }, reportUrl), chans, now);
        }
        this.sql.exec("INSERT INTO sitestate (site_id, fail_streak, failing_since, failing_open) VALUES (?, ?, ?, ?) ON CONFLICT (site_id) DO UPDATE SET fail_streak = excluded.fail_streak, failing_since = excluded.failing_since, failing_open = excluded.failing_open", site.id, streak, since, open);
        return;
      }
      if (ss.failing_open) h.fp.alerts += claim(this.sql, alertMessage({ kind: "recovered", subject: `recovered:${site.id}:${scanId}`, site: site.id, host: site.host, at: now, scan: scanId }, reportUrl), chans, now);
      this.sql.exec("INSERT INTO sitestate (site_id, fail_streak, failing_since, failing_open) VALUES (?, 0, NULL, 0) ON CONFLICT (site_id) DO UPDATE SET fail_streak = 0, failing_since = NULL, failing_open = 0", site.id);
    }

    trackedFor(siteId) {
      const m = new Map();
      for (const r of this.sql.exec("SELECT key, data, missing FROM tracked WHERE site_id = ?", siteId).toArray()) m.set(r.key, { ...JSON.parse(r.data), key: r.key, missing: r.missing });
      return m;
    }

    siteState(siteId) {
      return this.sql.exec("SELECT * FROM sitestate WHERE site_id = ?", siteId).toArray()[0] ?? { fail_streak: 0, failing_since: null, failing_open: 0 };
    }

    // ---- alerts, heartbeat, housekeeping -------------------------------------

    async sendAlerts(app, h, now, budget) {
      const limit = left(budget) - 2;
      if (limit > 0) await sendDue(this.sql, this.env, now, limit);
      const s = syncStatement(this.sql);
      if (s.stmt && !((h.d1RetryAt ?? 0) > now) && (await this.d1(app, h, [s.stmt], budget))) markSynced(this.sql, s.keys);
    }

    async heartbeat(app, h, now, budget) {
      const url = String(app.env.HEARTBEAT_URL ?? "").trim();
      if (!url || now - (h.heartbeatAt ?? 0) < 5 * MIN) return;
      const t = checkUrl(url);
      if (!t.ok || !spend(budget, 1)) return;
      h.heartbeatAt = now;
      try {
        const res = await net.fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(10_000) });
        res.body?.cancel().catch(() => {});
      } catch (err) {
        console.error(`heartbeat: ${errText(err)}`);
      }
    }

    /** Old scans beyond retention.scansPerSite and their findings (at most 2,000 rows a run), stuck "running" scans, old deliveries and footprint rows. */
    async housekeeping(app, h, now, budget) {
      pruneClaims(this.sql, now);
      const keep = app.cfg.retention.scansPerSite;
      const old = `SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY site_id ORDER BY id DESC) AS rn FROM scans) WHERE rn > ?1`;
      const cur = this.getCursor();
      const res = await this.d1(
        app,
        h,
        [
          { sql: `DELETE FROM findings WHERE rowid IN (SELECT rowid FROM findings WHERE scan_id IN (${old}) LIMIT ${HK_DELETES})`, params: [keep] },
          { sql: `DELETE FROM scans WHERE id IN (${old}) AND NOT EXISTS (SELECT 1 FROM findings WHERE findings.scan_id = scans.id)`, params: [keep] },
          { sql: "UPDATE scans SET status = 'failed', error = 'interrupted (not finished)', finished_at = ?1 WHERE status = 'running' AND started_ms < ?2 AND id != ?3", params: [sqlTime(now), now - 2 * SCAN_TIMEOUT_MS, cur?.scanId ?? ""] },
          { sql: "DELETE FROM deliveries WHERE created_at < ?1", params: [sqlTime(now - 30 * 24 * HOUR)] },
          { sql: "DELETE FROM footprint WHERE day < ?1", params: [utcDay(now - 30 * 24 * HOUR)] },
          { sql: "DELETE FROM findings WHERE site_id NOT IN (SELECT id FROM sites) AND rowid IN (SELECT rowid FROM findings WHERE site_id NOT IN (SELECT id FROM sites) LIMIT 500)", params: [] },
        ],
        budget,
      );
      return { ok: Boolean(res), deleted: res ? (res[0].meta?.changes ?? 0) + (res[1].meta?.changes ?? 0) : 0 };
    }
  };
}

function ownSet(site) {
  return new Set([normHost(site.host), ...(site.ownHosts ?? []).map(normHost)]);
}

function reportLink(app, siteId) {
  const base = String(app.env.PUBLIC_URL ?? "").trim().replace(/\/+$/, "");
  return base ? `${base}/r/${encodeURIComponent(siteId)}` : null;
}

/** X-Perchlight-Privacy: a hash of the site's token, so you can recognise (and allow) the scanner in WAF rules. */
export async function tokenTag(token) {
  return (await sha256Hex(`perchlight-privacy:${token}`)).slice(0, 16);
}
