// The admin API: /api/*, behind Authorization: Bearer <ADMIN_TOKEN> (16+
// characters, compared in constant time: both sides hashed first), as
// perchlight-updates / perchlight-hooks. Request bodies are capped at 16 KB
// and every statement is parameterised. The Worker never fetches your sites:
// verify and scan are passed to the Scanner.
import { json, fail, readJson, sqlTime, parseJson, utcDay } from "../lib/http.js";
import { safeEqual, randomToken, sha256Hex } from "../lib/crypto.js";
import { scannerStub } from "../lib/appctx.js";
import { checkSite, LIMITS } from "../lib/config.js";
import { instructions } from "../lib/verify.js";
import { buildReport } from "../lib/report.js";
import { MANUAL_MIN_MS } from "../scanner.js";

export async function isAdmin(request, env) {
  const token = String(env.ADMIN_TOKEN ?? "");
  if (token.length < 16) return false;
  const m = /^Bearer (.+)$/.exec(request.headers.get("Authorization") ?? "");
  if (!m) return false;
  return safeEqual(m[1].trim(), token);
}

function siteOut(row) {
  return {
    id: row.id,
    host: row.host,
    source: row.source,
    state: row.state,
    paused: Boolean(row.paused),
    every: row.every,
    ownHosts: parseJson(row.own_hosts, []),
    pages: parseJson(row.pages, ["/"]),
    settings: parseJson(row.settings, {}),
    verifiedBy: row.verify_method,
    verifiedScope: row.verified_scope ? `${row.verified_scope}:${row.verified_name}` : null,
    verifiedAt: row.verified_at,
    lastScanId: row.last_scan_id,
    lastScanAt: row.last_scan_at,
    lastStatus: row.last_status,
    nextScanAt: row.next_scan_at,
    high: row.high,
    medium: row.medium,
    shareLink: Boolean(row.share_token_hash),
    configError: row.config_error,
    verify: row.state === "active" ? undefined : instructions(row.host, row.verify_token),
  };
}

const settingsOf = (s) => ({ host: s.host, ownHosts: parseJson(s.own_hosts, []), pages: parseJson(s.pages, ["/"]).filter((p) => p !== "/"), every: s.every, ...parseJson(s.settings, {}) });

export async function handleApi(request, app, ctx, rest) {
  const { env } = app;
  if (String(env.ADMIN_TOKEN ?? "").length < 16) return fail(503, "Set the ADMIN_TOKEN secret (16+ characters) first.");
  if (!(await isAdmin(request, env))) return fail(401, "unauthorized", {});
  const db = env.DB;
  const method = request.method;
  const url = new URL(request.url);
  let parts;
  try {
    parts = rest.split("/").filter(Boolean).map((p) => decodeURIComponent(p));
  } catch {
    return fail(400, "bad path");
  }
  const now = app.now();
  const scanner = () => scannerStub(env);

  // ---- sites ----
  if (parts[0] === "sites" && parts.length === 1) {
    if (method === "GET") {
      const r = await db.prepare("SELECT * FROM sites ORDER BY id").all();
      return json({ ok: true, sites: (r.results ?? []).map(siteOut) });
    }
    if (method === "POST") {
      const body = await readJson(request);
      if (!body) return fail(400, "Send a JSON object of at most 16 KB.");
      const id = body.id === undefined ? `s${(await sha256Hex(randomToken())).slice(0, 8)}` : String(body.id);
      const { id: _drop, ...settings } = body;
      const c = checkSite(id, settings);
      if (c.error) return fail(400, c.error);
      const n = await db.prepare("SELECT COUNT(*) AS n FROM sites").first();
      if ((n?.n ?? 0) >= LIMITS.sites) return fail(409, `At most ${LIMITS.sites} sites.`);
      const token = randomToken();
      const s = c.site;
      const res = await db
        .prepare("INSERT INTO sites (id, host, source, own_hosts, pages, settings, every, verify_token, state) VALUES (?1, ?2, 'api', ?3, ?4, ?5, ?6, ?7, 'unverified') ON CONFLICT (id) DO NOTHING")
        .bind(s.id, s.host, JSON.stringify(s.ownHosts), JSON.stringify(s.pages), JSON.stringify(s.settings), s.every, token)
        .run();
      if (!res.meta?.changes) return fail(409, `A site with id "${s.id}" already exists.`);
      const row = await db.prepare("SELECT * FROM sites WHERE id = ?").bind(s.id).first();
      return json({ ok: true, site: siteOut(row), verify: instructions(s.host, token), next: `POST /api/sites/${s.id}/verify once the TXT record or the file is in place.` }, 201);
    }
    return fail(405, "method not allowed");
  }

  if (parts[0] === "sites" && parts.length >= 2) {
    const id = parts[1];
    const row = await db.prepare("SELECT * FROM sites WHERE id = ?").bind(id).first();
    if (!row) return fail(404, "not found");
    const sub = parts[2] ?? "";
    if (parts.length === 2) {
      if (method === "GET") return json({ ok: true, site: siteOut(row) });
      if (method === "PATCH") {
        const body = await readJson(request);
        if (!body) return fail(400, "Send a JSON object of at most 16 KB.");
        const { paused, ...changes } = body;
        if (paused !== undefined && typeof paused !== "boolean") return fail(400, "paused must be true or false");
        if (row.source === "config" && Object.keys(changes).some((k) => k !== "every")) return fail(409, "This site comes from privacy.json: only paused and every can be changed here; edit privacy.json for the rest.");
        let next = row;
        if (Object.keys(changes).length) {
          const c = checkSite(id, { ...settingsOf(row), ...changes });
          if (c.error) return fail(400, c.error);
          const s = c.site;
          const hostChanged = s.host !== row.host;
          await db
            .prepare(
              `UPDATE sites SET host = ?2, own_hosts = ?3, pages = ?4, settings = ?5, every = ?6,
                 state = CASE WHEN ?7 = 1 THEN 'unverified' ELSE state END,
                 verify_method = CASE WHEN ?7 = 1 THEN NULL ELSE verify_method END, verified_scope = CASE WHEN ?7 = 1 THEN NULL ELSE verified_scope END,
                 verified_name = CASE WHEN ?7 = 1 THEN NULL ELSE verified_name END, verified_at = CASE WHEN ?7 = 1 THEN NULL ELSE verified_at END WHERE id = ?1`,
            )
            .bind(id, s.host, JSON.stringify(s.ownHosts), JSON.stringify(s.pages), JSON.stringify(s.settings), s.every, hostChanged ? 1 : 0)
            .run();
        }
        if (paused !== undefined) await db.prepare("UPDATE sites SET paused = ? WHERE id = ?").bind(paused ? 1 : 0, id).run();
        next = await db.prepare("SELECT * FROM sites WHERE id = ?").bind(id).first();
        return json({ ok: true, site: siteOut(next) });
      }
      if (method === "DELETE") {
        if (row.source === "config") return fail(409, "This site comes from privacy.json: pause it here, or remove it from privacy.json.");
        await db.batch([
          db.prepare("DELETE FROM findings WHERE site_id = ?").bind(id),
          db.prepare("DELETE FROM scans WHERE site_id = ?").bind(id),
          db.prepare("DELETE FROM mutes WHERE site_id = ?").bind(id),
          db.prepare("DELETE FROM sites WHERE id = ?").bind(id),
        ]);
        await scanner().forgetSite(id);
        return json({ ok: true, deleted: id });
      }
      return fail(405, "method not allowed");
    }
    if (sub === "verify" && method === "POST") {
      const r = await scanner().verifySite(id);
      return json({ ok: r.ok, ...r }, r.ok ? 200 : 422);
    }
    if (sub === "scan" && method === "POST") {
      if (row.state !== "active") return fail(409, row.state === "verification_lost" ? "verification_lost" : "unverified", { detail: "Verify ownership first: POST /api/sites/:id/verify." });
      if (row.paused) return fail(409, "paused");
      const last = await db.prepare("SELECT started_ms FROM scans WHERE site_id = ? ORDER BY id DESC LIMIT 1").bind(id).first();
      if (last && now - last.started_ms < MANUAL_MIN_MS) {
        const wait = Math.ceil((MANUAL_MIN_MS - (now - last.started_ms)) / 1000);
        return fail(429, "At most one scan per site every 5 minutes.", { retryAfterSeconds: wait });
      }
      await scanner().requestScan(id);
      return json({ ok: true, queued: true }, 202);
    }
    if (sub === "report.json" && method === "GET") {
      return json(await buildReport(db, id));
    }
    if (sub === "share") {
      if (method === "POST") {
        const token = randomToken();
        await db.prepare("UPDATE sites SET share_token_hash = ? WHERE id = ?").bind(await sha256Hex(token), id).run();
        return json({ ok: true, url: `${app.base}/r/${encodeURIComponent(id)}?s=${token}`, note: "Shown once. Anyone with this link can read the report; DELETE /api/sites/:id/share revokes it." }, 201);
      }
      if (method === "DELETE") {
        await db.prepare("UPDATE sites SET share_token_hash = NULL WHERE id = ?").bind(id).run();
        return json({ ok: true, revoked: true });
      }
    }
    return fail(404, "not found");
  }

  // ---- scans ----
  if (parts[0] === "scans" && parts.length === 1 && method === "GET") {
    const site = url.searchParams.get("site");
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") ?? 30) || 30));
    const r = site
      ? await db.prepare("SELECT id, site_id, trigger, started_at, finished_at, status, pages_ok, pages_failed, subrequests, high, medium, low, info, new_count, resolved_count, error FROM scans WHERE site_id = ? ORDER BY id DESC LIMIT ?").bind(site, limit).all()
      : await db.prepare("SELECT id, site_id, trigger, started_at, finished_at, status, pages_ok, pages_failed, subrequests, high, medium, low, info, new_count, resolved_count, error FROM scans ORDER BY id DESC LIMIT ?").bind(limit).all();
    return json({ ok: true, scans: r.results ?? [] });
  }
  if (parts[0] === "scans" && parts.length === 2 && method === "GET") {
    const scan = await db.prepare("SELECT * FROM scans WHERE id = ?").bind(parts[1]).first();
    if (!scan) return fail(404, "not found");
    const f = await db.prepare("SELECT key, check_id, severity, page, subject, evidence, source, first_seen_at, carried FROM findings WHERE scan_id = ? LIMIT 2000").bind(parts[1]).all();
    return json({ ok: true, scan: { ...scan, notes: parseJson(scan.notes, {}), changes: parseJson(scan.changes, {}) }, findings: f.results ?? [] });
  }

  // ---- mutes ----
  if (parts[0] === "findings" && parts.length === 3 && parts[2] === "mute") {
    const key = parts[1];
    if (!/^[0-9a-f]{20}$/.test(key)) return fail(400, "A finding key is 20 hex characters.");
    let siteId = url.searchParams.get("site");
    let note = "";
    if (method === "POST") {
      const body = await readJson(request);
      if (!body) return fail(400, "Send a JSON object of at most 16 KB.");
      if (body.site !== undefined) siteId = String(body.site);
      note = String(body.note ?? "").slice(0, 500);
    }
    if (!siteId) {
      const r = await db.prepare("SELECT DISTINCT site_id FROM findings WHERE key = ? LIMIT 2").bind(key).all();
      const ids = (r.results ?? []).map((x) => x.site_id);
      if (ids.length !== 1) return fail(400, ids.length ? "That key is on more than one site: send \"site\"." : "No finding with that key; send \"site\" to mute it anyway.");
      siteId = ids[0];
    }
    const site = await db.prepare("SELECT id FROM sites WHERE id = ?").bind(siteId).first();
    if (!site) return fail(404, "site not found");
    if (method === "POST") {
      await db.prepare("INSERT INTO mutes (site_id, key, note, at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (site_id, key) DO UPDATE SET note = excluded.note, at = excluded.at").bind(siteId, key, note, sqlTime(now)).run();
      return json({ ok: true, muted: { site: siteId, key, note } });
    }
    if (method === "DELETE") {
      await db.prepare("DELETE FROM mutes WHERE site_id = ? AND key = ?").bind(siteId, key).run();
      return json({ ok: true, unmuted: { site: siteId, key } });
    }
    return fail(405, "method not allowed");
  }

  // ---- alerts, footprint, config ----
  if (parts[0] === "deliveries" && parts.length === 1 && method === "GET") {
    const status = url.searchParams.get("status");
    const r = status
      ? await db.prepare("SELECT * FROM deliveries WHERE status = ? ORDER BY created_at DESC LIMIT 100").bind(status).all()
      : await db.prepare("SELECT * FROM deliveries ORDER BY created_at DESC LIMIT 100").all();
    return json({ ok: true, deliveries: r.results ?? [] });
  }
  if (parts[0] === "deliveries" && parts.length === 3 && parts[2] === "retry" && method === "POST") {
    const ok = await scanner().retryDelivery(parts[1]);
    return ok ? json({ ok: true }) : fail(404, "No failed alert with that id.");
  }
  if (parts[0] === "test-alert" && method === "POST") {
    const r = await scanner().testAlert();
    return r.error ? fail(400, r.error) : json({ ok: true, ...r });
  }
  if (parts[0] === "footprint" && method === "GET") {
    const s = await scanner().status();
    const w = await db.prepare("SELECT day, k, n FROM footprint WHERE day >= ? ORDER BY day DESC, k").bind(utcDay(now - 7 * 86_400_000)).all();
    return json({ ok: true, scanner: s.footprint, workerRequests: w.results ?? [], note: "Counted by this deployment: the Scanner's own subrequests, D1 statements and rows (from D1's meta), Durable Object rows written; Worker requests are at-least counts written once a minute per isolate." });
  }
  if (parts[0] === "config" && method === "GET") {
    const s = await scanner().status();
    return json({ ok: true, errors: app.cfg.errors, sites: app.cfg.sites.map((x) => x.id), scanner: { ...s, footprint: undefined } });
  }
  if (parts[0] === "housekeeping" && method === "POST") {
    return json({ ok: true, ...(await scanner().housekeepingNow()) });
  }
  return fail(404, "not found");
}
