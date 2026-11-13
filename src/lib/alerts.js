// Sending alerts, once per (subject, kind, channel). Claim-then-send, copied
// from perchlight-hooks src/lib/alerts.js (from perchlight-status, itself from
// perchlight-forms
// src/lib/deliveries.js)): the claims live in the Scanner's own SQLite, a
// claim is an INSERT ... ON CONFLICT DO NOTHING, and a row is marked
// "sending" before the send starts. An alarm that runs twice never sends
// twice, and alerting doesn't depend on D1 having write quota left. Retries
// after 1, 5 and 30 minutes, 2 hours and 12 hours; a permanent refusal (4xx
// except 429) is "failed" with the reason; a send that may have gone out (a
// dropped call, a timeout after sending) is "unknown" and never retried.
// Each changed claim is copied to D1 `deliveries` for the desktop app.
// Subjects are unique per occurrence (they carry the scan id or the incident's
// start), so a second incident for the same site is a new alert.
import { EmailMessage } from "cloudflare:email";
import { mime, addressOnly, redactAddresses } from "./mime.js";
import { emailBody, webhookRequest, parseWebhooks } from "./notify.js";
import { randomId } from "./crypto.js";
import { sqlTime } from "./http.js";
import { checkUrl } from "./ssrf.js";
import { net } from "./net.js";

export const BACKOFF_MINUTES = [1, 5, 30, 120, 720];
export const STALE_MS = 2 * 60_000;
export const CLAIM_DAYS = 30;
const WEBHOOK_TIMEOUT_MS = 10_000;
const errText = (err) => (err instanceof Error ? err.message : String(err));

export const CLAIMS_SQL = `CREATE TABLE IF NOT EXISTS claims (
  subject TEXT NOT NULL, kind TEXT NOT NULL, channel TEXT NOT NULL,
  id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, sent_at INTEGER,
  claimed_at INTEGER, error TEXT, payload TEXT NOT NULL, synced INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (subject, kind, channel))`;

/** Every channel alerts go to. */
export function channels(cfg) {
  return [...cfg.alerts.email.map((e) => `email:${e}`), ...cfg.alerts.webhooks.map((w) => `webhook:${w}`)];
}

/** Claims one alert on every channel. Returns how many claims were new. */
export function claim(sql, msg, chans, now) {
  let made = 0;
  for (const ch of chans) {
    const cur = sql.exec(
      `INSERT INTO claims (subject, kind, channel, id, status, created_at, payload) VALUES (?, ?, ?, ?, 'pending', ?, ?)
       ON CONFLICT (subject, kind, channel) DO NOTHING`,
      msg.subject, msg.kind, ch, randomId("dl"), now, JSON.stringify(msg),
    );
    made += cur.rowsWritten > 0 ? 1 : 0;
  }
  return made;
}

/** A claim stuck in "sending" (the object was reset mid-send) may have gone out: unknown. */
export function releaseStale(sql, now) {
  sql.exec("UPDATE claims SET status = 'unknown', error = 'interrupted while sending; not retried so nothing is sent twice', synced = 0 WHERE status = 'sending' AND claimed_at < ?", now - STALE_MS);
}

export function dueCount(sql, now) {
  return sql.exec("SELECT COUNT(*) AS n FROM claims WHERE status IN ('pending', 'retry') AND next_at <= ?", now).toArray()[0].n;
}

export function nextClaimAt(sql) {
  const r = sql.exec("SELECT MIN(next_at) AS t FROM claims WHERE status IN ('pending', 'retry')").toArray()[0];
  return r?.t ?? null;
}

/** When to try again, or null when the retries are used up. */
export function nextAttempt(attempts, now) {
  if (attempts > BACKOFF_MINUTES.length) return null;
  return now + BACKOFF_MINUTES[attempts - 1] * 60_000;
}

async function sendEmail(env, to, msg, now) {
  const from = String(env.MAIL_FROM ?? "").trim();
  if (!from) return { status: "config", error: "MAIL_FROM isn't set in wrangler.jsonc vars." };
  if (!env.EMAIL || typeof env.EMAIL.send !== "function") return { status: "config", error: 'The "EMAIL" send_email binding is missing from wrangler.jsonc.' };
  const b = emailBody(msg);
  try {
    // mime() strips CR/LF from every header and RFC 2047-encodes non-ASCII: no header injection.
    const raw = mime({ from, to, subject: b.subject, text: b.text, html: b.html, now });
    await env.EMAIL.send(new EmailMessage(addressOnly(from), addressOnly(to), raw));
    return { status: "sent" };
  } catch (err) {
    const m = redactAddresses(errText(err));
    if (/not allowed|not verified|verified|destination|E_RECIPIENT|E_SENDER|domain/i.test(m)) {
      return { status: "config", error: `send_email: ${m}. Check the address is a verified destination in Email Routing and MAIL_FROM is on that domain.` };
    }
    return { status: "retry", error: `send_email: ${m}` };
  }
}

async function sendWebhook(env, name, msg, now, allowLocal) {
  const { hooks, error } = parseWebhooks(env, allowLocal);
  const hook = hooks[name];
  if (!hook) return { status: "config", error: error ?? `ALERT_WEBHOOKS has no https URL named "${name}".` };
  const t = checkUrl(hook.url);
  if (!t.ok) return { status: "config", error: `the webhook "${name}" ${t.error}` };
  const req = await webhookRequest(env, hook.format, msg, { now, token: hook.token });
  if ("error" in req) return { status: "config", error: req.error };
  try {
    const res = await net.fetch(hook.url, { method: "POST", headers: req.headers, body: req.body, redirect: "manual", signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS) });
    res.body?.cancel().catch(() => {});
    if (res.ok) return { status: "sent" };
    const e = `the webhook "${name}" answered HTTP ${res.status}`;
    if (res.status === 429 || res.status >= 500) return { status: "retry", error: e };
    return { status: "config", error: `${e}; check its URL in ALERT_WEBHOOKS` };
  } catch (err) {
    if (err && typeof err === "object" && (err.name === "TimeoutError" || err.name === "AbortError")) return { status: "unknown", error: `the webhook "${name}" timed out; it may have been delivered` };
    return { status: "retry", error: `the webhook "${name}" couldn't be reached: ${errText(err).slice(0, 120)}` };
  }
}

/** Sends one claimed alert. */
export async function sendOne(env, channel, msg, now, allowLocal = false) {
  if (channel.startsWith("email:")) return sendEmail(env, channel.slice(6), msg, now);
  if (channel.startsWith("webhook:")) return sendWebhook(env, channel.slice(8), msg, now, allowLocal);
  return { status: "config", error: `unknown channel ${channel}` };
}

/**
 * Sends due claims, at most `limit` (each costs one subrequest). Each is marked "sending" first.
 * @returns {Promise<{ tried: number, sent: number }>}
 */
export async function sendDue(sql, env, now, limit, allowLocal = false) {
  releaseStale(sql, now);
  let tried = 0;
  let sent = 0;
  if (limit <= 0) return { tried, sent };
  const due = sql.exec("SELECT * FROM claims WHERE status IN ('pending', 'retry') AND next_at <= ? ORDER BY created_at LIMIT ?", now, limit).toArray();
  for (const c of due) {
    const cur = sql.exec("UPDATE claims SET status = 'sending', claimed_at = ?, attempts = attempts + 1 WHERE subject = ? AND kind = ? AND channel = ? AND status IN ('pending', 'retry')", now, c.subject, c.kind, c.channel);
    if (!cur.rowsWritten) continue;
    tried++;
    let r;
    try {
      r = await sendOne(env, c.channel, JSON.parse(c.payload), now, allowLocal);
    } catch (err) {
      r = { status: "unknown", error: errText(err) };
    }
    const attempts = c.attempts + 1;
    let status = r.status;
    let nextAt = 0;
    if (status === "retry") {
      const n = nextAttempt(attempts, now);
      if (n === null) status = "failed";
      else nextAt = n;
    }
    if (status === "config") status = "failed";
    if (status === "sent") sent++;
    sql.exec(
      "UPDATE claims SET status = ?, next_at = ?, error = ?, claimed_at = NULL, sent_at = CASE WHEN ? = 'sent' THEN ? ELSE sent_at END, synced = 0 WHERE subject = ? AND kind = ? AND channel = ?",
      status, nextAt, r.error ? String(r.error).slice(0, 500) : null, status, now, c.subject, c.kind, c.channel,
    );
  }
  return { tried, sent };
}

/** One D1 statement copying claims changed since the last copy (json_each: one query, one bound parameter). */
export function syncStatement(sql, limit = 50) {
  const rows = sql.exec("SELECT * FROM claims WHERE synced = 0 ORDER BY created_at LIMIT ?", limit).toArray();
  if (!rows.length) return { stmt: null, keys: [] };
  const data = rows.map((c) => ({ id: c.id, subject: c.subject, kind: c.kind, channel: c.channel, status: c.status, attempts: c.attempts, err: c.error, created: sqlTime(c.created_at), sent: c.sent_at ? sqlTime(c.sent_at) : null }));
  return {
    stmt: {
      sql: `INSERT INTO deliveries (id, subject, kind, channel, status, attempts, last_error, created_at, sent_at)
            SELECT j.value ->> 'id', j.value ->> 'subject', j.value ->> 'kind', j.value ->> 'channel', j.value ->> 'status', j.value ->> 'attempts', j.value ->> 'err', j.value ->> 'created', j.value ->> 'sent' FROM json_each(?1) AS j WHERE true
            ON CONFLICT (id) DO UPDATE SET status = excluded.status, attempts = excluded.attempts, last_error = excluded.last_error, sent_at = excluded.sent_at`,
      params: [JSON.stringify(data)],
    },
    keys: rows.map((c) => [c.subject, c.kind, c.channel, c.status, c.attempts]),
  };
}

/** Marks copied claims, unless they changed again while D1 was being written. */
export function markSynced(sql, keys) {
  for (const [s, k, ch, status, attempts] of keys) sql.exec("UPDATE claims SET synced = 1 WHERE subject = ? AND kind = ? AND channel = ? AND status = ? AND attempts = ?", s, k, ch, status, attempts);
}

/** "Try again" from the desktop app or the admin API: a failed claim goes back to pending. */
export function retryById(sql, id) {
  const cur = sql.exec("UPDATE claims SET status = 'pending', next_at = 0, attempts = 0, error = NULL, synced = 0 WHERE id = ? AND status IN ('failed', 'unknown', 'retry')", id);
  return cur.rowsWritten > 0;
}

export function pruneClaims(sql, now) {
  sql.exec("DELETE FROM claims WHERE created_at < ? AND status NOT IN ('pending', 'retry', 'sending')", now - CLAIM_DAYS * 86_400_000);
}
