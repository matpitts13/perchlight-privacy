// What an alert says, and how it's sent to each channel. Text is fixed
// wording plus your site ids, hosts, page paths, check ids and finding
// subjects (hosts, cookie and header names, masked email addresses). NEVER
// evidence snippets, page content, verification or share tokens.
// Every alert ends with "Automated check, not legal advice."
// formatAt / webhookFormat / discordEscape / slackEscape / headerValue /
// truncateBytes / webhookRequest / parseWebhooks are copied from
// perchlight-hooks src/lib/notify.js (from perchlight-status).
import { escapeHtml } from "./http.js";
import { hmacHex } from "./crypto.js";
import { ALERT_FOOTER, maskEmails } from "./findings.js";

/** "12 Nov 2026, 14:02 UTC". */
export function formatAt(ms, timeZone = "UTC") {
  try {
    return new Intl.DateTimeFormat("en-GB", { timeZone, day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZoneName: "short" }).format(new Date(ms));
  } catch {
    return new Date(ms).toISOString().slice(0, 16).replace("T", " ") + " UTC";
  }
}

const LABEL = {
  "third-party.tracker": "loaded",
  "third-party.tag-manager": "tag manager (may load more trackers)",
  "third-party.ip-leak": "receives visitors' IP addresses",
  "third-party.other": "third party",
  "third-party.consent-gated": "consent-gated",
  "cookie.pre-consent": "cookie set before consent",
  "cookie.attributes": "cookie attributes",
  "policy.privacy-missing": "privacy policy link missing or not loading",
  "policy.imprint-missing": "imprint link missing or not loading",
  "header.hsts": "HSTS",
  "header.referrer-policy": "Referrer-Policy",
  "header.permissions-policy": "Permissions-Policy missing",
  "header.csp": "Content-Security-Policy",
  "header.nosniff": "nosniff missing",
  "mixed-content": "http: subresource",
  "form.insecure": "form over http:",
  "form.third-party": "form posts to another company",
  "email.exposed": "email address in page text",
  "email.mailto": "mailto: link",
  "robots.sensitive": "robots.txt advertises a path",
  "sitemap.sensitive": "sitemap advertises",
  "redirect.offsite": "redirects to an unverified host",
  "scan.blocked": "blocked by bot protection",
  "security-txt.missing": "security.txt missing",
};

/** "connect.facebook.net on /pricing (loaded)". Subjects only, masked; never evidence. */
export function describeFinding(f) {
  return `${maskEmails(f.subject)} on ${f.page} (${LABEL[f.check] ?? f.check})`;
}

/**
 * One alert's content. `subject` must be unique per occurrence (it is the claim key).
 * @returns {{ kind: string, subject: string, title: string, lines: string[], priority: number, tags: string, event: object }}
 */
export function alertMessage(ev, reportUrl = null) {
  const msg = (title, lines, priority = 3, tags = "warning") => ({
    kind: ev.kind,
    subject: ev.subject,
    title,
    lines: [...lines, ...(reportUrl ? [`Report: ${reportUrl}`] : []), ALERT_FOOTER],
    priority,
    tags,
    event: { kind: ev.kind, site: ev.site ?? null, host: ev.host ?? null, at: ev.at, scan: ev.scan ?? null },
  });
  const at = formatAt(ev.at);
  switch (ev.kind) {
    case "changes": {
      const parts = [ev.added.length ? `${ev.added.length} new` : null, ev.resolved.length ? `${ev.resolved.length} resolved` : null].filter(Boolean).join(", ");
      const lines = [
        ...ev.added.slice(0, 25).map((f) => `NEW (${f.severity}): ${describeFinding(f)}`),
        ...(ev.added.length > 25 ? [`...and ${ev.added.length - 25} more new.`] : []),
        ...ev.resolved.slice(0, 25).map((f) => `RESOLVED: ${describeFinding(f)}`),
        ...(ev.resolved.length > 25 ? [`...and ${ev.resolved.length - 25} more resolved.`] : []),
      ];
      return msg(`perchlight-privacy: ${ev.host}, ${parts}`, lines, ev.added.some((f) => f.severity === "high") ? 4 : 3, "mag");
    }
    case "verification_lost":
      return msg(`VERIFICATION LOST: ${ev.host}`, [`Ownership of ${ev.host} couldn't be confirmed twice in a row, at least 24 hours apart: ${ev.reason}.`, "Scans of this site have stopped. Restore the TXT record or the /.well-known/perchlight-privacy.txt file, then POST /api/sites/<id>/verify."], 4, "rotating_light");
    case "scan_failing":
      return msg(`SCANS FAILING: ${ev.host}`, [`The last ${ev.failures} scans of ${ev.host} couldn't run: ${ev.reason}.`, `Since ${formatAt(ev.since)}.`], 4, "warning");
    case "recovered":
      return msg(`RECOVERED: ${ev.host}`, [`Scans of ${ev.host} are completing again (${at}).`], 3, "white_check_mark");
    case "test":
      return msg("TEST: perchlight-privacy alert", ["This is a test alert from perchlight-privacy. If you can read it, this channel works.", `Sent ${at}.`], 3, "test_tube");
    default:
      return msg(`${ev.kind}: ${ev.host ?? ""}`, [String(ev.reason ?? "")]);
  }
}

export function emailBody(m) {
  const text = [...m.lines, "", "-- perchlight-privacy"].join("\n");
  const html = `<div style="font-family:system-ui,sans-serif;font-size:15px;line-height:1.5">${m.lines.map((l) => `<p>${escapeHtml(l)}</p>`).join("")}<p style="color:#666">perchlight-privacy</p></div>`;
  return { subject: m.title, text, html };
}

/** Which format a webhook URL wants, unless the config says. */
export function webhookFormat(url, configured) {
  if (["discord", "slack", "ntfy", "json"].includes(configured)) return configured;
  let host = "";
  let path = "";
  try {
    ({ hostname: host, pathname: path } = new URL(url));
  } catch {
    return "json";
  }
  if (/(^|\.)discord(app)?\.com$/.test(host) && path.startsWith("/api/webhooks")) return "discord";
  if (host === "hooks.slack.com") return "slack";
  if (/(^|\.)ntfy\./.test(host) || host === "ntfy.sh") return "ntfy";
  return "json";
}

export const discordEscape = (s) => String(s).replace(/([\\*_~`|>[\]()#@:-])/g, "\\$1");
export const slackEscape = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
/** An HTTP header value: one line, printable ASCII. */
export const headerValue = (s, max = 200) => String(s).replace(/[\r\n]+/g, " ").replace(/[^\x20-\x7e]/g, "?").trim().slice(0, max);

/** Cuts text to at most maxBytes of UTF-8, never inside a character. */
export function truncateBytes(text, maxBytes) {
  const enc = new TextEncoder();
  let out = "";
  let used = 0;
  for (const ch of text) {
    const n = enc.encode(ch).length;
    if (used + n > maxBytes) break;
    out += ch;
    used += n;
  }
  return out;
}

/**
 * The request for one webhook channel.
 * @returns {Promise<{ body: string, headers: Record<string, string> } | { error: string }>}
 */
export async function webhookRequest(env, format, m, { now = Date.now(), token } = {}) {
  switch (format) {
    case "discord": {
      const content = [`**${discordEscape(m.title)}**`, ...m.lines.map(discordEscape)].join("\n");
      return { body: JSON.stringify({ content: truncateBytes(content, 1900), allowed_mentions: { parse: [] } }), headers: { "Content-Type": "application/json" } };
    }
    case "slack": {
      const text = [`*${slackEscape(m.title)}*`, ...m.lines.map(slackEscape)].join("\n");
      return { body: JSON.stringify({ text: truncateBytes(text, 39000), link_names: false, unfurl_links: false, unfurl_media: false }), headers: { "Content-Type": "application/json" } };
    }
    case "ntfy": {
      let body = m.lines.join("\n");
      if (new TextEncoder().encode(body).length > 4000) body = `${truncateBytes(body, 3900)}\n...`;
      const headers = { "Content-Type": "text/plain; charset=utf-8", Title: headerValue(m.title, 120), Priority: String(m.priority ?? 3), Tags: headerValue(m.tags ?? "warning", 60) };
      if (token) headers.Authorization = `Bearer ${headerValue(token, 200)}`;
      return { body, headers };
    }
    default: {
      if (String(env.WEBHOOK_SECRET ?? "").length < 16) return { error: "Set the WEBHOOK_SECRET secret (16+ characters): JSON webhooks are signed with it." };
      const body = JSON.stringify({ type: m.kind, title: m.title, text: m.lines.join("\n"), event: m.event });
      const ts = String(Math.floor(now / 1000));
      return {
        body,
        headers: { "Content-Type": "application/json", "X-Perchlight-Timestamp": ts, "X-Perchlight-Signature": `sha256=${await hmacHex(env.WEBHOOK_SECRET, `${ts}.${body}`)}` },
      };
    }
  }
}

/** ALERT_WEBHOOKS: { name: "https://..." | { url, format?, token? } }. */
export function parseWebhooks(env, allowLocal = false) {
  const raw = env.ALERT_WEBHOOKS;
  if (!raw) return { hooks: {} };
  let v;
  try {
    v = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    return { hooks: {}, error: "ALERT_WEBHOOKS isn't valid JSON" };
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return { hooks: {}, error: "ALERT_WEBHOOKS must be a JSON object of name: URL" };
  const hooks = {};
  for (const [name, h] of Object.entries(v)) {
    const o = typeof h === "string" ? { url: h } : h && typeof h === "object" ? h : {};
    if (typeof o.url === "string" && (/^https:\/\//.test(o.url) || (allowLocal && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(o.url)))) {
      hooks[name] = { url: o.url, format: webhookFormat(o.url, o.format), token: typeof o.token === "string" ? o.token : undefined };
    }
  }
  return { hooks };
}
