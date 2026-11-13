// The report: one shape for GET /api/sites/:id/report.json (versioned
// "schema": 1) and the HTML page at /r/:site. Everything from your pages is
// rendered as escaped text; the page has no JavaScript.
import { parseJson, escapeHtml } from "./http.js";
import { SEVERITIES, WHY, DISCLAIMER, RANK } from "./findings.js";

export const LIMITATIONS = [
  "JavaScript-added trackers aren't seen: pixels loaded by a tag manager or consent manager, or cookies set by document.cookie. A tag manager found here \"may load more\".",
  "Single-page apps that render in JavaScript look almost empty to a static check.",
  "Consent logic isn't tested: a tracker found in the HTML may still be blocked at run time; only the common type=\"text/plain\" consent markup is recognised.",
  "It sees what Cloudflare's network gets from one location, not what every visitor gets (geo, A/B tests).",
  "The tracker list is a heuristic: hosts not in it are \"other third party\", not \"safe\".",
];

/** The latest completed scan of a site, as JSON. Two to four D1 reads. */
export async function buildReport(db, siteId) {
  const site = await db.prepare("SELECT * FROM sites WHERE id = ?").bind(siteId).first();
  if (!site) return null;
  const out = {
    schema: 1,
    site: {
      id: site.id,
      host: site.host,
      state: site.state,
      paused: Boolean(site.paused),
      verifiedBy: site.verify_method,
      verifiedScope: site.verified_scope ? `${site.verified_scope}:${site.verified_name}` : null,
      lastScanAt: site.last_scan_at,
      nextScanAt: site.next_scan_at,
    },
    scan: null,
    counts: { high: 0, medium: 0, low: 0, info: 0 },
    findings: { high: [], medium: [], low: [], info: [] },
    changes: { new: [], resolved: [] },
    disclaimer: DISCLAIMER,
    limitations: LIMITATIONS,
  };
  if (!site.last_scan_id) return out;
  const [scanRes, findRes, muteRes] = await db.batch([
    db.prepare("SELECT * FROM scans WHERE id = ?").bind(site.last_scan_id),
    db.prepare("SELECT * FROM findings WHERE scan_id = ? LIMIT 2000").bind(site.last_scan_id),
    db.prepare("SELECT key, note FROM mutes WHERE site_id = ?").bind(siteId),
  ]);
  const scan = scanRes.results?.[0];
  if (!scan) return out;
  const notes = parseJson(scan.notes, {});
  out.scan = {
    id: scan.id,
    trigger: scan.trigger,
    status: scan.status,
    startedAt: scan.started_at,
    finishedAt: scan.finished_at,
    pagesOk: scan.pages_ok,
    pagesFailed: scan.pages_failed,
    pages: notes.pages ?? {},
    consentManagers: notes.consentManagers ?? [],
    littleHtml: Boolean(notes.littleHtml),
  };
  const mutes = new Map((muteRes.results ?? []).map((m) => [m.key, m.note]));
  const rows = (findRes.results ?? []).sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.check_id.localeCompare(b.check_id) || a.page.localeCompare(b.page));
  for (const f of rows) {
    const sev = SEVERITIES.includes(f.severity) ? f.severity : "info";
    out.counts[sev]++;
    out.findings[sev].push({
      key: f.key,
      check: f.check_id,
      severity: sev,
      page: f.page,
      subject: f.subject,
      evidence: f.evidence,
      firstSeenAt: f.first_seen_at,
      source: f.source,
      carried: Boolean(f.carried),
      muted: mutes.has(f.key),
      muteNote: mutes.get(f.key) ?? null,
      why: WHY[f.check_id]?.[0] ?? null,
      source_url: WHY[f.check_id]?.[1] ?? null,
    });
  }
  out.changes = parseJson(scan.changes, { new: [], resolved: [] });
  return out;
}

const e = escapeHtml;

export const STYLE = `body{font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:960px;padding:16px;color:#1b1b1b;background:#fff}
h1{font-size:1.4em}h2{font-size:1.15em;margin-top:1.6em}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}td.ev{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
.sev{font-weight:600}.high{color:#b00020}.medium{color:#a15c00}.low{color:#36598f}.info{color:#555}.note{background:#f6f6f6;padding:10px;border-radius:6px}
.muted{opacity:.6}small{color:#555}form{max-width:360px}input{font:inherit;padding:6px;width:100%;box-sizing:border-box;margin:6px 0}button{font:inherit;padding:6px 14px}
@media (prefers-color-scheme:dark){body{background:#151515;color:#e6e6e6}th,td{border-color:#333}.note{background:#222}.high{color:#ff6b81}.medium{color:#f0a24a}.low{color:#8fb0ff}.info{color:#aaa}small{color:#aaa}}`;

function layout(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>${e(title)}</title><link rel="stylesheet" href="/r/style.css"></head><body>${body}</body></html>`;
}

export function renderReport(r) {
  const s = r.site;
  const parts = [`<h1>Privacy check: ${e(s.host)}</h1>`, `<p class="note"><strong>Not legal advice.</strong> ${e(r.disclaimer)}</p>`];
  parts.push(`<p>State: ${e(s.state)}${s.paused ? " (paused)" : ""} · verified by ${e(s.verifiedBy ?? "-")} ${s.verifiedScope ? `(${e(s.verifiedScope)})` : ""} · next scan ${e(s.nextScanAt ?? "-")} UTC</p>`);
  if (!r.scan) {
    parts.push("<p>No completed scan yet.</p>");
  } else {
    const sc = r.scan;
    parts.push(`<p>Scan ${e(sc.id)} (${e(sc.trigger)}): <strong>${e(sc.status)}</strong>, finished ${e(sc.finishedAt ?? "-")} UTC, ${e(sc.pagesOk)} pages checked${sc.pagesFailed ? `, ${e(sc.pagesFailed)} couldn't be read (their previous findings are carried forward)` : ""}.</p>`);
    parts.push(`<p>High ${r.counts.high} · medium ${r.counts.medium} · low ${r.counts.low} · info ${r.counts.info}</p>`);
    if (sc.consentManagers.length) parts.push(`<p class="note">Consent manager found: ${e(sc.consentManagers.join(", "))}. Trackers in the HTML may still be held back by it at run time; consent logic isn't tested.</p>`);
    if (sc.littleHtml) parts.push(`<p class="note">Little HTML found; this site may render in JavaScript, which a static check can't see.</p>`);
    const ch = r.changes ?? { new: [], resolved: [] };
    if (ch.new.length || ch.resolved.length) {
      parts.push("<h2>Changes since the previous scan</h2><ul>");
      for (const f of ch.new) parts.push(`<li>NEW (${e(f.severity)}): ${e(f.check)} · ${e(f.subject)} on ${e(f.page)}</li>`);
      for (const f of ch.resolved) parts.push(`<li>RESOLVED: ${e(f.check)} · ${e(f.subject)} on ${e(f.page)}</li>`);
      parts.push("</ul>");
    }
    for (const sev of ["high", "medium", "low", "info"]) {
      const list = r.findings[sev];
      if (!list.length) continue;
      parts.push(`<h2 class="${sev}">${sev[0].toUpperCase()}${sev.slice(1)} (${list.length})</h2><table><thead><tr><th>Check</th><th>Page</th><th>Subject</th><th>Evidence</th><th>First seen</th></tr></thead><tbody>`);
      for (const f of list) {
        const why = f.why ? `<br><small>${e(f.why)}${f.source_url ? ` Source: ${e(f.source_url)}` : ""}</small>` : "";
        const muted = f.muted ? `<br><small>Muted${f.muteNote ? `: ${e(f.muteNote)}` : ""}</small>` : "";
        parts.push(`<tr class="${f.muted ? "muted" : ""}"><td class="sev ${sev}">${e(f.check)}${why}${muted}</td><td>${e(f.page)}${f.carried ? "<br><small>carried forward</small>" : ""}</td><td>${e(f.subject)}</td><td class="ev">${e(f.evidence)}</td><td>${e(f.firstSeenAt)}</td></tr>`);
      }
      parts.push("</tbody></table>");
    }
  }
  parts.push("<h2>What this can't see</h2><ul>");
  for (const l of r.limitations) parts.push(`<li>${e(l)}</li>`);
  parts.push("</ul><p><small>perchlight-privacy · static check (HTML and headers only) · automated, not legal advice</small></p>");
  return layout(`Privacy check: ${s.host}`, parts.join(""));
}

export function renderLogin(siteId, message = "") {
  return layout(
    "Sign in",
    `<h1>perchlight-privacy report</h1>${message ? `<p class="note">${e(message)}</p>` : ""}<p>This report lists a site's weak spots, so it needs the admin token or a share link.</p>
<form method="post" action="/r/login"><input type="hidden" name="site" value="${e(siteId)}"><label>Admin token<input type="password" name="token" autocomplete="current-password" required></label><button type="submit">Sign in</button></form>`,
  );
}
