// privacy.json and API site settings, checked (docs/SDD.md, "Config").
// A site with a mistake is reported with the reason and left out; the rest
// keep working. `npm test` checks the shipped privacy.json.
import { checkHostName, checkUrl, normHost } from "./ssrf.js";
import { isPublicSuffix } from "./psl.js";

export const LIMITS = { sites: 10, pages: 20, discover: 20, ownHosts: 20, necessaryCookies: 50, emails: 10, webhooks: 10, idLength: 32, pathLength: 300, minEveryS: 6 * 3600, scansPerSite: 100 };
export const DEFAULT_EVERY_S = 86_400;
const LEVELS = ["high", "medium", "low"];

/** "6h", "1d", "90m", "2d12h" -> seconds, or null. */
export function parseEvery(s) {
  const str = String(s ?? "").trim().toLowerCase();
  if (!/^(\d+[dhm])+$/.test(str)) return null;
  let total = 0;
  for (const m of str.matchAll(/(\d+)([dhm])/g)) total += Number(m[1]) * { d: 86400, h: 3600, m: 60 }[m[2]];
  return total > 0 && total <= 30 * 86400 ? total : null;
}

/** Seconds between scans for a stored `every`, never under 6 hours. */
export function everySeconds(s) {
  const v = parseEvery(s);
  return Math.max(v ?? DEFAULT_EVERY_S, LIMITS.minEveryS);
}

const isStrList = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");

/** One page entry: a path ("/pricing") or a full https URL on a host you'll verify. Returns { value } or { error }. */
export function checkPage(p) {
  if (typeof p !== "string" || !p.trim()) return { error: "must be a path like /pricing or an https URL" };
  const s = p.trim();
  if (s.length > LIMITS.pathLength) return { error: `is longer than ${LIMITS.pathLength} characters` };
  if (s.startsWith("/") && !s.startsWith("//")) {
    if (/[\s\\]/.test(s)) return { error: "contains spaces or backslashes" };
    return { value: s };
  }
  const t = checkUrl(s);
  if (!t.ok) return { error: `"${s}" ${t.error}` };
  return { value: t.url.toString() };
}

/**
 * Checks one site's settings.
 * @returns {{ site?: object, error?: string }}
 */
export function checkSite(id, raw) {
  if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(id)) return { error: `site id "${id}" must be 1-32 lower-case letters, digits or dashes` };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { error: `site "${id}" must be an object` };
  const host = normHost(raw.host);
  const hostErr = checkHostName(host);
  if (hostErr) return { error: `site "${id}": host ${hostErr}` };
  if (isPublicSuffix(host)) return { error: `site "${id}": host ${host} is a public suffix, not a site` };
  const own = raw.ownHosts ?? [];
  if (!isStrList(own) || own.length > LIMITS.ownHosts) return { error: `site "${id}": ownHosts must be a list of at most ${LIMITS.ownHosts} host names` };
  const ownHosts = [];
  for (const h of own) {
    const e = checkHostName(h);
    if (e) return { error: `site "${id}": ownHosts "${h}" ${e}` };
    ownHosts.push(normHost(h));
  }
  const pagesRaw = raw.pages ?? ["/"];
  if (!Array.isArray(pagesRaw)) return { error: `site "${id}": pages must be a list` };
  const pages = ["/"];
  for (const p of pagesRaw) {
    const r = checkPage(p);
    if (r.error) return { error: `site "${id}": page ${r.error}` };
    if (!pages.includes(r.value)) pages.push(r.value);
  }
  if (pages.length > LIMITS.pages) return { error: `site "${id}": at most ${LIMITS.pages} pages a scan (the home page included)` };
  const discover = raw.discover ?? 0;
  if (!Number.isInteger(discover) || discover < 0 || discover > LIMITS.discover) return { error: `site "${id}": discover must be 0-${LIMITS.discover}` };
  const every = raw.every ?? "1d";
  const everyS = parseEvery(every);
  if (everyS === null) return { error: `site "${id}": every "${every}" isn't a duration like "6h" or "1d"` };
  if (everyS < LIMITS.minEveryS) return { error: `site "${id}": every must be at least 6h (keeps the tool from load-testing small hosts)` };
  if (raw.imprint !== undefined && typeof raw.imprint !== "boolean") return { error: `site "${id}": imprint must be true or false` };
  const nec = raw.necessaryCookies ?? [];
  if (!isStrList(nec) || nec.length > LIMITS.necessaryCookies || nec.some((n) => !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$/.test(n))) return { error: `site "${id}": necessaryCookies must be a list of cookie names` };
  const alertLevel = raw.alertLevel ?? "medium";
  if (!LEVELS.includes(alertLevel)) return { error: `site "${id}": alertLevel must be "high", "medium" or "low" (info never alerts)` };
  let ua = raw.userAgent ?? "browser";
  if (ua === "default") ua = "browser";
  if (!["browser", "honest"].includes(ua)) return { error: `site "${id}": userAgent must be "browser" (default) or "honest"` };
  const known = new Set(["host", "ownHosts", "pages", "discover", "every", "imprint", "necessaryCookies", "alertLevel", "userAgent"]);
  const unknown = Object.keys(raw).filter((k) => !known.has(k));
  if (unknown.length) return { error: `site "${id}": unknown setting(s) ${unknown.join(", ")}` };
  return {
    site: { id, host, ownHosts, pages, every, everyS, settings: { discover, imprint: Boolean(raw.imprint), necessaryCookies: nec, alertLevel, userAgent: ua } },
  };
}

/** The whole privacy.json. */
export function checkConfig(raw) {
  const errors = [];
  const cfg = { sites: [], alerts: { email: [], webhooks: [] }, retention: { scansPerSite: 30 }, errors };
  if (!raw || typeof raw !== "object") {
    errors.push("privacy.json must be an object");
    return cfg;
  }
  const known = new Set(["sites", "alerts", "retention", "$schema"]);
  for (const k of Object.keys(raw)) if (!known.has(k)) errors.push(`unknown top-level setting "${k}"`);
  const sites = raw.sites ?? {};
  if (typeof sites !== "object" || Array.isArray(sites)) errors.push("sites must be an object of id: settings");
  else {
    const ids = Object.keys(sites);
    if (ids.length > LIMITS.sites) errors.push(`at most ${LIMITS.sites} sites; the rest are left out`);
    for (const id of ids.slice(0, LIMITS.sites)) {
      const r = checkSite(id, sites[id]);
      if (r.error) errors.push(r.error);
      else cfg.sites.push(r.site);
    }
  }
  const a = raw.alerts ?? {};
  const email = a.email ?? [];
  const webhooks = a.webhooks ?? [];
  if (!isStrList(email) || email.length > LIMITS.emails || email.some((e) => !/^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(e))) errors.push(`alerts.email must be a list of at most ${LIMITS.emails} addresses`);
  else cfg.alerts.email = email;
  if (!isStrList(webhooks) || webhooks.length > LIMITS.webhooks || webhooks.some((w) => !/^[A-Za-z0-9_-]{1,64}$/.test(w))) errors.push(`alerts.webhooks must be a list of at most ${LIMITS.webhooks} names from ALERT_WEBHOOKS`);
  else cfg.alerts.webhooks = webhooks;
  const keep = raw.retention?.scansPerSite ?? 30;
  if (!Number.isInteger(keep) || keep < 3 || keep > LIMITS.scansPerSite) errors.push(`retention.scansPerSite must be 3-${LIMITS.scansPerSite}`);
  else cfg.retention.scansPerSite = keep;
  return cfg;
}
