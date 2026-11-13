// The checks (docs/SDD.md, "Checks"): observations, headers and cookies in,
// findings out. Pure functions, so each is tested against fixtures.
import { classify, snippetMatches, CHECK_FOR_CATEGORY } from "./trackers.js";
import { resolveUrl } from "./parse.js";
import { finding, urlSubject } from "./findings.js";

const TP_SEVERITY = { "third-party.tracker": "high", "third-party.tag-manager": "high", "third-party.ip-leak": "medium", "third-party.other": "info", "third-party.consent-gated": "info" };

export const PRIVACY_TEXT = /privacy|privacidad|privacidade|privacit[éy]|confidentialit|datenschutz|protection des donn[ée]es|donn[ée]es personnelles|riservatezza|privacybeleid|gegevensbescherming|protecci[óo]n de datos|prote[çc][ãa]o de dados/i;
export const PRIVACY_PATH = /privacy|datenschutz|confidentialit|privacidad|privacidade|privacybeleid|riservatezza|data-protection|protection-des-donnees|gegevensbescherming/i;
export const IMPRINT_TEXT = /impressum|imprint|legal notice|mentions l[ée]gales|aviso legal|note legali|colofon|informa[çc][õo]es legais/i;
export const IMPRINT_PATH = /impressum|imprint|legal-notice|mentions-legales|aviso-legal|note-legali|colofon/i;

/** Paths robots.txt and sitemaps shouldn't advertise. */
export const SENSITIVE_PATH = /(^|[/._-])(admin|administrator|wp-admin|staging|stage|backups?|bak|private|internal|tests?|testing|old|dev|development)([/._-]|$)|\.git\b|\.env\b|\.sql\b|\.bak\b/i;

function tag(r, u) {
  const attr = r.tag === "object" ? "data" : r.tag === "link" ? "href" : "src";
  return `<${r.tag} ${attr}="${u.protocol}//${urlSubject(u)}">`;
}

const safeDecode = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

function describe(entry) {
  return entry ? ` (${entry.name}, ${entry.company})` : "";
}

/**
 * Findings from one parsed page.
 * @param {object} obs  from parseHtml
 * @param {{ pageUrl: string, page: string, own: Set<string>, isHome: boolean }} ctx
 * @returns {{ findings: object[], consent: string[], policy: { privacy: string[], imprint: string[] }, stylesheets: string[], littleHtml: boolean }}
 */
export function pageFindings(obs, ctx) {
  const out = [];
  const consent = new Set();
  const pageHttps = ctx.pageUrl.startsWith("https:");
  const stylesheets = [];
  const namesBySrc = new Set();
  const isOwn = (h) => ctx.own.has(h.toLowerCase());

  for (const r of obs.resources) {
    const u = resolveUrl(r.url, ctx.pageUrl, obs.base);
    if (!u) continue;
    const host = u.hostname.toLowerCase();
    if (pageHttps && u.protocol === "http:") {
      const active = r.kind === "active";
      out.push(finding("mixed-content", active ? "high" : "medium", ctx.page, urlSubject(u), `${active ? "active" : "passive"} http: subresource ${tag(r, u)}`));
    }
    if (isOwn(host)) {
      if (r.stylesheet && u.protocol === "https:") stylesheets.push(u.toString());
      continue;
    }
    const entry = classify(host, u.pathname);
    if (entry?.category === "consent") {
      consent.add(entry.name);
      continue;
    }
    if (entry) namesBySrc.add(entry.name);
    const check = r.gated ? "third-party.consent-gated" : entry ? CHECK_FOR_CATEGORY[entry.category] : "third-party.other";
    out.push(finding(check, TP_SEVERITY[check], ctx.page, host, `${tag(r, u)}${describe(entry)}`));
  }

  for (const s of obs.inlineScripts) {
    for (const entry of snippetMatches(s.text)) {
      if (entry.category === "consent") {
        consent.add(entry.name);
        continue;
      }
      // The same tracker already found by its <script src> isn't reported twice.
      if (!s.gated && namesBySrc.has(entry.name)) continue;
      const check = s.gated ? "third-party.consent-gated" : CHECK_FOR_CATEGORY[entry.category];
      const m = entry.re.map((r) => r.exec(s.text)).find(Boolean);
      const at = m ? Math.max(0, m.index - 20) : 0;
      out.push(finding(check, TP_SEVERITY[check], ctx.page, entry.h, `inline script: …${s.text.slice(at, at + 90)}…${describe(entry)}`));
    }
  }

  for (const f of obs.forms) {
    const u = resolveUrl(f.action ?? "", ctx.pageUrl, obs.base);
    if (!u) continue;
    if (u.protocol === "http:") out.push(finding("form.insecure", "high", ctx.page, urlSubject(u), `<form action="http://${urlSubject(u)}"> sends form data unencrypted`));
    else if (!isOwn(u.hostname)) {
      const entry = classify(u.hostname, u.pathname);
      out.push(finding("form.third-party", "medium", ctx.page, u.hostname.toLowerCase(), `<form action="https://${urlSubject(u)}"> posts to another company${describe(entry)}`));
    }
  }
  if (obs.hasPassword && !pageHttps) out.push(finding("form.insecure", "high", ctx.page, "password-over-http", "a password field on a page served over http:"));

  const mailto = new Set();
  for (const l of obs.links) {
    if (!/^mailto:/i.test(l.href)) continue;
    const addr = safeDecode(l.href.slice(7).split("?")[0]).trim().toLowerCase();
    for (const a of addr.split(",")) {
      const t = a.trim();
      if (!t.includes("@")) continue;
      mailto.add(t);
      out.push(finding("email.mailto", "info", ctx.page, t, `mailto: link to ${t}`, `mailto:${t}`));
    }
  }
  for (const e of obs.emails) {
    if (mailto.has(e)) continue;
    out.push(finding("email.exposed", "low", ctx.page, e, `plain-text address ${e} in the page`, `email:${e}`));
  }

  const policy = { privacy: [], imprint: [] };
  if (ctx.isHome) {
    for (const l of obs.links) {
      const u = resolveUrl(l.href, ctx.pageUrl, obs.base);
      if (!u) continue;
      const path = safeDecode(u.pathname);
      if (PRIVACY_TEXT.test(l.text) || PRIVACY_PATH.test(path)) policy.privacy.push(u.toString());
      if (IMPRINT_TEXT.test(l.text) || IMPRINT_PATH.test(path)) policy.imprint.push(u.toString());
    }
  }
  const littleHtml = obs.textChars < 200 && obs.links.length + obs.resources.length < 5;
  return { findings: out, consent: [...consent], policy, stylesheets: [...new Set(stylesheets)], littleHtml };
}

/** Header checks on one response (docs/SDD.md: run on the home page). */
export function headerFindings(headers, { page = "/", metaReferrer = null, httpCheck = null } = {}) {
  const out = [];
  const get = (n) => headers.get(n);
  const hsts = get("Strict-Transport-Security");
  if (!hsts) {
    const httpOnly = httpCheck?.hsts ? " (it's sent on http:// only, where browsers ignore it)" : "";
    out.push(finding("header.hsts", "medium", page, "Strict-Transport-Security", `Strict-Transport-Security missing${httpOnly}`));
  } else {
    const m = /max-age\s*=\s*"?(\d+)/i.exec(hsts);
    const age = m ? Number(m[1]) : 0;
    if (age < 15_552_000) out.push(finding("header.hsts", "medium", page, "Strict-Transport-Security", `Strict-Transport-Security: ${hsts} (max-age under 180 days)`));
  }
  if (httpCheck && httpCheck.checked && !httpCheck.toHttps) out.push(finding("header.hsts", "medium", page, "http-redirect", `http:// answered ${httpCheck.status ?? "without a redirect"} instead of redirecting to https://`));

  const rpRaw = get("Referrer-Policy") ?? metaReferrer;
  if (!rpRaw) out.push(finding("header.referrer-policy", "low", page, "Referrer-Policy", "Referrer-Policy missing (browsers default to strict-origin-when-cross-origin)"));
  else {
    const tokens = rpRaw.toLowerCase().split(",").map((t) => t.trim()).filter(Boolean);
    const last = tokens[tokens.length - 1];
    if (last === "unsafe-url" || last === "no-referrer-when-downgrade") out.push(finding("header.referrer-policy", "medium", page, "Referrer-Policy", `Referrer-Policy: ${rpRaw} sends full URLs to other sites`));
  }

  if (!get("Permissions-Policy")) out.push(finding("header.permissions-policy", "low", page, "Permissions-Policy", "Permissions-Policy missing"));

  const csp = get("Content-Security-Policy");
  const xfo = get("X-Frame-Options");
  if (!csp) out.push(finding("header.csp", "low", page, "Content-Security-Policy", "Content-Security-Policy missing"));
  const dirs = new Map();
  for (const part of (csp ?? "").split(";")) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name && !dirs.has(name.toLowerCase())) dirs.set(name.toLowerCase(), vals.map((v) => v.toLowerCase()));
  }
  if (csp) {
    const script = dirs.get("script-src") ?? dirs.get("default-src") ?? [];
    const relaxed = script.some((v) => v.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(v) || v === "'strict-dynamic'");
    const unsafe = [script.includes("'unsafe-eval'") ? "'unsafe-eval'" : null, script.includes("'unsafe-inline'") && !relaxed ? "'unsafe-inline'" : null].filter(Boolean);
    if (unsafe.length) out.push(finding("header.csp", "low", page, "csp-script-src", `Content-Security-Policy allows ${unsafe.join(" and ")} in script-src`));
  }
  if (!dirs.has("frame-ancestors") && !xfo) out.push(finding("header.csp", "low", page, "frame-ancestors", "no frame-ancestors directive and no X-Frame-Options (the page can be framed)"));

  if ((get("X-Content-Type-Options") ?? "").trim().toLowerCase() !== "nosniff") out.push(finding("header.nosniff", "info", page, "X-Content-Type-Options", "X-Content-Type-Options: nosniff missing"));
  return out;
}

// ---- cookies -------------------------------------------------------------

const TRACKING_COOKIES = [/^_ga(_\*)?$/, /^_gid$/, /^_gat/, /^_gcl_/, /^_gac_/, /^__utm/, /^_fbp$/, /^_fbc$/, /^fr$/, /^_hj/, /^_pk_/, /^_uet(sid|vid)$/, /^muid$/i, /^_clck$/, /^_clsk$/, /^ide$/i, /^test_cookie$/, /^ajs_/, /^mp_/, /^_ttp$/, /^_tt_/, /^li_/, /^bcookie$/, /^lidc$/, /^_pin_unauth$/, /^_scid$/, /^_rdt_uuid$/, /^__hstc$/, /^hubspotutk$/, /^_mkto_trk$/, /^amplitude_id/, /^ph_/, /^_derived_epik$/];
const NECESSARY_COOKIES = [/^__cf_bm$/, /^cf_clearance$/, /^_cfuvid$/, /^__cflb$/, /^csrf/i, /^xsrf/i, /^_csrf/i, /^cookieconsent/i, /^optanonconsent$/i, /^optanonalertboxclosed$/i, /^cookieyes-consent$/, /^cc_cookie$/, /^cmplz_/, /^euconsent/i, /^didomi_token$/, /^usercentrics/i, /^klaro$/];

/** _ga_ABC123 -> _ga_*; a long random suffix -> * (so it isn't "new" every scan). */
export function normalizeCookieName(name) {
  const n = String(name).trim();
  const pre = /^(_ga_|_gac_|_hjSession_|_hjSessionUser_|_hjid_|_pk_id\.|_pk_ses\.|amplitude_id_|mp_|ph_|AMP_|_dc_gtm_|_gat_|wordpress_logged_in_|wordpress_sec_|wp-settings-time-|wp-settings-|_shopify_)/.exec(n);
  if (pre) return `${pre[1]}*`;
  return n.replace(/[0-9a-f]{8,}|\d{4,}/gi, "*");
}

/** Parses one Set-Cookie value. */
export function parseSetCookie(v) {
  const parts = String(v).split(";");
  const [nameValue, ...attrs] = parts;
  const eq = nameValue.indexOf("=");
  const name = (eq < 0 ? nameValue : nameValue.slice(0, eq)).trim();
  const a = {};
  for (const x of attrs) {
    const i = x.indexOf("=");
    const k = (i < 0 ? x : x.slice(0, i)).trim().toLowerCase();
    if (k) a[k] = i < 0 ? true : x.slice(i + 1).trim();
  }
  return { name, attrs: a };
}

export function classifyCookie(name, necessary = []) {
  const norm = normalizeCookieName(name);
  if (necessary.some((n) => n.toLowerCase() === name.toLowerCase() || n.toLowerCase() === norm.toLowerCase())) return "info";
  if (NECESSARY_COOKIES.some((r) => r.test(name))) return "info";
  if (TRACKING_COOKIES.some((r) => r.test(name) || r.test(norm))) return "high";
  return "medium";
}

const MAX_LIFETIME_DAYS = 395; // 13 months

export function cookieFindings(values, { page, https = true, necessary = [], now = Date.now() }) {
  const out = [];
  for (const v of values.slice(0, 50)) {
    const c = parseSetCookie(v);
    if (!c.name) continue;
    const norm = normalizeCookieName(c.name);
    const shown = Object.entries(c.attrs)
      .filter(([k]) => ["max-age", "expires", "secure", "samesite", "httponly", "domain", "path"].includes(k))
      .map(([k, val]) => (val === true ? k : `${k}=${val}`))
      .join("; ");
    const ev = `Set-Cookie: ${c.name}=…${shown ? `; ${shown}` : ""}`;
    const sev = classifyCookie(c.name, necessary);
    out.push(finding("cookie.pre-consent", sev, page, norm, `${ev} on a first visit, before any consent`));
    const problems = [];
    if (https && !c.attrs.secure) problems.push("no Secure");
    if (!c.attrs.samesite) problems.push("no SameSite");
    let days = null;
    if (c.attrs["max-age"] && /^-?\d+$/.test(String(c.attrs["max-age"]))) days = Number(c.attrs["max-age"]) / 86400;
    else if (c.attrs.expires) {
      const t = Date.parse(String(c.attrs.expires));
      if (Number.isFinite(t)) days = (t - now) / 86_400_000;
    }
    if (days !== null && days > MAX_LIFETIME_DAYS) problems.push(`lifetime ${Math.round(days)} days (over 13 months)`);
    if (problems.length) out.push(finding("cookie.attributes", "low", page, norm, `${c.name}: ${problems.join(", ")}`));
  }
  return out;
}

// ---- robots.txt, sitemap, CSS ---------------------------------------------

export function robotsFindings(text) {
  const out = [];
  const sitemaps = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim();
    const m = /^disallow\s*:\s*(\S+)/i.exec(line);
    if (m && SENSITIVE_PATH.test(m[1]) && out.length < 20) out.push(finding("robots.sensitive", "low", "/robots.txt", m[1].slice(0, 100), `Disallow: ${m[1]}`));
    const s = /^sitemap\s*:\s*(\S+)/i.exec(line);
    if (s && sitemaps.length < 3) sitemaps.push(s[1]);
  }
  return { findings: out, sitemaps };
}

/**
 * @param {string} xml  first 1 MB of the first sitemap
 * @param {{ host: string, own: Set<string>, page: string }} ctx
 */
export function sitemapFindings(xml, ctx) {
  const out = [];
  const paths = [];
  const seen = new Set();
  for (const m of String(xml).matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
    let u;
    try {
      u = new URL(m[1].replace(/&amp;/g, "&"));
    } catch {
      continue;
    }
    const host = u.hostname.toLowerCase();
    if (host !== ctx.host && !ctx.own.has(host)) {
      if (!seen.has(host) && out.length < 20) {
        seen.add(host);
        out.push(finding("sitemap.sensitive", "medium", ctx.page, host, `sitemap lists a URL on another host: ${urlSubject(u)}`));
      }
      continue;
    }
    if (SENSITIVE_PATH.test(u.pathname) && !seen.has(u.pathname) && out.length < 20) {
      seen.add(u.pathname);
      out.push(finding("sitemap.sensitive", "medium", ctx.page, u.pathname.slice(0, 100), `sitemap lists ${urlSubject(u)}`));
    }
    if (host === ctx.host && paths.length < 50) paths.push(u.pathname + u.search);
  }
  return { findings: out, paths };
}

/** Third-party hosts in a same-host stylesheet: @import and url() inside @font-face (how fonts hide in themes). */
export function cssFindings(css, cssUrl, ctx) {
  const out = [];
  const urls = [];
  for (const m of String(css).matchAll(/@import\s+(?:url\(\s*)?["']?([^"')\s;]+)/gi)) urls.push(["@import", m[1]]);
  for (const block of String(css).matchAll(/@font-face\s*{[^}]*}/gi)) for (const m of block[0].matchAll(/url\(\s*["']?([^"')\s]+)/gi)) urls.push(["@font-face", m[1]]);
  const via = (() => {
    try {
      return new URL(cssUrl).pathname;
    } catch {
      return cssUrl;
    }
  })();
  for (const [kind, raw] of urls) {
    let u;
    try {
      u = new URL(raw, cssUrl);
    } catch {
      continue;
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") continue;
    const host = u.hostname.toLowerCase();
    if (ctx.own.has(host)) continue;
    const entry = classify(host, u.pathname);
    if (entry?.category === "consent") continue;
    const check = entry ? CHECK_FOR_CATEGORY[entry.category] : "third-party.other";
    out.push(finding(check, TP_SEVERITY[check], ctx.page, host, `via ${via}: ${kind} ${urlSubject(u)}${describe(entry)}`));
  }
  return out;
}

/** Bot protection answered instead of the page (Bot Fight Mode, a managed challenge). */
export function isBlocked(status, headers, bodyStart) {
  if ((headers.get("cf-mitigated") ?? "").toLowerCase() === "challenge") return true;
  return (status === 403 || status === 503 || status === 429) && /challenge-platform|cf-chl-|Just a moment\.\.\.|Attention Required! \| Cloudflare/i.test(bodyStart);
}
