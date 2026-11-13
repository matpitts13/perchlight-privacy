// Finding records (docs/SDD.md, "Each finding"): a stable key (hash of check
// id, page and subject), severity, page, subject, an evidence snippet of at
// most 200 characters with email addresses masked, and source "static".
// "Why this often matters" lines live here, not in the database.
import { sha256Hex } from "./crypto.js";

export const SEVERITIES = ["high", "medium", "low", "info"];
export const RANK = { high: 3, medium: 2, low: 1, info: 0 };
export const EVIDENCE_MAX = 200;

export const DISCLAIMER =
  "Automated technical check, not legal advice. Findings are observations from the HTML and headers your server sends to a first-time visitor; whether your site complies with GDPR, ePrivacy, CCPA or similar laws depends on facts this tool can't see. No finding means \"compliant\".";
export const ALERT_FOOTER = "Automated check, not legal advice.";

const EPRIVACY = "https://eur-lex.europa.eu/eli/dir/2002/58/oj";
const GDPR = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const EDPB_CONSENT = "https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en";
const MDN = (h) => `https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/${h}`;

export const WHY = {
  "third-party.tracker": ["Trackers and ad pixels loaded before consent usually need prior consent under the ePrivacy Directive (Art. 5(3)) and GDPR; under CCPA, sharing for ads may need an opt-out.", EDPB_CONSENT],
  "third-party.tag-manager": ["A tag manager can load more trackers at run time that this static check can't see; review what it loads before consent.", EDPB_CONSENT],
  "third-party.ip-leak": ["Fonts, CDNs and embeds receive each visitor's IP address; EU courts have found that sending it to a third party without a legal basis can breach GDPR (for example, a 2022 Munich ruling on Google Fonts).", GDPR],
  "third-party.other": ["Another company's server receives visitors' IP addresses and request details. Not necessarily a problem; worth knowing who they are.", GDPR],
  "third-party.consent-gated": ["Marked for a consent manager, so it likely loads only after consent. Check that it really does.", EDPB_CONSENT],
  "cookie.pre-consent": ["Non-essential cookies set before consent usually need prior consent under ePrivacy Art. 5(3); strictly necessary ones don't.", EPRIVACY],
  "cookie.attributes": ["Cookies without Secure or SameSite are easier to steal or misuse; lifetimes over 13 months go beyond what EU regulators usually accept for consent cookies.", MDN("Set-Cookie")],
  "policy.privacy-missing": ["GDPR (Art. 13) and CCPA require clear information about how personal data is used; a privacy policy linked from every page is the usual way.", GDPR],
  "policy.imprint-missing": ["Some countries (Germany, Austria) require an easy-to-find imprint (Impressum) on business websites.", "https://www.gesetze-im-internet.de/ddg/__5.html"],
  "header.hsts": ["Without HSTS, a first visit over http: can be intercepted; 180 days or more is the usual minimum.", MDN("Strict-Transport-Security")],
  "header.referrer-policy": ["Referrer-Policy controls how much of a page's URL is sent to other sites, which can leak personal data in URLs.", MDN("Referrer-Policy")],
  "header.permissions-policy": ["Permissions-Policy limits which browser features (camera, location...) embedded content can use.", MDN("Permissions-Policy")],
  "header.csp": ["A Content-Security-Policy limits what scripts and frames can load, which contains injected trackers and clickjacking.", MDN("Content-Security-Policy")],
  "header.nosniff": ["X-Content-Type-Options: nosniff stops browsers guessing content types, a small hardening step.", MDN("X-Content-Type-Options")],
  "mixed-content": ["http: resources on an https: page can be read or changed in transit; browsers block active ones.", "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
  "form.insecure": ["Form data sent over http: (or a password page served over http:) can be read in transit; GDPR Art. 32 asks for appropriate security.", GDPR],
  "form.third-party": ["The company that receives the form gets the data people type in; it's often fine (a newsletter provider) but usually needs a processing agreement.", GDPR],
  "email.exposed": ["Plain-text email addresses are collected by spam bots.", "https://owasp.org/www-community/attacks/Email_Harvesting"],
  "email.mailto": ["mailto: links are fine; listed so you know which addresses are public.", "https://owasp.org/www-community/attacks/Email_Harvesting"],
  "robots.sensitive": ["robots.txt is public: listing private paths there advertises them.", "https://www.rfc-editor.org/rfc/rfc9309"],
  "sitemap.sensitive": ["Sitemaps are public; private paths or URLs on other hosts in them are advertised to anyone.", "https://www.sitemaps.org/protocol.html"],
  "redirect.offsite": ["A page redirected to a host that isn't verified for this site, so it wasn't followed or checked.", null],
  "scan.blocked": ["Bot protection on your zone blocked the scanner; allow requests with the X-Perchlight-Privacy header in a WAF rule to check this page.", "https://developers.cloudflare.com/waf/custom-rules/skip/"],
  "security-txt.missing": ["/.well-known/security.txt tells researchers how to report security problems (RFC 9116).", "https://www.rfc-editor.org/rfc/rfc9116"],
};

const EMAIL_RE = /([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24})/g;

/** j***@example.com */
export function maskEmails(s) {
  return String(s ?? "").replace(EMAIL_RE, (_, first, domain) => `${first}***@${domain}`);
}

/** Evidence: masked, one line, at most 200 characters. */
export function evidence(s) {
  const one = maskEmails(String(s ?? "").replace(/\s+/g, " ").trim());
  return one.length > EVIDENCE_MAX ? `${one.slice(0, EVIDENCE_MAX - 1)}…` : one;
}

/** host + path, no query or fragment (so cache-busting strings don't make a new finding). */
export function urlSubject(u) {
  return `${u.host}${u.pathname}`.slice(0, 150);
}

/**
 * A finding. `subjectKey` (default: subject) is what the key hashes, when the
 * shown subject is masked (an email address).
 */
export function finding(check, severity, page, subject, ev, subjectKey) {
  return { check, severity, page, subject: String(subject).slice(0, 200), evidence: evidence(ev), source: "static", subjectKey: subjectKey ?? String(subject) };
}

/** The stable key: first 20 hex characters of SHA-256(check | page | subject). */
export async function findingKey(f) {
  return (await sha256Hex(`${f.check}|${f.page}|${f.subjectKey ?? f.subject}`)).slice(0, 20);
}

/** Adds keys, keeps one finding per key (the most severe). */
export async function withKeys(list) {
  const out = new Map();
  for (const f of list) {
    const key = f.key ?? (await findingKey(f));
    const prev = out.get(key);
    if (!prev || RANK[f.severity] > RANK[prev.severity]) {
      const { subjectKey: _drop, ...rest } = f;
      out.set(key, { ...rest, key });
    }
  }
  return [...out.values()];
}

export function countBySeverity(list) {
  const c = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of list) c[f.severity] = (c[f.severity] ?? 0) + 1;
  return c;
}

export const atOrAbove = (sev, level) => RANK[sev] >= RANK[level];
