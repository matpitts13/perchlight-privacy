// Ownership verification (docs/SDD.md, "Ownership verification"):
// - DNS TXT `_perchlight-privacy.<name> = "perchlight-privacy-verify=<token>"`
//   at the host or a parent up to the registrable domain (at most 3 lookups)
//   verifies that name and all its subdomains;
// - `https://<host>/.well-known/perchlight-privacy.txt` containing the token
//   (first 1 KB, trimmed, no redirects followed) verifies that host only.
// Result "unknown" (DoH or the file unreachable) is never treated as lost.
import { txtRecords } from "./dns.js";
import { txtCandidates } from "./psl.js";
import { safeFetch } from "./fetcher.js";
import { safeEqual } from "./crypto.js";

export const TXT_PREFIX = "_perchlight-privacy.";
export const WELL_KNOWN = "/.well-known/perchlight-privacy.txt";

export function instructions(host, token) {
  const names = txtCandidates(host);
  return {
    token,
    txt: { name: `${TXT_PREFIX}${names[names.length - 1]}`, value: `perchlight-privacy-verify=${token}`, covers: `${names[names.length - 1]} and all its subdomains (or add it at ${TXT_PREFIX}${host} for this host and its subdomains)` },
    file: { url: `https://${host}${WELL_KNOWN}`, content: token, covers: `${host} only` },
  };
}

/**
 * @param {{ host: string, verify_token: string }} site
 * @param {{ budget: object, headers: Record<string,string>, stats?: object }} ctx
 * @returns {Promise<{ result: "ok", method: "txt"|"file", scope: { kind: "domain"|"host", name: string }, detail: string } | { result: "failed"|"unknown", detail: string, found: string[] }>}
 */
export async function verifyOwnership(site, ctx) {
  const want = `perchlight-privacy-verify=${site.verify_token}`;
  const found = [];
  let txtUnknown = null;
  for (const name of txtCandidates(site.host)) {
    const r = await txtRecords(`${TXT_PREFIX}${name}`, ctx.budget);
    if (!r.ok) {
      txtUnknown = r.error;
      continue;
    }
    for (const t of r.texts) {
      if (await safeEqual(t.trim(), want)) return { result: "ok", method: "txt", scope: { kind: "domain", name }, detail: `TXT record found at ${TXT_PREFIX}${name}` };
      if (t.startsWith("perchlight-privacy-verify=")) found.push(`${TXT_PREFIX}${name}: a perchlight-privacy-verify record with a different token`);
    }
  }
  // The file proves control of the web server, so it covers this host only.
  // The scope for this one request is the claimed host; the SSRF rules, the
  // private-address check and "no redirects" still apply.
  const f = await safeFetch(`https://${site.host}${WELL_KNOWN}`, { scope: { kind: "host", name: site.host }, budget: ctx.budget, dnsOk: ctx.dnsOk ?? {}, headers: ctx.headers, stats: ctx.stats }, { follow: 0, maxBytes: 1024, timeoutMs: 10_000 });
  let fileUnknown = null;
  if (f.ok) {
    if (f.status >= 200 && f.status < 300) {
      const body = new TextDecoder().decode(f.body).trim();
      if ((await safeEqual(body, site.verify_token)) || (await safeEqual(body, want))) {
        return { result: "ok", method: "file", scope: { kind: "host", name: site.host }, detail: `file found at https://${site.host}${WELL_KNOWN}` };
      }
      found.push(`${WELL_KNOWN}: present, but doesn't contain this site's token`);
    } else found.push(`${WELL_KNOWN}: HTTP ${f.status}${f.status >= 300 && f.status < 400 ? " (redirects aren't followed for the file check)" : ""}`);
  } else if (f.kind === "refused") {
    found.push(`${WELL_KNOWN}: ${f.error}`);
  } else fileUnknown = f.error;
  if (txtUnknown && fileUnknown) return { result: "unknown", detail: `couldn't check: ${txtUnknown}; ${fileUnknown}`, found };
  if (txtUnknown && !found.some((x) => x.startsWith(WELL_KNOWN))) return { result: "unknown", detail: `couldn't check the TXT record: ${txtUnknown}`, found };
  if (txtUnknown) return { result: "unknown", detail: `couldn't check the TXT record (${txtUnknown}), and the file check failed`, found };
  if (fileUnknown) return { result: "unknown", detail: `no TXT record found, and couldn't reach the file: ${fileUnknown}`, found };
  return { result: "failed", detail: "no matching TXT record and no matching file", found };
}
