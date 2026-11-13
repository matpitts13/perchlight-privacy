// DNS-over-HTTPS to Cloudflare's resolver (the only third party this tool
// talks to about your site): TXT lookups for ownership, A/AAAA lookups to
// refuse a verified host that now points at a private address
// (docs/SDD.md, "Ownership verification", "Security (SSRF)").
// The URL is fixed; only the queried name varies, and it is URL-encoded.
import { net } from "./net.js";
import { spend } from "./budget.js";
import { readCapped, errText } from "./http.js";
import { blockedIp, normHost } from "./ssrf.js";

export const DOH_URL = "https://cloudflare-dns.com/dns-query";
const DOH_TIMEOUT_MS = 5000;
const TYPES = { A: 1, AAAA: 28, CNAME: 5, TXT: 16 };

/**
 * One DoH query.
 * @returns {Promise<{ ok: true, answers: { type: number, data: string }[] } | { ok: false, error: string }>}
 */
export async function doh(name, type, budget) {
  if (!spend(budget, 1)) return { ok: false, error: "no subrequests left in this run", budget: true };
  const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`;
  let res;
  try {
    res = await net.fetch(url, { headers: { accept: "application/dns-json" }, redirect: "manual", signal: AbortSignal.timeout(DOH_TIMEOUT_MS) });
  } catch (err) {
    return { ok: false, error: `DNS-over-HTTPS unreachable: ${errText(err).slice(0, 120)}` };
  }
  if (!res.ok) {
    res.body?.cancel().catch(() => {});
    return { ok: false, error: `DNS-over-HTTPS answered HTTP ${res.status}` };
  }
  let data;
  try {
    const r = await readCapped(res.body, 64 * 1024, Date.now() + DOH_TIMEOUT_MS);
    data = JSON.parse(new TextDecoder().decode(r.bytes));
  } catch {
    return { ok: false, error: "DNS-over-HTTPS answer wasn't valid JSON" };
  }
  // 0 NOERROR, 3 NXDOMAIN (no such name: a definite "no records"); anything else is a failure.
  if (data?.Status === 3) return { ok: true, answers: [] };
  if (data?.Status !== 0) return { ok: false, error: `DNS lookup failed (status ${data?.Status})` };
  const want = TYPES[type];
  const answers = (Array.isArray(data.Answer) ? data.Answer : []).filter((a) => a && a.type === want && typeof a.data === "string").map((a) => ({ type: a.type, data: a.data }));
  return { ok: true, answers };
}

/**
 * A TXT record's text: quoted strings joined (a long record is split into
 * several 255-byte strings), escapes undone. Unquoted data is returned as is.
 */
export function parseTxt(data) {
  const s = String(data ?? "").trim();
  if (!s.startsWith('"')) return s;
  const parts = [];
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(s))) parts.push(m[1].replace(/\\(\d{3}|.)/g, (_, e) => (e.length === 3 ? String.fromCharCode(Number(e)) : e)));
  return parts.join("");
}

/** TXT strings at a name. */
export async function txtRecords(name, budget) {
  const r = await doh(name, "TXT", budget);
  if (!r.ok) return r;
  return { ok: true, texts: r.answers.map((a) => parseTxt(a.data)) };
}

/**
 * Checks that a host doesn't resolve to a private, loopback, link-local or
 * otherwise internal address (A and AAAA, 2 subrequests).
 * @returns {Promise<{ ok: true, addresses: string[] } | { ok: false, private?: boolean, error: string }>}
 */
export async function checkResolves(host, budget) {
  const h = normHost(host);
  const addresses = [];
  for (const type of ["A", "AAAA"]) {
    const r = await doh(h, type, budget);
    if (!r.ok) return { ok: false, error: r.error };
    for (const a of r.answers) {
      const why = blockedIp(a.data);
      if (why) return { ok: false, private: true, error: `${h} resolves to a ${why} address (${a.data}); not fetched` };
      addresses.push(a.data);
    }
  }
  if (!addresses.length) return { ok: false, error: `${h} has no A or AAAA records` };
  return { ok: true, addresses };
}
