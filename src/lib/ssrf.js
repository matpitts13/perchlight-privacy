// URL rules for every outgoing request (docs/SDD.md, "Security (SSRF)").
// The IP-range tables, IPv6 parsing and private-name rules are copied from
// perchlight-hooks src/lib/ssrf.js. This tool is stricter: it never fetches
// an IP literal at all (only verified host names), only port 443 (80 for the
// single http:// redirect check), and the host must be inside the site's
// verified scope. DNS answers are checked against the same ranges
// (blockedIp) by src/lib/dns.js before a host is first fetched in a scan.
//
// The WHATWG URL parser normalises decimal, hex, octal and short IPv4 forms
// (https://2130706433/, https://0x7f.1/) to dotted decimal and compresses
// IPv6, so the checks see canonical addresses.

const V4_BLOCKED = [
  ["0.0.0.0", 8, "unspecified"],
  ["10.0.0.0", 8, "private"],
  ["100.64.0.0", 10, "CGNAT"],
  ["127.0.0.0", 8, "loopback"],
  ["169.254.0.0", 16, "link-local"],
  ["172.16.0.0", 12, "private"],
  ["192.0.0.0", 24, "IETF protocol assignments"],
  ["192.0.2.0", 24, "documentation"],
  ["192.168.0.0", 16, "private"],
  ["198.18.0.0", 15, "benchmarking"],
  ["198.51.100.0", 24, "documentation"],
  ["203.0.113.0", 24, "documentation"],
  ["224.0.0.0", 4, "multicast"],
  ["240.0.0.0", 4, "reserved"],
];

function v4ToInt(s) {
  const p = String(s).split(".");
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((n, x) => n * 256 + Number(x), 0);
}

/** Why an IPv4 address is refused, or null. */
export function blockedV4(s) {
  const n = typeof s === "number" ? s : v4ToInt(s);
  if (n === null) return null;
  for (const [base, bits, why] of V4_BLOCKED) {
    const b = v4ToInt(base);
    const size = 2 ** (32 - bits);
    if (n >= b && n < b + size) return why;
  }
  return null;
}

/** 8 groups of 16 bits, or null. */
function v6Groups(s) {
  let str = String(s).toLowerCase();
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(str);
  if (m) {
    const n = v4ToInt(m[2]);
    if (n === null) return null;
    str = `${m[1]}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = str.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const g = [...head, ...Array(fill).fill("0"), ...tail];
  if (g.length !== 8 || g.some((x) => !/^[0-9a-f]{1,4}$/.test(x))) return null;
  return g.map((x) => parseInt(x, 16));
}

/** Why an IPv6 address is refused, or null. */
export function blockedV6(s) {
  const g = v6Groups(s);
  if (!g) return "not a valid IPv6 address";
  const zero = (from, to) => g.slice(from, to).every((x) => x === 0);
  const v4 = (g[6] << 16) + g[7];
  const embedded = () => blockedV4(v4 >>> 0);
  if (zero(0, 8)) return "unspecified";
  if (zero(0, 7) && g[7] === 1) return "loopback";
  if (zero(0, 5) && g[5] === 0xffff) return embedded() ? `IPv4-mapped ${embedded()}` : null;
  if (zero(0, 6)) return embedded() ? `IPv4-compatible ${embedded()}` : null;
  if (g[0] === 0x64 && g[1] === 0xff9b && zero(2, 6)) return embedded() ? `NAT64 ${embedded()}` : null;
  // 6to4 (2002::/16) embeds an IPv4 address in groups 1-2.
  if (g[0] === 0x2002) {
    const e = blockedV4((((g[1] << 16) + g[2]) >>> 0));
    return e ? `6to4 ${e}` : null;
  }
  // Teredo (2001::/32) embeds the client's IPv4 address, XORed, in groups 6-7.
  if (g[0] === 0x2001 && g[1] === 0) {
    const e = blockedV4(((((g[6] ^ 0xffff) << 16) + (g[7] ^ 0xffff)) >>> 0));
    return e ? `Teredo ${e}` : null;
  }
  if ((g[0] & 0xfe00) === 0xfc00) return "unique local (private)";
  if ((g[0] & 0xffc0) === 0xfe80) return "link-local";
  if ((g[0] & 0xff00) === 0xff00) return "multicast";
  if (g[0] === 0x2001 && g[1] === 0x0db8) return "documentation";
  return null;
}

/** Why a resolved address (from DNS) is refused, or null. */
export function blockedIp(addr) {
  const a = String(addr).trim();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(a)) return v4ToInt(a) === null ? "not a valid IPv4 address" : blockedV4(a);
  if (a.includes(":")) return blockedV6(a);
  return "not an IP address";
}

const BLOCKED_NAMES = /(^|\.)(localhost|local|internal|home\.arpa|localdomain|invalid|test|example|onion)$/i;

/** A host is an IP literal (v4 dotted/numeric, or bracketed v6). */
export function isIpLiteral(host) {
  const h = String(host).toLowerCase().replace(/\.+$/, "");
  return h.startsWith("[") || /^[\d.]+$/.test(h) || /^0x[0-9a-f.x]+$/i.test(h);
}

/** Normalised host: lower case, no trailing dot. */
export const normHost = (h) => String(h ?? "").toLowerCase().replace(/\.+$/, "");

/**
 * Whether a configured site host is acceptable: a public-looking DNS name,
 * not an IP literal or local / reserved name.
 */
export function checkHostName(host) {
  const h = normHost(host);
  if (!h || h.length > 253) return "isn't a host name";
  if (isIpLiteral(h)) return "is an IP address (only host names you've verified can be scanned)";
  if (BLOCKED_NAMES.test(h)) return `is a local or reserved name (${h})`;
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(h)) return "isn't a valid host name (letters, digits, dots and dashes; no port, no path)";
  return null;
}

/**
 * Static rules for one outgoing URL (before the scope check).
 * @returns {{ ok: true, url: URL, host: string } | { ok: false, error: string }}
 */
export function checkUrl(raw, { allowHttp = false } = {}) {
  let u;
  try {
    u = new URL(String(raw));
  } catch {
    return { ok: false, error: "isn't a valid URL" };
  }
  if (u.protocol !== "https:" && !(allowHttp && u.protocol === "http:")) {
    return { ok: false, error: u.protocol === "http:" ? "uses http: (only https: is fetched)" : `uses the ${u.protocol} scheme (only https: is fetched)` };
  }
  if (u.username || u.password) return { ok: false, error: "contains a user name or password" };
  if (u.port !== "") return { ok: false, error: `uses port ${u.port} (only ${u.protocol === "http:" ? "80" : "443"} is allowed)` };
  const host = normHost(u.hostname);
  if (isIpLiteral(host)) return { ok: false, error: `points at an IP address (${host}); only verified host names are fetched` };
  const why = checkHostName(host);
  if (why) return { ok: false, error: `host ${why}` };
  return { ok: true, url: u, host };
}

/**
 * Whether a host is inside a verified scope.
 * @param {{ kind: "domain" | "host", name: string } | null} scope
 */
export function inScope(host, scope) {
  if (!scope || !scope.name) return false;
  const h = normHost(host);
  const n = normHost(scope.name);
  if (scope.kind === "domain") return h === n || h.endsWith(`.${n}`);
  return h === n;
}

/** The host only, for display (never the path or query). */
export function hostOf(raw) {
  try {
    return new URL(String(raw)).host;
  } catch {
    return "";
  }
}
