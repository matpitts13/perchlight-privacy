// A small public-suffix rule: common multi-part suffixes only, not the full
// Public Suffix List (docs/SDD.md, "Couldn't verify"). Used to stop the TXT
// walk at the registrable domain, so `_perchlight-privacy.co.uk` is never
// asked about and a record there could never verify anyone's site.
const MULTI = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co", "com.pe", "com.uy",
  "co.za", "org.za", "co.in", "net.in", "org.in", "firm.in",
  "com.cn", "net.cn", "org.cn", "com.tw", "com.hk", "com.sg", "com.my", "com.ph", "co.id", "co.th", "com.vn",
  "com.tr", "co.il", "org.il", "co.kr", "or.kr", "com.es", "com.pl", "co.at", "or.at", "gv.at", "com.ua", "com.pt", "com.gr", "com.ru",
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "herokuapp.com", "blogspot.com",
  "azurewebsites.net", "cloudfront.net", "appspot.com", "firebaseapp.com", "web.app", "fly.dev", "onrender.com", "glitch.me",
]);

/** The registrable domain ("shop.example.co.uk" -> "example.co.uk"). */
export function registrableDomain(host) {
  const labels = String(host).toLowerCase().replace(/\.+$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const last2 = labels.slice(-2).join(".");
  return labels.slice(MULTI.has(last2) ? -3 : -2).join(".");
}

/** True when the host is itself only a suffix ("co.uk", "workers.dev"). */
export function isPublicSuffix(host) {
  const h = String(host).toLowerCase().replace(/\.+$/, "");
  return MULTI.has(h) || !h.includes(".");
}

/** Names to try for the TXT record: the host, then parents up to the registrable domain; at most 3. */
export function txtCandidates(host) {
  const h = String(host).toLowerCase().replace(/\.+$/, "");
  const reg = registrableDomain(h);
  const out = [];
  let cur = h;
  while (out.length < 3) {
    out.push(cur);
    if (cur === reg || !cur.includes(".")) break;
    cur = cur.slice(cur.indexOf(".") + 1);
  }
  return out;
}
