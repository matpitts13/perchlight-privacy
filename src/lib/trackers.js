// Host classification from src/data/trackers.json (docs/SDD.md, "Tracker list").
// An entry "host" matches that host and its subdomains; an entry with a path
// ("facebook.com/tr", "googletagmanager.com/gtag/") also needs the URL path
// to start with it, and wins over a host-only entry.
import data from "../data/trackers.json";

export const CHECK_FOR_CATEGORY = {
  analytics: "third-party.tracker",
  ads: "third-party.tracker",
  social: "third-party.tracker",
  "session-replay": "third-party.tracker",
  "tag-manager": "third-party.tag-manager",
  fonts: "third-party.ip-leak",
  cdn: "third-party.ip-leak",
  embed: "third-party.ip-leak",
};

const byHost = new Map();
const withPath = [];
const snippetEntries = [];
for (const t of data.trackers) {
  const i = t.host.indexOf("/");
  const entry = { ...t, h: i < 0 ? t.host : t.host.slice(0, i), p: i < 0 ? null : t.host.slice(i), re: (t.snippets ?? []).map((s) => new RegExp(s)) };
  if (entry.p) withPath.push(entry);
  else byHost.set(entry.h, entry);
  if (entry.re.length) snippetEntries.push(entry);
}

const hostMatches = (host, h) => host === h || host.endsWith(`.${h}`);

/** The tracker entry for a host (+ path), or null. */
export function classify(host, path = "/") {
  const hst = String(host).toLowerCase().replace(/\.+$/, "");
  for (const e of withPath) if (hostMatches(hst, e.h) && path.startsWith(e.p)) return e;
  let cur = hst;
  for (;;) {
    const e = byHost.get(cur);
    if (e) return e;
    const dot = cur.indexOf(".");
    if (dot < 0) return null;
    cur = cur.slice(dot + 1);
  }
}

/** Tracker entries whose snippet patterns (or host names) appear in an inline script. */
export function snippetMatches(text) {
  const out = [];
  for (const e of snippetEntries) if (e.re.some((r) => r.test(text))) out.push(e);
  return out;
}

export const trackerCount = data.trackers.length;
