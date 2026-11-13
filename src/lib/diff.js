// Change detection (docs/SDD.md, "Change detection and alerts"), as a pure
// function over the Scanner's `tracked` table (one row per open finding key
// per site):
// - a key in this scan that isn't tracked (or was resolved) is NEW;
// - a tracked key absent from a DONE scan gets missing + 1, and is RESOLVED
//   only when missing reaches 2 (absent from 2 completed scans in a row), so
//   one flaky page never produces "resolved" then "new";
// - a PARTIAL scan can add NEW keys but never counts anything as missing
//   (pages that failed had their previous findings carried forward); a
//   FAILED scan is never diffed at all.

export const RESOLVE_AFTER = 2;

/**
 * @param {Map<string, object>} tracked  key -> { key, check, severity, page, subject, evidence, first_seen_at, missing }
 * @param {object[]} current  this scan's findings (with keys), carried-forward ones included
 * @param {"done"|"partial"} status
 * @param {number} now
 * @returns {{ added: object[], resolved: object[], upserts: object[], deletes: string[] }}
 */
export function diffScan(tracked, current, status, now) {
  const added = [];
  const resolved = [];
  const upserts = [];
  const deletes = [];
  const seen = new Set();
  for (const f of current) {
    seen.add(f.key);
    const t = tracked.get(f.key);
    if (!t) {
      added.push(f);
      upserts.push({ ...f, first_seen_at: now, missing: 0 });
    } else upserts.push({ ...f, first_seen_at: t.first_seen_at, missing: 0 });
  }
  if (status === "done") {
    for (const [key, t] of tracked) {
      if (seen.has(key)) continue;
      const missing = (t.missing ?? 0) + 1;
      if (missing >= RESOLVE_AFTER) {
        resolved.push(t);
        deletes.push(key);
      } else upserts.push({ ...t, missing });
    }
  }
  return { added, resolved, upserts, deletes };
}
