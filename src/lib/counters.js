// Worker request counts kept in isolate memory and written at most once a
// minute per isolate (copied from perchlight-hooks src/lib/counters.js,
// without the "not stored" counts). They're "at least" numbers: an isolate
// can be evicted before it writes.
import { utcDay } from "./http.js";

const FLUSH_MS = 60_000;
let foot = new Map();
let lastFlush = 0;

export function bump(k, n = 1) {
  const key = `${utcDay(Date.now())}|${k}`;
  foot.set(key, (foot.get(key) ?? 0) + n);
}

/** Writes the counts if a minute has passed (or `force`). One D1 statement. */
export async function flush(db, now, force = false) {
  if (!db || (!force && now - lastFlush < FLUSH_MS) || !foot.size) return false;
  lastFlush = now;
  const f = [...foot].map(([k, n]) => {
    const [day, key] = k.split("|");
    return { day, k: key, n };
  });
  foot = new Map();
  try {
    await db
      .prepare(`INSERT INTO footprint (day, k, n) SELECT j.value ->> 'day', j.value ->> 'k', j.value ->> 'n' FROM json_each(?1) AS j WHERE true
                ON CONFLICT (day, k) DO UPDATE SET n = n + excluded.n`)
      .bind(JSON.stringify(f))
      .run();
    return true;
  } catch (err) {
    for (const x of f) foot.set(`${x.day}|${x.k}`, (foot.get(`${x.day}|${x.k}`) ?? 0) + x.n);
    console.error(`counters: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  }
}

/** Tests only. */
export function resetCounters() {
  foot = new Map();
  lastFlush = 0;
}
