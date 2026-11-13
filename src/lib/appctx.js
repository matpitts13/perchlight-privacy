// What the routes and the Scanner take: env, the checked config, the public
// base URL and now(). As perchlight-hooks src/lib/appctx.js.
import { checkConfig } from "./config.js";

const checked = new WeakMap();
export function configFor(raw) {
  let c = checked.get(raw);
  if (!c) {
    c = checkConfig(raw);
    checked.set(raw, c);
  }
  return c;
}

/** The time source (tests replace clock.now). */
export const clock = { now: () => Date.now() };

export function makeApp(raw, env, { origin, now } = {}) {
  const cfg = configFor(raw);
  const base = (String(env.PUBLIC_URL ?? "").trim() || origin || "").replace(/\/+$/, "");
  return { env, cfg, base, now: now ?? (() => clock.now()) };
}

/** The Scanner's stub (one instance). */
export function scannerStub(env) {
  return env.SCANNER.get(env.SCANNER.idFromName("scanner"));
}

/** Tests only: bindings merged over the Durable Object's env (a fake send_email, a broken D1). */
export const testHooks = { env: null };
