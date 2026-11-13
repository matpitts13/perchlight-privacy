// The Worker, built around a privacy config (privacy.json in production;
// tests pass their own). It never fetches your sites and never decides
// findings: the Scanner Durable Object does. No cron trigger.
import { makeApp, scannerStub } from "./lib/appctx.js";
import { json, text } from "./lib/http.js";
import { handleApi } from "./routes/api.js";
import { handleReport } from "./routes/report.js";
import { bump, flush } from "./lib/counters.js";

export { makeApp };

// The lazy fallback: at most once a minute per isolate, ask the Scanner to
// re-arm its alarm if it stopped (as perchlight-hooks and perchlight-status).
const WATCHDOG_MS = 60_000;
let watchdogAt = 0;
export function resetWatchdog() {
  watchdogAt = 0;
}

function watchdog(env, ctx) {
  const now = Date.now();
  if (!env.SCANNER || now - watchdogAt < WATCHDOG_MS) return;
  watchdogAt = now;
  ctx.waitUntil(scannerStub(env).ensureAlarm().catch((err) => console.error(`watchdog: ${err instanceof Error ? err.message : String(err)}`)));
}

export function makeWorker(raw) {
  return {
    async fetch(request, env, ctx) {
      const url = new URL(request.url);
      const path = url.pathname;
      const app = makeApp(raw, env, { origin: url.origin });
      try {
        let res;
        if (path.startsWith("/api/")) {
          bump("admin");
          res = await handleApi(request, app, ctx, path.slice(5));
        } else if (path.startsWith("/r/")) {
          bump("report");
          res = await handleReport(request, app, path);
        } else if (path === "/tick") {
          bump("tick");
          watchdog(env, ctx);
          return text("ok\n");
        } else if (path === "/") return text("perchlight-privacy\n");
        else return text("not found\n", 404);
        watchdog(env, ctx);
        ctx.waitUntil(flush(env.DB, Date.now()).catch(() => {}));
        return res;
      } catch (err) {
        // Never log query strings (a share token is one).
        console.error(`${request.method} ${path}: ${err instanceof Error ? err.stack : String(err)}`);
        return path.startsWith("/api/") ? json({ ok: false, error: "Something went wrong." }, 500) : text("error\n", 500);
      }
    },
  };
}
