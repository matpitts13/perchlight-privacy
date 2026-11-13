// perchlight-privacy: a privacy and compliance checker for sites you own, on
// Cloudflare Workers + D1 + one small Durable Object. Your sites are in
// privacy.json at the repo root (a push redeploys) or added via the API.
// There is no cron trigger (docs/SDD.md).
import config from "../privacy.json";
import { makeWorker } from "./app.js";
import { scannerClass } from "./scanner.js";

export default makeWorker(config);
export const Scanner = scannerClass(config);
