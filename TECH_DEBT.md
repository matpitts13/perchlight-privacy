# Tech debt

- **Alert webhooks on a non-443 port are refused** (`src/lib/alerts.js` uses the scanner's strict `checkUrl`). A self-hosted ntfy on `:8443` can't be used. Fix: a separate, perchlight-hooks-style rule set for owner-configured webhook URLs (ports allowed, private ranges still refused). Found while building v0.1 (2026-11-12).
- **A "Try again" on an alert whose claim was pruned (older than 30 days) stays `retry_requested`** in D1 and is re-read (at most 20 rows) on every scan start. Harmless; fix: mark such rows `failed` with "too old to retry" in `startDue`.
