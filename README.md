# perchlight-privacy

A free, self-hosted privacy and compliance checker for websites you own. It runs on your own Cloudflare account (one Worker, one D1 database, one small Durable Object), fetches your pages the way a first-time visitor's browser would, before any consent, and tells you what it finds. Part of the [Perchlight](https://perchlight.ravenburst.com) family.

> **Not legal advice.** Findings are technical observations from the HTML and headers your server sends, with plain-language notes on why they often matter under GDPR, ePrivacy, CCPA and similar laws. Whether your site complies depends on facts this tool can't see (your consent banner, your contracts, your users). No finding means "compliant". The report page, the JSON and every alert say so too.

- **Third parties** your pages load: trackers and ad pixels, tag managers ("may load more trackers this tool can't see"), and fonts, CDNs and embeds that receive visitors' IP addresses (Google Fonts is the well-known one). Tracker tags marked for a consent manager (`type="text/plain"` with `data-category` and friends) are reported separately, lower.
- **Cookies set before consent** on a first visit, classified: known tracking cookies high, known necessary ones (and the ones you list) info, the rest medium; plus missing `Secure` / `SameSite` and lifetimes over 13 months.
- **Policy pages:** a privacy-policy link on the home page (in English, German, French, Spanish, Italian, Dutch and Portuguese) that loads; an imprint when you ask for it.
- **Headers:** HSTS, Referrer-Policy, Permissions-Policy, Content-Security-Policy, X-Content-Type-Options, and whether `http://` redirects to `https://`.
- **Mixed content, insecure and third-party forms, email addresses in plain text, `robots.txt` and sitemaps that advertise private paths**, and `security.txt`.

It re-checks on a schedule (a Durable Object alarm; **no cron trigger**) and alerts you by email or webhook **when something changes**: "NEW (high): connect.facebook.net on /pricing (loaded)". There's a server-rendered HTML report (no JavaScript), a JSON API, and screens for the Perchlight desktop app.

It only checks domains you've proved you control (a DNS TXT record or a file under `/.well-known/`), so it can't be pointed at someone else's site or your internal network.

The design is in [docs/SDD.md](docs/SDD.md).

## What it can't see

It's a **static** checker: it reads the HTML and headers your server sends.

- **JavaScript-added trackers aren't seen**: pixels loaded by a tag manager, by a consent manager after "Accept", or by your app's bundle; cookies set by `document.cookie` (`_ga` set by script). A tag manager found in the HTML is reported, with "may load more".
- **Single-page apps** that render in JavaScript look almost empty; the report says "Little HTML found".
- **Consent logic isn't tested.** A tracker in the HTML may still be blocked by a consent manager at run time; only the common `type="text/plain"` markup is recognised.
- **Bot protection on your own zone** (Bot Fight Mode, challenges) may block the scanner: reported as `scan.blocked`. Requests carry `X-Perchlight-Privacy: <hash of the site's token>` so you can allow them in a WAF rule.
- **Geo and A/B differences:** it sees what Cloudflare's network gets from one location.
- **It's a heuristic list** (`src/data/trackers.json`, about 180 hosts, written for this project). Hosts not in it are "other third party", not "safe".

## Set up

You need a Cloudflare account (the free plan is enough) and Node 22+.

1. **Email to you (free, optional).** Cloudflare dashboard → your domain → Email → Email Routing → enable it and add your address under *Destination addresses* (it must be verified). Put an address on that domain in `wrangler.jsonc` `vars.MAIL_FROM`, and your verified addresses in `privacy.json` `alerts.email`.
2. **Deploy.**
   ```sh
   npm install
   npx wrangler d1 create perchlight-privacy         # copy the database_id into wrangler.jsonc (or a gitignored wrangler.mine.jsonc)
   npx wrangler secret put ADMIN_TOKEN               # 16+ random characters: openssl rand -hex 32
   npx wrangler secret put ALERT_WEBHOOKS            # optional: {"discord-ops":"https://discord.com/api/webhooks/..."}
   npx wrangler secret put WEBHOOK_SECRET            # needed for JSON alert webhooks
   npm run deploy                                    # applies migrations, then deploys
   ```
   Set `vars.PUBLIC_URL` to your Worker's URL (e.g. `https://perchlight-privacy.you.workers.dev`) so alerts and share links point at it. `workers.dev` is the recommended home: a Worker fetching a site served by another Worker on the same zone may need a service binding.
3. **Add a site and prove you own it.**
   ```sh
   curl -H "Authorization: Bearer $ADMIN_TOKEN" -X POST https://<host>/api/sites \
        -d '{"id":"main","host":"example.com","pages":["/pricing","/contact"]}'
   ```
   The answer has a token and two ways to use it:
   - **DNS TXT** `_perchlight-privacy.example.com` = `perchlight-privacy-verify=<token>`: verifies `example.com` **and all its subdomains** (the record can also sit on a parent: the host and up to two parents are tried, never past the registrable domain);
   - **a file** at `https://example.com/.well-known/perchlight-privacy.txt` containing the token: verifies **that host only** (a file proves control of the web server, not the domain; redirects aren't followed).

   Then `POST /api/sites/main/verify`. The first scan starts within seconds.
4. **Check it works.** `curl https://<host>/tick` arms the Scanner; `POST /api/test-alert` sends a test alert to every channel; `GET /api/sites/main/report.json` or `https://<host>/r/main` shows the report.

## `privacy.json`

Sites can live in `privacy.json` at the repo root (reviewed, checked by `npm test`, a push redeploys) or be added through the API (stored only in D1). At most 10 sites, 20 pages a site.

```jsonc
{
  "sites": {
    "main": {
      "host": "example.com",
      "ownHosts": ["www.example.com", "static.example.com"], // not "third party" (fetched only if also verified)
      "pages": ["/", "/pricing", "/contact", "/checkout"],   // paths, or https URLs on a verified host; the home page is always first
      "discover": 0,                 // up to 20 more paths from the sitemap (first sitemap, first 1 MB)
      "every": "1d",                 // at least "6h"
      "imprint": false,              // check for an imprint (Germany, Austria)
      "necessaryCookies": ["sid", "XSRF-TOKEN"],
      "alertLevel": "medium",        // "high" | "medium" | "low"; info never alerts
      "userAgent": "browser"         // browser-like (default) or "honest": perchlight-privacy/0.1
    }
  },
  "alerts": { "email": ["you@example.com"], "webhooks": ["discord-ops"] },
  "retention": { "scansPerSite": 30 }
}
```

A site with a mistake is left out with the reason (`GET /api/config`), and the rest keep working. Config sites can be paused (API or app) but not deleted; changing a site's host resets its verification.

## Checks

| Check id | What it reports | Severity |
|---|---|---|
| `third-party.tracker` | A known tracker or ad host in `<script src>`, `<img>`, `<iframe>`, `<link>` (srcset, `<base>` and protocol-relative URLs resolved), or an inline snippet (`gtag(`, `fbq(`, `_paq.push`, `hj(`, ...) | high |
| `third-party.tag-manager` | Google Tag Manager, Segment, Tealium, Adobe Tags: "may load more trackers this tool can't see" | high |
| `third-party.ip-leak` | Fonts, CDNs, embeds (Google Fonts, cdnjs, jsDelivr, YouTube, Vimeo, Maps...) that receive visitors' IP addresses, including `@import` / `@font-face` in up to 5 same-host stylesheets | medium |
| `third-party.other` | Any other host not in your own host list | info |
| `third-party.consent-gated` | A tag marked for a consent manager (`type="text/plain"` + `data-category` / `data-cookiecategory` / `data-cookieconsent`, or OneTrust's `optanon-category-*`) | info |
| `cookie.pre-consent` | `Set-Cookie` on a first visit (no cookies are ever sent): tracking names high, necessary info, the rest medium. Random suffixes are normalised (`_ga_*`). Values are never stored. | high / medium / info |
| `cookie.attributes` | No `Secure`, no `SameSite`, or a lifetime over 13 months | low |
| `policy.privacy-missing` | No privacy-policy link on the home page, or it doesn't load (not 2xx after redirects). A link to another host (a policy generator) counts as linked, because it can't be fetched. | high |
| `policy.imprint-missing` | The same for an imprint, only with `imprint: true` | medium |
| `header.hsts` | Missing, `max-age` under 180 days, sent on `http:` only; or `http://` not redirecting to `https://` | medium |
| `header.referrer-policy` | Missing (low), or `unsafe-url` / `no-referrer-when-downgrade` (medium); `<meta name="referrer">` counts | low / medium |
| `header.permissions-policy` | Missing | low |
| `header.csp` | Missing; `unsafe-inline` (without a nonce or hash) or `unsafe-eval` in `script-src`; no `frame-ancestors` and no `X-Frame-Options` | low |
| `header.nosniff` | `X-Content-Type-Options: nosniff` missing | info |
| `mixed-content` | `http:` subresources on an `https:` page: script, iframe, stylesheet, embed high; images and media medium | high / medium |
| `form.insecure` | `<form action>` on `http:`, or a password field on an `http:` page | high |
| `form.third-party` | `<form action>` on another company's host | medium |
| `email.exposed` / `email.mailto` | Addresses in page text (masked: `j***@example.com`) / `mailto:` links | low / info |
| `robots.sensitive` | `Disallow:` lines naming `admin`, `staging`, `backup`, `private`, `internal`, `.git`, `.env`, `test`, `old`, `dev`... (robots.txt is public) | low |
| `sitemap.sensitive` | Sitemap URLs on another host, or matching the same patterns | medium |
| `redirect.offsite` | A page redirected to a host that isn't verified: not followed | info |
| `scan.blocked` | Bot protection answered with a challenge | medium |
| `security-txt.missing` | No `/.well-known/security.txt` with a `Contact:` line | info |

Header checks run on the home page. Each finding has a stable key (a hash of check id, page and subject: a host, a cookie or header name, or host + path without the query string, so cache-busting doesn't make a "new" finding), a severity, the page, at most 200 characters of evidence with email addresses masked, a "why this often matters" line with a public source, and `source: "static"`. **Page HTML is never stored.**

## Scans, changes and alerts

- **A scan** is split into chunks, one alarm each: *prepare* (re-check ownership, re-resolve the host and refuse private addresses, the `http://` redirect check, `robots.txt`, the sitemap, `security.txt`), *pages* (up to 10 a chunk, 6 at a time), *finalize* (the policy links, same-host CSS, the diff, alerts). A 20-page scan takes 4 alarm runs. Each fetch reserves its worst case (1 request + 5 redirects + 2 DNS lookups) from a 45-subrequest budget per run, with 4 kept back for D1 and an alert. The cursor and partial findings live in the Scanner's SQLite, so an eviction resumes the scan; a scan not finished within 30 minutes is closed as failed and the previous findings stay current.
- **Schedule:** `every` (default daily, at least 6 hours), counted from the last scan's start. **Manual scan:** `POST /api/sites/:id/scan`, at most one per site every 5 minutes (`429` with `retryAfterSeconds`); `409 unverified` for an unverified site, and no request reaches it.
- **Ownership** is re-checked at the start of every scan. A failed check skips the scan; a second failure at least 24 hours after the first moves the site to `verification_lost`, stops its scans and sends one alert. DoH or the file being unreachable is "unknown": the scan is skipped, never counted as lost.
- **Change detection:** each finding key is tracked per site. A key not seen before is **new**; a key absent from a completed scan is **resolved only when it's absent from 2 completed scans in a row**, so one flaky page never produces "resolved" then "new". A page that fails (timeout, 404, 5xx, bot challenge) has its previous findings **carried forward** and makes the scan `partial`; a partial scan can report new findings but never counts anything as missing; a failed scan is never compared.
- **Alerts:** one per site per scan, with every new and resolved finding at or above `alertLevel` (muted keys left out, `info` never), plus verification lost (once), scans failing twice in a row (once), and recovery. They name hosts, pages and subjects, never evidence, and link the report. Email (`send_email` to verified addresses), Discord, Slack, ntfy and signed JSON webhooks (`X-Perchlight-Signature: sha256=HMAC-SHA256(WEBHOOK_SECRET, "<X-Perchlight-Timestamp>.<body>")`), as perchlight-hooks. Claim-then-send in the Scanner's SQLite, committed together with the diff, so an alarm that runs twice never alerts twice. Retries after 1, 5 and 30 minutes, 2 hours, 12 hours. Every alert ends with "Automated check, not legal advice."
- **Muting:** `POST /api/findings/:key/mute {"note": "YouTube embed reviewed, consent-gated on click"}`: shown on the report as muted, never alerted.

## No cron trigger: how work is timed

One Durable Object, `Scanner`, with one alarm set to the next due thing (the next chunk, the next due scan, an alert retry, housekeeping every 6 hours, or at most an hour). Each run sets its next alarm first and saves its whole state every run. Nothing can make it spin: a D1 failure, a chunk that throws, or a run that throws waits with exponential backoff (30 s doubling to 30 minutes). If the alarm ever stops, any API request or `GET /tick` re-arms it (at most once a minute per isolate). Set `HEARTBEAT_URL` (for example a perchlight-hooks heartbeat) to hear about it if this tool stops.

## API

`Authorization: Bearer <ADMIN_TOKEN>` (16+ characters, constant-time compare: both sides hashed first; `/api/*` answers `503` until it's set). JSON bodies are capped at 16 KB.

| Endpoint | What |
|---|---|
| `GET /api/sites` · `POST /api/sites` · `GET/PATCH/DELETE /api/sites/:id` | Sites. `POST` returns the token and both instructions. Config sites: `PATCH {"paused": true}` or `{"every": "12h"}` only, no delete. |
| `POST /api/sites/:id/verify` | Check ownership now; returns the result and what was found |
| `POST /api/sites/:id/scan` | Manual scan (`429` within 5 minutes of the last, `409` unverified / paused) |
| `GET /api/sites/:id/report.json` | Latest completed scan: site, scan, pages, findings by severity with "why", changes, consent managers found, `disclaimer`, `limitations`; `"schema": 1` |
| `GET /api/scans?site=&limit=` · `GET /api/scans/:id` | History; one scan with its findings |
| `POST /api/findings/:key/mute` · `DELETE /api/findings/:key/mute?site=` | Mute with a note (`site` is inferred when the key is on one site) |
| `POST /api/sites/:id/share` · `DELETE /api/sites/:id/share` | Create (shown once) or revoke a share link |
| `GET /api/deliveries?status=failed` · `POST /api/deliveries/:id/retry` · `POST /api/test-alert` | Alerts |
| `GET /api/footprint` · `GET /api/config` · `POST /api/housekeeping` | Counted use; config errors and the Scanner's state; retention now |
| `GET /r/:site` | The HTML report: the admin token as a header, a session cookie from the login form, or `?s=<share token>` |
| `GET /tick` · `GET /` | Re-arm the alarm · plain-text name |

The report page sends `Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, HSTS, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, sets no cookie unless you log in, and passes this tool's own header checks. Everything from your pages is shown as escaped text.

## Perchlight desktop app

`perchlight/perchlight.json` adds screens for **Sites** (state, verified by, last and next scan, high / medium counts; *Paused* and *Every* editable), **Scans**, **Findings (latest scan)** (by severity: check, page, subject, evidence, first seen, muted) and **Alerts** (*Try again*). Replace `YOUR-D1-DATABASE-ID`. Muting is through the API (the key is a hidden column on the Findings screen), because the v1 app schema has no "call the API" action.

## Security notes

- **SSRF:** every outgoing request goes through one function, `safeFetch`: `https:` only (`http:` only for the one "does `http://` redirect" request, never followed), port 443 (80 for that one), no user info, **no IP literals at all**, no `localhost` / `*.local` / `*.internal` / `*.home.arpa` / single-label names, and the host must be inside the site's verified scope (TXT: the domain and its subdomains; file: that host). `ownHosts` are fetched only if they're verified too. The first time a host is fetched in a scan, its A and AAAA records are re-resolved over DoH and any private, loopback, link-local, CGNAT, multicast, reserved or documentation address (IPv4, and IPv6 including mapped, NAT64, 6to4 and Teredo forms) refuses it. Redirects are followed by hand, at most 5 hops, each checked the same way; a redirect to an unverified host isn't followed and is reported. Bodies are read to 2 MB at most (flagged `truncated`), with a 15-second cap for the whole chain. Nothing about your site goes to a third party except the DoH lookups to Cloudflare's resolver.
- **Secrets:** the admin token and share tokens are compared in constant time (SHA-256 both sides, then `timingSafeEqual`); share tokens are stored as SHA-256 only; the report login cookie is an HMAC of the admin token, `HttpOnly; Secure; SameSite=Strict`. Logs never print query strings.
- **Data:** every SQL statement is parameterised; request bodies, link text, inline scripts (32 KB each), robots.txt (512 KB), sitemaps (1 MB) and stylesheets (512 KB) are capped.

## What it costs

Nothing inside the free plans (Workers Free, D1 Free, Durable Objects Free with SQLite storage, `send_email` to your own addresses, Discord / Slack / ntfy webhooks). A 20-page scan is about 4 alarm runs and 30 to 45 subrequests (most chunks well under the 45 budget). The test for the SDD's example (3 sites, 20 pages each, daily) counted **under 1,000 D1 rows written** for a day of scans (under 1% of the free 100,000). At the limits the config allows (10 sites, 20 pages, every 6 hours) it's 40 scans and about 1,400 page fetches a day on your own sites. `GET /api/footprint` shows measured counts.

## Tested, and not tested

- **`npm test`: 113 tests** with vitest and the Workers pool (local D1 and the Scanner Durable Object; a fake network, so no test ever reaches a real site). They cover:
  - SSRF: every rule (IP literals in every form, local names, credentials, ports, schemes), scope (domain vs host, file verification not covering subdomains), private DNS answers (including 6to4 and Teredo), redirects checked hop by hop (an IP-literal `Location` not followed, an unverified host reported as `redirect.offsite`), 5-hop limit, body cap, time cap, no cookies sent, the per-hop subrequest budget
  - ownership: TXT on the host and on a parent, split TXT strings, wrong tokens, the well-known file (no redirects), re-check before every scan, loss after two failures 24 hours apart with one alert, scans stopping, restore by verify, DoH unreachable as "unknown", a verified host now resolving to a private address
  - each check against fixture HTML and headers: the SDD's acceptance page (exact findings at the stated severities), consent-gated markup, srcset / `<base>` / protocol-relative / uppercase tags, inline snippets including one split across text chunks, emails in text vs `mailto:` vs script JSON, forms, mixed content, policy links in 7 languages, HSTS / Referrer-Policy / CSP parsing, cookie classification and normalisation, robots, sitemaps, CSS `@import` / `@font-face`, bot challenges, stable keys across query strings
  - scanning: a 20-page scan (each page redirecting once) in at most 5 alarm runs, none over 45 subrequests; eviction mid-scan resuming the same scan; partial scans with 3 timed-out pages (carried forward, nothing resolved, even over several scans); 404/5xx pages; the 30-minute timeout; a site deleted mid-scan; discovery capped
  - change detection and alerts: one alert for a new script naming it, "resolved" only after 2 completed scans, muted keys never alerting, `alertLevel`, an alarm run twice alerting once, two failed scans alerting once
  - the alarm: no hot loop while D1 fails (30 s, 60 s, 120 s, 240 s) and the scan finishing afterwards, a throwing run backing off, `/tick` and API requests re-arming a stopped alarm, no `triggers` in `wrangler.jsonc`
  - API and report: admin auth (missing, wrong, short token), body limits, site limits, config sites, mutes, share links (hashed, revocable, wrong-site tokens refused), the login cookie, the report page passing its own header checks and rendering `<script>` in evidence as text, the footprint for the SDD's example under 1,000 D1 rows written
- **Locally with `wrangler dev`:** not run for v0.1 (the tests use the same local D1 and Durable Object runtime).
- **Not tested on a real Cloudflare account yet** (free, but needs you): deploying; DoH to `cloudflare-dns.com` from a Durable Object; `Headers.getSetCookie()` / `getAll("Set-Cookie")` on real `fetch()` responses; real CPU per page for `HTMLRewriter`; whether D1 calls and followed redirects count as subrequests (assumed yes); same-zone `fetch()` to a site on another Worker or Pages project; real D1 rows written (index rows); Discord, ntfy and a verified Email Routing address receiving real alerts; Bot Fight Mode on a real zone.
- **Not tested, because it costs money:** Browser Run beyond the free 10 minutes (not used in v0.1); paid consent managers (their markup is matched from public documentation); Workers Paid.

## License

MIT. See [LICENSE](LICENSE). The tracker list is written for this project. Not affiliated with Cloudflare, Google, Meta, Cookiebot, CookieYes, Usercentrics, OneTrust or any company named in the tracker list.
