# SDD: perchlight-privacy

**Version:** 0.1
**Date:** 2026-11-12
**Status:** Approved 2026-11-12 (all 10 open questions resolved as recommended)

## Summary

A free, self-hosted privacy and compliance checker for websites you own. It runs on your own Cloudflare account (one Worker, one D1 database, one small Durable Object) and fetches your pages the way a first-time visitor's browser would, before any consent is given. It reports what it finds:

- **Third parties** your pages load: trackers, ad pixels, analytics, and fonts or CDNs that pass visitors' IP addresses to someone else (Google Fonts is the well-known one).
- **Cookies set before consent** by the server on a first visit.
- **Policy pages:** whether a privacy policy (and, where you ask for it, an imprint) is linked and loads.
- **Headers:** HSTS, Referrer-Policy, Permissions-Policy, Content-Security-Policy and a few related ones.
- **Mixed content, forms** that post over `http:` or to another company, **email addresses** in plain text, and **robots.txt and sitemaps** that advertise private paths.

It re-checks on a schedule (a Durable Object alarm, no cron trigger) and alerts you by email or webhook when something changes: "NEW: connect.facebook.net loaded on /pricing". There's a plain HTML report page and a JSON API, and the Perchlight desktop app gets screens for sites, scans and findings.

It only checks domains you've proved you control (a DNS TXT record or a file under `/.well-known/`), so it can't be pointed at someone else's site or your internal network.

**What it can't see:** this is a static checker. It reads the HTML and headers your server sends. Trackers that are added later by JavaScript (a tag manager loading a pixel, a script setting `_ga`) are invisible to it unless the tag manager itself is found, which it is, and reported as "may load more". See "Limitations". It finds common problems; it doesn't certify anything.

**Not legal advice.** Findings are technical observations with plain-language notes on why they often matter under GDPR, ePrivacy, CCPA and similar laws. Whether your site complies depends on facts this tool can't see (your consent banner, your contracts, your users). The report, the README and every alert say so.

## Why

- Paid scanners (Cookiebot, CookieYes, Usercentrics and similar) scan with a real browser and are good at what this can't do, but cost a monthly fee per domain beyond small free tiers (their current prices weren't checked for this draft). Free one-off scanners (webbkoll, Blacklight, securityheaders.com) don't watch your site over time or tell you when a new script shows up.
- The most common real-world slip for small sites isn't the banner; it's a new embed, font or pixel added in a template change that nobody noticed. A scheduled check that alerts on **changes** catches that.
- Everything stays in your account; nothing about your site is sent to a third party except the DNS-over-HTTPS lookup to Cloudflare's resolver.

## Requirements

### Must have

- **Sites and ownership.** Add a site by host (`example.com`, `shop.example.com`). Nothing is fetched from it until it's verified by either:
  - **DNS TXT:** `_perchlight-privacy.example.com TXT "perchlight-privacy-verify=<token>"` verifies `example.com` and all its subdomains;
  - **Well-known file:** `https://<host>/.well-known/perchlight-privacy.txt` containing the token verifies that exact host only.
  The token is 128 random bits per site. Ownership is re-checked at the start of every scan; if it fails twice in a row (24 hours apart at least), scans stop and you get one alert.
- **SSRF protection** (see "Security"): every fetch is to a verified host over `https:`, redirects are followed by hand and checked hop by hop, no IP literals, no private names.
- **Pages:** per site, the home page plus up to 19 more paths you list (20 pages a scan). Optional discovery of up to 20 paths from the sitemap (Should).
- **Checks** (all from static HTML and headers, parsed with `HTMLRewriter`):

| Check id | What it reports | Default severity |
|---|---|---|
| `third-party.tracker` | A known tracker or ad host loaded by `<script src>`, `<img>`, `<iframe>`, `<link>` or found in an inline script snippet (`gtag(`, `fbq(`, `_paq.push`, `hj(`) | high |
| `third-party.tag-manager` | A tag manager (Google Tag Manager, Segment, Tealium); "may load more trackers this tool can't see" | high |
| `third-party.ip-leak` | Fonts, CDNs, embeds (`fonts.googleapis.com`, `fonts.gstatic.com`, `cdnjs`, `jsdelivr`, YouTube/Vimeo/Maps iframes) that receive the visitor's IP | medium |
| `third-party.other` | Any other host not in your site's own host list | info |
| `third-party.consent-gated` | A tracker tag marked for a consent manager (`type="text/plain"` with `data-category`/`data-cookiecategory`/`data-cookieconsent`), reported separately and lower | info |
| `cookie.pre-consent` | `Set-Cookie` on a first visit with no cookies sent; names matched against a list (`_ga`, `_fbp`, `_gcl_au`, ...) are high, known necessary ones (`__cf_bm`, `cf_clearance`, `csrf*`, session names you list) are info, the rest medium | high / medium / info |
| `cookie.attributes` | Cookie without `Secure` on https, or without `SameSite`, or with a lifetime over 13 months | low |
| `policy.privacy-missing` | No link whose text or path matches the privacy-policy patterns (English, German, French, Spanish, Italian, Dutch, Portuguese) on the home page, or it doesn't load (not 2xx after redirects) | high |
| `policy.imprint-missing` | Same, for an imprint (`Impressum`, `Legal notice`, `Mentions légales`); only when the site sets `imprint: true` | medium |
| `header.hsts` | Missing, `max-age` under 15,552,000 (180 days), or present on `http:` only | medium |
| `header.referrer-policy` | Missing (browsers default to `strict-origin-when-cross-origin`, so low), or `unsafe-url` / `no-referrer-when-downgrade` (medium) | low / medium |
| `header.permissions-policy` | Missing | low |
| `header.csp` | Missing; or present with `unsafe-inline`/`unsafe-eval` in `script-src`; or no `frame-ancestors` and no `X-Frame-Options` | low |
| `header.nosniff` | `X-Content-Type-Options: nosniff` missing | info |
| `mixed-content` | `http:` subresources on an `https:` page; active (script, iframe, stylesheet, form) high, passive (img, media) medium | high / medium |
| `form.insecure` | `<form action>` on `http:`, or a page with `<input type=password>` served over `http:` | high |
| `form.third-party` | `<form action>` on another company's host (reported with the host; often fine, for example a newsletter provider, but it means that company gets the data) | medium |
| `email.exposed` | Email addresses in page text (not `mailto:`) | low |
| `email.mailto` | `mailto:` links | info |
| `robots.sensitive` | `Disallow:` lines in `robots.txt` that name paths matching `admin`, `staging`, `backup`, `private`, `internal`, `.git`, `.env`, `test`, `old`, `dev` (robots.txt is public; it advertises those paths) | low |
| `sitemap.sensitive` | Sitemap URLs on another host, or matching the same patterns | medium |

- **Each finding** has a stable key (hash of check id, page path and subject, such as the host or cookie name), a severity, the page, a short evidence snippet (at most 200 characters, emails masked as `j***@example.com`), and a "why this often matters" line with a link to a public source. The full HTML is never stored.
- **Scheduled re-check** per site (default daily, minimum every 6 hours), run by one Durable Object alarm. **No cron trigger** (the account's 5 are used by other Perchlight tools, as perchlight-forms' ADR 0001 records).
- **Alerts on change** compared with the previous completed scan: new findings at or above the alert level (default `medium`), findings resolved, verification lost, a scan that couldn't run. One alert per site per scan. Email (`send_email` to verified addresses) and Discord, Slack, ntfy and signed JSON webhooks, as perchlight-hooks.
- **Report page:** `GET /r/<site id>` server-rendered HTML, no JavaScript, behind the admin token or a per-site share link (decision 4). It passes this tool's own header checks.
- **JSON API** behind `ADMIN_TOKEN` (see "API").
- **Not-legal-advice** text on the report page, in the JSON (`"disclaimer"`), in every alert footer and the README.
- **Its own footprint stated in numbers** (see "Footprint"); `GET /api/footprint` shows counted use.
- **Desktop app screens** in `perchlight/perchlight.json`.
- Deploy to Cloudflare button, `npm test` (vitest with `@cloudflare/vitest-pool-workers`), README, MIT licence, no runtime dependencies, graphify on creation, GitHub Actions CI on the free tier.

### Should have

- **Sitemap discovery:** `discover: 10` adds up to that many paths from the sitemap (first sitemap only, first 1 MB read), still capped at 20 pages a scan.
- **Same-origin stylesheets:** fetch up to 5 same-host CSS files per scan and look for `@import` and `@font-face url()` on third-party hosts (the usual way Google Fonts hides in a theme).
- **Manual scan** from the API or the app (at most one per site every 5 minutes).
- **Muting** a finding by key with a note ("YouTube embed reviewed, consent-gated on click"); muted findings show in the report but never alert.
- **`security.txt`** presence check (info).
- **An outgoing heartbeat** (`HEARTBEAT_URL`) after each Scanner run, as perchlight-hooks, so a perchlight-hooks heartbeat notices if this stops.

### Out of scope (v0.1), and why

- **A headless browser.** Cloudflare's Browser Rendering (now called Browser Run) is available on Workers Free with **10 minutes of browser time a day, 3 concurrent browsers, 1 new browser every 20 seconds, and REST API requests at 1 every 10 seconds** ([limits](https://developers.cloudflare.com/browser-rendering/platform/limits/), [pricing](https://developers.cloudflare.com/browser-rendering/platform/pricing/), checked 2026-11-12). That's enough for roughly 20 to 60 page loads a day, which is real but tight, and the useful path (watching network requests and `document.cookie` with Puppeteer) needs the `@cloudflare/puppeteer` dependency. Left for later (decision 1); finding records carry `source: "static"` so a `"browser"` source fits without a schema change.
- **Reading JavaScript bundles** for tracker hosts: large minified files, high CPU, many false positives.
- **Scanning sites you haven't verified**, or arbitrary URLs: that's a free SSRF and abuse tool on your account.
- **Checking the consent banner itself** (does "Reject" work, dark patterns, consent records). Needs a browser and clicking, and is a legal judgement.
- **A full crawl.** 20 pages a scan; pick the templates that matter (home, pricing, checkout, contact, blog post).
- **TLS details** (certificate expiry, ciphers): `fetch()` doesn't expose them. perchlight-status covers expiry checks if wanted.
- **Generating policies or banners**, legal verdicts, compliance scores or badges ("GDPR compliant" would be advice, and usually false comfort).
- **Accessibility, performance, SEO.**

## Technical design

### Pieces

```
You / scripts --> /api/* (ADMIN_TOKEN)         Worker (src/)
Browser ------> /r/<site> (token or share link)  - admin API, report page, /tick
Perchlight app --> D1 (direct reads)             - never fetches your sites itself
                                                 |
                                                 +--> D1: sites, scans, findings, mutes, deliveries, state
                                                 +--> Durable Object "Scanner" (SQLite, Free), one instance:
                                                        one alarm = next due scan or next chunk
                                                        --DoH--> cloudflare-dns.com (TXT check)
                                                        --fetch--> your verified hosts only
                                                        --> send_email / Discord / Slack / ntfy / JSON
```

- **Worker:** API, report page, `GET /tick` (re-arms the Scanner if its alarm is missing, as perchlight-hooks). Requests here are small D1 reads, designed for a few ms of CPU.
- **Scanner Durable Object** (one instance, named `scanner`): the only thing that fetches your sites, decides findings and sends alerts. One instance bounds Durable Object duration to at most 24 hours a day, inside the free GB-s (same reasoning as perchlight-hooks).
- **No KV, no R2, no Queues, no cron trigger.**

### Shared with the family (copied, not imported, with a comment naming the source)

| From | What |
|---|---|
| perchlight-forms `src/lib/budget.js` | per-invocation subrequest budget (45 of 50) |
| perchlight-forms `src/lib/deliveries.js` | claim-then-send, retries 1 / 5 / 30 min, 2 h, 12 h |
| perchlight-status `src/lib/notify.js` | Discord / Slack / ntfy / JSON formats and escaping |
| perchlight-status Checker / perchlight-hooks Scheduler | one alarm, set the next alarm first, hot state every run, lazy `ensureAlarm()` |
| perchlight-hooks `src/lib/ssrf.js` | IP-literal and private-name rules, manual redirects re-checked |
| perchlight-updates `admin.js` | `Authorization: Bearer <ADMIN_TOKEN>`, constant-time compare |

### Config

`privacy.json` in your copy of the repo (a push redeploys), checked by `npm test`. Sites can also be added through the API (stored only in D1).

```jsonc
{
  "sites": {
    "main": {
      "host": "example.com",
      "ownHosts": ["example.com", "www.example.com", "static.example.com"], // not "third party"
      "pages": ["/", "/pricing", "/contact", "/blog/hello-world", "/checkout"],
      "discover": 0,                 // Should: extra paths from the sitemap
      "every": "1d",                 // min "6h"
      "imprint": false,              // check for an imprint (Germany, Austria)
      "necessaryCookies": ["sid", "XSRF-TOKEN"],
      "alertLevel": "medium",        // "high" | "medium" | "low"
      "userAgent": "default"         // or "browser" (decision 7)
    }
  },
  "alerts": { "email": ["you@example.com"], "webhooks": ["discord-ops"] },
  "retention": { "scansPerSite": 30 }
}
```

Secrets: `ADMIN_TOKEN`, `ALERT_WEBHOOKS`, `WEBHOOK_SECRET`, `HEARTBEAT_URL` (optional). Limits checked: at most 10 sites, 20 pages a site.

### Ownership verification

1. `POST /api/sites` returns the token and both instructions.
2. `POST /api/sites/:id/verify` asks the Scanner to check (Worker never fetches):
   - **TXT:** `GET https://cloudflare-dns.com/dns-query?name=_perchlight-privacy.<domain>&type=TXT` with `accept: application/dns-json` (one subrequest). Any TXT string equal to `perchlight-privacy-verify=<token>` passes. The `<domain>` tried is the host, then each parent up to the registrable domain (at most 3 lookups; the public-suffix rule is a small bundled list of common multi-part suffixes such as `co.uk`, not the full list: see "Couldn't verify").
   - **File:** `GET https://<host>/.well-known/perchlight-privacy.txt`, no redirects followed, body (first 1 KB) trimmed must equal the token. Verifies that host only.
3. `verified_at`, `verify_method` and `verified_scope` (`domain` or `host`) are stored. Every scan re-checks first (1 to 3 subrequests).

Why both: TXT is the strong proof and covers subdomains; the file suits people whose DNS is elsewhere or who can't add records. A file proves control of the web server, not the domain, so it covers one host.

### Security (SSRF)

Every outgoing fetch goes through one function, `safeFetch(url, site)`:

- `https:` only; `http:` is allowed only for the single "does `http://` redirect to `https://`" check on the home page.
- The host must be the verified host, or a subdomain when verified by TXT. Also listed `ownHosts` must themselves be verified to be fetched (listing a host only stops it being called third party).
- No user info in the URL, no port other than 443 (80 for the redirect check).
- Not an IP literal; not `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa` (rules from perchlight-hooks).
- `redirect: "manual"`; up to 5 hops, each `Location` checked by the same rules. A redirect to an unverified host is **not followed** and becomes a finding (`redirect.offsite`, info) with the target host.
- Response bodies are read to 2 MB at most (stream cut after that, flagged `truncated`).
- Optional DNS check: the A/AAAA answers from DoH are checked against private ranges once per scan (1 to 2 subrequests). A Worker's `fetch()` runs on Cloudflare's network and can't reach your LAN anyway, but this stops a verified domain being pointed at internal addresses later. Recommended on (decision 3).
- No content from your pages is ever rendered as HTML in the report: evidence snippets are escaped text.

### Scanning

A **scan** is split into **chunks** so no single invocation is heavy:

| Chunk | Subrequests (budget 45) | Work |
|---|---|---|
| 1. Prepare | verify 1-3, DoH A/AAAA 2, `http://` home redirect 1, `robots.txt` 1, sitemap 1-2, D1 2 | ownership, robots and sitemap checks, page list |
| 2..n. Pages | up to 10 pages per chunk (each up to 5 redirect hops counted), D1 1 | fetch, parse, findings per page |
| last. Links | privacy/imprint link fetch 1-2, CSS up to 5 (Should), D1 2 | policy checks, diff with previous scan, alerts |

Each chunk is one alarm invocation; the next chunk is set 1 second later. A 20-page scan is about 4 alarm invocations and 30 to 40 subrequests in total. In-progress state (cursor, partial findings) lives in the Scanner's SQLite, so an eviction resumes rather than restarts; a scan not finished within 30 minutes is marked `failed: timed out` and the previous findings stay current.

**One page fetch:** `GET` with no cookies, `Accept-Language: en` (decision 7 for the UA), then:

- **Headers** (header checks, `Set-Cookie` via `headers.getAll("Set-Cookie")`, Workers' API for multiple cookies).
- **HTMLRewriter** handlers on `script`, `link`, `img`, `iframe`, `source`, `video`, `audio`, `embed`, `object`, `form`, `input[type=password]`, `a[href]`, `meta[http-equiv]`, plus text handlers on `script` (inline snippets, first 32 KB per script) and on body text for emails. Text arrives in chunks, so each handler buffers up to 1 KB across chunk boundaries for the regexes. The rewriter's output is discarded (`await new HTMLRewriter().on(...).transform(res).arrayBuffer()`, or consumed to the 2 MB cap).
- `srcset` is split; relative URLs are resolved against `<base href>` or the page URL.
- Hosts are classified by the bundled `trackers.json` (see "Tracker list"), else `ownHosts`, else `third-party.other`.

**CPU.** `HTMLRewriter` is a native streaming parser, so the heavy part runs outside JavaScript; the handlers do string checks and a few regexes. Expected tens of ms per page at most (not measured: see "Couldn't verify"). Chunks run in the Durable Object, whose CPU limit is 30 s per invocation by default ([DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/)); a probe on this account found 255 ms and 1,026 ms invocations completed (perchlight-hooks, measured 2026-11-11). The design still bounds work: 10 pages a chunk, 2 MB a page, 32 KB per inline script, 1 MB of sitemap. The Worker's own request paths stay around the Free plan's 10 ms.

**First visit only.** No cookies are ever sent, so every `Set-Cookie` is "before consent". Cookies from the first page are not carried to later pages (each page is a first visit), so per-page cookies are attributed to the page that set them.

### Tracker list

`src/data/trackers.json`, written for this project (MIT): about 150 hosts with company, category (`analytics`, `ads`, `social`, `session-replay`, `tag-manager`, `fonts`, `cdn`, `embed`, `consent`) and the inline snippet patterns. Hand-written rather than copied, because the large public lists carry licences that may not fit (DuckDuckGo Tracker Radar's and Disconnect's licences weren't confirmed for this draft) (decision 2). Consent managers (`consent` category) aren't findings; their presence is shown on the report ("Consent manager found: Cookiebot") because it changes how to read the other findings.

### Change detection and alerts

- At the end of a scan, its finding keys are compared with the last **completed** scan's: `new`, `resolved`, `unchanged`. A failed or partial scan is never compared against (it would look like many "resolved").
- **Flapping:** a finding is only reported `resolved` after it's absent from 2 completed scans in a row, so a page that times out once doesn't produce "resolved" then "new".
- **One alert per site per scan** with all changes at or above `alertLevel`, muted keys left out: "perchlight-privacy: example.com, 2 new, 1 resolved. NEW (high): connect.facebook.net on /pricing (ad pixel, Meta). NEW (medium): fonts.googleapis.com on /blog/hello-world. RESOLVED: Referrer-Policy now set." Links to the report page, never evidence snippets with emails.
- Also alerted: verification lost (once), scan failing twice in a row (once), recovery.
- Claim-then-send in the Scanner's SQLite, retries as perchlight-hooks. Every alert ends with "Automated check, not legal advice."

### API

`Authorization: Bearer <ADMIN_TOKEN>`.

| Endpoint | What |
|---|---|
| `GET /api/sites` · `POST /api/sites` · `PATCH/DELETE /api/sites/:id` | Sites (config sites can be paused, not deleted). `POST` returns the verification token and instructions. |
| `POST /api/sites/:id/verify` | Check ownership now; returns the result and what was found. |
| `POST /api/sites/:id/scan` | Manual scan (429 within 5 minutes of the last). |
| `GET /api/sites/:id/report.json` | Latest completed scan: site, scan time, pages, findings by severity, changes since the previous scan, `disclaimer`. Stable shape, versioned `"schema": 1`. |
| `GET /api/scans?site=` · `GET /api/scans/:id` | History and one scan's findings. |
| `POST /api/findings/:key/mute` · `DELETE …/mute` | Mute with a note. |
| `POST /api/sites/:id/share` · `DELETE …/share` | Create or revoke a share link (decision 4). |
| `GET /api/deliveries?status=failed` · `POST /api/test-alert` · `GET /api/footprint` | Alerts and use. |
| `GET /r/:site` | HTML report (admin token as a header or cookie set from a login form, or `?s=<share token>`). |
| `GET /tick` · `GET /` | Re-arm alarm · plain-text name. |

The report page sends `Content-Security-Policy: default-src 'none'; style-src 'self'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and sets no cookies unless you log in.

### Data model (D1)

- `sites`: `id`, `host`, `source` (`config` | `api`), `own_hosts` (JSON), `pages` (JSON), `settings` (JSON), `verify_token`, `verify_method`, `verified_scope`, `verified_at`, `verify_failures`, `state` (`unverified` | `active` | `paused` | `verification_lost`), `every_s`, `next_scan_at`, `last_scan_id`, `share_token_hash`.
- `scans`: `id`, `site_id`, `trigger` (`schedule` | `manual`), `started_at`, `finished_at`, `status` (`running` | `done` | `partial` | `failed`), `pages_ok`, `pages_failed`, `subrequests`, `high`, `medium`, `low`, `info`, `new_count`, `resolved_count`, `error`. Index `(site_id, id)`.
- `findings`: `scan_id`, `site_id`, `key`, `check_id`, `severity`, `page`, `subject` (host, cookie or header name), `evidence` (≤ 200 chars, masked), `source` (`static`), `first_seen_at`. Primary key `(scan_id, key)`.
- `mutes`: `site_id`, `key`, `note`, `at`.
- `deliveries`: as perchlight-forms, kinds `changes` | `verification_lost` | `scan_failing` | `recovered`.
- `state`: housekeeping times, footprint counters per day.

**Scanner SQLite:** `queue` (site, next_run_at), `cursor` (scan id, chunk, page index, partial findings), `claims` (alerts, 30 days), `run` (one row, written every run).

**Retention:** `scansPerSite` (default 30) completed scans and their findings; housekeeping deletes at most 2,000 rows a run.

### Desktop app screens (`perchlight/perchlight.json`)

- **Sites:** host, state, verified by, last scan, next scan, high / medium counts. Editable: paused, `every`.
- **Scans:** by site, newest first: status, pages, counts, new, resolved.
- **Findings:** latest scan by site, sorted by severity: check, page, subject, evidence, first seen. Action *Mute* through the API.
- **Failed alerts:** *Try again*.

### Footprint

Free limits: Workers 100,000 requests a day, 10 ms CPU, 50 subrequests per invocation ([Workers limits](https://developers.cloudflare.com/workers/platform/limits/), checked 2026-11-12); D1 100,000 rows written and 5,000,000 read a day, 500 MB per database, 50 queries per invocation ([D1 limits](https://developers.cloudflare.com/d1/platform/limits/)); Durable Objects 100,000 requests, 100,000 rows written and 13,000 GB-s a day ([DO pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/), as recorded in perchlight-hooks 2026-11-11). Rows written assume each insert or delete also writes one row per index.

**One 20-page scan:**

| | Count |
|---|---|
| Subrequests (all chunks) | ~35 (verify 3, DNS 2, robots 1, sitemap 1, pages 20, redirects ~3, policy 2, D1 ~8) |
| Durable Object alarm invocations | ~4 |
| D1 rows written (scan row, ~40 findings, later deleted, with index rows) | ~170 |
| DO rows written (cursor per chunk, alarm, claims) | ~12 |
| Worker requests | 0 |

**Example:** 3 sites, 20 pages each, daily scans, the report viewed 20 times a day.

| | Limit (Free) | Example | Share |
|---|---|---|---|
| Worker requests (reports, API, `/tick`) | 100,000/day | ~50 | < 0.1% |
| DO requests (alarms) | 100,000/day | ~15 | < 0.1% |
| Subrequests per invocation (worst chunk) | 50 | ≤ 45 (budgeted) | ≤ 90% |
| D1 rows written | 100,000/day | ~520 | 0.5% |
| DO rows written | 100,000/day | ~40 | < 0.1% |
| D1 storage (30 scans × 3 sites × ~40 findings × ~0.5 KB) | 500 MB | ~2 MB | 0.4% |
| DO duration (4 short runs a scan) | 13,000 GB-s/day | < 10 GB-s | < 0.1% |
| Browser Run | 10 min/day | 0 (not used) | 0% |

**At the limits the config allows** (10 sites, 20 pages, every 6 hours): 40 scans a day, ~6,800 D1 rows written (6.8%), ~1,400 page fetches a day on your own sites. This tool is cheap; the budget is never the constraint, the 50-subrequest chunk size is.

## Limitations (said plainly in the README and on every report)

- **JavaScript-added trackers aren't seen.** Pixels loaded by a tag manager, by a consent manager after "Accept", or by your app's bundle; cookies set by `document.cookie` (`_ga`, `_fbp` set by script). The tool reports the tag manager and says "may load more".
- **Single-page apps** that render everything in JavaScript look almost empty to it; findings will be few, and the report says "Little HTML found; this site may render in JavaScript".
- **Consent logic isn't tested.** A tracker found in the HTML may still be blocked by a consent manager at runtime; consent-gated markup is recognised only for the common `type="text/plain"` patterns.
- **Bot protection on your own zone** (Bot Fight Mode, challenges) may block the scanner: detected by `cf-mitigated: challenge` or a challenge page, reported as `scan.blocked` with how to allow it.
- **Geo and A/B differences:** it sees what Cloudflare's network gets from one location, not what an EU visitor gets.
- **It's a heuristic list.** Hosts not in `trackers.json` are "other third party", not "safe".
- **Not legal advice**, and no finding means "compliant".

## Edge cases

- **Verification token removed after verifying:** the next scan's check fails; one more failed check at least 24 hours later moves the site to `verification_lost` and scans stop, with one alert. Restored by `POST /verify`.
- **TXT on the parent domain, site on a subdomain:** found by walking up to 3 levels. Wildcard DNS doesn't matter: the record name is specific.
- **DoH unreachable:** verification is `unknown`, the scan is skipped (not counted as lost) and retried next schedule; two in a row alerts `scan_failing`.
- **Home page redirects to `www.`:** followed only if `www.` is verified (TXT on the domain covers it). Otherwise `redirect.offsite` and the scan is `partial`.
- **Page 404 or 5xx:** recorded on the scan (`pages_failed`), its previous findings are carried forward unchanged (not "resolved"), and the scan is `partial`.
- **2 MB cut:** findings from the part read; flagged on the page.
- **Huge `robots.txt` or sitemap index:** first 512 KB of robots, first sitemap file only (not every child of an index), first 1 MB.
- **Same host, many cookies with random suffixes** (`_ga_ABC123`): keys use a normalised name (`_ga_*`) so they don't count as new every scan.
- **Nonces and cache-busting query strings** in script URLs: subjects are host plus path without query, so a version bump isn't "new".
- **Email addresses in `<script>` JSON or obfuscated (`name [at] example.com`):** not reported (only plain text nodes and attribute values outside `href`).
- **A site served by a Worker on the same zone as this tool:** a Worker's `fetch()` to a Worker on the same zone may need a service binding ([Workers limits](https://developers.cloudflare.com/workers/platform/limits/)); recommended deploy is on `workers.dev`. Not confirmed for every routing setup (see "Couldn't verify").
- **Alarm runs twice** (alarms are at least once): the chunk cursor and alert claims make it idempotent; a page may be fetched twice, which is harmless.
- **Clock between scans changes `every`:** next scan recomputed from the last start.
- **Deleting a site mid-scan:** the cursor is dropped at the next chunk; no alert.

## Testing

- **Unit:** each check against fixture HTML and header sets (including chunked text across boundaries, `srcset`, `<base>`, protocol-relative URLs, uppercase tags, inline `gtag`/`fbq` snippets, consent-gated `type="text/plain"`); cookie classification and name normalisation; policy link patterns per language; HSTS/CSP/Referrer parsing; mixed-content active vs passive; email regex and masking; robots and sitemap patterns; finding keys stable across query strings; diff with the 2-scan resolve rule; SSRF rules (every rule from perchlight-hooks plus "host not verified", "subdomain under file verification", redirect to unverified host); TXT parsing of quoted and split strings.
- **Integration** (`@cloudflare/vitest-pool-workers`, local D1 and Scanner, fake sites served by the test): verify by TXT (fake DoH) and file; a 20-page scan split into chunks within 45 subrequests each; eviction mid-scan resumes; partial scan not compared; one alert per scan, none for muted keys; verification lost after two failures; report page headers and escaping (a page containing `<script>` in evidence stays text); footprint counters.
- **Locally with `wrangler dev`** (free): scan a local fixture site with known trackers and headers.
- **With your real account (free):** verify and scan a test site on a free `workers.dev` or Pages domain with a Google Font, a Meta pixel snippet (not activated), a GTM container and a `Set-Cookie`. Confirm `headers.getAll("Set-Cookie")`, DoH from a DO, same-zone behaviour, real CPU per page, real rows written.
- **Not tested** (costs money): Browser Run beyond the free 10 minutes, paid consent managers, Workers Paid.

## Decisions (all decided 2026-11-12, as recommended)

1. **Browser Run "deep check": decided, not in v0.1.** Ship the static checker; findings keep `source` (`"static"`) so an opt-in weekly deep check of the home page with Browser Run's free 10 minutes a day fits in v0.2 without a schema change.
2. **Tracker list: decided, our own.** A small MIT list written for this project (`src/data/trackers.json`, about 180 hosts that matter to small sites) with an "other third party" catch-all. A larger public list only after confirming its licence allows redistribution in an MIT repo.
3. **DNS answers checked for private addresses: decided, yes, every scan.** A and AAAA over DoH the first time a host is fetched in a scan (2 subrequests); a private, loopback, link-local or otherwise internal answer refuses the host.
4. **Report page access: decided, admin only by default,** plus an optional per-site share link (128-bit random token, stored as SHA-256, revocable).
5. **What alerts: decided.** New findings at `medium` or above (`alertLevel`), resolved findings, verification lost, two failed scans in a row (and recovery). `info` never alerts; `low` only when `alertLevel` is lowered.
6. **Imprint check: decided, off by default;** `imprint: true` per site.
7. **User-Agent: decided, browser-like by default** with an `X-Perchlight-Privacy: <hash of the site token>` header to recognise and allow it in WAF rules; the honest UA (`perchlight-privacy/0.1 (+repo URL)`) is the `userAgent: "honest"` setting.
8. **Pages: decided, listed** (home always included) in v0.1; sitemap discovery as a Should (`discover`), capped at 20 pages a scan.
9. **Minimum interval: decided, 6 hours.**
10. **Page HTML: decided, never stored.** Findings and 200-character evidence (emails masked) only.

### Implementation notes for v0.1 (where the code refines this document)

- **Change tracking lives in the Scanner's SQLite** (a `tracked` table: one row per open finding key per site, with a "missing" count), not in D1. The diff, the alert claim and the end of the scan commit in one storage transaction, so a repeated alarm can't alert twice. D1 `findings` still holds every kept scan's findings for the report and the app.
- **`sites.state` is `unverified | active | verification_lost`**, with pausing as a separate `paused` column (editable in the app as a boolean). D1 also has `verified_name` (the domain or host the proof covers), `verify_failed_ms`, `config_error` and denormalised `last_scan_at` / `last_status` / `high` / `medium` for the app; `scans` has `notes` (pages, consent managers, little-HTML) and `changes`; `findings` has `carried`.
- **Header checks run on the home page only** (one set of header findings per site, not 20).
- **A form posting to `http:` is `form.insecure` only,** not also `mixed-content`, so one problem is one finding.
- **Third-party subjects are the host** (one finding per host per page); mixed-content subjects are host + path without the query.
- **Status:** a scan where no page answered at all is `failed`; one where some pages answered with an error, a challenge or an unverified redirect is `partial` (with those findings) and still counts towards "failing twice in a row".
- **The http:// redirect check** is reported under `header.hsts` (subject `http-redirect`), and `security.txt` as `security-txt.missing` (info).
- **The desktop app's Findings screen** reads a `latest_findings` view; muting is through the API (the v1 app schema has no API action).

## Acceptance criteria

- An unverified site can't be scanned: `POST /scan` returns `409 unverified` and no request reaches the host.
- A site verified by TXT on `example.com` scans `www.example.com`; one verified by file on `www.example.com` doesn't fetch `shop.example.com` and reports `redirect.offsite` if redirected there.
- Pages listing `http://127.0.0.1`, `https://10.0.0.5`, `https://[::1]`, `https://localhost`, or a verified host redirecting to `169.254.169.254` are refused or not followed, with a clear message.
- A fixture page with a Google Fonts `<link>`, a `connect.facebook.net` script, an inline `gtag(` snippet, a GTM container, an `http:` image, a form posting to `http:`, a plain-text email and `Set-Cookie: _ga=…` produces exactly the matching findings at the stated severities; the same tracker with `type="text/plain" data-category="marketing"` produces only `third-party.consent-gated`.
- A home page without a privacy-policy link produces `policy.privacy-missing`; adding a footer link "Datenschutz" to a page that returns 200 clears it on the next scan.
- Missing HSTS, Referrer-Policy and Permissions-Policy are each reported; setting them clears them.
- A 20-page scan completes in ≤ 5 alarm invocations, none using more than 45 subrequests.
- Adding a new third-party script to one page sends exactly one alert naming it; removing it sends "resolved" only after 2 completed scans without it; a muted finding never alerts.
- A scan where 3 pages time out is `partial` and produces no "resolved" for those pages.
- No cron trigger in `wrangler.jsonc`; a stopped alarm is re-armed by `/tick` or any API request.
- The report page and JSON include the not-legal-advice text; the report page passes its own header checks and renders `<script>` in evidence as text.
- `GET /api/footprint` after a day of the example (3 sites, 20 pages, daily) shows under 1,000 D1 rows written.

## Couldn't verify (2026-11-12)

- Whether a Durable Object alarm invocation has the same 50-subrequest limit as a Worker request (assumed yes), and whether D1 calls count toward it (assumed yes, as perchlight-forms).
- Real CPU time of `HTMLRewriter` with these handlers per MB of HTML on Workers Free.
- `headers.getAll("Set-Cookie")` on `fetch()` responses (documented for `Headers` in Workers; not tested on responses) versus `getSetCookie()`.
- DNS-over-HTTPS to `cloudflare-dns.com` from a Worker or Durable Object (expected to work; not tested).
- Same-zone `fetch()` from this Worker to a site served by another Worker or Pages project on the same zone.
- Licences of DuckDuckGo Tracker Radar and Disconnect's tracker list for inclusion in an MIT repo.
- A full public-suffix rule without bundling the whole list (a short list of common multi-part suffixes is assumed enough).
- Whether Browser Run's REST "quick actions" expose the page's network requests (which would allow a deep check without Puppeteer).
- `send_email` daily limits to verified addresses; whether D1 index updates count as extra rows written.
- Current prices of Cookiebot, CookieYes, Usercentrics and similar scanners.

## Sources

- Browser Run (Browser Rendering) limits and pricing (Free: 10 minutes/day, 3 concurrent browsers, 1 new browser per 20 s, REST 1 request per 10 s; Paid: 10 hours/month then $0.09/hour): https://developers.cloudflare.com/browser-rendering/platform/limits/ · https://developers.cloudflare.com/browser-rendering/platform/pricing/ (checked 2026-11-12)
- Workers limits (Free: 100,000 requests/day, 10 ms CPU per HTTP request, 50 subrequests, 6 simultaneous connections, 128 MB): https://developers.cloudflare.com/workers/platform/limits/ (checked 2026-11-12)
- Workers `Request` (`redirect: "manual"` supported, `"error"` not; `getAll()` for `Set-Cookie`): https://developers.cloudflare.com/workers/runtime-apis/request/
- D1 limits (Free: 10 databases, 500 MB each, 50 queries per invocation, 2 MB rows): https://developers.cloudflare.com/d1/platform/limits/ (checked 2026-11-12)
- Durable Objects limits, pricing and alarms: as cited in `../perchlight-hooks/docs/SDD.md` (checked 2026-11-11)
- Cron trigger budget: `../perchlight-forms/docs/adr/0001-lazy-housekeeping-no-cron.md`
