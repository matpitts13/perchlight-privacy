# Changelog

## v0.1.0

The first release of perchlight-privacy: a free, self-hosted privacy and compliance checker for websites you own, on your own Cloudflare account (Workers + D1 + one Durable Object).

**Set up** with `npm run deploy`. See the [README](https://github.com/matpitts13/perchlight-privacy#readme).

### What's in it

- **Prove you own the site first:** a DNS TXT record (covers the domain and its subdomains) or a `/.well-known/` file (covers one host). Ownership is re-checked before every scan.
- **Locked-down fetching:** https only, verified hosts only, no IP addresses or private names, private DNS answers rejected, and redirects checked one hop at a time. Your copy can't be used to probe other people's sites.
- **Twenty checks** rated high, medium, low or info. They cover trackers and ad pixels, cookies set before consent, privacy and security headers, mixed content, forms posting insecurely or to third parties, exposed email addresses, privacy policy links, and an optional legal-contact (imprint) check.
- **Consent-aware:** a tracker tagged for a consent manager is reported apart, at lower severity. A tag manager gets "may load more trackers this tool can't see".
- **Scheduled re-checks on a Durable Object alarm,** so it doesn't use one of your account's 5 cron triggers. Scans run in chunks inside the free subrequest limit, at most every 6 hours.
- **Alerts only on change:** new medium-or-higher findings, resolved findings (after two clean scans in a row), lost verification, and two failed scans in a row. Failed or partial scans are never compared against.
- **A private report page** with an optional share link, plus a JSON API and screens for the [Perchlight](https://github.com/matpitts13/perchlight) desktop app.
- **Page HTML is never stored.**

### Honest limits

It reads pages the way a simple downloader does, so trackers that scripts add later aren't visible. This is not legal advice.

### Tested, and not tested

117 automated tests run against a real local D1 and Durable Object. Outbound fetches are faked, so no test touches a real site.

Not tested: deploying on a real account, DNS-over-HTTPS from a Durable Object, reading cookies from real responses, real CPU per page, how subrequests are counted for D1 calls and redirects, real email and webhook delivery, and Cloudflare's paid real-browser rendering.
