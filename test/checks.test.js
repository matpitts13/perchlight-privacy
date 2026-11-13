import { describe, it, expect } from "vitest";
import { parseHtml, splitSrcset } from "../src/lib/parse.js";
import { pageFindings, headerFindings, cookieFindings, normalizeCookieName, classifyCookie, robotsFindings, sitemapFindings, cssFindings, isBlocked } from "../src/lib/checks.js";
import { maskEmails, evidence, withKeys, findingKey } from "../src/lib/findings.js";
import { classify } from "../src/lib/trackers.js";
import { GOOD_HEADERS } from "./helpers.js";
import { ACCEPTANCE_HTML } from "./fixtures.js";

const enc = (s) => new TextEncoder().encode(s);
const own = new Set(["example.com", "www.example.com"]);

async function page(html, { url = "https://example.com/", isHome = true, path = "/" } = {}) {
  const obs = await parseHtml(enc(html));
  return pageFindings(obs, { pageUrl: url, page: path, own, isHome });
}
const pairs = (fs) => [...new Set(fs.map((f) => `${f.check}|${f.subject}|${f.severity}`))].sort();

describe("the acceptance fixture page", () => {
  it("produces exactly the matching findings at the stated severities", async () => {
    const r = await page(ACCEPTANCE_HTML);
    expect(pairs(r.findings)).toEqual(
      [
        "third-party.ip-leak|fonts.googleapis.com|medium",
        "third-party.tracker|connect.facebook.net|high",
        "third-party.tracker|google-analytics.com|high",
        "third-party.tag-manager|googletagmanager.com|high",
        "mixed-content|example.com/logo.png|medium",
        "form.insecure|example.com/subscribe|high",
        "email.exposed|jane.doe@example.com|low",
      ].sort(),
    );
    const cookies = cookieFindings(["_ga=GA1.1.123.456; Path=/; Max-Age=31536000; Secure; SameSite=Lax"], { page: "/", necessary: [] });
    expect(pairs(cookies)).toEqual(["cookie.pre-consent|_ga|high"]);
    expect(headerFindings(new Headers(GOOD_HEADERS), { httpCheck: { checked: true, toHttps: true } })).toEqual([]);
    expect(r.policy.privacy).toEqual(["https://example.com/privacy"]);
  });

  it("the same tracker marked for a consent manager is only consent-gated", async () => {
    const r = await page(`<script type="text/plain" data-category="marketing" src="https://connect.facebook.net/en_US/fbevents.js"></script>
      <script type="text/plain" data-cookiecategory="analytics">gtag('config','G-1')</script>
      <iframe data-cookieconsent="marketing" type="text/plain" src="https://www.youtube.com/embed/x"></iframe>`);
    expect(pairs(r.findings)).toEqual(["third-party.consent-gated|connect.facebook.net|info", "third-party.consent-gated|google-analytics.com|info", "third-party.consent-gated|www.youtube.com|info"]);
  });

  it("text/plain without a consent category is still reported normally", async () => {
    const r = await page(`<script type="text/plain" src="https://connect.facebook.net/x.js"></script>`);
    expect(pairs(r.findings)).toEqual(["third-party.tracker|connect.facebook.net|high"]);
  });
});

describe("parsing", () => {
  it("srcset, <base>, protocol-relative URLs, uppercase tags", async () => {
    const r = await page(`<HEAD><BASE HREF="https://cdn.example.com/assets/"></HEAD><BODY>
      <IMG SRC="a.png" SRCSET="https://images.thirdparty.io/a-1x.png 1x, https://other-images.net/a-2x.png 2x">
      <SCRIPT SRC="//cdnjs.cloudflare.com/ajax/libs/x.js"></SCRIPT>
      <picture><source srcset="https://img.cdn-x.org/p.webp 480w, /local.webp 800w"></picture></BODY>`);
    expect(pairs(r.findings)).toEqual(
      [
        "third-party.other|cdn.example.com|info",
        "third-party.other|images.thirdparty.io|info",
        "third-party.other|other-images.net|info",
        "third-party.ip-leak|cdnjs.cloudflare.com|medium",
        "third-party.other|img.cdn-x.org|info",
      ].sort(),
    );
  });

  it("splits srcset", () => {
    expect(splitSrcset("a.jpg 1x, b.jpg 2x")).toEqual(["a.jpg", "b.jpg"]);
    expect(splitSrcset("https://x/a.jpg 480w,https://x/c.jpg 800w")).toEqual(["https://x/a.jpg", "https://x/c.jpg"]);
  });

  it("inline snippets: fbq, _paq.push, hj; a tracker found by src isn't counted twice", async () => {
    const r = await page(`<script src="https://connect.facebook.net/en_US/fbevents.js"></script>
      <script>fbq('init','123');fbq('track','PageView');</script>
      <script>var _paq=window._paq||[];_paq.push(['trackPageView']);</script>
      <script>(function(h,o,t,j,a,r){h.hj=h.hj||function(){};hj('identify')})(window,document)</script>
      <script type="application/ld+json">{"x":"fbq("}</script>`);
    expect(pairs(r.findings)).toEqual(["third-party.tracker|connect.facebook.net|high", "third-party.tracker|matomo.cloud|high", "third-party.tracker|static.hotjar.com|high"]);
  });

  it("finds a snippet split across text chunks (a large inline script)", async () => {
    const pad = "/* " + "x".repeat(20000) + " */";
    const r = await page(`<script>${pad} gtag('config','G-1'); ${pad}</script>`);
    expect(pairs(r.findings)).toEqual(["third-party.tracker|google-analytics.com|high"]);
  });

  it("emails: plain text reported (masked), mailto separate, script JSON and obfuscated not reported", async () => {
    const long = "word ".repeat(3000);
    const r = await page(`<p>${long} contact sales@example.com today ${long}</p>
      <a href="mailto:Help@Example.com?subject=hi">Help@Example.com</a>
      <script>var x = {"email":"hidden@example.com"}</script>
      <p>name [at] example.com</p>`);
    const fs = r.findings;
    expect(pairs(fs)).toEqual(["email.exposed|sales@example.com|low", "email.mailto|help@example.com|info"]);
    for (const f of fs) expect(f.evidence).not.toMatch(/sales@|help@/);
    expect(fs.find((f) => f.check === "email.exposed").evidence).toContain("s***@example.com");
  });

  it("forms: third-party action, password field; JSON-LD and data: URLs ignored", async () => {
    const r = await page(`<form action="https://example.us21.list-manage.com/subscribe/post"><input type="email"></form>
      <form><input type="PASSWORD"></form><img src="data:image/png;base64,AAAA">`);
    expect(pairs(r.findings)).toEqual(["form.third-party|example.us21.list-manage.com|medium"]);
    const http = await page(`<form><input type="password"></form>`, { url: "http://example.com/login" });
    expect(pairs(http.findings)).toContain("form.insecure|password-over-http|high");
  });

  it("mixed content: active is high, passive medium", async () => {
    const r = await page(`<script src="http://example.com/a.js"></script><iframe src="http://example.com/f"></iframe><link rel="stylesheet" href="http://example.com/s.css"><video src="http://example.com/v.mp4"></video>`);
    expect(pairs(r.findings)).toEqual(["mixed-content|example.com/a.js|high", "mixed-content|example.com/f|high", "mixed-content|example.com/s.css|high", "mixed-content|example.com/v.mp4|medium"].sort());
  });

  it("privacy and imprint links in each language, by text or path", async () => {
    for (const [html, kind] of [
      ['<a href="/x">Datenschutzerklärung</a>', "privacy"],
      ['<a href="/x">Politique de confidentialité</a>', "privacy"],
      ['<a href="/x">Política de privacidad</a>', "privacy"],
      ['<a href="/x">Informativa sulla privacy</a>', "privacy"],
      ['<a href="/x">Privacybeleid</a>', "privacy"],
      ['<a href="/x">Política de Privacidade</a>', "privacy"],
      ['<a href="/legal/datenschutz">Rechtliches</a>', "privacy"],
      ['<a href="/x">Impressum</a>', "imprint"],
      ['<a href="/x">Mentions l&eacute;gales</a>', "imprint"],
      ['<a href="/x">Legal notice</a>', "imprint"],
    ]) {
      const r = await page(html);
      expect(r.policy[kind], html).toHaveLength(1);
    }
    const none = await page('<a href="/about">About</a>');
    expect(none.policy.privacy).toEqual([]);
  });

  it("keeps no HTML: observations are URLs, short link text and capped inline scripts", async () => {
    const obs = await parseHtml(enc(`<script>${"y".repeat(50000)}</script><a href="/a">${"t".repeat(500)}</a>`));
    expect(obs.inlineScripts[0].text.length).toBe(32 * 1024);
    expect(obs.links[0].text.length).toBeLessThanOrEqual(200);
  });
});

describe("headers", () => {
  const h = (o) => new Headers(o);
  it("missing HSTS, Referrer-Policy, Permissions-Policy, CSP, nosniff are each reported", () => {
    expect(pairs(headerFindings(h({})))).toEqual(
      [
        "header.hsts|Strict-Transport-Security|medium",
        "header.referrer-policy|Referrer-Policy|low",
        "header.permissions-policy|Permissions-Policy|low",
        "header.csp|Content-Security-Policy|low",
        "header.csp|frame-ancestors|low",
        "header.nosniff|X-Content-Type-Options|info",
      ].sort(),
    );
  });
  it("HSTS under 180 days; http not redirecting; HSTS on http only", () => {
    const f = headerFindings(h({ ...GOOD_HEADERS, "Strict-Transport-Security": "max-age=86400" }), { httpCheck: { checked: true, toHttps: false, status: 200 } });
    expect(pairs(f)).toEqual(["header.hsts|Strict-Transport-Security|medium", "header.hsts|http-redirect|medium"]);
    const { "Strict-Transport-Security": _x, ...noHsts } = GOOD_HEADERS;
    expect(headerFindings(h(noHsts), { httpCheck: { checked: true, toHttps: true, hsts: true } })[0].evidence).toMatch(/http:\/\/ only/);
  });
  it("Referrer-Policy: unsafe-url medium; last valid token wins; meta referrer counts", () => {
    expect(pairs(headerFindings(h({ ...GOOD_HEADERS, "Referrer-Policy": "unsafe-url" })))).toEqual(["header.referrer-policy|Referrer-Policy|medium"]);
    expect(headerFindings(h({ ...GOOD_HEADERS, "Referrer-Policy": "unsafe-url, strict-origin" }))).toEqual([]);
    const { "Referrer-Policy": _r, ...noRp } = GOOD_HEADERS;
    expect(headerFindings(h(noRp), { metaReferrer: "no-referrer" })).toEqual([]);
  });
  it("CSP: unsafe-inline / unsafe-eval in script-src; nonces make unsafe-inline moot; X-Frame-Options instead of frame-ancestors", () => {
    expect(pairs(headerFindings(h({ ...GOOD_HEADERS, "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'" })))).toEqual(["header.csp|csp-script-src|low"]);
    expect(headerFindings(h({ ...GOOD_HEADERS, "Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'" }))).toEqual([]);
    expect(headerFindings(h({ ...GOOD_HEADERS, "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY" }))).toEqual([]);
  });
});

describe("cookies", () => {
  it("normalises random suffixes", () => {
    expect(normalizeCookieName("_ga_ABC123XYZ")).toBe("_ga_*");
    expect(normalizeCookieName("_hjSession_1234567")).toBe("_hjSession_*");
    expect(normalizeCookieName("sess_3f9a01bcde")).toBe("sess_*");
    expect(normalizeCookieName("sid")).toBe("sid");
  });
  it("tracking high, necessary info (built-in and listed), the rest medium", () => {
    expect(classifyCookie("_ga")).toBe("high");
    expect(classifyCookie("_ga_ABC123")).toBe("high");
    expect(classifyCookie("_fbp")).toBe("high");
    expect(classifyCookie("_gcl_au")).toBe("high");
    expect(classifyCookie("__cf_bm")).toBe("info");
    expect(classifyCookie("cf_clearance")).toBe("info");
    expect(classifyCookie("csrftoken")).toBe("info");
    expect(classifyCookie("sid", ["sid"])).toBe("info");
    expect(classifyCookie("prefs")).toBe("medium");
  });
  it("attributes: no Secure, no SameSite, over 13 months; values never in evidence", () => {
    const f = cookieFindings(["prefs=SECRETVALUE; Max-Age=63072000", "ok=1; Secure; SameSite=Lax; Max-Age=3600"], { page: "/p" });
    expect(pairs(f)).toEqual(["cookie.attributes|prefs|low", "cookie.pre-consent|ok|medium", "cookie.pre-consent|prefs|medium"]);
    expect(f.find((x) => x.check === "cookie.attributes").evidence).toMatch(/no Secure, no SameSite, lifetime 730 days/);
    for (const x of f) expect(x.evidence).not.toContain("SECRETVALUE");
  });
});

describe("robots.txt, sitemaps, CSS, bot protection", () => {
  it("robots: sensitive Disallow paths; Sitemap lines", () => {
    const r = robotsFindings("User-agent: *\nDisallow: /admin/\nDisallow: /blog/\nDisallow: /.git\nDisallow: /staging-2024/\nDisallow: /old/\n# Disallow: /private/\nSitemap: https://example.com/sm.xml\n");
    expect(r.findings.map((f) => f.subject)).toEqual(["/admin/", "/.git", "/staging-2024/", "/old/"]);
    expect(r.sitemaps).toEqual(["https://example.com/sm.xml"]);
  });
  it("sitemap: other hosts and sensitive paths; same-host paths for discovery", () => {
    const xml = `<urlset><url><loc>https://example.com/</loc></url><url><loc>https://example.com/pricing?x=1&amp;y=2</loc></url>
      <url><loc>https://staging.example.org/</loc></url><url><loc>https://example.com/backup/db.zip</loc></url></urlset>`;
    const r = sitemapFindings(xml, { host: "example.com", own, page: "/sitemap" });
    expect(pairs(r.findings)).toEqual(["sitemap.sensitive|/backup/db.zip|medium", "sitemap.sensitive|staging.example.org|medium"]);
    expect(r.paths).toEqual(["/", "/pricing?x=1&y=2", "/backup/db.zip"]);
  });
  it("CSS: @import and @font-face on third-party hosts (fonts hiding in a theme)", () => {
    const css = `@import url("https://fonts.googleapis.com/css2?family=Roboto");@font-face{font-family:x;src:url(https://fonts.gstatic.com/s/x.woff2) format("woff2")}
      .bg{background:url(https://images.other.net/bg.png)}@font-face{src:url(/fonts/local.woff2)}`;
    const f = cssFindings(css, "https://example.com/theme/style.css", { page: "/", own });
    expect(pairs(f)).toEqual(["third-party.ip-leak|fonts.googleapis.com|medium", "third-party.ip-leak|fonts.gstatic.com|medium"]);
    expect(f[0].evidence).toMatch(/via \/theme\/style\.css/);
  });
  it("bot protection: cf-mitigated or a challenge page", () => {
    expect(isBlocked(403, new Headers({ "cf-mitigated": "challenge" }), "")).toBe(true);
    expect(isBlocked(503, new Headers(), "<title>Just a moment...</title>")).toBe(true);
    expect(isBlocked(200, new Headers(), "Just a moment...")).toBe(false);
  });
});

describe("findings", () => {
  it("masks emails and caps evidence at 200 characters", () => {
    expect(maskEmails("mail john.smith@example.com or a@b.co")).toBe("mail j***@example.com or a***@b.co");
    expect(evidence("x".repeat(500))).toHaveLength(200);
  });
  it("keys are stable across query strings and nonces (subject is host or host+path)", async () => {
    const a = await page('<script src="https://connect.facebook.net/en_US/fbevents.js?v=1.2&nonce=abc"></script>');
    const b = await page('<script src="https://connect.facebook.net/en_US/fbevents.js?v=9.9"></script>');
    expect((await withKeys(a.findings))[0].key).toBe((await withKeys(b.findings))[0].key);
    const m1 = await page('<img src="http://example.com/a.png?cb=1">');
    const m2 = await page('<img src="http://example.com/a.png?cb=2">');
    expect(await findingKey(m1.findings[0])).toBe(await findingKey(m2.findings[0]));
    expect(await findingKey({ check: "x", page: "/", subject: "s" })).toMatch(/^[0-9a-f]{20}$/);
  });
  it("tracker classification: path entries win; subdomains match", () => {
    expect(classify("www.googletagmanager.com", "/gtag/js").category).toBe("analytics");
    expect(classify("www.googletagmanager.com", "/gtm.js").category).toBe("tag-manager");
    expect(classify("www.facebook.com", "/tr").category).toBe("ads");
    expect(classify("eu.cookiebot.com", "/").category).toBe("consent");
    expect(classify("unknown.example.org", "/")).toBeNull();
  });
  it("consent managers are noted, not findings", async () => {
    const r = await page('<script id="Cookiebot" src="https://consent.cookiebot.com/uc.js" data-cbid="x"></script>');
    expect(r.findings).toEqual([]);
    expect(r.consent).toEqual(["Cookiebot"]);
  });
});
