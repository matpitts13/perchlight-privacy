// One page's HTML -> raw observations, with HTMLRewriter (a native streaming
// parser; the handlers only collect attribute values and short text).
// Nothing here keeps the HTML: only URLs, link texts (200 chars), inline
// script text (first 32 KB per script, to look for tracker snippets) and
// email addresses found in text. The rewriter's output is discarded.
// URLs are resolved later, against <base href> or the page URL, because
// <base> may come after the first resource in a streaming parse.

export const INLINE_SCRIPT_MAX = 32 * 1024;
const LINK_TEXT_MAX = 200;
const EMAIL_RE = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}/g;
const CARRY = 256;

/** Consent-manager markup: type="text/plain" with a category attribute (Cookiebot, CookieYes, Klaro, OneTrust's optanon class...). */
function consentGated(el) {
  const type = (el.getAttribute("type") ?? "").trim().toLowerCase();
  if (type !== "text/plain") return false;
  return el.hasAttribute("data-category") || el.hasAttribute("data-cookiecategory") || el.hasAttribute("data-cookieconsent") || /\boptanon-category-/.test(el.getAttribute("class") ?? "");
}

const LOADING_RELS = /\b(stylesheet|preload|modulepreload|prefetch|preconnect|dns-prefetch|icon|manifest|apple-touch-icon)\b/i;

/** "a.jpg 1x, b.jpg 2x" -> ["a.jpg", "b.jpg"] */
export function splitSrcset(v) {
  return String(v ?? "")
    .split(/,\s+|,(?=[^\s,]+\s+\d)/)
    .map((p) => p.trim().split(/\s+/)[0])
    .filter(Boolean);
}

/**
 * @param {Uint8Array} bytes
 * @returns {Promise<object>} observations
 */
export async function parseHtml(bytes) {
  const obs = {
    base: null,
    resources: [], // { tag, kind: "active"|"passive"|"connect", url, gated }
    inlineScripts: [], // { text, gated }
    forms: [], // { action }
    hasPassword: false,
    links: [], // { href, text }
    emails: new Set(),
    metaReferrer: null,
    textChars: 0,
    elements: 0,
  };
  let script = null;
  let rawDepth = 0;
  let anchor = null;
  let carry = "";
  const add = (tag, kind, url, gated = false) => {
    if (url && !/^(data|blob|javascript|about|mailto|tel):/i.test(url.trim())) obs.resources.push({ tag, kind, url: url.trim(), gated });
  };
  const rewriter = new HTMLRewriter()
    .on("base[href]", {
      element(el) {
        if (obs.base === null) obs.base = el.getAttribute("href");
      },
    })
    .on("script", {
      element(el) {
        obs.elements++;
        const gated = consentGated(el);
        const src = el.getAttribute("src");
        if (src) add("script", "active", src, gated);
        const type = (el.getAttribute("type") ?? "").trim().toLowerCase();
        // JSON data blocks aren't code; templates aren't run.
        const isCode = !src && (type === "" || gated || /javascript|ecmascript|module/.test(type));
        script = isCode ? { text: "", gated } : null;
        rawDepth++;
        el.onEndTag(() => {
          rawDepth = Math.max(0, rawDepth - 1);
          if (script && script.text) obs.inlineScripts.push(script);
          script = null;
        });
      },
      text(t) {
        if (script && script.text.length < INLINE_SCRIPT_MAX) script.text += t.text.slice(0, INLINE_SCRIPT_MAX - script.text.length);
      },
    })
    .on("style", {
      element(el) {
        rawDepth++;
        el.onEndTag(() => {
          rawDepth = Math.max(0, rawDepth - 1);
        });
      },
    })
    .on("link[href]", {
      element(el) {
        obs.elements++;
        const rel = el.getAttribute("rel") ?? "";
        if (!LOADING_RELS.test(rel)) return;
        const isStyle = /\bstylesheet\b/i.test(rel);
        const before = obs.resources.length;
        add("link", isStyle ? "active" : /preconnect|dns-prefetch/i.test(rel) ? "connect" : "passive", el.getAttribute("href"));
        if (isStyle && obs.resources.length > before) obs.resources[before].stylesheet = true;
      },
    })
    .on("img", {
      element(el) {
        obs.elements++;
        add("img", "passive", el.getAttribute("src"));
        for (const u of splitSrcset(el.getAttribute("srcset"))) add("img", "passive", u);
      },
    })
    .on("source", {
      element(el) {
        add("source", "passive", el.getAttribute("src"));
        for (const u of splitSrcset(el.getAttribute("srcset"))) add("source", "passive", u);
      },
    })
    .on("video", {
      element(el) {
        add("video", "passive", el.getAttribute("src"));
        add("video", "passive", el.getAttribute("poster"));
      },
    })
    .on("audio", {
      element(el) {
        add("audio", "passive", el.getAttribute("src"));
      },
    })
    .on("iframe", {
      element(el) {
        obs.elements++;
        add("iframe", "active", el.getAttribute("src"), consentGated(el));
      },
    })
    .on("embed", {
      element(el) {
        add("embed", "active", el.getAttribute("src"));
      },
    })
    .on("object", {
      element(el) {
        add("object", "active", el.getAttribute("data"));
      },
    })
    .on("form", {
      element(el) {
        obs.elements++;
        obs.forms.push({ action: el.getAttribute("action") });
      },
    })
    .on("input[type]", {
      element(el) {
        if ((el.getAttribute("type") ?? "").trim().toLowerCase() === "password") obs.hasPassword = true;
      },
    })
    .on("a[href]", {
      element(el) {
        obs.elements++;
        anchor = { href: el.getAttribute("href").trim(), text: "" };
        obs.links.push(anchor);
        const title = el.getAttribute("title");
        if (title) anchor.text = title.slice(0, LINK_TEXT_MAX);
        el.onEndTag(() => {
          anchor = null;
        });
      },
      text(t) {
        if (anchor && anchor.text.length < LINK_TEXT_MAX) anchor.text = (anchor.text + t.text).slice(0, LINK_TEXT_MAX);
      },
    })
    .on("meta", {
      element(el) {
        const name = (el.getAttribute("name") ?? "").toLowerCase();
        if (name === "referrer") obs.metaReferrer = (el.getAttribute("content") ?? "").trim().toLowerCase();
        const content = el.getAttribute("content");
        if (content && content.includes("@") && name !== "referrer") scanEmails(content, true);
      },
    })
    .onDocument({
      text(t) {
        if (rawDepth > 0) return;
        obs.textChars += t.text.trim().length;
        // Text arrives in chunks: keep a short carry so an address split across chunks is found once.
        const buf = carry + t.text;
        scanEmails(buf, t.lastInTextNode);
        carry = t.lastInTextNode ? "" : buf.slice(-CARRY);
      },
    });

  function scanEmails(s, final) {
    if (!s.includes("@")) return;
    for (const m of s.matchAll(EMAIL_RE)) {
      // A match touching the end of a non-final chunk may continue in the next one.
      if (!final && m.index + m[0].length >= s.length) continue;
      obs.emails.add(m[0].toLowerCase());
    }
  }

  await rewriter.transform(new Response(bytes, { headers: { "Content-Type": "text/html; charset=utf-8" } })).arrayBuffer();
  // Entities in link text (&amp; etc.) are left raw by the rewriter; decode the common ones for matching.
  for (const l of obs.links) l.text = decodeEntities(l.text).replace(/\s+/g, " ").trim();
  return obs;
}

export function decodeEntities(s) {
  return String(s)
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Math.min(Number(n), 0x10ffff)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(Math.min(parseInt(n, 16), 0x10ffff)))
    .replace(/&(amp|lt|gt|quot|apos|nbsp|eacute|egrave|ecirc|agrave|ccedil|uuml|ouml|auml|oacute|iacute|aacute|ntilde|atilde|otilde);/gi, (m, n) =>
      ({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", eacute: "é", egrave: "è", ecirc: "ê", agrave: "à", ccedil: "ç", uuml: "ü", ouml: "ö", auml: "ä", oacute: "ó", iacute: "í", aacute: "á", ntilde: "ñ", atilde: "ã", otilde: "õ" })[n.toLowerCase()] ?? m,
    );
}

/** Resolves a raw attribute URL against the base and page URL; null when it isn't http(s). */
export function resolveUrl(raw, pageUrl, base) {
  let b = pageUrl;
  if (base) {
    try {
      b = new URL(base, pageUrl).toString();
    } catch {
      // ignore a broken <base>
    }
  }
  try {
    const u = new URL(raw, b);
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch {
    return null;
  }
}
