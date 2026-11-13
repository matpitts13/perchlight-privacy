// Raw MIME for the send_email binding: text + HTML, base64 bodies.
// Copied from perchlight-booking src/lib/mime.js (from perchlight-forms),
// without the calendar invite. Every header value has CR/LF removed and
// non-ASCII header text is RFC 2047 encoded, so nothing can start a new header.

const enc = new TextEncoder();

export function b64(s) {
  let bin = "";
  for (const b of enc.encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Removes line breaks and other control characters from a header value. */
export function headerSafe(s) {
  return String(s ?? "").replace(/[\x00-\x1f\x7f\u2028\u2029]+/g, " ").trim();
}

/** RFC 2047 encoded-words, only when the text isn't plain ASCII. */
export function encodeHeader(s) {
  const clean = headerSafe(s);
  if (/^[\x20-\x7e]*$/.test(clean)) return clean;
  const words = [];
  let chunk = "";
  for (const ch of clean) {
    if (enc.encode(chunk + ch).length > 45) {
      words.push(chunk);
      chunk = "";
    }
    chunk += ch;
  }
  if (chunk) words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${b64(w)}?=`).join("\r\n ");
}

/** "Name <a@b>" or "a@b" -> "a@b". */
export function addressOnly(a) {
  const m = /<([^>]+)>/.exec(String(a));
  return (m ? m[1] : String(a)).trim();
}

function addressHeader(a) {
  const s = headerSafe(a);
  const m = /^(.*?)\s*<([^<>\s]+)>$/.exec(s);
  if (!m) return s;
  const name = m[1].replace(/^"|"$/g, "").trim();
  if (!name) return `<${m[2]}>`;
  const shown = /^[\x20-\x7e]*$/.test(name) ? `"${name.replace(/["\\]/g, "")}"` : encodeHeader(name);
  return `${shown} <${m[2]}>`;
}

function body64(text) {
  return b64(text.replace(/\r?\n/g, "\r\n")).replace(/.{76}(?=.)/g, "$&\r\n");
}

function part(type, text) {
  return [`Content-Type: ${type}; charset=utf-8`, "Content-Transfer-Encoding: base64", "", body64(text)].join("\r\n");
}

export function mime({ from, to, subject, text, html, now = Date.now() }) {
  const domain = addressOnly(from).split("@")[1] ?? "localhost";
  const alt = `=_pl_a${crypto.randomUUID().replace(/-/g, "")}`;
  return [
    `From: ${addressHeader(from)}`,
    `To: ${addressHeader(to)}`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date(now).toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@${headerSafe(domain)}>`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${alt}"`,
    "",
    `--${alt}`,
    part("text/plain", text),
    `--${alt}`,
    part("text/html", html ?? ""),
    `--${alt}--`,
    "",
  ].join("\r\n");
}

/** Error text can quote the recipient; keep addresses out of logs and the database.
 *  (From perchlight-list src/lib/senders/common.js.) */
export function redactAddresses(text) {
  return String(text).replace(/[^\s@"'<>(),;:]+@[^\s@"'<>(),;:]+/g, "[address]");
}
