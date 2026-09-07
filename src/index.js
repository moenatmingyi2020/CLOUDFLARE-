// Cloudflare Worker version of index.php
// Deploy this file as a Cloudflare Worker.

const UPSTREAM_ORIGIN = "https://web.joegyi.uk";
const BASE64_SECRET = "joegyi_2026_super_secret";
const AUTH_SECRET_PREFIX = "joegyi_2026_auth_secret_";
const TELEGRAM_SECRET = "joegyi_2026";
const TOKEN_MAX_AGE = 600;

export default {
  async fetch(request) {
    return handleRequest(request);
  },
};

async function handleRequest(request) {
  const requestUrl = new URL(request.url);
  const path = requestUrl.pathname || "/";
  const pathParts = path.replace(/^\/+|\/+$/g, "").split("/");
  if (path === "/") pathParts.length = 0;

  let actualPath = path;
  let isValidBase64Token = false;
  let isBase64Expired = false;
  let isValidTelegramToken = false;
  let isValidAuthCookie = false;
  let shouldSetAuthCookie = false;

  // HTTP_HOST without the port, matching the PHP implementation.
  const currentHost = (request.headers.get("Host") || requestUrl.host).split(":")[0];
  const cookieName = `auth_${currentHost.replace(/\./g, "_")}`;
  const expectedAuthCookie = await hmacSha256Hex(
    "authorized",
    `${AUTH_SECRET_PREFIX}${currentHost}`,
  );

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  if (cookies[cookieName] && timingSafeEqual(cookies[cookieName], expectedAuthCookie)) {
    isValidAuthCookie = true;
  }

  // Validate the optional first path segment as a timestamp:secret Base64 token.
  if (pathParts.length >= 2) {
    const possibleToken = pathParts[0];
    const decoded = strictBase64Decode(possibleToken);

    if (decoded !== null && decoded.includes(":")) {
      const separator = decoded.indexOf(":");
      const tokenTimeText = decoded.slice(0, separator);
      const secret = decoded.slice(separator + 1);
      const tokenTime = phpInt(tokenTimeText);

      if (secret === BASE64_SECRET) {
        isValidBase64Token = true;
        pathParts.shift();
        actualPath = `/${pathParts.join("/")}`;

        if (Math.floor(Date.now() / 1000) - tokenTime > TOKEN_MAX_AGE) {
          isBase64Expired = true;
        }
      }
    }
  }

  if (actualPath === "/") {
    actualPath = "/index.html";
  }

  // Validate the Telegram-style ?t=timestamp_hash token.
  const telegramToken = requestUrl.searchParams.get("t") || "";
  if (telegramToken !== "") {
    const tokenParts = telegramToken.split("_");

    if (tokenParts.length === 2) {
      const tokenTime = phpInt(tokenParts[0]);
      const tokenHash = tokenParts[1];
      const now = Math.floor(Date.now() / 1000);

      if (
        now - tokenTime <= TOKEN_MAX_AGE &&
        md5(`${tokenTime}${TELEGRAM_SECRET}`).slice(0, 8) === tokenHash
      ) {
        isValidTelegramToken = true;
        isValidAuthCookie = true;
        shouldSetAuthCookie = true;
      }
    }
  }

  const isMainEntry = actualPath === "/index.html" || actualPath === "/index.php";
  const isProtectedHtml = actualPath.endsWith(".html") && !isMainEntry;

  // Match the PHP behavior: only an exact same-host Referer is trusted.
  let isFromInside = false;
  const referer = request.headers.get("Referer");
  if (referer) {
    try {
      isFromInside = new URL(referer).hostname === currentHost;
    } catch {
      isFromInside = false;
    }
  }

  if (isMainEntry) {
    if (
      !isValidTelegramToken &&
      !isValidAuthCookie &&
      !(isValidBase64Token && !isBase64Expired) &&
      !isFromInside
    ) {
      return new Response("<h1>404 Not Found (Home Page - Invalid Token)</h1>", {
        status: 404,
        headers: { "Content-Type": "text/html; charset=UTF-8" },
      });
    }
  } else if (isProtectedHtml) {
    if (!isValidBase64Token || isBase64Expired) {
      return new Response("<h1>404 Not Found (Internal Link - Invalid Token)</h1>", {
        status: 404,
        headers: { "Content-Type": "text/html; charset=UTF-8" },
      });
    }
  }

  // Remove only ?t= before forwarding the request to the original server.
  const cleanQuery = new URLSearchParams(requestUrl.searchParams);
  cleanQuery.delete("t");
  const queryString = cleanQuery.toString();
  const targetUrl = `${UPSTREAM_ORIGIN}${actualPath}${queryString ? `?${queryString}` : ""}`;

  // Forward the incoming request, including its method, body, and headers.
  const upstreamHeaders = new Headers(request.headers);
  upstreamHeaders.delete("Host");

  const upstreamRequest = new Request(targetUrl, {
    method: request.method,
    headers: upstreamHeaders,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    redirect: "follow",
  });

  let upstreamResponse;
  try {
    upstreamResponse = await fetch(upstreamRequest);
  } catch {
    return new Response("<h1>502 Bad Gateway</h1>", { status: 502 });
  }

  const responseHeaders = new Headers(upstreamResponse.headers);
  const extension = actualPath.split(".").pop()?.toLowerCase();
  if (extension === "css") {
    responseHeaders.set("Content-Type", "text/css");
  } else if (extension === "js") {
    responseHeaders.set("Content-Type", "application/javascript");
  }

  if (shouldSetAuthCookie) {
    const expires = new Date(Date.now() + 86400 * 365 * 10 * 1000).toUTCString();
    responseHeaders.append(
      "Set-Cookie",
      // Do not add Domain here. A host-only cookie is accepted reliably on
      // custom domains, workers.dev domains, and preview deployments alike.
      `${cookieName}=${expectedAuthCookie}; Expires=${expires}; Max-Age=${86400 * 365 * 10}; Path=/; Secure; HttpOnly; SameSite=Lax`,
    );
    // Do not let a cached token response hide the Set-Cookie header.
    responseHeaders.set("Cache-Control", "private, no-store");
  }

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders,
  });
}

function parseCookies(header) {
  const result = {};
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name) result[name] = value;
  }
  return result;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return difference === 0;
}

function phpInt(value) {
  const match = String(value).trim().match(/^[+-]?\d+/);
  if (!match) return 0;
  const number = Number.parseInt(match[0], 10);
  return Number.isFinite(number) ? number : 0;
}

function strictBase64Decode(value) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return null;
  }
  try {
    return atob(value);
  } catch {
    return null;
  }
}

async function hmacSha256Hex(message, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

// Small dependency-free MD5 implementation for the Telegram token check.
function md5(input) {
  const bytes = new TextEncoder().encode(input);
  const bitLength = bytes.length * 8;
  const paddedLength = (((bytes.length + 8) >> 6) + 1) * 64;
  const buffer = new Uint8Array(paddedLength);
  buffer.set(bytes);
  buffer[bytes.length] = 0x80;
  const view = new DataView(buffer.buffer);
  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const shifts = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const constants = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000));
  const rotateLeft = (value, amount) => (value << amount) | (value >>> (32 - amount));

  for (let offset = 0; offset < buffer.length; offset += 64) {
    const words = Array.from({ length: 16 }, (_, i) => view.getUint32(offset + i * 4, true));
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let i = 0; i < 64; i++) {
      let f;
      let g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      const next = d;
      d = c;
      c = b;
      const sum = (a + f + constants[i] + words[g]) >>> 0;
      b = (b + rotateLeft(sum, shifts[i])) >>> 0;
      a = next;
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  return [a0, b0, c0, d0]
    .map((word) => Array.from({ length: 4 }, (_, i) => ((word >>> (i * 8)) & 0xff).toString(16).padStart(2, "0")).join(""))
    .join("");
}
