export default {
  async fetch(request, env, ctx) {
    // ==========================================
    // ၁။ ဝင်လာသော URL ကို ယူခြင်း
    // ==========================================
    const url = new URL(request.url);
    let path = url.pathname;
    let pathParts = path.split('/').filter(p => p !== '');
    let actualPath = path;

    let isValidBase64Token = false;
    let isBase64Expired = false;
    let isValidTelegramToken = false;
    let isValidAuthCookie = false;

    // ဝင်လာသော ဒိုမိန်းကို ယူခြင်း
    const currentHost = url.hostname.split(':')[0];

    // ==========================================
    // ၂။ Authorization Cookie စစ်ဆေးခြင်း
    // ==========================================
    const cookieName = 'auth_' + currentHost.replace(/\./g, '_');
    const secretKey = 'joegyi_2026_auth_secret_' + currentHost;
    
    // HMAC-SHA256 ကို Web Crypto API အသုံးပြု၍ ဖန်တီးခြင်း
    const expectedAuthCookie = await hmacSha256('authorized', secretKey);

    // Request မှ Cookie ဖတ်ခြင်း
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookies = Object.fromEntries(cookieHeader.split(';').map(c => {
      const parts = c.split('=');
      return [parts[0].trim(), parts.slice(1).join('=').trim()];
    }));

    if (cookies[cookieName] && cookies[cookieName] === expectedAuthCookie) {
      isValidAuthCookie = true;
    }

    // ==========================================
    // ၃။ အတွင်းလင့်ခ်များအတွက် JS (Base64) Token စစ်ဆေးခြင်း
    // ==========================================
    if (pathParts.length >= 1) {
      const possibleToken = pathParts[0];
      try {
        const decoded = atob(possibleToken); // Base64 Decode
        if (decoded.includes(':')) {
          const [tokenTimeStr, secret] = decoded.split(':');
          const tokenTime = parseInt(tokenTimeStr, 10);
          
          if (secret === "joegyi_2026_super_secret") {
            isValidBase64Token = true;
            pathParts.shift(); // Token ဖြုတ်မည်
            actualPath = '/' + pathParts.join('/');
            
            const now = Math.floor(Date.now() / 1000);
            if (now - tokenTime > 600) { // ၁၀ မိနစ်
              isBase64Expired = true;
            }
          }
        }
      } catch (e) {
        // Base64 မဟုတ်ပါက ကျော်သွားမည်
      }
    }

    // ==========================================
    // ၄။ Path သည် / ဖြစ်နေပါက /index.html သို့ ပြောင်းပေးမည်
    // ==========================================
    if (actualPath === '/' || actualPath === '') {
      actualPath = '/index.html';
    }

    // ==========================================
    // ၅။ ပင်မစာမျက်နှာအတွက် Telegram (?t=) Token စစ်ဆေးခြင်း
    // ==========================================
    const t = url.searchParams.get('t');
    let cookieToSet = null;

    if (t) {
      const tParts = t.split('_');
      if (tParts.length === 2) {
        const tTime = parseInt(tParts[0], 10);
        const tHash = tParts[1];
        const now = Math.floor(Date.now() / 1000);
        
        if (now - tTime <= 600) {
          // MD5 ဖြင့် တိုက်စစ်မည်
          const checkStr = tTime + "joegyi_2026";
          const checkHash = md5(checkStr).substring(0, 8);
          
          if (checkHash === tHash) {
            isValidTelegramToken = true;
            isValidAuthCookie = true;
            
            // ရာသက်ပန် (၁၀ နှစ်) Cookie သတ်မှတ်ခြင်း
            const expires = new Date(Date.now() + (10 * 365 * 86400 * 1000)).toUTCString();
            cookieToSet = `${cookieName}=${expectedAuthCookie}; Expires=${expires}; Path=/; Domain=${currentHost}; Secure; HttpOnly; SameSite=Lax`;
          }
        }
      }
    }

    // ==========================================
    // ၆။ လုံခြုံရေး စည်းမျဉ်းများ (Access Rules)
    // ==========================================
    const isMainEntry = (actualPath === '/index.html' || actualPath === '/index.php');
    const isProtectedHtml = actualPath.endsWith('.html') && !isMainEntry;

    // ==========================================
    // ၇။ Website အတွင်းမှ လာခြင်းဟုတ်မဟုတ် စစ်ဆေးခြင်း
    // ==========================================
    let isFromInside = false;
    const referer = request.headers.get('Referer');
    if (referer) {
      try {
        const refUrl = new URL(referer);
        if (refUrl.hostname === currentHost) {
          isFromInside = true;
        }
      } catch (e) {}
    }

    // ==========================================
    // ၈ & ၉။ Access စစ်ဆေးခြင်း
    // ==========================================
    if (isMainEntry) {
      if (!isValidTelegramToken && !isValidAuthCookie && !(isValidBase64Token && !isBase64Expired) && !isFromInside) {
        return new Response("<h1>404 Not Found (Home Page - Invalid Token)</h1>", { status: 404, headers: { 'Content-Type': 'text/html' } });
      }
    } else if (isProtectedHtml) {
      if (!isValidBase64Token || isBase64Expired) {
        return new Response("<h1>404 Not Found (Internal Link - Invalid Token)</h1>", { status: 404, headers: { 'Content-Type': 'text/html' } });
      }
    }

    // ==========================================
    // ၁၀။ မူရင်းဆာဗာသို့ Request ပို့မည် (t ဖြုတ်မည်)
    // ==========================================
    url.searchParams.delete('t');
    let cleanQuery = url.searchParams.toString();
    cleanQuery = cleanQuery ? '?' + cleanQuery : '';

    // ==========================================
    // ၁၁။ Original Server URL
    // ==========================================
    const targetUrl = "https://web.joegyi.uk" + actualPath + cleanQuery;

    // ==========================================
    // ၁၂ & ၁၃။ Header များကို ပို့ပေးရန် ပြင်ဆင်ခြင်း
    // ==========================================
    const headersToForward = new Headers(request.headers);
    headersToForward.delete('Host'); // Cloudflare မှ အလိုအလျောက် သတ်မှတ်ပေးရန် ဖယ်ထုတ်သည်

    const fetchInit = {
      method: request.method,
      headers: headersToForward,
      redirect: 'manual'
    };

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      fetchInit.body = request.body;
    }

    // ==========================================
    // ၁၄။ Request လုပ်မည်
    // ==========================================
    const response = await fetch(targetUrl, fetchInit);

    // ==========================================
    // ၁၅ & ၁၆။ Header နှင့် Content-Type ပြန်ချပေးရန်
    // ==========================================
    const responseHeaders = new Headers(response.headers);

    if (cookieToSet) {
      responseHeaders.append('Set-Cookie', cookieToSet);
    }

    if (actualPath.endsWith('.css')) {
      responseHeaders.set('Content-Type', 'text/css');
    } else if (actualPath.endsWith('.js')) {
      responseHeaders.set('Content-Type', 'application/javascript');
    }

    // ==========================================
    // ၁၇။ Response ပြန်ပြမည်
    // ==========================================
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};

// ==========================================
// Helper Functions (HMAC-SHA256 & MD5)
// ==========================================

// HMAC-SHA256 ပြုလုပ်ရန်
async function hmacSha256(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Telegram Token တွက်ရန် MD5 Algorithm (Cloudflare အတွက်)
function md5(string) {
  function md5cycle(x, k) {
    var a = x[0], b = x[1], c = x[2], d = x[3];
    a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586); c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426); c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417); c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101); c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
    a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632); c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083); c = ggCloudflare Worker တွင် အသုံးပြုနိုင်ရန်အတွက် မူလ PHP ကုဒ်၏ လုံခြုံရေးစည်းမျဉ်းများ၊ Cookie မှတ်သားခြင်း၊ Token စစ်ဆေးခြင်းနှင့် Proxy လုပ်ဆောင်ချက်အားလုံးကို JavaScript (ES Module Format) ဖြင့် အောက်ပါအတိုင်း ရေးသားနိုင်ပါသည်။ 

```javascript
export default {
    async fetch(request, env, ctx) {
        // ==========================================
        // Crypto Functions (MD5 နှင့် HMAC-SHA256 အတွက်)
        // ==========================================
        async function getMD5(data) {
            const encoder = new TextEncoder();
            const hash = await crypto.subtle.digest('MD5', encoder.encode(data));
            return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async function getHMAC(secret, data) {
            const encoder = new TextEncoder();
            const key = await crypto.subtle.importKey(
                'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
            );
            const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
            return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // ==========================================
        // ၁။ ဝင်လာသော URL ကို ယူခြင်း
        // ==========================================
        const url = new URL(request.url);
        const currentHost = url.hostname; // Port မပါဝင်ပါ
        let path = url.pathname;
        let pathParts = path.split('/').filter(p => p !== '');

        let actualPath = path;
        let isValidBase64Token = false;
        let isBase64Expired = false;
        let isValidTelegramToken = false;
        let isValidAuthCookie = false;

        // ==========================================
        // ၂။ Authorization Cookie စစ်ဆေးခြင်း
        // ==========================================
        const cookieName = 'auth_' + currentHost.replace(/\./g, '_');
        const secretKey = 'joegyi_2026_auth_secret_' + currentHost;
        const expectedAuthCookie = await getHMAC(secretKey, 'authorized');

        const cookieHeader = request.headers.get('Cookie') || '';
        const cookies = {};
        cookieHeader.split(';').forEach(c => {
            const parts = c.split('=');
            if (parts.length >= 2) {
                cookies[parts[0].trim()] = decodeURIComponent(parts.slice(1).join('=')).trim();
            }
        });

        if (cookies[cookieName] === expectedAuthCookie) {
            isValidAuthCookie = true;
        }

        // ==========================================
        // ၃။ အတွင်းလင့်ခ်များအတွက် JS (Base64) Token စစ်ဆေးခြင်း
        // ==========================================
        if (pathParts.length >= 1) {
            let possibleToken = pathParts[0];
            try {
                let decoded = atob(possibleToken);
                if (decoded.includes(':')) {
                    let [tokenTimeStr, secret] = decoded.split(':');
                    let tokenTime = parseInt(tokenTimeStr, 10);

                    if (secret === "joegyi_2026_super_secret") {
                        isValidBase64Token = true;
                        
                        // Token ဖြုတ်ပြီး မူရင်း Path ကို ယူမည်
                        pathParts.shift();
                        actualPath = '/' + pathParts.join('/');
                        
                        const now = Math.floor(Date.now() / 1000);
                        if ((now - tokenTime) > 600) { // 600 စက္ကန့် စစ်ဆေးမည်
                            isBase64Expired = true;
                        }
                    }
                }
            } catch (e) {
                // Invalid Base64 (လျစ်လျူရှုမည်)
            }
        }

        // ==========================================
        // ၄။ Path သည် / ဖြစ်နေပါက /index.html သို့ ပြောင်းပေးမည်
        // ==========================================
        if (actualPath === '/' || actualPath === '') {
            actualPath = '/index.html';
        }

        // ==========================================
        // ၅။ ပင်မစာမျက်နှာအတွက် Telegram (?t=) Token စစ်ဆေးခြင်း
        // ==========================================
        const t = url.searchParams.get('t') || '';
        let cookieToSet = null;

        if (t !== '') {
            let tParts = t.split('_');
            if (tParts.length === 2) {
                let tTime = parseInt(tParts[0], 10);
                let tHash = tParts[1];
                let now = Math.floor(Date.now() / 1000);

                if ((now - tTime) <= 600) {
                    let checkString = tTime + "joegyi_2026";
                    let checkHashFull = await getMD5(checkString);
                    let checkHash = checkHashFull.substring(0, 8);

                    if (checkHash === tHash) {
                        isValidTelegramToken = true;

                        // ၁၀ နှစ်သက်တမ်းရှိသော Cookie သတ်မှတ်မည်
                        const expires = new Date(Date.now() + (10 * 365 * 86400 * 1000)).toUTCString();
                        cookieToSet = `${cookieName}=${expectedAuthCookie}; Expires=${expires}; Path=/; Domain=${currentHost}; Secure; HttpOnly; SameSite=Lax`;
                        isValidAuthCookie = true;
                    }
                }
            }
        }

        // ==========================================
        // ၆။ လုံခြုံရေး စည်းမျဉ်းများ (Access Rules)
        // ==========================================
        const isMainEntry = (actualPath === '/index.html' || actualPath === '/index.php');
        const isProtectedHtml = actualPath.endsWith('.html') && !isMainEntry;

        // ==========================================
        // ၇။ Website အတွင်းမှ လာခြင်းဟုတ်မဟုတ် စစ်ဆေးခြင်း
        // ==========================================
        let isFromInside = false;
        const referer = request.headers.get('Referer');
        if (referer) {
            try {
                const refHost = new URL(referer).hostname;
                if (refHost === currentHost) {
                    isFromInside = true;
                }
            } catch (e) {}
        }

        // ==========================================
        // ၈။ Home Page Access စစ်ဆေးခြင်း
        // ==========================================
        if (isMainEntry) {
            if (!isValidTelegramToken && !isValidAuthCookie && !(isValidBase64Token && !isBase64Expired) && !isFromInside) {
                return new Response("<h1>404 Not Found (Home Page - Invalid Token)</h1>", {
                    status: 404,
                    headers: { "Content-Type": "text/html" }
                });
            }
        }
        // ==========================================
        // ၉။ Protected HTML Access စစ်ဆေးခြင်း
        // ==========================================
        else if (isProtectedHtml) {
            if (!isValidBase64Token || isBase64Expired) {
                return new Response("<h1>404 Not Found (Internal Link - Invalid Token)</h1>", {
                    status: 404,
                    headers: { "Content-Type": "text/html" }
                });
            }
        }

        // ==========================================
        // ၁၀။ မူရင်းဆာဗာသို့ Request ပို့မည် (t ကို ဖြတ်ထုတ်မည်)
        // ==========================================
        const targetUrl = new URL("[https://web.joegyi.uk](https://web.joegyi.uk)" + actualPath);
        url.searchParams.forEach((value, key) => {
            if (key !== 't') {
                targetUrl.searchParams.append(key, value);
            }
        });

        // ==========================================
        // ၁၁။ Headers နှင့် cURL အစားထိုး Fetch ပြုလုပ်ခြင်း
        // ==========================================
        const fetchHeaders = new Headers(request.headers);
        fetchHeaders.delete('host'); // Cloudflare မှ Target Host ကို အလိုအလျောက် သတ်မှတ်ပေးမည်

        const proxyRequest = new Request(targetUrl, {
            method: request.method,
            headers: fetchHeaders,
            body: ['GET', 'HEAD'].includes(request.method) ? null : request.body,
            redirect: 'manual'
        });

        const response = await fetch(proxyRequest);

        // ==========================================
        // ၁၂။ Response ကို ပြန်လည်ပြင်ဆင်ခြင်း
        // ==========================================
        const responseHeaders = new Headers(response.headers);
        
        // Content-Type များကို သေချာစွာ ပြန်ချပေးရန်
        if (actualPath.endsWith('.css')) responseHeaders.set('Content-Type', 'text/css');
        if (actualPath.endsWith('.js')) responseHeaders.set('Content-Type', 'application/javascript');

        if (cookieToSet) {
            responseHeaders.append('Set-Cookie', cookieToSet);
        }

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    }
};
          
