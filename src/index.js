export default {
    async fetch(request, env, ctx) {
        // ==========================================
        // Crypto Functions 
        // ==========================================
        async function getMD5(data) {
            const encoder = new TextEncoder();
            const hash = await crypto.subtle.digest('MD5', encoder.encode(data));
            return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async function getHMAC(secret, data) {
            const encoder = new TextEncoder();
            const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
            const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
            return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        const url = new URL(request.url);
        const currentHost = url.hostname; 
        let path = url.pathname;
        let pathParts = path.split('/').filter(p => p !== '');

        let actualPath = path;
        let isValidBase64Token = false;
        let isBase64Expired = false;
        let isValidTelegramToken = false;
        let isValidAuthCookie = false;

        const cookieName = 'auth_' + currentHost.replace(/\./g, '_');
        const secretKey = 'joegyi_2026_auth_secret_' + currentHost;
        const expectedAuthCookie = await getHMAC(secretKey, 'authorized');

        // ==========================================
        // ပြင်ဆင်ချက် ၁ - Cookie ဖတ်သည့်စနစ်ကို ပိုမိုတိကျအောင် ပြောင်းထားသည်
        // ==========================================
        const cookieHeader = request.headers.get('Cookie') || '';
        if (cookieHeader.includes(`${cookieName}=${expectedAuthCookie}`)) {
            isValidAuthCookie = true;
        }

        if (pathParts.length >= 1) {
            let possibleToken = pathParts[0];
            try {
                let decoded = atob(possibleToken);
                if (decoded.includes(':')) {
                    let [tokenTimeStr, secret] = decoded.split(':');
                    let tokenTime = parseInt(tokenTimeStr, 10);
                    if (secret === "joegyi_2026_super_secret") {
                        isValidBase64Token = true;
                        pathParts.shift();
                        actualPath = '/' + pathParts.join('/');
                        const now = Math.floor(Date.now() / 1000);
                        if ((now - tokenTime) > 600) {
                            isBase64Expired = true;
                        }
                    }
                }
            } catch (e) {}
        }

        if (actualPath === '/' || actualPath === '') {
            actualPath = '/index.html';
        }

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
                        isValidAuthCookie = true;

                        // ==========================================
                        // ပြင်ဆင်ချက် ၂ - Domain ဖြုတ်ပြီး Max-Age ကို အသုံးပြုထားသည်
                        // ==========================================
                        const maxAge = 10 * 365 * 86400; // ၁၀ နှစ် (စက္ကန့်ဖြင့်)
                        const expires = new Date(Date.now() + (maxAge * 1000)).toUTCString();
                        cookieToSet = `${cookieName}=${expectedAuthCookie}; Max-Age=${maxAge}; Expires=${expires}; Path=/; Secure; HttpOnly; SameSite=Lax`;
                    }
                }
            }
        }

        const isMainEntry = (actualPath === '/index.html' || actualPath === '/index.php');
        const isProtectedHtml = actualPath.endsWith('.html') && !isMainEntry;

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

        if (isMainEntry) {
            if (!isValidTelegramToken && !isValidAuthCookie && !(isValidBase64Token && !isBase64Expired) && !isFromInside) {
                return new Response("<h1>404 Not Found (Home Page - Invalid Token)</h1>", {
                    status: 404,
                    headers: { "Content-Type": "text/html" }
                });
            }
        } else if (isProtectedHtml) {
            if (!isValidBase64Token || isBase64Expired) {
                return new Response("<h1>404 Not Found (Internal Link - Invalid Token)</h1>", {
                    status: 404,
                    headers: { "Content-Type": "text/html" }
                });
            }
        }

        const targetUrl = new URL("https://web.joegyi.uk" + actualPath);
        url.searchParams.forEach((value, key) => {
            if (key !== 't') {
                targetUrl.searchParams.append(key, value);
            }
        });

        const fetchHeaders = new Headers(request.headers);
        fetchHeaders.delete('host'); 

        const proxyRequest = new Request(targetUrl, {
            method: request.method,
            headers: fetchHeaders,
            body: ['GET', 'HEAD'].includes(request.method) ? null : request.body,
            redirect: 'manual'
        });

        const response = await fetch(proxyRequest);
        const responseHeaders = new Headers(response.headers);
        
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
