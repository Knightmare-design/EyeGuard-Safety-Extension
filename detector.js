// detector.js
function urlHeuristics(url) {
let score = 0;
try {
const u = new URL(url);
const host = u.hostname;
// IP in URL
if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) score += WEIGHTS.urlIp;
// punycode (xn--)
if (host.includes('xn--')) score += WEIGHTS.punycode;
// suspicious tlds (heuristic list)
if (/\.(zip|mov|click|xyz|top|tk|ru|cn)\b/.test(host)) score += WEIGHTS.suspiciousTLD;
// lots of subdomains
if (host.split('.').length > 4) score += WEIGHTS.manySubdomains;
} catch (e) {
// if URL parse fails, consider that suspicious
score += 5;
}
return score;
}


function permissionRisk(permissions = []) {
let score = 0;
if (permissions.includes('camera') || permissions.includes('videoCapture')) score += WEIGHTS.permission_camera;
if (permissions.includes('microphone') || permissions.includes('audioCapture')) score += WEIGHTS.permission_microphone;
if (permissions.includes('geolocation')) score += WEIGHTS.permission_geolocation;
if (permissions.includes('clipboardRead') || permissions.includes('clipboard-write') || permissions.includes('clipboardRead')) score += WEIGHTS.permission_clipboard;
if (permissions.includes('notifications')) score += WEIGHTS.permission_notifications;
return score;
}


function scriptRisk(scriptText = '') {
let score = 0;
if (!scriptText) return score;
if (/eval\s*\(/.test(scriptText) || /new Function\(/.test(scriptText)) score += WEIGHTS.evalUse;
if (/document\.write\s*\(/.test(scriptText)) score += WEIGHTS.documentWrite;
if (/while\s*\(true\)/.test(scriptText) || /for\s*\(;;\)/.test(scriptText)) score += WEIGHTS.endlessLoop;


// obfuscation: long base64-ish sequences or extremely long packed script
if (scriptText.length > 5000 && /[A-Za-z0-9+\/]{200,}/.test(scriptText)) score += WEIGHTS.obfuscation;
return score;
}


function networkRisk(requests = []) {
let score = 0;
try {
const origin = (location && location.origin) ? location.origin : null;
const foreign = requests.filter(r => origin ? !r.url.startsWith(origin) : true);
if (foreign.length > 10) score += WEIGHTS.foreignRequests;
for (const r of requests) {
if ((r.method || 'GET').toUpperCase() === 'POST' && (r.bodySize || 0) > 500000) score += WEIGHTS.largePost;
if (r.url.includes('pastebin') || r.url.includes('discord')) score += WEIGHTS.pastebinRefer;
}
} catch (e) {
// ignore
}
return score;
}


function phishingRisk(pageSignals = {}) {
let score = 0;
try {
const text = (pageSignals.bodyText || '').toLowerCase();
if (pageSignals.hasPasswordField) score += WEIGHTS.passwordFields;
if (/login|verify|secure|bank|account|confirm|suspended/.test(pageSignals.title || '')) score += WEIGHTS.phishingText;
if (/urgent|verify now|confirm your|suspended|limited access/.test(text)) score += WEIGHTS.phishingText;
} catch (e) {}
return score;
}


function pageSignalRisk(pageSignals = {}) {
let score = 0;
if (typeof pageSignals.inlineHandlers === 'number' && pageSignals.inlineHandlers >= 50) score += WEIGHTS.inlineHandlers;
if (typeof pageSignals.iframeCount === 'number' && pageSignals.iframeCount >= 10) score += WEIGHTS.manyIframes;
if (pageSignals.timedOut) score += WEIGHTS.timedOutScript;
if (pageSignals.error) score += 8;
return score;
}


function calculate(data = {}) {
// data: { url, permissions, scriptText, requests, pageSignals }
let total = 0;
total += urlHeuristics(data.url || '');
total += permissionRisk(data.permissions || []);
total += scriptRisk(data.scriptText || '');
total += networkRisk(data.requests || []);
total += phishingRisk(data.pageSignals || {});
total += pageSignalRisk(data.pageSignals || {});
return total; // higher = more suspicious
}


function interpret(score) {
// thresholds tuned for conservative defaults
if (score >= 85) return { level: 'BLOCK', score };
if (score >= 45) return { level: 'WARN', score };
return { level: 'ALLOW', score };
}


return { calculate, interpret };
})();