// background.js - EyeCo Elite service worker (MV3)

// =========================
// Detector (heuristic engine)
// =========================
const Detector = (() => {
  const WEIGHTS = {
    urlIp: 30,
    punycode: 25,
    suspiciousTLD: 12,
    manySubdomains: 10,
    permission_camera: 25,
    permission_microphone: 25,
    permission_geolocation: 15,
    permission_clipboard: 10,
    permission_notifications: 8,
    evalUse: 20,
    obfuscation: 25,
    documentWrite: 8,
    endlessLoop: 25,
    foreignRequests: 12,
    largePost: 25,
    pastebinRefer: 12,
    passwordFields: 10,
    phishingText: 12,
    inlineHandlers: 10,
    manyIframes: 8,
    timedOutScript: 8
  };

  function urlHeuristics(url) {
    let score = 0;
    try {
      const u = new URL(url);
      const host = u.hostname;
      if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) score += WEIGHTS.urlIp;
      if (host.includes('xn--')) score += WEIGHTS.punycode;
      if (/\.(zip|mov|click|xyz|top|tk|ru|cn)\b/.test(host)) score += WEIGHTS.suspiciousTLD;
      if (host.split('.').length > 4) score += WEIGHTS.manySubdomains;
    } catch (e) { score += 5; }
    return score;
  }

  function permissionRisk(permissions = []) {
    let score = 0;
    if (permissions.includes('camera') || permissions.includes('videoCapture')) score += WEIGHTS.permission_camera;
    if (permissions.includes('microphone') || permissions.includes('audioCapture')) score += WEIGHTS.permission_microphone;
    if (permissions.includes('geolocation')) score += WEIGHTS.permission_geolocation;
    if (permissions.includes('clipboardRead') || permissions.includes('clipboard-write')) score += WEIGHTS.permission_clipboard;
    if (permissions.includes('notifications')) score += WEIGHTS.permission_notifications;
    return score;
  }

  function scriptRisk(scriptText = '') {
    let score = 0;
    if (!scriptText) return 0;
    if (/eval\s*\(|new Function\(/.test(scriptText)) score += WEIGHTS.evalUse;
    if (/document\.write\s*\(/.test(scriptText)) score += WEIGHTS.documentWrite;
    if (/while\s*\(true\)|for\s*\(;;\)/.test(scriptText)) score += WEIGHTS.endlessLoop;
    if (scriptText.length > 5000 && /[A-Za-z0-9+\/]{200,}/.test(scriptText)) score += WEIGHTS.obfuscation;
    return score;
  }

  function networkRisk(requests = [], origin = null) {
    let score = 0;
    try {
      const foreign = origin ? requests.filter(r => !r.url.startsWith(origin)) : requests;
      if (foreign.length > 10) score += WEIGHTS.foreignRequests;
      for (const r of requests) {
        if ((r.method || 'GET').toUpperCase() === 'POST' && (r.bodySize || 0) > 500000) score += WEIGHTS.largePost;
        if (r.url.includes('pastebin') || r.url.includes('discord')) score += WEIGHTS.pastebinRefer;
      }
    } catch (e) {}
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
    let total = 0;
    total += urlHeuristics(data.url || '');
    total += permissionRisk(data.permissions || []);
    total += scriptRisk(data.scriptText || '');
    total += networkRisk(data.requests || [], data.origin || null);
    total += phishingRisk(data.pageSignals || {});
    total += pageSignalRisk(data.pageSignals || {});
    return total;
  }

  function interpret(score) {
    if (score >= 85) return { level: 'BLOCK', score };
    if (score >= 45) return { level: 'WARN', score };
    return { level: 'ALLOW', score };
  }

  return { calculate, interpret };
})();

// =========================
// Global tracking & config
// =========================
const WINDOW_MS = 10 * 1000; // sliding window (10s)
let recentRequests = []; // {t, tabId, initiator, url, method, bodySize}
let totalRequests = 0;
const EXCEPTIONS_KEY = 'blockingExceptions';
const MALICIOUS_DOWNLOADS_KEY = 'maliciousDownloads';

// prune old requests
function prune(now = Date.now()) {
  const cutoff = now - WINDOW_MS;
  while (recentRequests.length && recentRequests[0].t < cutoff) recentRequests.shift();
}

function getRequestCountForTab(tabId) {
  prune();
  return recentRequests.filter(r => r.tabId === tabId).length;
}

function updateBadge() {
  try {
    prune();
    const count = recentRequests.length;
    if (count === 0) {
      chrome.action.setBadgeText({ text: '' });
      return;
    }
    chrome.action.setBadgeText({ text: count > 999 ? '999+' : String(count) });
    let color = '#55ff55';
    if (count >= 20 && count < 100) color = '#ffaa00';
    if (count >= 100) color = '#ff5555';
    chrome.action.setBadgeBackgroundColor({ color });
  } catch (e) {
    console.error('updateBadge error', e);
  }
}

// =========================
// Web request capture
// =========================
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      const now = Date.now();
      recentRequests.push({
        t: now,
        tabId: details.tabId,
        initiator: details.initiator || details.originUrl || details.documentUrl || 'unknown',
        url: details.url,
        method: details.method,
        bodySize: (details.requestBody && details.requestBody.raw) ? details.requestBody.raw.reduce((s, p) => s + (p.bytes || 0), 0) : 0
      });
      totalRequests++;
      prune(now);
      updateBadge();
    } catch (e) {
      console.error('webRequest handler error', e);
    }
  },
  { urls: ['<all_urls>'] },
  []
);

// =========================
// Download protection (ELITE)
// =========================
chrome.downloads.onCreated.addListener(async (item) => {
  try {
    let risk = 0;
    const filename = (item.filename || '').toLowerCase();
    const url = (item.url || '').toLowerCase();

    // Dangerous filetypes
    if (filename.match(/\.(exe|msi|bat|cmd|scr|ps1|vbs|jar|apk|dll)$/)) risk += 40;
    // Double extension trick
    if (filename.match(/\.(pdf|jpg|png|docx|zip)\.(exe|bat|scr)$/)) risk += 50;
    // Archives
    if (filename.match(/\.(zip|rar|7z)$/)) risk += 15;
    // Social engineering keywords
    if (filename.match(/(invoice|payment|secure|update|verify|crack|keygen|patch)/)) risk += 20;
    // EICAR
    if (filename.includes('eicar') || url.includes('eicar')) risk += 100;
    // blob/data URLs
    if (url.startsWith('blob:') || url.startsWith('data:')) risk += 20;
    // downloads without referrer may be drive-by
    if (!item.referrer) risk += 15;

    if (risk >= 60) {
      try { await chrome.downloads.cancel(item.id); } catch (e) {}
      const wUrl = chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(item.url)}&host=Download&score=${risk}`;
      chrome.tabs.create({ url: wUrl });

      // Save blocked download
      chrome.storage.local.get({ [MALICIOUS_DOWNLOADS_KEY]: [] }, (data) => {
        const arr = data[MALICIOUS_DOWNLOADS_KEY] || [];
        arr.push({ filename: item.filename, url: item.url, risk, time: Date.now() });
        chrome.storage.local.set({ [MALICIOUS_DOWNLOADS_KEY]: arr });
      });

      chrome.action.setBadgeText({ text: '!' });
      chrome.action.setBadgeBackgroundColor({ color: '#ff5555' });
      setTimeout(() => updateBadge(), 6000);
    }
  } catch (e) {
    console.error('downloads.onCreated error', e);
  }
});

// =========================
// Tab update detection / main flow
// =========================
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://')) {
    runDetectionForTab(tabId, tab.url).catch(err => console.error('runDetectionForTab error', err));
  }
});

async function loadExceptions() {
  const s = await chrome.storage.local.get(EXCEPTIONS_KEY);
  return s[EXCEPTIONS_KEY] || [];
}

async function runDetectionForTab(tabId, url) {
  try {
    let hostname;
    try { hostname = new URL(url).hostname; } catch (e) { hostname = url; }
    const exceptions = await loadExceptions();
    if (exceptions.includes(hostname)) return; // whitelisted

    const reqCount = getRequestCountForTab(tabId);

    // Collect page signals via scripting
    const scriptPromise = chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        try {
          const cookieCount = document.cookie ? document.cookie.split(';').filter(Boolean).length : 0;
          const localStorageKeys = (() => { try { return Object.keys(localStorage).length; } catch (e) { return -1; } })();
          const sessionStorageKeys = (() => { try { return Object.keys(sessionStorage).length; } catch (e) { return -1; } })();
          const inlineHandlers = document.querySelectorAll('[onload],[onclick],[onerror],[onmouseover],[onfocus],[onchange],[onkeydown]').length;
          const iframeCount = document.querySelectorAll('iframe').length;
          const hasServiceWorker = !!(navigator.serviceWorker && navigator.serviceWorker.controller);
          const hasPasswordField = !!document.querySelector('input[type=password]');
          const title = document.title || '';
          const bodyText = document.body ? document.body.innerText.slice(0, 5000) : '';
          // scripts summary (only lengths to avoid heavy transfer)
          const scripts = Array.from(document.scripts || []).slice(0, 30).map(s => ({ src: s.src || null, inlineLength: s.src ? 0 : (s.textContent || '').length }));
          return { cookieCount, localStorageKeys, sessionStorageKeys, inlineHandlers, iframeCount, hasServiceWorker, hasPasswordField, title, bodyText, scripts };
        } catch (e) {
          return { error: String(e) };
        }
      }
    });

    const res = await Promise.race([scriptPromise, new Promise(resolve => setTimeout(() => resolve(null), 1500))]);
    let pageSignals = null;
    if (!res) pageSignals = { timedOut: true };
    else {
      const entry = Array.isArray(res) ? res[0] : res;
      pageSignals = entry && entry.result ? entry.result : { error: 'no-result' };
    }

    // Tab-specific recent requests
    prune();
    const tabRequests = recentRequests.filter(r => r.tabId === tabId).slice(-200);

    // Build data for Detector
    const data = {
      url,
      permissions: [], // site-granted permissions are not easily obtainable from background; left empty
      scriptText: (Array.isArray(pageSignals.scripts) ? 'INLINE_LEN:' + pageSignals.scripts.reduce((s, x) => s + (x.inlineLength || 0), 0) : ''),
      requests: tabRequests.map(r => ({ url: r.url, method: r.method, bodySize: r.bodySize })),
      pageSignals,
      origin: (new URL(url)).origin
    };

    // Calculate score
    const score = Detector.calculate(data);
    const decision = Detector.interpret(score);

    // Take action
    if (decision.level === 'BLOCK') {
      try {
        const originalUrl = url;
        chrome.tabs.remove(tabId, () => {
          const wUrl = chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(originalUrl)}&host=${encodeURIComponent(hostname)}&score=${decision.score}`;
          chrome.tabs.create({ url: wUrl });
          chrome.action.setBadgeText({ text: '!' });
          chrome.action.setBadgeBackgroundColor({ color: '#ff5555' });
          setTimeout(() => updateBadge(), 6000);
        });
      } catch (e) {
        console.error('error closing tab or opening warning page', e);
      }
    } else if (decision.level === 'WARN') {
      chrome.action.setBadgeText({ text: '!' });
      chrome.action.setBadgeBackgroundColor({ color: '#ffaa00' });
      setTimeout(() => updateBadge(), 6000);
    }
  } catch (e) {
    console.error('runDetectionForTab top error', e);
  }
}

// =========================
// Message handler (popup + test force)
// =========================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  try {
    if (msg === 'getStats') {
      prune();
      const counts = {};
      for (const r of recentRequests) {
        const key = r.initiator || String(r.tabId) || 'unknown';
        counts[key] = (counts[key] || 0) + 1;
      }
      const top = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0,8).map(([k,v]) => ({ initiator: k, count: v }));
      sendResponse({ requestsLastWindow: recentRequests.length, totalRequests, topInitiators: top });
      return true;
    }

    if (msg && msg.type === 'FORCE_BLOCK') {
      const origUrl = msg.url || 'about:blank';
      const host = (() => { try { return new URL(origUrl).hostname; } catch { return origUrl; } })();
      const wUrl = chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(origUrl)}&host=${encodeURIComponent(host)}&score=999`;
      chrome.tabs.create({ url: wUrl });
      sendResponse({ ok: true });
      return true;
    }

  } catch (e) {
    console.error('onMessage error', e);
    try { sendResponse({ error: String(e) }); } catch (_) {}
    return true;
  }
});
