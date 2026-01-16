// popup.js - UI logic with test button and robust fallbacks
const SELF_ID = chrome.runtime.id;
const permList = ['camera','microphone','geolocation','notifications','clipboard-read','clipboard-write'];

function $id(id){ return document.getElementById(id); }
function withTimeout(promise, ms, fallback){ return Promise.race([promise, new Promise(res => setTimeout(() => res(fallback), ms))]); }

(async function main() {
  $id('site').textContent = 'Loading site info...';
  $id('sitePerms').textContent = 'Loading permissions...';
  $id('siteStorage').textContent = 'Loading storage signals...';
  $id('activity').textContent = 'Loading...';
  $id('extensions').textContent = 'Loading...';

  // Manage button
  $id('manageBtn').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('manage.html') });
  });

  // Test button - force warning for current tab
  $id('testMalicious').addEventListener('click', async () => {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabs || !tabs[0]) return alert('No active tab found!');
      chrome.runtime.sendMessage({ type: 'FORCE_BLOCK', url: tabs[0].url }, (r) => {
        if (chrome.runtime.lastError) console.error(chrome.runtime.lastError.message);
      });
    } catch (e) { console.error('testMalicious error', e); }
  });

  // Active tab info
  let tab;
  try {
    const tabs = await withTimeout(chrome.tabs.query({ active: true, currentWindow: true }), 1000, []);
    if (!tabs || !tabs[0]) $id('site').textContent = 'Unable to get active tab.';
    else {
      tab = tabs[0];
      try { $id('site').textContent = new URL(tab.url).hostname; } catch { $id('site').textContent = tab.url || 'unknown'; }
    }
  } catch (e) { $id('site').textContent = 'Error reading tab.'; console.error(e); }

  // permissions (navigator.permissions)
  (async () => {
    const out = [];
    for (const name of permList) {
      try {
        const res = await withTimeout(navigator.permissions.query({ name }), 800, null);
        out.push(res ? `${name}: ${res.state}` : `${name}: unknown`);
      } catch (e) { out.push(`${name}: unsupported`); }
    }
    $id('sitePerms').innerHTML = out.join('<br>');
  })();

  // storage & page signals via scripting
  (async () => {
    if (!tab || typeof tab.id !== 'number') { $id('siteStorage').textContent = 'Storage signals: no active tab'; return; }
    try {
      const res = await withTimeout(chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          try {
            const cookieCount = document.cookie ? document.cookie.split(';').filter(Boolean).length : 0;
            const localStorageKeys = (() => { try { return Object.keys(localStorage).length; } catch (e) { return -1; } })();
            const sessionStorageKeys = (() => { try { return Object.keys(sessionStorage).length; } catch (e) { return -1; } })();
            const inlineHandlers = document.querySelectorAll('[onload],[onclick],[onerror],[onmouseover],[onfocus],[onchange],[onkeydown]').length;
            const iframeCount = document.querySelectorAll('iframe').length;
            const hasPasswordField = !!document.querySelector('input[type=password]');
            const hasServiceWorker = !!(navigator.serviceWorker && navigator.serviceWorker.controller);
            const title = document.title || '';
            return { cookieCount, localStorageKeys, sessionStorageKeys, inlineHandlers, iframeCount, hasPasswordField, hasServiceWorker, title };
          } catch (e) { return { error: String(e) }; }
        }
      }), 1500, null);

      if (!res) $id('siteStorage').textContent = 'Storage signals: timed out or blocked';
      else {
        const r = Array.isArray(res) ? res[0].result : res.result;
        if (!r) $id('siteStorage').textContent = 'Storage signals: unavailable';
        else if (r.error) $id('siteStorage').textContent = `Storage signals error: ${r.error}`;
        else $id('siteStorage').innerHTML = `Cookies: ${r.cookieCount}<br>localStorage keys: ${r.localStorageKeys}<br>Inline handlers: ${r.inlineHandlers}<br>IFRames: ${r.iframeCount}<br>Password field: ${r.hasPasswordField ? 'yes' : 'no'}`;
      }
    } catch (e) { console.error('scripting error', e); $id('siteStorage').textContent = 'Storage signals: error'; }
  })();

  // activity (from background)
  (async () => {
    try {
      const stats = await withTimeout(new Promise(resolve => chrome.runtime.sendMessage('getStats', r => {
        if (chrome.runtime.lastError) resolve({ error: chrome.runtime.lastError.message }); else resolve(r);
      })), 800, null);
      if (!stats) $id('activity').textContent = 'Activity: unavailable (timeout)';
      else if (stats.error) $id('activity').textContent = `Activity error: ${stats.error}`;
      else $id('activity').innerHTML = `Requests (last 10s): <strong>${stats.requestsLastWindow}</strong><br>Total requests: <strong>${stats.totalRequests}</strong>`;
    } catch (e) { console.error('getStats error', e); $id('activity').textContent = 'Activity: error'; }
  })();

  // installed extensions (management)
  (async () => {
    try {
      const exts = await withTimeout(new Promise(res => chrome.management.getAll(res)), 1200, null);
      const container = $id('extensions');
      if (!exts) { container.textContent = 'Unable to list extensions (management permission needed or timed out).'; return; }
      container.innerHTML = '';
      exts.sort((a,b) => (b.enabled - a.enabled) || a.name.localeCompare(b.name));
      for (const ext of exts) {
        const perms = [...(ext.permissions || []), ...(ext.hostPermissions || [])];
        const div = document.createElement('div');
        div.style.marginBottom = '8px';
        div.innerHTML = `<div style="font-weight:600;color:#e6e9eb">${ext.name}</div><div class="small">${ext.enabled ? 'Enabled' : 'Disabled'} · ID: ${ext.id}</div><div class="small muted" style="margin-top:4px">Permissions: ${perms.length ? perms.join(', ') : 'None'}</div>`;
        container.appendChild(div);
      }
    } catch (e) { console.error('management error', e); $id('extensions').textContent = 'Extensions: error (see console)'; }
  })();

})();
