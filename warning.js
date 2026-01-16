// warning.js
const EXCEPTIONS_KEY = 'blockingExceptions';

function qs(name) {
  const params = new URLSearchParams(location.search);
  return params.get(name);
}

const origUrl = qs('url') || '';
const host = qs('host') || (origUrl ? (() => { try { return new URL(origUrl).hostname; } catch { return origUrl; } })() : 'unknown');
const score = qs('score') || '';

document.getElementById('hostLabel').textContent = host ? `Blocked: ${host} · Score: ${score}` : '';

document.getElementById('allowBtn').addEventListener('click', async () => {
  try {
    const s = await chrome.storage.local.get(EXCEPTIONS_KEY);
    const arr = s[EXCEPTIONS_KEY] || [];
    if (!arr.includes(host)) arr.push(host);
    await chrome.storage.local.set({ [EXCEPTIONS_KEY]: arr });
    if (origUrl) chrome.tabs.create({ url: origUrl });
    window.close();
  } catch (e) {
    console.error(e);
  }
});

document.getElementById('dismissBtn').addEventListener('click', () => {
  window.close();
});
