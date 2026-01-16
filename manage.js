// manage.js - manage site exceptions
const EXCEPTIONS_KEY = 'blockingExceptions';
function $(id){ return document.getElementById(id); }

async function load() {
  const s = await chrome.storage.local.get(EXCEPTIONS_KEY);
  const list = s[EXCEPTIONS_KEY] || [];
  render(list);
}

function render(list) {
  const container = $('list');
  container.innerHTML = '';
  if (!list.length) {
    container.textContent = 'No sites are currently allowed (exceptions). Use the form below to allow a site.';
    return;
  }
  for (const host of list) {
    const row = document.createElement('div');
    row.className = 'site';
    const left = document.createElement('div');
    left.innerHTML = `<div style="font-weight:600">${host}</div><div class="small">Allowed (blocking disabled)</div>`;
    const btn = document.createElement('button');
    btn.className = 'toggle remove';
    btn.textContent = 'Remove';
    btn.addEventListener('click', async () => {
      const s = await chrome.storage.local.get(EXCEPTIONS_KEY);
      const arr = s[EXCEPTIONS_KEY] || [];
      const newArr = arr.filter(x => x !== host);
      await chrome.storage.local.set({ [EXCEPTIONS_KEY]: newArr });
      load();
    });
    row.appendChild(left);
    row.appendChild(btn);
    container.appendChild(row);
  }
}

$('addBtn').addEventListener('click', async () => {
  const v = $('addInput').value.trim();
  if (!v) return;
  let host = v;
  try { host = (new URL(v)).hostname; } catch (e) { host = v.replace(/^https?:\/\//, '').split('/')[0]; }
  const s = await chrome.storage.local.get(EXCEPTIONS_KEY);
  const arr = s[EXCEPTIONS_KEY] || [];
  if (!arr.includes(host)) {
    arr.push(host);
    await chrome.storage.local.set({ [EXCEPTIONS_KEY]: arr });
  }
  $('addInput').value = '';
  load();
});

// initial
load();
