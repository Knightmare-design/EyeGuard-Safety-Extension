# EyeGuard Elite — Local Malicious Site Detector

This folder contains a Chromium extension (Chrome/Edge) that detects potentially malicious sites using a multi-signal heuristic engine, blocks suspicious downloads, and shows a clear warning page. All data is stored locally.

## Installation (developer)
1. Place the folder (e.g. `eyeGuard-elite/`) on your computer.
2. Make sure `icons/icon16.png`, `icons/icon48.png`, `icons/icon128.png` are present.
3. Open `chrome://extensions` (or `edge://extensions`).
4. Enable **Developer mode**.
5. Click **Load unpacked** and select the extension folder.
6. Reload after edits.

## Files
- `manifest.json` — extension manifest (MV3)
- `background.js` — service worker with Detector + network + download protection
- `popup.html` / `popup.js` — toolbar UI & test button
- `manage.html` / `manage.js` — exceptions manager
- `warning.html` / `warning.js` — block UI
- `icons/` — you supply PNGs

## Testing
- Use the **Test Warning** button in the popup to force the warning.
- Use WICAR's **JavaScript Crypto Miner** to test JS behavior detection.
- Use WICAR's **EICAR** to test download blocking (download detection).
- Add trusted hosts in **Malicious Sites** manager.

## Tuning
Adjust thresholds and weights inside `background.js` (Detector weights) to tune sensitivity.

## Privacy
All lists and logs are stored in `chrome.storage.local` only; nothing is sent externally.

