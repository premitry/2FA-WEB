/**
 * 2FA Vault — a serverless Two-Factor Authentication code generator.
 *
 * Privacy model:
 *   - All entries are stored ONLY in the user's browser (localStorage).
 *   - The Cloudflare Worker never sees, stores, or proxies any secret.
 *   - Shareable links use the URL fragment (`#`), which by HTTP spec is
 *     NEVER transmitted to the server. The server cannot read shared secrets.
 *
 * TOTP implementation follows RFC 6238 (HOTP/TOTP) using the Web Crypto API.
 */

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Only respond to GETs on the root path. Everything else is 404.
    if (request.method !== 'GET') {
      return new Response('Method Not Allowed', { status: 405 });
    }
    if (url.pathname !== '/' && url.pathname !== '/index.html') {
      return new Response('Not Found', { status: 404 });
    }

    return new Response(HTML, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'public, max-age=300',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        // Strict CSP: no remote resources, no inline event handlers.
        // 'unsafe-inline' is needed only because the styles/scripts are inlined.
        'content-security-policy':
          "default-src 'none'; " +
          "style-src 'unsafe-inline'; " +
          "script-src 'unsafe-inline'; " +
          "img-src 'self' data:; " +
          "connect-src 'self'; " +
          "font-src 'self'; " +
          "base-uri 'none'; " +
          "form-action 'none'; " +
          "frame-ancestors 'none'",
      },
    });
  },
};

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0a0e1a">
<meta name="description" content="A privacy-first TOTP / 2FA code generator. Your secrets never leave your browser.">
<title>2FA Vault</title>
<link rel="icon" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2338bdf8'><path d='M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z'/></svg>">
<style>
  *, *::before, *::after { box-sizing: border-box; }
  :root {
    --bg: #0a0e1a;
    --bg-elevated: #161b2e;
    --bg-input: #1e253f;
    --border: #2a3454;
    --text: #f1f5f9;
    --text-dim: #94a3b8;
    --text-faint: #64748b;
    --accent: #38bdf8;
    --accent-hover: #0ea5e9;
    --danger: #ef4444;
    --warning: #fbbf24;
    --success: #10b981;
    --radius: 14px;
    --radius-sm: 8px;
    --shadow: 0 10px 30px rgba(0,0,0,.4);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
  }
  html, body { margin: 0; padding: 0; min-height: 100%; }
  body {
    background:
      radial-gradient(1200px 600px at 10% -10%, rgba(56,189,248,0.08), transparent 60%),
      radial-gradient(900px 500px at 110% 10%, rgba(168,85,247,0.06), transparent 60%),
      var(--bg);
    color: var(--text);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    padding-bottom: 6rem;
  }
  header {
    position: sticky; top: 0; z-index: 10;
    display: flex; align-items: center; justify-content: space-between;
    padding: 1rem 1.25rem;
    background: rgba(10, 14, 26, 0.85);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
  }
  .logo { display: flex; align-items: center; gap: .6rem; font-weight: 700; font-size: 1.1rem; letter-spacing: -0.01em; }
  .logo svg { width: 28px; height: 28px; color: var(--accent); flex-shrink: 0; }
  .header-actions { display: flex; gap: .5rem; }
  main {
    max-width: 720px;
    margin: 0 auto;
    padding: 1.25rem;
    display: grid;
    gap: .75rem;
  }
  .empty {
    text-align: center; padding: 4rem 1rem; color: var(--text-dim);
  }
  .empty svg { width: 64px; height: 64px; opacity: .35; margin-bottom: 1rem; }
  .empty h2 { font-weight: 600; margin: 0 0 .5rem; color: var(--text); }
  .empty p { margin: 0 0 1.5rem; }

  /* Entry card */
  .entry {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem 1.25rem;
    display: grid;
    grid-template-columns: 1fr auto;
    grid-template-rows: auto auto;
    gap: .25rem 1rem;
    align-items: center;
    transition: border-color .15s, transform .15s;
  }
  .entry:hover { border-color: rgba(56,189,248,0.4); }
  .entry .meta { grid-column: 1 / 2; min-width: 0; }
  .entry .issuer { font-weight: 600; font-size: 1rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .entry .account { font-size: .85rem; color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .entry .code-wrap {
    grid-column: 1 / 2;
    grid-row: 2;
    display: flex; align-items: center; gap: .75rem;
    margin-top: .25rem;
  }
  .entry .code {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 2rem;
    font-weight: 600;
    letter-spacing: 0.15em;
    color: var(--accent);
    cursor: pointer;
    user-select: all;
    background: none; border: none; padding: 0;
    transition: color .15s, transform .1s;
  }
  .entry .code:hover { color: var(--accent-hover); }
  .entry .code:active { transform: scale(0.98); }
  .entry .code.copied { color: var(--success); }
  .entry .code.error { color: var(--danger); font-size: 1rem; letter-spacing: 0; }
  .entry .actions {
    grid-column: 2;
    grid-row: 1 / 3;
    display: flex; flex-direction: column; align-items: center; gap: .5rem;
  }
  .progress-ring {
    width: 36px; height: 36px;
    transform: rotate(-90deg);
  }
  .progress-ring circle {
    fill: none;
    stroke-width: 3;
  }
  .progress-ring .bg { stroke: var(--border); }
  .progress-ring .fg {
    stroke: var(--accent);
    stroke-linecap: round;
    transition: stroke-dashoffset .9s linear, stroke .3s;
  }
  .progress-ring.warning .fg { stroke: var(--warning); }
  .progress-ring.danger .fg { stroke: var(--danger); }
  .menu-wrap { position: relative; }
  .menu-btn {
    background: none; border: none; color: var(--text-dim);
    width: 32px; height: 32px; border-radius: 50%;
    display: grid; place-items: center; cursor: pointer;
    transition: background .15s, color .15s;
  }
  .menu-btn:hover { background: var(--bg-input); color: var(--text); }
  .menu {
    position: absolute; top: 100%; right: 0; margin-top: .25rem;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow);
    padding: .25rem;
    min-width: 160px;
    z-index: 20;
  }
  .menu[hidden] { display: none; }
  .menu button {
    display: flex; align-items: center; gap: .5rem;
    width: 100%; padding: .55rem .75rem;
    background: none; border: none; color: var(--text);
    text-align: left; font-size: .9rem; border-radius: 6px; cursor: pointer;
  }
  .menu button:hover { background: var(--bg-input); }
  .menu button.danger { color: var(--danger); }
  .menu svg { width: 16px; height: 16px; flex-shrink: 0; }

  /* Buttons */
  button {
    font-family: inherit;
  }
  .btn {
    display: inline-flex; align-items: center; gap: .4rem;
    padding: .55rem 1rem;
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: var(--radius-sm);
    font-weight: 500; font-size: .9rem;
    cursor: pointer;
    transition: background .15s, border-color .15s;
  }
  .btn:hover { background: var(--border); }
  .btn-primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #001018;
  }
  .btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
  .btn-icon { padding: .55rem; }
  .btn svg { width: 16px; height: 16px; }

  /* Language switcher */
  .lang-switcher {
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: .55rem .55rem .55rem .65rem;
    border-radius: var(--radius-sm);
    font-family: inherit;
    font-size: .85rem;
    font-weight: 500;
    cursor: pointer;
    appearance: none;
    -webkit-appearance: none;
    background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12' fill='%2394a3b8'><path d='M3 4.5l3 3 3-3z'/></svg>");
    background-repeat: no-repeat;
    background-position: right .35rem center;
    padding-right: 1.5rem;
  }
  .lang-switcher:hover { border-color: var(--accent); }
  .lang-switcher:focus { outline: none; border-color: var(--accent); }

  /* Dialog */
  dialog {
    background: var(--bg-elevated);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0;
    max-width: 440px;
    width: calc(100% - 2rem);
    box-shadow: var(--shadow);
  }
  dialog::backdrop {
    background: rgba(0,0,0,0.6);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
  }
  .dialog-body { padding: 1.5rem; }
  .dialog-body h2 { margin: 0 0 1rem; font-size: 1.15rem; font-weight: 600; }
  .tabs { display: flex; gap: .25rem; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
  .tabs button {
    flex: 1;
    padding: .6rem;
    background: none; border: none;
    color: var(--text-dim); cursor: pointer;
    font-size: .9rem;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }
  .tabs button.active { color: var(--accent); border-bottom-color: var(--accent); }

  .field { display: block; margin-bottom: 1rem; }
  .field label { display: block; font-size: .85rem; color: var(--text-dim); margin-bottom: .35rem; }
  .field input, .field select, .field textarea {
    width: 100%;
    padding: .65rem .75rem;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text);
    font-size: .95rem;
    font-family: inherit;
    transition: border-color .15s;
  }
  .field input:focus, .field select:focus, .field textarea:focus {
    outline: none; border-color: var(--accent);
  }
  .field textarea { resize: vertical; min-height: 90px; font-family: ui-monospace, monospace; font-size: .85rem; }
  .field-row { display: grid; grid-template-columns: 1fr 1fr; gap: .75rem; }
  details summary { cursor: pointer; color: var(--text-dim); font-size: .85rem; padding: .5rem 0; user-select: none; }
  details summary:hover { color: var(--text); }
  details[open] summary { margin-bottom: .5rem; }

  .dialog-actions {
    display: flex; gap: .5rem; justify-content: flex-end;
    padding: 1rem 1.5rem;
    border-top: 1px solid var(--border);
    background: rgba(0,0,0,0.15);
    border-bottom-left-radius: var(--radius);
    border-bottom-right-radius: var(--radius);
  }

  /* Import preview */
  .preview-card {
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 1rem;
    margin: 1rem 0;
  }
  .preview-card .issuer { font-weight: 600; }
  .preview-card .account { color: var(--text-dim); font-size: .9rem; }

  /* Share */
  .share-link {
    word-break: break-all;
    font-family: ui-monospace, monospace;
    font-size: .8rem;
    background: var(--bg-input);
    padding: .75rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    margin-bottom: .75rem;
    max-height: 100px;
    overflow-y: auto;
  }
  .privacy-note {
    background: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.3);
    color: #6ee7b7;
    padding: .65rem .85rem;
    border-radius: var(--radius-sm);
    font-size: .8rem;
    line-height: 1.45;
    margin-bottom: 1rem;
  }
  .privacy-note strong { color: var(--success); }

  /* Toast */
  #toast {
    position: fixed; left: 50%; bottom: 1.5rem;
    transform: translateX(-50%) translateY(2rem);
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    color: var(--text);
    padding: .75rem 1.25rem;
    border-radius: var(--radius-sm);
    font-size: .9rem;
    box-shadow: var(--shadow);
    opacity: 0; pointer-events: none;
    transition: opacity .2s, transform .2s;
    z-index: 100;
    max-width: 90%;
  }
  #toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
  #toast.success { border-color: var(--success); }
  #toast.error { border-color: var(--danger); }

  /* Footer */
  footer {
    text-align: center;
    color: var(--text-faint);
    font-size: .8rem;
    padding: 2rem 1rem 1rem;
  }
  footer a { color: var(--text-dim); }

  @media (max-width: 480px) {
    .entry .code { font-size: 1.7rem; letter-spacing: 0.1em; }
    .field-row { grid-template-columns: 1fr; }
    header { padding: .85rem 1rem; }
    .logo { font-size: 1rem; }
  }
</style>
</head>
<body>
<header>
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
    <span>2FA Vault</span>
  </div>
  <div class="header-actions">
    <select id="langSwitcher" class="lang-switcher" data-i18n-attr="aria-label:aria.lang">
      <option value="en">EN</option>
      <option value="id">ID</option>
    </select>
    <button id="addBtn" class="btn btn-primary">
      <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
      <span data-i18n="app.add">Add</span>
    </button>
  </div>
</header>

<main id="entries"></main>

<div id="emptyState" class="empty" hidden>
  <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
  <h2 data-i18n="app.empty.title">No 2FA entries yet</h2>
  <p data-i18n="app.empty.desc">Add one manually, paste an otpauth:// URI, or import from a shared link.</p>
  <button id="addBtnEmpty" class="btn btn-primary">
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
    <span data-i18n="app.empty.cta">Add your first entry</span>
  </button>
</div>

<footer>
  <p>
    <span data-i18n="app.footer">Your secrets never leave your browser.</span>
    <a href="https://datatracker.ietf.org/doc/html/rfc6238" target="_blank" rel="noopener">RFC 6238</a>
    <span data-i18n="app.footer.tech">TOTP &middot; running on Cloudflare Workers.</span>
  </p>
</footer>

<!-- Add/Edit dialog -->
<dialog id="addDialog">
  <div class="dialog-body">
    <h2 id="addDialogTitle" data-i18n="dialog.add.title">Add 2FA Entry</h2>
    <div class="tabs" role="tablist">
      <button type="button" data-tab="manual" class="active" role="tab" data-i18n="tab.manual">Manual</button>
      <button type="button" data-tab="uri" role="tab" data-i18n="tab.uri">otpauth URI</button>
    </div>

    <form id="addForm">
      <div data-tab-panel="manual">
        <div class="field">
          <label for="issuer" data-i18n="field.issuer">Issuer / Service</label>
          <input id="issuer" type="text" placeholder="Google, GitHub, ..." autocomplete="off">
        </div>
        <div class="field">
          <label for="account" data-i18n="field.account">Account name</label>
          <input id="account" type="text" placeholder="user@example.com" autocomplete="off">
        </div>
        <div class="field">
          <label for="secret" data-i18n="field.secret">Secret key (Base32)</label>
          <input id="secret" type="text" placeholder="JBSWY3DPEHPK3PXP" autocomplete="off" spellcheck="false">
        </div>
        <details>
          <summary data-i18n="field.advanced">Advanced options</summary>
          <div class="field-row">
            <div class="field">
              <label for="digits" data-i18n="field.digits">Digits</label>
              <select id="digits">
                <option value="6" selected>6</option>
                <option value="7">7</option>
                <option value="8">8</option>
              </select>
            </div>
            <div class="field">
              <label for="period" data-i18n="field.period">Period (s)</label>
              <input id="period" type="number" min="10" max="120" value="30">
            </div>
          </div>
          <div class="field">
            <label for="algorithm" data-i18n="field.algorithm">Algorithm</label>
            <select id="algorithm">
              <option value="SHA-1" selected>SHA1</option>
              <option value="SHA-256">SHA256</option>
              <option value="SHA-512">SHA512</option>
            </select>
          </div>
        </details>
      </div>

      <div data-tab-panel="uri" hidden>
        <div class="field">
          <label for="uri" data-i18n="field.uri">Paste otpauth:// URI</label>
          <textarea id="uri" placeholder="otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example" autocomplete="off" spellcheck="false"></textarea>
        </div>
      </div>
    </form>
  </div>
  <div class="dialog-actions">
    <button type="button" class="btn" data-close data-i18n="btn.cancel">Cancel</button>
    <button type="button" id="saveBtn" class="btn btn-primary" data-i18n="btn.save">Save</button>
  </div>
</dialog>

<!-- Import dialog (when opening a shared link) -->
<dialog id="importDialog">
  <div class="dialog-body">
    <h2 data-i18n="dialog.import.title">Import shared 2FA entry</h2>
    <p style="margin: 0 0 1rem; color: var(--text-dim); font-size: .9rem;" data-i18n="dialog.import.desc">
      Someone shared a 2FA entry with you via a link. The secret was decoded
      locally in your browser.
    </p>
    <div id="importPreview"></div>
  </div>
  <div class="dialog-actions">
    <button type="button" class="btn" data-close data-i18n="btn.discard">Discard</button>
    <button type="button" id="importBtn" class="btn btn-primary" data-i18n="btn.import">Add to my vault</button>
  </div>
</dialog>

<!-- Share dialog -->
<dialog id="shareDialog">
  <div class="dialog-body">
    <h2 data-i18n="dialog.share.title">Shareable link</h2>
    <div class="privacy-note">
      <strong data-i18n="dialog.share.privacy.label">Privacy:</strong>
      <span data-i18n="dialog.share.privacy.desc">the secret is encoded after the # in the URL. By HTTP spec, fragments are never sent to the server &mdash; this Worker, Cloudflare, and any proxy in between cannot read it.</span>
    </div>
    <div id="shareLink" class="share-link"></div>
  </div>
  <div class="dialog-actions">
    <button type="button" class="btn" data-close data-i18n="btn.close">Close</button>
    <button type="button" id="copyShareBtn" class="btn btn-primary">
      <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
      <span data-i18n="btn.copylink">Copy link</span>
    </button>
  </div>
</dialog>

<div id="toast" role="status" aria-live="polite"></div>

<script>
(() => {
'use strict';

// ============================================================
// i18n (English + Bahasa Indonesia)
// ============================================================
const LOCALES = {
  en: {
    'app.add': 'Add',
    'app.empty.title': 'No 2FA entries yet',
    'app.empty.desc': 'Add one manually, paste an otpauth:// URI, or import from a shared link.',
    'app.empty.cta': 'Add your first entry',
    'app.footer': 'Your secrets never leave your browser.',
    'app.footer.tech': 'TOTP \u00b7 running on Cloudflare Workers.',
    'dialog.add.title': 'Add 2FA Entry',
    'dialog.edit.title': 'Edit 2FA Entry',
    'tab.manual': 'Manual',
    'tab.uri': 'otpauth URI',
    'field.issuer': 'Issuer / Service',
    'field.account': 'Account name',
    'field.secret': 'Secret key (Base32)',
    'field.advanced': 'Advanced options',
    'field.digits': 'Digits',
    'field.period': 'Period (s)',
    'field.algorithm': 'Algorithm',
    'field.uri': 'Paste otpauth:// URI',
    'btn.cancel': 'Cancel',
    'btn.save': 'Save',
    'btn.discard': 'Discard',
    'btn.import': 'Add to my vault',
    'btn.close': 'Close',
    'btn.copylink': 'Copy link',
    'dialog.import.title': 'Import shared 2FA entry',
    'dialog.import.desc': 'Someone shared a 2FA entry with you via a link. The secret was decoded locally in your browser.',
    'dialog.share.title': 'Shareable link',
    'dialog.share.privacy.label': 'Privacy:',
    'dialog.share.privacy.desc': 'the secret is encoded after the # in the URL. By HTTP spec, fragments are never sent to the server \u2014 this Worker, Cloudflare, and any proxy in between cannot read it.',
    'menu.share': 'Share via link',
    'menu.otpauth': 'Copy otpauth URI',
    'menu.edit': 'Edit',
    'menu.delete': 'Delete',
    'aria.copyCode': 'Copy code for {0}',
    'aria.moreActions': 'More actions',
    'aria.lang': 'Language',
    'code.hint': 'Click to copy',
    'code.copied': 'Copied!',
    'code.invalid': 'invalid secret',
    'untitled': 'Untitled',
    'unknown': 'Unknown',
    'confirm.delete': 'Delete "{0}"?',
    'meta.format': '{0} \u00b7 {1} digits \u00b7 {2}s',
    'toast.codeCopied': 'Code copied to clipboard',
    'toast.copyFailed': 'Could not copy',
    'toast.uriCopied': 'otpauth URI copied',
    'toast.linkCopied': 'Share link copied',
    'toast.entryAdded': 'Entry added',
    'toast.entryUpdated': 'Entry updated',
    'toast.entryDeleted': 'Entry deleted',
    'toast.entryImported': 'Entry imported',
    'toast.alreadyInVault': 'Already in your vault',
    'toast.invalidShareLink': 'Invalid share link',
    'toast.invalidOtpauth': 'Invalid otpauth link: {0}',
    'err.secretRequired': 'Secret is required',
    'err.secretEmpty': 'Secret is empty',
    'err.secretTooShort': 'Secret too short (need at least 80 bits)',
    'err.secretMustBeString': 'Secret must be a string',
    'err.invalidBase32': 'Invalid Base32 character: {0}',
    'err.notOtpauth': 'Not an otpauth:// URI',
    'err.invalidProtocol': 'Invalid protocol',
    'err.onlyTotp': 'Only TOTP is supported (got {0})',
    'err.missingSecret': 'Missing secret',
    'err.pasteUri': 'Paste an otpauth:// URI',
  },
  id: {
    'app.add': 'Tambah',
    'app.empty.title': 'Belum ada entry 2FA',
    'app.empty.desc': 'Tambahkan secara manual, paste URI otpauth://, atau import dari link yang dibagikan.',
    'app.empty.cta': 'Tambah entry pertama',
    'app.footer': 'Secret kamu tidak pernah keluar dari browser.',
    'app.footer.tech': 'TOTP \u00b7 berjalan di Cloudflare Workers.',
    'dialog.add.title': 'Tambah Entry 2FA',
    'dialog.edit.title': 'Edit Entry 2FA',
    'tab.manual': 'Manual',
    'tab.uri': 'URI otpauth',
    'field.issuer': 'Issuer / Layanan',
    'field.account': 'Nama akun',
    'field.secret': 'Secret key (Base32)',
    'field.advanced': 'Opsi lanjutan',
    'field.digits': 'Jumlah digit',
    'field.period': 'Periode (detik)',
    'field.algorithm': 'Algoritma',
    'field.uri': 'Paste URI otpauth://',
    'btn.cancel': 'Batal',
    'btn.save': 'Simpan',
    'btn.discard': 'Buang',
    'btn.import': 'Tambah ke vault saya',
    'btn.close': 'Tutup',
    'btn.copylink': 'Salin link',
    'dialog.import.title': 'Import entry 2FA dari link',
    'dialog.import.desc': 'Seseorang membagikan entry 2FA padamu lewat link. Secret-nya didecode lokal di browsermu.',
    'dialog.share.title': 'Link untuk dibagikan',
    'dialog.share.privacy.label': 'Privasi:',
    'dialog.share.privacy.desc': 'secret di-encode setelah tanda # di URL. Sesuai spec HTTP, fragment tidak pernah dikirim ke server \u2014 Worker ini, Cloudflare, maupun proxy mana pun tidak bisa membacanya.',
    'menu.share': 'Bagikan lewat link',
    'menu.otpauth': 'Salin URI otpauth',
    'menu.edit': 'Edit',
    'menu.delete': 'Hapus',
    'aria.copyCode': 'Salin kode untuk {0}',
    'aria.moreActions': 'Aksi lainnya',
    'aria.lang': 'Bahasa',
    'code.hint': 'Klik untuk menyalin',
    'code.copied': 'Tersalin!',
    'code.invalid': 'secret tidak valid',
    'untitled': 'Tanpa nama',
    'unknown': 'Tidak diketahui',
    'confirm.delete': 'Hapus "{0}"?',
    'meta.format': '{0} \u00b7 {1} digit \u00b7 {2}d',
    'toast.codeCopied': 'Kode tersalin ke clipboard',
    'toast.copyFailed': 'Gagal menyalin',
    'toast.uriCopied': 'URI otpauth tersalin',
    'toast.linkCopied': 'Link tersalin',
    'toast.entryAdded': 'Entry ditambahkan',
    'toast.entryUpdated': 'Entry diperbarui',
    'toast.entryDeleted': 'Entry dihapus',
    'toast.entryImported': 'Entry berhasil diimport',
    'toast.alreadyInVault': 'Sudah ada di vault',
    'toast.invalidShareLink': 'Link share tidak valid',
    'toast.invalidOtpauth': 'Link otpauth tidak valid: {0}',
    'err.secretRequired': 'Secret wajib diisi',
    'err.secretEmpty': 'Secret kosong',
    'err.secretTooShort': 'Secret terlalu pendek (minimal 80 bit)',
    'err.secretMustBeString': 'Secret harus berupa string',
    'err.invalidBase32': 'Karakter Base32 tidak valid: {0}',
    'err.notOtpauth': 'Bukan URI otpauth://',
    'err.invalidProtocol': 'Protokol tidak valid',
    'err.onlyTotp': 'Hanya TOTP yang didukung (dapat {0})',
    'err.missingSecret': 'Secret tidak ada',
    'err.pasteUri': 'Silakan paste URI otpauth://',
  },
};

const LANG_KEY = '2fa-vault.lang.v1';
let currentLang = (() => {
  try {
    const stored = localStorage.getItem(LANG_KEY);
    if (stored && LOCALES[stored]) return stored;
  } catch {}
  const nav = (navigator.language || 'en').toLowerCase();
  return nav.startsWith('id') ? 'id' : 'en';
})();

function t(key, ...args) {
  const dict = LOCALES[currentLang] || LOCALES.en;
  const tpl = dict[key] || LOCALES.en[key] || key;
  return args.length
    ? tpl.replace(/\\{(\\d+)\\}/g, (_, i) => String(args[+i]))
    : tpl;
}

function applyTranslations() {
  document.documentElement.lang = currentLang;
  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-attr]').forEach(el => {
    const spec = el.getAttribute('data-i18n-attr');
    spec.split(',').forEach(pair => {
      const [attr, key] = pair.split(':').map(s => s.trim());
      if (attr && key) el.setAttribute(attr, t(key));
    });
  });
}

function setLang(lang) {
  if (!LOCALES[lang]) return;
  currentLang = lang;
  try { localStorage.setItem(LANG_KEY, lang); } catch {}
  applyTranslations();
  render();
  tick();
}

// ============================================================
// Constants & state
// ============================================================
const STORAGE_KEY = '2fa-vault.entries.v1';
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** @type {Array<{id: string, issuer: string, account: string, secret: string, digits: number, period: number, algorithm: string}>} */
let entries = loadEntries();
let editingId = null;
let pendingImport = null;
let activeMenu = null;
const codeCache = new Map(); // id -> { code, counter }

// ============================================================
// Storage
// ============================================================
function loadEntries() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveEntries() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}

function newId() {
  return 'e_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

// ============================================================
// Base32 (RFC 4648, no-padding tolerant)
// ============================================================
function base32Decode(input) {
  if (typeof input !== 'string') throw new Error(t('err.secretMustBeString'));
  const cleaned = input.replace(/\\s+/g, '').replace(/=+$/, '').toUpperCase();
  if (!cleaned) throw new Error(t('err.secretEmpty'));
  let bits = '';
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(t('err.invalidBase32', ch));
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

// ============================================================
// TOTP (RFC 6238) using Web Crypto
// ============================================================
async function generateTOTP(secret, opts = {}) {
  const digits = opts.digits || 6;
  const period = opts.period || 30;
  const algorithm = opts.algorithm || 'SHA-1';
  const t = Math.floor(((opts.timestamp ?? Date.now()) / 1000) / period);

  // 8-byte big-endian counter
  const counterBytes = new ArrayBuffer(8);
  const view = new DataView(counterBytes);
  view.setUint32(0, Math.floor(t / 0x100000000));
  view.setUint32(4, t >>> 0);

  const keyBytes = base32Decode(secret);
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: algorithm } },
    false,
    ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = sig[sig.length - 1] & 0x0f;
  const num =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  const mod = 10 ** digits;
  return String(num % mod).padStart(digits, '0');
}

// ============================================================
// otpauth:// URI parser & builder
// ============================================================
function parseOtpauthURI(uri) {
  if (typeof uri !== 'string' || !uri.trim().toLowerCase().startsWith('otpauth://')) {
    throw new Error(t('err.notOtpauth'));
  }
  const u = new URL(uri.trim());
  if (u.protocol !== 'otpauth:') throw new Error(t('err.invalidProtocol'));
  if (u.host.toLowerCase() !== 'totp') throw new Error(t('err.onlyTotp', u.host));

  const label = decodeURIComponent(u.pathname.replace(/^\\//, ''));
  let issuer = u.searchParams.get('issuer') || '';
  let account = label;
  if (label.includes(':')) {
    const idx = label.indexOf(':');
    const labelIssuer = label.slice(0, idx).trim();
    const labelAccount = label.slice(idx + 1).trim();
    if (!issuer) issuer = labelIssuer;
    account = labelAccount;
  }

  const secret = u.searchParams.get('secret');
  if (!secret) throw new Error(t('err.missingSecret'));

  const algoRaw = (u.searchParams.get('algorithm') || 'SHA1').toUpperCase();
  const algorithm =
    algoRaw === 'SHA1' ? 'SHA-1' :
    algoRaw === 'SHA256' ? 'SHA-256' :
    algoRaw === 'SHA512' ? 'SHA-512' :
    algoRaw.startsWith('SHA-') ? algoRaw : 'SHA-1';

  return {
    issuer: issuer || t('unknown'),
    account: account || '',
    secret: secret.replace(/\\s+/g, '').toUpperCase(),
    digits: parseInt(u.searchParams.get('digits') || '6', 10),
    period: parseInt(u.searchParams.get('period') || '30', 10),
    algorithm,
  };
}

function buildOtpauthURI(entry) {
  const algoOut = entry.algorithm.replace('-', '');
  const label = encodeURIComponent(
    (entry.issuer ? entry.issuer + ':' : '') + (entry.account || '')
  );
  const params = new URLSearchParams({
    secret: entry.secret,
    issuer: entry.issuer || '',
    digits: String(entry.digits),
    period: String(entry.period),
    algorithm: algoOut,
  });
  return 'otpauth://totp/' + label + '?' + params.toString();
}

// ============================================================
// Share-via-fragment (base64url JSON)
// ============================================================
function b64urlEncode(str) {
  // Encode UTF-8 string -> base64url (no padding)
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function buildShareLink(entry) {
  // Strip the local id; receivers create their own.
  const payload = {
    v: 1,
    issuer: entry.issuer,
    account: entry.account,
    secret: entry.secret,
    digits: entry.digits,
    period: entry.period,
    algorithm: entry.algorithm,
  };
  const encoded = b64urlEncode(JSON.stringify(payload));
  return location.origin + location.pathname + '#import=' + encoded;
}

function parseShareFragment() {
  const hash = location.hash || '';
  if (hash.startsWith('#import=')) {
    try {
      const data = JSON.parse(b64urlDecode(hash.slice('#import='.length)));
      if (!data.secret) throw new Error(t('err.missingSecret'));
      return {
        issuer: String(data.issuer || t('unknown')),
        account: String(data.account || ''),
        secret: String(data.secret).replace(/\\s+/g, '').toUpperCase(),
        digits: parseInt(data.digits || 6, 10),
        period: parseInt(data.period || 30, 10),
        algorithm: data.algorithm || 'SHA-1',
      };
    } catch (e) {
      console.error('Invalid import fragment:', e);
      toast(t('toast.invalidShareLink'), 'error');
    }
  } else if (hash.startsWith('#otpauth=')) {
    try {
      return parseOtpauthURI(decodeURIComponent(hash.slice('#otpauth='.length)));
    } catch (e) {
      toast(t('toast.invalidOtpauth', e.message), 'error');
    }
  }
  return null;
}

// ============================================================
// Validation
// ============================================================
function validateSecret(secret) {
  if (!secret) throw new Error(t('err.secretRequired'));
  // base32Decode throws on invalid input; also fail on empty result.
  const bytes = base32Decode(secret);
  if (bytes.length < 10) throw new Error(t('err.secretTooShort'));
  return secret.replace(/\\s+/g, '').toUpperCase();
}

// ============================================================
// Rendering
// ============================================================
const $entries = document.getElementById('entries');
const $emptyState = document.getElementById('emptyState');

function render() {
  $entries.innerHTML = '';
  if (entries.length === 0) {
    $emptyState.hidden = false;
    return;
  }
  $emptyState.hidden = true;
  for (const e of entries) {
    $entries.appendChild(renderEntry(e));
  }
}

function renderEntry(entry) {
  const card = document.createElement('article');
  card.className = 'entry';
  card.dataset.id = entry.id;

  const meta = document.createElement('div');
  meta.className = 'meta';
  const issuer = document.createElement('div');
  issuer.className = 'issuer';
  issuer.textContent = entry.issuer || t('untitled');
  const account = document.createElement('div');
  account.className = 'account';
  account.textContent = entry.account || '';
  meta.append(issuer, account);

  const codeWrap = document.createElement('div');
  codeWrap.className = 'code-wrap';
  const codeBtn = document.createElement('button');
  codeBtn.className = 'code';
  codeBtn.type = 'button';
  codeBtn.dataset.role = 'code';
  codeBtn.textContent = '------';
  codeBtn.title = t('code.hint');
  codeBtn.setAttribute('aria-label', t('aria.copyCode', entry.issuer || t('untitled')));
  codeWrap.appendChild(codeBtn);

  const actions = document.createElement('div');
  actions.className = 'actions';

  // Progress ring
  const ringSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  ringSvg.setAttribute('class', 'progress-ring');
  ringSvg.setAttribute('viewBox', '0 0 36 36');
  ringSvg.dataset.role = 'ring';
  const r = 16;
  const circumference = 2 * Math.PI * r;
  const bg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  bg.setAttribute('class', 'bg');
  bg.setAttribute('cx', '18'); bg.setAttribute('cy', '18'); bg.setAttribute('r', String(r));
  const fg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  fg.setAttribute('class', 'fg');
  fg.setAttribute('cx', '18'); fg.setAttribute('cy', '18'); fg.setAttribute('r', String(r));
  fg.setAttribute('stroke-dasharray', String(circumference));
  fg.setAttribute('stroke-dashoffset', '0');
  ringSvg.append(bg, fg);

  // Menu
  const menuWrap = document.createElement('div');
  menuWrap.className = 'menu-wrap';
  const menuBtn = document.createElement('button');
  menuBtn.className = 'menu-btn';
  menuBtn.type = 'button';
  menuBtn.setAttribute('aria-label', t('aria.moreActions'));
  menuBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>';
  const menu = document.createElement('div');
  menu.className = 'menu';
  menu.hidden = true;
  // Keep icons inline; labels come from i18n.
  const ICON_SHARE = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92s2.92-1.31 2.92-2.92-1.31-2.92-2.92-2.92z"/></svg>';
  const ICON_COPY = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>';
  const ICON_EDIT = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34a.9959.9959 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>';
  const ICON_TRASH = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>';
  function makeMenuItem(action, icon, labelKey, danger = false) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.dataset.action = action;
    if (danger) btn.className = 'danger';
    btn.innerHTML = icon + ' <span></span>';
    btn.querySelector('span').textContent = t(labelKey);
    return btn;
  }
  menu.append(
    makeMenuItem('share', ICON_SHARE, 'menu.share'),
    makeMenuItem('otpauth', ICON_COPY, 'menu.otpauth'),
    makeMenuItem('edit', ICON_EDIT, 'menu.edit'),
    makeMenuItem('delete', ICON_TRASH, 'menu.delete', true),
  );
  menuWrap.append(menuBtn, menu);

  actions.append(ringSvg, menuWrap);
  card.append(meta, codeWrap, actions);
  return card;
}

// ============================================================
// Update codes / progress (called every second)
// ============================================================
async function tick() {
  const now = Date.now();
  for (const entry of entries) {
    const card = $entries.querySelector('[data-id="' + cssEscape(entry.id) + '"]');
    if (!card) continue;
    const codeEl = card.querySelector('[data-role="code"]');
    const ring = card.querySelector('[data-role="ring"]');
    const fg = ring.querySelector('.fg');

    const period = entry.period || 30;
    const counter = Math.floor(now / 1000 / period);
    const elapsed = (now / 1000) % period;
    const remaining = period - elapsed;

    // Update progress ring
    const r = 16;
    const c = 2 * Math.PI * r;
    const offset = c - (remaining / period) * c;
    fg.setAttribute('stroke-dashoffset', String(offset));
    ring.classList.toggle('warning', remaining <= 10 && remaining > 5);
    ring.classList.toggle('danger', remaining <= 5);

    // Update code only when counter rolls over (or first time)
    const cached = codeCache.get(entry.id);
    if (!cached || cached.counter !== counter) {
      try {
        const code = await generateTOTP(entry.secret, {
          digits: entry.digits, period: entry.period, algorithm: entry.algorithm, timestamp: now,
        });
        codeCache.set(entry.id, { code, counter });
        if (!codeEl.classList.contains('copied')) {
          codeEl.textContent = formatCode(code);
        }
        codeEl.classList.remove('error');
      } catch (e) {
        codeEl.textContent = t('code.invalid');
        codeEl.classList.add('error');
        codeCache.delete(entry.id);
      }
    } else if (codeEl.textContent === '------' || codeEl.classList.contains('error')) {
      codeEl.textContent = formatCode(cached.code);
      codeEl.classList.remove('error');
    }
  }
}

function formatCode(code) {
  // 6 digits -> "123 456" ; 8 digits -> "1234 5678"
  if (code.length === 6) return code.slice(0, 3) + ' ' + code.slice(3);
  if (code.length === 8) return code.slice(0, 4) + ' ' + code.slice(4);
  return code;
}

function cssEscape(s) {
  // Minimal CSS.escape polyfill for selectors
  if (window.CSS && CSS.escape) return CSS.escape(s);
  return String(s).replace(/[^a-zA-Z0-9_-]/g, m => '\\\\' + m);
}

// ============================================================
// Toast
// ============================================================
const $toast = document.getElementById('toast');
let toastTimer = null;
function toast(msg, kind = '') {
  $toast.textContent = msg;
  $toast.className = 'show ' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $toast.className = $toast.className.replace('show', '').trim(); }, 2200);
}

// ============================================================
// Clipboard
// ============================================================
async function copyToClipboard(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) { /* fall through */ }
  // Fallback for non-secure contexts
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch { return false; }
}

// ============================================================
// Dialog helpers
// ============================================================
function openDialog(id) {
  const d = document.getElementById(id);
  if (typeof d.showModal === 'function') d.showModal();
  else d.setAttribute('open', '');
}
function closeDialog(d) {
  if (typeof d === 'string') d = document.getElementById(d);
  if (typeof d.close === 'function') d.close();
  else d.removeAttribute('open');
}

document.querySelectorAll('dialog').forEach(d => {
  d.addEventListener('click', e => {
    // Backdrop click closes
    if (e.target === d) closeDialog(d);
    // [data-close] buttons close
    if (e.target.closest('[data-close]')) closeDialog(d);
  });
});

// ============================================================
// Add / Edit dialog
// ============================================================
const $addDialog = document.getElementById('addDialog');
const $addDialogTitle = document.getElementById('addDialogTitle');
const $tabs = $addDialog.querySelectorAll('.tabs button');
const $panels = $addDialog.querySelectorAll('[data-tab-panel]');
const $issuer = document.getElementById('issuer');
const $account = document.getElementById('account');
const $secret = document.getElementById('secret');
const $digits = document.getElementById('digits');
const $period = document.getElementById('period');
const $algorithm = document.getElementById('algorithm');
const $uri = document.getElementById('uri');

function setTab(name) {
  $tabs.forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $panels.forEach(p => { p.hidden = p.dataset.tabPanel !== name; });
}
$tabs.forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));

function openAddDialog(entry = null) {
  editingId = entry ? entry.id : null;
  $addDialogTitle.textContent = entry ? t('dialog.edit.title') : t('dialog.add.title');
  $issuer.value = entry ? entry.issuer : '';
  $account.value = entry ? entry.account : '';
  $secret.value = entry ? entry.secret : '';
  $digits.value = entry ? String(entry.digits) : '6';
  $period.value = entry ? String(entry.period) : '30';
  $algorithm.value = entry ? entry.algorithm : 'SHA-1';
  $uri.value = '';
  setTab('manual');
  openDialog('addDialog');
  setTimeout(() => $issuer.focus(), 50);
}

document.getElementById('addBtn').addEventListener('click', () => openAddDialog());
document.getElementById('addBtnEmpty').addEventListener('click', () => openAddDialog());

document.getElementById('saveBtn').addEventListener('click', async () => {
  let data;
  const activeTab = $addDialog.querySelector('.tabs button.active').dataset.tab;
  try {
    if (activeTab === 'uri') {
      const uri = $uri.value.trim();
      if (!uri) throw new Error(t('err.pasteUri'));
      data = parseOtpauthURI(uri);
    } else {
      data = {
        issuer: $issuer.value.trim() || t('untitled'),
        account: $account.value.trim(),
        secret: $secret.value.trim(),
        digits: parseInt($digits.value, 10) || 6,
        period: parseInt($period.value, 10) || 30,
        algorithm: $algorithm.value || 'SHA-1',
      };
    }
    data.secret = validateSecret(data.secret);
  } catch (e) {
    toast(e.message, 'error');
    return;
  }

  if (editingId) {
    const idx = entries.findIndex(e => e.id === editingId);
    if (idx >= 0) entries[idx] = { ...entries[idx], ...data };
  } else {
    entries.push({ id: newId(), ...data });
  }
  saveEntries();
  codeCache.clear();
  closeDialog($addDialog);
  render();
  await tick();
  toast(editingId ? t('toast.entryUpdated') : t('toast.entryAdded'), 'success');
});

// ============================================================
// Delegated entry actions (copy code, menu)
// ============================================================
$entries.addEventListener('click', async (e) => {
  const codeBtn = e.target.closest('[data-role="code"]');
  if (codeBtn) {
    const card = codeBtn.closest('.entry');
    const id = card.dataset.id;
    const cached = codeCache.get(id);
    if (!cached) return;
    const ok = await copyToClipboard(cached.code);
    if (ok) {
      codeBtn.classList.add('copied');
      codeBtn.textContent = t('code.copied');
      setTimeout(() => {
        codeBtn.classList.remove('copied');
        codeBtn.textContent = formatCode(cached.code);
      }, 1100);
      toast(t('toast.codeCopied'), 'success');
    } else {
      toast(t('toast.copyFailed'), 'error');
    }
    return;
  }

  const menuBtn = e.target.closest('.menu-btn');
  if (menuBtn) {
    e.stopPropagation();
    const menu = menuBtn.nextElementSibling;
    const isOpen = !menu.hidden;
    closeAllMenus();
    if (!isOpen) {
      menu.hidden = false;
      activeMenu = menu;
    }
    return;
  }

  const action = e.target.closest('[data-action]');
  if (action) {
    const card = action.closest('.entry');
    const id = card.dataset.id;
    const entry = entries.find(en => en.id === id);
    if (!entry) return;
    closeAllMenus();
    handleAction(action.dataset.action, entry);
  }
});

function closeAllMenus() {
  document.querySelectorAll('.menu').forEach(m => { m.hidden = true; });
  activeMenu = null;
}
document.addEventListener('click', (e) => {
  if (activeMenu && !e.target.closest('.menu-wrap')) closeAllMenus();
});

async function handleAction(action, entry) {
  if (action === 'edit') {
    openAddDialog(entry);
  } else if (action === 'delete') {
    if (confirm(t('confirm.delete', entry.issuer || t('untitled')))) {
      entries = entries.filter(e => e.id !== entry.id);
      codeCache.delete(entry.id);
      saveEntries();
      render();
      toast(t('toast.entryDeleted'));
    }
  } else if (action === 'share') {
    const link = buildShareLink(entry);
    document.getElementById('shareLink').textContent = link;
    document.getElementById('copyShareBtn').dataset.link = link;
    openDialog('shareDialog');
  } else if (action === 'otpauth') {
    const uri = buildOtpauthURI(entry);
    const ok = await copyToClipboard(uri);
    toast(ok ? t('toast.uriCopied') : t('toast.copyFailed'), ok ? 'success' : 'error');
  }
}

document.getElementById('copyShareBtn').addEventListener('click', async (e) => {
  const link = e.currentTarget.dataset.link;
  if (!link) return;
  const ok = await copyToClipboard(link);
  toast(ok ? t('toast.linkCopied') : t('toast.copyFailed'), ok ? 'success' : 'error');
});

// ============================================================
// Import-from-fragment flow
// ============================================================
function showImportDialog(data) {
  pendingImport = data;
  const preview = document.getElementById('importPreview');
  preview.innerHTML = '';
  const card = document.createElement('div');
  card.className = 'preview-card';
  const issuer = document.createElement('div');
  issuer.className = 'issuer';
  issuer.textContent = data.issuer || t('untitled');
  const account = document.createElement('div');
  account.className = 'account';
  account.textContent = data.account || '';
  const meta = document.createElement('div');
  meta.style.cssText = 'margin-top:.5rem;color:var(--text-faint);font-size:.8rem;';
  meta.textContent = t('meta.format', data.algorithm.replace('-', ''), data.digits, data.period);
  card.append(issuer, account, meta);
  preview.appendChild(card);
  openDialog('importDialog');
}

document.getElementById('importBtn').addEventListener('click', () => {
  if (!pendingImport) return;
  try {
    pendingImport.secret = validateSecret(pendingImport.secret);
  } catch (e) {
    toast(e.message, 'error');
    return;
  }
  // Avoid duplicates by (issuer, account, secret)
  const dup = entries.find(e =>
    e.issuer === pendingImport.issuer &&
    e.account === pendingImport.account &&
    e.secret === pendingImport.secret);
  if (dup) {
    toast(t('toast.alreadyInVault'), 'success');
  } else {
    entries.push({ id: newId(), ...pendingImport });
    saveEntries();
    render();
    tick();
    toast(t('toast.entryImported'), 'success');
  }
  pendingImport = null;
  closeDialog('importDialog');
  // Clean fragment so reload doesn't re-prompt
  history.replaceState(null, '', location.pathname + location.search);
});

document.getElementById('importDialog').addEventListener('close', () => {
  if (pendingImport) {
    pendingImport = null;
    history.replaceState(null, '', location.pathname + location.search);
  }
});

// ============================================================
// Bootstrap
// ============================================================
function start() {
  // Apply translations + initialize switcher BEFORE first render so cards
  // are built with the right language from the start.
  applyTranslations();
  const switcher = document.getElementById('langSwitcher');
  switcher.value = currentLang;
  switcher.addEventListener('change', e => setLang(e.target.value));

  render();
  tick();
  setInterval(tick, 1000);

  const shared = parseShareFragment();
  if (shared) showImportDialog(shared);
}

// Keyboard shortcut: 'a' to add (when no input focused)
document.addEventListener('keydown', (e) => {
  if (e.key === 'a' && !e.ctrlKey && !e.metaKey && !e.altKey) {
    const tag = document.activeElement && document.activeElement.tagName;
    if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') {
      const dialogOpen = Array.from(document.querySelectorAll('dialog')).some(d => d.open);
      if (!dialogOpen) { e.preventDefault(); openAddDialog(); }
    }
  }
});

start();
})();
</script>
</body>
</html>`;
