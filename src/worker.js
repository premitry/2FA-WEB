/**
 * 2FA Vault — instant TOTP / 2FA code generator on Cloudflare Workers.
 *
 * UX: paste a secret key, the code appears instantly. No dialogs to add.
 * Optionally save to your vault (localStorage), share via fragment links.
 *
 * Privacy:
 *   - Entries live ONLY in the visitor's browser (localStorage).
 *   - The Worker only serves the static HTML; it never sees a secret.
 *   - Share links encode the secret in the URL fragment (`#`), which by
 *     HTTP spec is never transmitted to the origin server.
 *
 * TOTP: RFC 6238, SHA-1, 30s period, 6 digits — using Web Crypto.
 */

export default {
  async fetch(request) {
    if (request.method !== 'GET') return new Response('Method Not Allowed', { status: 405 });
    const url = new URL(request.url);
    if (url.pathname !== '/' && url.pathname !== '/index.html') {
      return new Response('Not Found', { status: 404 });
    }
    return new Response(HTML, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'public, max-age=300',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'content-security-policy':
          "default-src 'none'; " +
          "style-src 'unsafe-inline'; " +
          "script-src 'unsafe-inline'; " +
          "img-src 'self' data:; " +
          "connect-src 'self'; " +
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
<meta name="description" content="Instant TOTP / 2FA code generator. Paste a secret, get a code. Your secrets never leave your browser.">
<title>2FA Vault</title>
<link rel="icon" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2338bdf8'><path d='M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z'/></svg>">
<style>
  *, *::before, *::after { box-sizing: border-box; }
  :root {
    --bg: #0a0e1a;
    --surface: #161b2e;
    --surface-2: #1e253f;
    --border: #2a3454;
    --text: #f1f5f9;
    --text-dim: #94a3b8;
    --text-faint: #64748b;
    --accent: #38bdf8;
    --accent-2: #0ea5e9;
    --danger: #ef4444;
    --warning: #fbbf24;
    --success: #10b981;
    --r: 14px;
    --r-sm: 8px;
    --shadow: 0 10px 30px rgba(0,0,0,.4);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
  }
  html, body { margin: 0; padding: 0; min-height: 100%; }
  body {
    background:
      radial-gradient(1200px 600px at 10% -10%, rgba(56,189,248,.10), transparent 60%),
      radial-gradient(900px 500px at 110% 10%, rgba(168,85,247,.06), transparent 60%),
      var(--bg);
    color: var(--text);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    padding-bottom: 4rem;
  }
  button { font-family: inherit; }

  /* Header */
  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 1rem 1.25rem;
    max-width: 640px; margin: 0 auto;
  }
  .brand { display: flex; align-items: center; gap: .55rem; font-weight: 700; font-size: 1.05rem; }
  .brand svg { width: 26px; height: 26px; color: var(--accent); }
  .lang {
    background: var(--surface-2); border: 1px solid var(--border); color: var(--text);
    padding: .45rem .5rem .45rem .65rem; border-radius: var(--r-sm);
    font-size: .8rem; font-weight: 600; cursor: pointer;
    appearance: none; -webkit-appearance: none;
    background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12' fill='%2394a3b8'><path d='M3 4.5l3 3 3-3z'/></svg>");
    background-repeat: no-repeat; background-position: right .35rem center;
    padding-right: 1.4rem;
  }
  .lang:hover, .lang:focus { border-color: var(--accent); outline: none; }

  main { max-width: 640px; margin: 0 auto; padding: 0 1.25rem; }

  /* The instant generator */
  .generator {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r);
    padding: 1.25rem;
    box-shadow: var(--shadow);
  }
  .input-stack { display: grid; gap: .65rem; }
  .input-stack input {
    width: 100%; padding: .8rem 1rem;
    background: var(--surface-2); border: 1px solid var(--border);
    border-radius: var(--r-sm); color: var(--text);
    font-size: .95rem; font-family: inherit;
    transition: border-color .15s, background .15s;
  }
  .input-stack input:focus { outline: none; border-color: var(--accent); background: #232b48; }
  #secretInput { font-family: ui-monospace, "SF Mono", Menlo, monospace; letter-spacing: .03em; }

  .secret-row { display: flex; gap: .5rem; }
  .secret-row input { flex: 1; }
  .save-btn {
    width: 48px; height: 48px; flex-shrink: 0;
    background: var(--accent); border: 1px solid var(--accent);
    border-radius: var(--r-sm); color: #001018;
    display: grid; place-items: center; cursor: pointer;
    transition: background .15s, transform .1s;
  }
  .save-btn:hover { background: var(--accent-2); border-color: var(--accent-2); }
  .save-btn:active { transform: scale(.97); }
  .save-btn:disabled { opacity: .4; cursor: not-allowed; }
  .save-btn svg { width: 22px; height: 22px; }

  /* Live preview */
  .preview {
    margin-top: 1rem; padding: 1rem;
    background: rgba(56,189,248,.06);
    border: 1px solid rgba(56,189,248,.25);
    border-radius: var(--r-sm);
    display: grid; gap: .5rem;
  }
  .preview-row {
    display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  }
  .big-code {
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 2.4rem; font-weight: 700;
    color: var(--accent); letter-spacing: .12em;
    cursor: pointer; user-select: all;
    background: none; border: none; padding: 0;
    transition: color .15s, transform .1s;
    line-height: 1.1;
  }
  .big-code:hover { color: var(--accent-2); }
  .big-code:active { transform: scale(.98); }
  .big-code.copied { color: var(--success); }

  .timer { display: flex; align-items: center; gap: .5rem; color: var(--text-dim); font-size: .85rem; }
  .ring { width: 28px; height: 28px; transform: rotate(-90deg); }
  .ring circle { fill: none; stroke-width: 3; }
  .ring .bg { stroke: rgba(148,163,184,.25); }
  .ring .fg {
    stroke: var(--accent);
    stroke-linecap: round;
    transition: stroke-dashoffset .9s linear, stroke .3s;
  }
  .ring.warn .fg { stroke: var(--warning); }
  .ring.danger .fg { stroke: var(--danger); }

  .hint { margin-top: .9rem; color: var(--text-faint); font-size: .85rem; text-align: center; }
  .err {
    margin-top: .9rem; padding: .55rem .75rem;
    background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.3);
    color: #fca5a5; border-radius: var(--r-sm);
    font-size: .85rem;
  }

  /* Saved section */
  .saved-h {
    color: var(--text-dim); font-size: .8rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: .08em;
    margin: 1.5rem 0 .65rem;
  }
  .entries { display: grid; gap: .5rem; }
  .entry {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    padding: .75rem 1rem;
    display: flex; align-items: center; justify-content: space-between;
    gap: 1rem;
    transition: border-color .15s;
  }
  .entry:hover { border-color: rgba(56,189,248,.4); }
  .entry-info { min-width: 0; flex: 1; }
  .entry-name {
    font-size: .85rem; color: var(--text-dim);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    margin-bottom: .15rem;
  }
  .entry-code {
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 1.6rem; font-weight: 600;
    color: var(--accent); letter-spacing: .1em;
    cursor: pointer; user-select: all;
    background: none; border: none; padding: 0;
    transition: color .15s, transform .1s;
  }
  .entry-code:hover { color: var(--accent-2); }
  .entry-code:active { transform: scale(.98); }
  .entry-code.copied { color: var(--success); }
  .entry-code.error { color: var(--danger); font-size: .9rem; letter-spacing: 0; }

  .entry-actions { display: flex; align-items: center; gap: .35rem; flex-shrink: 0; }
  .entry-ring { width: 28px; height: 28px; transform: rotate(-90deg); margin-right: .15rem; }
  .entry-ring circle { fill: none; stroke-width: 3; }
  .entry-ring .bg { stroke: rgba(148,163,184,.25); }
  .entry-ring .fg {
    stroke: var(--accent); stroke-linecap: round;
    transition: stroke-dashoffset .9s linear, stroke .3s;
  }
  .entry-ring.warn .fg { stroke: var(--warning); }
  .entry-ring.danger .fg { stroke: var(--danger); }

  .icon-btn {
    width: 32px; height: 32px; border-radius: 50%;
    background: none; border: none; color: var(--text-dim);
    cursor: pointer; display: grid; place-items: center;
    transition: background .15s, color .15s;
  }
  .icon-btn:hover { background: var(--surface-2); color: var(--text); }
  .icon-btn.danger:hover { color: var(--danger); }
  .icon-btn svg { width: 16px; height: 16px; }

  /* Toast */
  .toast {
    position: fixed; left: 50%; bottom: 1.5rem;
    transform: translateX(-50%) translateY(2rem);
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text); padding: .65rem 1.1rem;
    border-radius: var(--r-sm); font-size: .85rem;
    box-shadow: var(--shadow);
    opacity: 0; pointer-events: none;
    transition: opacity .2s, transform .2s;
    z-index: 100; max-width: 90%;
  }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
  .toast.success { border-color: var(--success); }
  .toast.error { border-color: var(--danger); }

  /* Dialogs (only used for share & import — kept minimal) */
  dialog {
    background: var(--surface); color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--r); padding: 0;
    max-width: 420px; width: calc(100% - 2rem);
    box-shadow: var(--shadow);
  }
  dialog::backdrop {
    background: rgba(0,0,0,.6);
    backdrop-filter: blur(4px); -webkit-backdrop-filter: blur(4px);
  }
  .dlg-body { padding: 1.25rem; }
  .dlg-body h3 { margin: 0 0 .75rem; font-size: 1.05rem; font-weight: 600; }
  .dlg-body p { margin: 0 0 .9rem; color: var(--text-dim); font-size: .85rem; }
  .privacy-note {
    background: rgba(16,185,129,.08); border: 1px solid rgba(16,185,129,.3);
    color: #6ee7b7; padding: .6rem .8rem; border-radius: var(--r-sm);
    font-size: .8rem; line-height: 1.5; margin-bottom: .9rem;
  }
  .share-link {
    width: 100%; padding: .65rem .8rem;
    background: var(--surface-2); border: 1px solid var(--border);
    border-radius: var(--r-sm); color: var(--text);
    font-family: ui-monospace, monospace; font-size: .75rem;
    word-break: break-all;
  }
  .preview-mini-card {
    background: var(--surface-2); border: 1px solid var(--border);
    border-radius: var(--r-sm); padding: .75rem 1rem;
  }
  .preview-mini-name { font-weight: 600; font-size: .95rem; }
  .preview-mini-secret {
    color: var(--text-faint); font-family: ui-monospace, monospace; font-size: .8rem;
    margin-top: .15rem;
  }
  .dlg-actions {
    display: flex; gap: .5rem; justify-content: flex-end;
    padding: .85rem 1.25rem;
    border-top: 1px solid var(--border);
    background: rgba(0,0,0,.15);
    border-bottom-left-radius: var(--r);
    border-bottom-right-radius: var(--r);
  }
  .btn {
    padding: .5rem 1rem; font-size: .85rem; font-weight: 500;
    border-radius: var(--r-sm); cursor: pointer;
    border: 1px solid var(--border); background: var(--surface-2); color: var(--text);
    transition: background .15s, border-color .15s;
  }
  .btn:hover { background: var(--border); }
  .btn.primary {
    background: var(--accent); border-color: var(--accent); color: #001018;
  }
  .btn.primary:hover { background: var(--accent-2); border-color: var(--accent-2); }

  /* Footer */
  .foot {
    text-align: center; padding: 2rem 1rem 1rem;
    color: var(--text-faint); font-size: .75rem;
    max-width: 640px; margin: 0 auto;
  }
  .foot a { color: var(--text-dim); }

  @media (max-width: 480px) {
    .big-code { font-size: 2rem; letter-spacing: .1em; }
    .entry-code { font-size: 1.4rem; }
    main, header, .foot { padding-left: 1rem; padding-right: 1rem; }
  }
</style>
</head>
<body>

<header>
  <div class="brand">
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
    <span>2FA Vault</span>
  </div>
  <select id="langSwitcher" class="lang" data-i18n-attr="aria-label:aria.lang">
    <option value="en">EN</option>
    <option value="id">ID</option>
  </select>
</header>

<main>
  <section class="generator">
    <div class="input-stack">
      <input id="nameInput" type="text" autocomplete="off" maxlength="60"
             data-i18n-attr="placeholder:placeholder.name">
      <div class="secret-row">
        <input id="secretInput" type="text" autocomplete="off" spellcheck="false"
               data-i18n-attr="placeholder:placeholder.secret">
        <button id="saveBtn" class="save-btn" type="button" disabled
                data-i18n-attr="title:btn.save,aria-label:btn.save">
          <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
          </svg>
        </button>
      </div>
    </div>

    <div id="preview" class="preview" hidden>
      <div class="preview-row">
        <button id="previewCode" class="big-code" type="button"
                data-i18n-attr="title:btn.copy,aria-label:btn.copy">000 000</button>
        <div class="timer">
          <svg id="previewRingSvg" class="ring" viewBox="0 0 36 36">
            <circle class="bg" cx="18" cy="18" r="16"></circle>
            <circle id="previewRing" class="fg" cx="18" cy="18" r="16"></circle>
          </svg>
          <span id="previewCountdown">30s</span>
        </div>
      </div>
    </div>

    <div id="hint" class="hint" data-i18n="hint.empty">
      Paste your secret key to see the code instantly.
    </div>
    <div id="errorMsg" class="err" hidden></div>
  </section>

  <h2 id="savedHeading" class="saved-h" data-i18n="saved.heading" hidden>Saved</h2>
  <div id="entries" class="entries"></div>
</main>

<footer class="foot">
  <span data-i18n="foot.privacy">Your secrets never leave your browser.</span>
  <a href="https://datatracker.ietf.org/doc/html/rfc6238" target="_blank" rel="noopener">RFC 6238</a>
  <span data-i18n="foot.tech">TOTP &middot; running on Cloudflare Workers.</span>
</footer>

<dialog id="shareDialog">
  <div class="dlg-body">
    <h3 data-i18n="share.title">Shareable link</h3>
    <div class="privacy-note" data-i18n="share.privacy">
      The secret is encoded after the # in the URL. Per HTTP spec, fragments are never
      transmitted to the server &mdash; this Worker, Cloudflare, and any proxy in
      between cannot read it.
    </div>
    <input id="shareLink" class="share-link" readonly>
  </div>
  <div class="dlg-actions">
    <button class="btn" type="button" data-close data-i18n="btn.close">Close</button>
    <button id="copyShareBtn" class="btn primary" type="button" data-i18n="btn.copylink">Copy link</button>
  </div>
</dialog>

<dialog id="importDialog">
  <div class="dlg-body">
    <h3 data-i18n="import.title">Import shared 2FA</h3>
    <p data-i18n="import.desc">
      Someone shared a 2FA entry with you. The secret was decoded locally in your browser.
    </p>
    <div id="importPreview"></div>
  </div>
  <div class="dlg-actions">
    <button class="btn" type="button" data-close data-i18n="btn.discard">Discard</button>
    <button id="importBtn" class="btn primary" type="button" data-i18n="btn.import">Add to vault</button>
  </div>
</dialog>

<div id="toast" class="toast" role="status" aria-live="polite"></div>

<script>
(() => {
'use strict';

// ============================================================
// i18n
// ============================================================
const LOCALES = {
  en: {
    'aria.lang': 'Language',
    'placeholder.name': 'Name (optional)',
    'placeholder.secret': 'Paste your secret key (Base32)',
    'hint.empty': 'Paste your secret key to see the code instantly.',
    'btn.save': 'Save to vault',
    'btn.copy': 'Click to copy',
    'btn.copied': 'Copied',
    'btn.share': 'Share via link',
    'btn.delete': 'Delete',
    'btn.close': 'Close',
    'btn.copylink': 'Copy link',
    'btn.discard': 'Discard',
    'btn.import': 'Add to vault',
    'saved.heading': 'Saved',
    'share.title': 'Shareable link',
    'share.privacy': 'The secret is encoded after the # in the URL. Per HTTP spec, fragments are never transmitted to the server \\u2014 this Worker, Cloudflare, and any proxy in between cannot read it.',
    'import.title': 'Import shared 2FA',
    'import.desc': 'Someone shared a 2FA entry with you. The secret was decoded locally in your browser.',
    'foot.privacy': 'Your secrets never leave your browser.',
    'foot.tech': 'TOTP \\u00b7 running on Cloudflare Workers.',
    'untitled': 'Untitled',
    'aria.copyCode': 'Copy code for {0}',
    'aria.deleteEntry': 'Delete {0}',
    'aria.shareEntry': 'Share {0}',
    'meta.seconds': '{0}s',
    'toast.codeCopied': 'Code copied',
    'toast.linkCopied': 'Link copied',
    'toast.copyFailed': 'Could not copy',
    'toast.saved': 'Saved to vault',
    'toast.deleted': 'Deleted',
    'toast.imported': 'Imported',
    'toast.alreadyInVault': 'Already in your vault',
    'toast.invalidShareLink': 'Invalid share link',
    'err.invalidSecret': 'Invalid secret key',
    'err.secretTooShort': 'Secret too short (need at least 80 bits)',
  },
  id: {
    'aria.lang': 'Bahasa',
    'placeholder.name': 'Nama (opsional)',
    'placeholder.secret': 'Paste secret key (Base32)',
    'hint.empty': 'Paste secret key, kode langsung muncul di sini.',
    'btn.save': 'Simpan ke vault',
    'btn.copy': 'Klik untuk menyalin',
    'btn.copied': 'Tersalin',
    'btn.share': 'Bagikan lewat link',
    'btn.delete': 'Hapus',
    'btn.close': 'Tutup',
    'btn.copylink': 'Salin link',
    'btn.discard': 'Buang',
    'btn.import': 'Tambah ke vault',
    'saved.heading': 'Tersimpan',
    'share.title': 'Link untuk dibagikan',
    'share.privacy': 'Secret di-encode setelah tanda # di URL. Sesuai spec HTTP, fragment tidak pernah dikirim ke server \\u2014 Worker ini, Cloudflare, maupun proxy mana pun tidak bisa membacanya.',
    'import.title': 'Import 2FA dari link',
    'import.desc': 'Seseorang membagikan entry 2FA padamu. Secret-nya didecode lokal di browsermu.',
    'foot.privacy': 'Secret kamu tidak pernah keluar dari browser.',
    'foot.tech': 'TOTP \\u00b7 berjalan di Cloudflare Workers.',
    'untitled': 'Tanpa nama',
    'aria.copyCode': 'Salin kode untuk {0}',
    'aria.deleteEntry': 'Hapus {0}',
    'aria.shareEntry': 'Bagikan {0}',
    'meta.seconds': '{0}d',
    'toast.codeCopied': 'Kode tersalin',
    'toast.linkCopied': 'Link tersalin',
    'toast.copyFailed': 'Gagal menyalin',
    'toast.saved': 'Tersimpan',
    'toast.deleted': 'Terhapus',
    'toast.imported': 'Berhasil import',
    'toast.alreadyInVault': 'Sudah ada di vault',
    'toast.invalidShareLink': 'Link tidak valid',
    'err.invalidSecret': 'Secret key tidak valid',
    'err.secretTooShort': 'Secret terlalu pendek (minimal 80 bit)',
  },
};

const LANG_KEY = '2fa-vault.lang.v1';
let lang = (() => {
  try {
    const s = localStorage.getItem(LANG_KEY);
    if (s && LOCALES[s]) return s;
  } catch {}
  return (navigator.language || 'en').toLowerCase().startsWith('id') ? 'id' : 'en';
})();

function t(key, ...args) {
  const dict = LOCALES[lang] || LOCALES.en;
  const tpl = dict[key] || LOCALES.en[key] || key;
  return args.length
    ? tpl.replace(/\\{(\\d+)\\}/g, (_, i) => String(args[+i]))
    : tpl;
}

function applyTranslations() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-attr]').forEach(el => {
    el.getAttribute('data-i18n-attr').split(',').forEach(pair => {
      const [attr, key] = pair.split(':').map(s => s.trim());
      if (attr && key) el.setAttribute(attr, t(key));
    });
  });
}

// ============================================================
// Base32 + TOTP (RFC 6238, SHA-1 / 30s / 6 digits)
// ============================================================
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input) {
  const cleaned = String(input).replace(/\\s+/g, '').replace(/=+$/, '').toUpperCase();
  if (!cleaned) throw new Error('empty');
  let bits = '';
  for (const ch of cleaned) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error('bad-char');
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

async function totp(secret, ts = Date.now()) {
  const period = 30, digits = 6;
  const counter = Math.floor(ts / 1000 / period);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const keyBytes = base32Decode(secret);
  if (keyBytes.length < 10) throw new Error('too-short');
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const off = sig[sig.length - 1] & 0x0f;
  const num = ((sig[off] & 0x7f) << 24) |
              ((sig[off + 1] & 0xff) << 16) |
              ((sig[off + 2] & 0xff) << 8) |
              (sig[off + 3] & 0xff);
  return String(num % 10 ** digits).padStart(digits, '0');
}

function fmtCode(code) {
  return code.length === 6 ? code.slice(0, 3) + ' ' + code.slice(3) : code;
}

// ============================================================
// Storage
// ============================================================
const STORAGE = '2fa-vault.entries.v1';

function loadEntries() {
  try {
    const raw = localStorage.getItem(STORAGE);
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch { return []; }
}

function saveEntries() {
  try { localStorage.setItem(STORAGE, JSON.stringify(entries)); } catch {}
}

function newId() {
  return 'e_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

let entries = loadEntries();
let pendingImport = null;

// ============================================================
// Share-via-fragment (base64url JSON; never sent to the server)
// ============================================================
function b64urlEncode(str) {
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
  const payload = { v: 1, n: entry.name, s: entry.secret };
  return location.origin + location.pathname + '#i=' + b64urlEncode(JSON.stringify(payload));
}
function parseImportFragment() {
  const h = location.hash;
  if (!h.startsWith('#i=')) return null;
  try {
    const data = JSON.parse(b64urlDecode(h.slice(3)));
    if (!data.s) throw 0;
    return {
      name: String(data.n || ''),
      secret: String(data.s).replace(/\\s+/g, '').toUpperCase(),
    };
  } catch {
    return false; // signal a malformed fragment
  }
}

// ============================================================
// Toast + Clipboard
// ============================================================
const $toast = document.getElementById('toast');
let toastTimer;
function toast(msg, kind = '') {
  $toast.textContent = msg;
  $toast.className = 'toast show ' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $toast.className = 'toast ' + kind; }, 1800);
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {}
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch { return false; }
}

// ============================================================
// DOM refs
// ============================================================
const $name = document.getElementById('nameInput');
const $secret = document.getElementById('secretInput');
const $saveBtn = document.getElementById('saveBtn');
const $preview = document.getElementById('preview');
const $previewCode = document.getElementById('previewCode');
const $previewRingSvg = document.getElementById('previewRingSvg');
const $previewRing = document.getElementById('previewRing');
const $previewCountdown = document.getElementById('previewCountdown');
const $hint = document.getElementById('hint');
const $errorMsg = document.getElementById('errorMsg');
const $entries = document.getElementById('entries');
const $savedHeading = document.getElementById('savedHeading');
const $langSwitcher = document.getElementById('langSwitcher');

// ============================================================
// Live preview (instant)
// ============================================================
const RING_C = 2 * Math.PI * 16;
$previewRing.setAttribute('stroke-dasharray', String(RING_C));

let currentSecret = ''; // last validated secret typed into the secret input
let currentCode = '';

async function updatePreview() {
  const raw = $secret.value.replace(/\\s+/g, '').toUpperCase();
  if (!raw) {
    currentSecret = ''; currentCode = '';
    $preview.hidden = true; $hint.hidden = false; $errorMsg.hidden = true;
    $saveBtn.disabled = true;
    return;
  }
  try {
    const code = await totp(raw);
    currentSecret = raw; currentCode = code;
    $previewCode.textContent = fmtCode(code);
    $previewCode.classList.remove('copied');
    $preview.hidden = false; $hint.hidden = true; $errorMsg.hidden = true;
    $saveBtn.disabled = false;
  } catch (e) {
    currentSecret = ''; currentCode = '';
    $preview.hidden = true; $hint.hidden = true;
    $errorMsg.hidden = false;
    $errorMsg.textContent = e.message === 'too-short'
      ? t('err.secretTooShort')
      : t('err.invalidSecret');
    $saveBtn.disabled = true;
  }
}

// ============================================================
// Update rings + codes every second
// ============================================================
let lastCounter = Math.floor(Date.now() / 1000 / 30);
async function tickRings() {
  const remaining = 30 - ((Date.now() / 1000) % 30);
  const offset = RING_C - (remaining / 30) * RING_C;
  const sec = Math.ceil(remaining);

  // Preview ring
  $previewRing.style.strokeDashoffset = String(offset);
  $previewCountdown.textContent = t('meta.seconds', sec);
  $previewRingSvg.classList.toggle('warn', remaining <= 10 && remaining > 5);
  $previewRingSvg.classList.toggle('danger', remaining <= 5);

  // Saved entry rings
  for (const card of $entries.children) {
    const ringSvg = card.querySelector('.entry-ring');
    const fg = ringSvg && ringSvg.querySelector('.fg');
    if (fg) fg.style.strokeDashoffset = String(offset);
    if (ringSvg) {
      ringSvg.classList.toggle('warn', remaining <= 10 && remaining > 5);
      ringSvg.classList.toggle('danger', remaining <= 5);
    }
  }

  // On counter rollover: refresh all codes
  const counter = Math.floor(Date.now() / 1000 / 30);
  if (counter !== lastCounter) {
    lastCounter = counter;
    if (currentSecret) updatePreview();
    refreshSavedCodes();
  }
}

async function refreshSavedCodes() {
  for (const e of entries) {
    const card = $entries.querySelector('[data-id="' + e.id + '"]');
    if (!card) continue;
    const codeEl = card.querySelector('.entry-code');
    if (!codeEl) continue;
    try {
      const code = await totp(e.secret);
      if (!codeEl.classList.contains('copied')) {
        codeEl.textContent = fmtCode(code);
      }
      codeEl.classList.remove('error');
      codeEl.dataset.code = code;
    } catch {
      codeEl.textContent = '------';
      codeEl.classList.add('error');
      delete codeEl.dataset.code;
    }
  }
}

// ============================================================
// Render saved
// ============================================================
function render() {
  $entries.innerHTML = '';
  $savedHeading.hidden = entries.length === 0;
  for (const e of entries) {
    $entries.appendChild(renderEntry(e));
  }
  refreshSavedCodes();
}

function renderEntry(entry) {
  const name = entry.name || t('untitled');

  const card = document.createElement('div');
  card.className = 'entry';
  card.dataset.id = entry.id;

  const info = document.createElement('div');
  info.className = 'entry-info';

  const nameEl = document.createElement('div');
  nameEl.className = 'entry-name';
  nameEl.textContent = name;

  const codeBtn = document.createElement('button');
  codeBtn.type = 'button';
  codeBtn.className = 'entry-code';
  codeBtn.textContent = '------';
  codeBtn.title = t('aria.copyCode', name);
  codeBtn.setAttribute('aria-label', t('aria.copyCode', name));
  codeBtn.addEventListener('click', async () => {
    const code = codeBtn.dataset.code;
    if (!code) return;
    const ok = await copyText(code);
    if (ok) {
      codeBtn.classList.add('copied');
      setTimeout(() => codeBtn.classList.remove('copied'), 800);
      toast(t('toast.codeCopied'), 'success');
    } else {
      toast(t('toast.copyFailed'), 'error');
    }
  });

  info.append(nameEl, codeBtn);

  const actions = document.createElement('div');
  actions.className = 'entry-actions';

  // Progress ring
  const ringSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  ringSvg.setAttribute('class', 'entry-ring');
  ringSvg.setAttribute('viewBox', '0 0 36 36');
  const bg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  bg.setAttribute('class', 'bg');
  bg.setAttribute('cx', '18'); bg.setAttribute('cy', '18'); bg.setAttribute('r', '16');
  const fg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  fg.setAttribute('class', 'fg');
  fg.setAttribute('cx', '18'); fg.setAttribute('cy', '18'); fg.setAttribute('r', '16');
  fg.setAttribute('stroke-dasharray', String(RING_C));
  fg.setAttribute('stroke-dashoffset', '0');
  ringSvg.append(bg, fg);

  // Share button
  const shareBtn = document.createElement('button');
  shareBtn.type = 'button';
  shareBtn.className = 'icon-btn';
  shareBtn.title = t('btn.share');
  shareBtn.setAttribute('aria-label', t('aria.shareEntry', name));
  shareBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92s2.92-1.31 2.92-2.92-1.31-2.92-2.92-2.92z"/></svg>';
  shareBtn.addEventListener('click', () => openShare(entry));

  // Delete button
  const delBtn = document.createElement('button');
  delBtn.type = 'button';
  delBtn.className = 'icon-btn danger';
  delBtn.title = t('btn.delete');
  delBtn.setAttribute('aria-label', t('aria.deleteEntry', name));
  delBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>';
  delBtn.addEventListener('click', () => {
    entries = entries.filter(e => e.id !== entry.id);
    saveEntries();
    render();
    toast(t('toast.deleted'));
  });

  actions.append(ringSvg, shareBtn, delBtn);
  card.append(info, actions);
  return card;
}

// ============================================================
// Save the current preview entry
// ============================================================
async function saveCurrent() {
  if (!currentSecret) { $secret.focus(); return; }
  const name = $name.value.trim();

  if (entries.find(e => e.secret === currentSecret)) {
    toast(t('toast.alreadyInVault'));
  } else {
    entries.push({ id: newId(), name, secret: currentSecret });
    saveEntries();
    render();
    toast(t('toast.saved'), 'success');
  }
  $name.value = '';
  $secret.value = '';
  currentSecret = ''; currentCode = '';
  $preview.hidden = true;
  $hint.hidden = false;
  $errorMsg.hidden = true;
  $saveBtn.disabled = true;
  $secret.focus();
}

// ============================================================
// Wire up
// ============================================================
let debounceTimer;
$secret.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(updatePreview, 80);
});
$secret.addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); saveCurrent(); }
});
$name.addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); $secret.focus(); }
});
$saveBtn.addEventListener('click', saveCurrent);

$previewCode.addEventListener('click', async () => {
  if (!currentCode) return;
  const ok = await copyText(currentCode);
  if (ok) {
    $previewCode.classList.add('copied');
    setTimeout(() => $previewCode.classList.remove('copied'), 800);
    toast(t('toast.codeCopied'), 'success');
  } else {
    toast(t('toast.copyFailed'), 'error');
  }
});

$langSwitcher.addEventListener('change', () => {
  lang = $langSwitcher.value;
  try { localStorage.setItem(LANG_KEY, lang); } catch {}
  applyTranslations();
  render();
});

// Dialog backdrop / close-buttons
document.querySelectorAll('dialog').forEach(d => {
  d.addEventListener('click', e => {
    if (e.target === d) d.close();
    if (e.target.closest('[data-close]')) d.close();
  });
});

// Share dialog
function openShare(entry) {
  const link = buildShareLink(entry);
  const $link = document.getElementById('shareLink');
  $link.value = link;
  document.getElementById('copyShareBtn').dataset.link = link;
  const dlg = document.getElementById('shareDialog');
  if (typeof dlg.showModal === 'function') dlg.showModal();
  else dlg.setAttribute('open', '');
  setTimeout(() => { $link.select(); }, 50);
}
document.getElementById('copyShareBtn').addEventListener('click', async (e) => {
  const link = e.currentTarget.dataset.link;
  if (!link) return;
  const ok = await copyText(link);
  toast(ok ? t('toast.linkCopied') : t('toast.copyFailed'), ok ? 'success' : 'error');
});

// Import dialog
document.getElementById('importBtn').addEventListener('click', () => {
  if (!pendingImport) return;
  if (entries.find(e => e.secret === pendingImport.secret)) {
    toast(t('toast.alreadyInVault'));
  } else {
    entries.push({ id: newId(), name: pendingImport.name, secret: pendingImport.secret });
    saveEntries();
    render();
    toast(t('toast.imported'), 'success');
  }
  pendingImport = null;
  document.getElementById('importDialog').close();
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
$langSwitcher.value = lang;
applyTranslations();
render();
tickRings();
setInterval(tickRings, 1000);

// Handle import-from-link
const incoming = parseImportFragment();
if (incoming === false) {
  toast(t('toast.invalidShareLink'), 'error');
  history.replaceState(null, '', location.pathname + location.search);
} else if (incoming) {
  pendingImport = incoming;
  const $preview = document.getElementById('importPreview');
  $preview.innerHTML = '';
  const card = document.createElement('div');
  card.className = 'preview-mini-card';
  const n = document.createElement('div');
  n.className = 'preview-mini-name';
  n.textContent = incoming.name || t('untitled');
  const s = document.createElement('div');
  s.className = 'preview-mini-secret';
  s.textContent = incoming.secret.slice(0, 4) + '\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022';
  card.append(n, s);
  $preview.appendChild(card);
  const dlg = document.getElementById('importDialog');
  if (typeof dlg.showModal === 'function') dlg.showModal();
  else dlg.setAttribute('open', '');
}

// Focus the secret input on load (instant by default)
setTimeout(() => $secret.focus(), 50);
})();
</script>
</body>
</html>`;
