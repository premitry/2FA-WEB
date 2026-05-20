# 2FA Vault

A privacy-first **TOTP / 2FA code generator** that runs on Cloudflare Workers.
Think Google Authenticator / Authy, but as a single-page web app you can self-host
on the free Workers tier.

## Highlights

- **Secrets never touch the server.** Entries are stored in the browser's
  `localStorage` only. The Worker just serves the static HTML/JS — there is no
  API, no database, no KV namespace involved.
- **Per-browser vault.** When user A opens the app they see only their own
  entries. User B on a different browser sees nothing — no leakage between
  visitors.
- **Save / share via link.** Generate a shareable URL whose secret is encoded in
  the URL **fragment** (`#import=…`). By the HTTP spec, fragments are *never*
  transmitted to the origin server, so neither this Worker nor Cloudflare nor
  any proxy can see what is being shared.
- **Standards compliant.** TOTP per [RFC 6238][rfc6238] using the Web Crypto
  API. Supports 6/7/8 digit codes, configurable period, and `SHA1` /
  `SHA256` / `SHA512` algorithms. Imports `otpauth://` URIs from QR code
  scanners.
- **Single file, zero dependencies.** Everything (HTML, CSS, JS) is bundled
  inside `src/worker.js`. No build step required.

[rfc6238]: https://datatracker.ietf.org/doc/html/rfc6238

## How privacy works

| Concern | Mechanism |
| --- | --- |
| User A's entries leaking to user B | All entries live in `localStorage`, scoped to the visitor's browser & origin. |
| Worker logging or storing secrets | The Worker only handles `GET /` and returns static HTML. It never receives a secret. |
| Server seeing shared link payload | Share links use the URL fragment (`#`), which browsers strip before sending the request to the server. |
| Cross-site embedding | CSP `frame-ancestors 'none'` prevents the page from being framed. |

## Local development

```bash
npm install
npm run dev      # runs `wrangler dev`
```

Open http://localhost:8787.

## Deploy to Cloudflare

1. Install Wrangler and authenticate:
   ```bash
   npm install
   npx wrangler login
   ```
2. Deploy:
   ```bash
   npm run deploy
   ```
3. Wrangler will print a `*.workers.dev` URL — open it in your browser.

To attach a custom domain, edit the `[[routes]]` block in `wrangler.toml`.

## Usage

1. **Add an entry.** Click *+ Add* and either fill the form or paste an
   `otpauth://totp/...` URI (the same string a QR code encodes).
2. **Copy a code.** Click the 6-digit code on a card. It's copied to your
   clipboard; the progress ring shows how many seconds remain on the current
   window.
3. **Share.** Open the entry's `⋮` menu → *Share via link*. Copy the resulting
   URL and send it through any channel. The recipient sees a confirmation
   prompt before importing into their own vault.
4. **Edit / Delete.** Same `⋮` menu.

## Project structure

```
src/worker.js     # Cloudflare Worker (serves the entire app)
wrangler.toml     # Cloudflare config
package.json      # Scripts & wrangler dev dependency
```

## Security notes

- This is **not** an end-to-end encrypted product. If your device is
  compromised, an attacker can read the vault from `localStorage`.
- Share links are unauthenticated — anyone with the URL can import the entry.
  Treat them like the original secret.
- The HTML is served with a strict Content-Security-Policy: no remote scripts,
  no framing, no form submission, no unexpected network requests.

## License

MIT
