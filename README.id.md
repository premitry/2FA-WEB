# 2FA Vault

[English](README.md) · **Bahasa Indonesia**

Aplikasi web **generator kode TOTP / 2FA** yang mengutamakan privasi dan
berjalan di Cloudflare Workers. Anggap saja seperti Google Authenticator /
Authy, tapi dalam bentuk single-page web app yang bisa kamu host sendiri lewat
tier gratis Cloudflare Workers.

## Fitur Utama

- **Secret tidak pernah menyentuh server.** Semua entry hanya disimpan di
  `localStorage` browser pengunjung. Worker hanya menyajikan HTML/JS statis —
  tidak ada API, database, atau KV namespace.
- **Vault per-browser.** Saat user A membuka aplikasi, dia hanya melihat
  entry-nya sendiri. User B di browser lain tidak melihat apa-apa — tidak ada
  kebocoran antar pengunjung.
- **Simpan / bagikan lewat link.** Bangkitkan URL yang bisa dibagikan, di mana
  secret-nya di-encode di **fragment URL** (`#import=…`). Sesuai spesifikasi
  HTTP, fragment *tidak pernah* dikirim ke server origin — jadi Worker ini,
  Cloudflare, maupun proxy mana pun tidak bisa melihat isi link yang dibagikan.
- **Sesuai standar.** Implementasi TOTP mengikuti [RFC 6238][rfc6238]
  menggunakan Web Crypto API. Mendukung kode 6/7/8 digit, periode bisa diatur,
  dan algoritma `SHA1` / `SHA256` / `SHA512`. Bisa import URI `otpauth://`
  dari hasil scan QR code.
- **Satu file, tanpa dependency.** Semua (HTML, CSS, JS) di-bundle dalam
  `src/worker.js`. Tidak perlu build step.

[rfc6238]: https://datatracker.ietf.org/doc/html/rfc6238

## Cara Kerja Privasi

| Kekhawatiran | Mekanisme |
| --- | --- |
| Entry user A bocor ke user B | Semua entry ada di `localStorage`, dibatasi per browser & origin pengunjung. |
| Worker mencatat atau menyimpan secret | Worker hanya menangani `GET /` dan mengembalikan HTML statis. Tidak pernah menerima secret. |
| Server melihat isi share link | Share link memakai fragment URL (`#`), yang dibuang browser sebelum request dikirim ke server. |
| Disisipkan di situs lain (clickjacking) | CSP `frame-ancestors 'none'` mencegah halaman di-frame. |

## Development Lokal

```bash
npm install
npm run dev      # menjalankan `wrangler dev`
```

Buka http://localhost:8787.

## Deploy ke Cloudflare

1. Install Wrangler dan login:
   ```bash
   npm install
   npx wrangler login
   ```
2. Deploy:
   ```bash
   npm run deploy
   ```
3. Wrangler akan mencetak URL `*.workers.dev` — buka di browser.

Untuk pakai domain sendiri, edit blok `[[routes]]` di `wrangler.toml`.

## Cara Pakai

1. **Tambah entry.** Klik *+ Add* lalu isi form, atau paste URI
   `otpauth://totp/...` (string yang sama yang di-encode di QR code).
2. **Copy kode.** Klik angka 6-digit pada kartu. Kode tersalin ke clipboard;
   ring progress menunjukkan berapa detik tersisa sebelum kode berganti.
3. **Bagikan.** Buka menu `⋮` pada entry → *Share via link*. Salin URL yang
   muncul dan kirim lewat channel apa pun. Penerima akan mendapat dialog
   konfirmasi sebelum entry masuk ke vault mereka.
4. **Edit / Hapus.** Lewat menu `⋮` yang sama.

## Struktur Project

```
src/worker.js     # Cloudflare Worker (menyajikan seluruh aplikasi)
wrangler.toml     # Konfigurasi Cloudflare
package.json      # Script & dependency wrangler
```

## Catatan Keamanan

- Ini **bukan** produk dengan end-to-end encryption. Kalau perangkatmu
  dibobol, attacker bisa membaca vault dari `localStorage`.
- Share link tidak terotentikasi — siapa pun yang punya URL-nya bisa import
  entry tersebut. Perlakukan seperti secret aslinya.
- HTML disajikan dengan Content-Security-Policy yang ketat: tidak ada script
  eksternal, tidak boleh di-frame, tidak ada form submission, tidak ada
  request jaringan tak terduga.

## Lisensi

MIT
