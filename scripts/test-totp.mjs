// Smoke-test the TOTP implementation against RFC 6238 test vectors.
// We mirror the same algorithm used in src/worker.js verbatim.
import { webcrypto as crypto } from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input) {
  const cleaned = input.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  let bits = '';
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid Base32 character: ' + ch);
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

async function generateTOTP(secret, opts = {}) {
  const digits = opts.digits || 6;
  const period = opts.period || 30;
  const algorithm = opts.algorithm || 'SHA-1';
  const t = Math.floor(((opts.timestamp ?? Date.now()) / 1000) / period);

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

// RFC 6238 Appendix B uses these ASCII secrets:
//   SHA-1   "12345678901234567890"                                         (20 bytes)
//   SHA-256 "12345678901234567890123456789012"                             (32 bytes)
//   SHA-512 "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
function asciiToBase32(s) {
  let bits = '';
  for (const ch of s) bits += ch.charCodeAt(0).toString(2).padStart(8, '0');
  while (bits.length % 5) bits += '0';
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    out += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  }
  return out;
}

const SECRET_SHA1 = asciiToBase32('12345678901234567890');
const SECRET_SHA256 = asciiToBase32('12345678901234567890123456789012');
const SECRET_SHA512 = asciiToBase32('1234567890123456789012345678901234567890123456789012345678901234');

const vectors = [
  { ts: 59,           algo: 'SHA-1',   secret: SECRET_SHA1,   expect: '94287082' },
  { ts: 59,           algo: 'SHA-256', secret: SECRET_SHA256, expect: '46119246' },
  { ts: 59,           algo: 'SHA-512', secret: SECRET_SHA512, expect: '90693936' },
  { ts: 1111111109,   algo: 'SHA-1',   secret: SECRET_SHA1,   expect: '07081804' },
  { ts: 1111111111,   algo: 'SHA-1',   secret: SECRET_SHA1,   expect: '14050471' },
  { ts: 1234567890,   algo: 'SHA-1',   secret: SECRET_SHA1,   expect: '89005924' },
  { ts: 2000000000,   algo: 'SHA-1',   secret: SECRET_SHA1,   expect: '69279037' },
  { ts: 20000000000,  algo: 'SHA-1',   secret: SECRET_SHA1,   expect: '65353130' },
];

let pass = 0, fail = 0;
for (const v of vectors) {
  const code = await generateTOTP(v.secret, {
    timestamp: v.ts * 1000,
    algorithm: v.algo,
    digits: 8,
    period: 30,
  });
  const ok = code === v.expect;
  console.log(
    `${ok ? 'PASS' : 'FAIL'}  T=${String(v.ts).padStart(11)}  ${v.algo}  expected=${v.expect}  got=${code}`
  );
  if (ok) pass++; else fail++;
}
console.log(`\n${pass}/${vectors.length} passed.`);
process.exit(fail ? 1 : 0);
