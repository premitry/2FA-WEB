// Smoke-test the Worker handler: import it, invoke fetch, validate response.
import worker from '../src/worker.js';

async function check(name, fn) {
  try { await fn(); console.log('PASS  ' + name); return true; }
  catch (e) { console.error('FAIL  ' + name + ': ' + e.message); return false; }
}

let ok = 0, total = 0;
async function expect(name, fn) { total++; if (await check(name, fn)) ok++; }

await expect('GET / returns 200 + text/html', async () => {
  const res = await worker.fetch(new Request('https://x/'));
  if (res.status !== 200) throw new Error('status=' + res.status);
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('text/html')) throw new Error('content-type=' + ct);
});

await expect('GET / body is well-formed HTML', async () => {
  const res = await worker.fetch(new Request('https://x/'));
  const body = await res.text();
  for (const tag of ['<!DOCTYPE html>', '<title>2FA Vault</title>', '</html>']) {
    if (!body.includes(tag)) throw new Error('missing: ' + tag);
  }
  // Make sure template-literal escapes survived (regex should be \s+, not \\s+ or \s+ doubled)
  if (body.includes('\\\\s+')) throw new Error('Double-escaped regex leaked into HTML');
  if (!body.includes('replace(/\\s+/g')) throw new Error('Expected /\\s+/g regex not found');
});

await expect('GET /unknown returns 404', async () => {
  const res = await worker.fetch(new Request('https://x/whatever'));
  if (res.status !== 404) throw new Error('status=' + res.status);
});

await expect('POST / returns 405', async () => {
  const res = await worker.fetch(new Request('https://x/', { method: 'POST' }));
  if (res.status !== 405) throw new Error('status=' + res.status);
});

await expect('Security headers present', async () => {
  const res = await worker.fetch(new Request('https://x/'));
  const csp = res.headers.get('content-security-policy') || '';
  if (!csp.includes("frame-ancestors 'none'")) throw new Error('CSP missing frame-ancestors');
  if (res.headers.get('x-content-type-options') !== 'nosniff') throw new Error('missing X-Content-Type-Options');
});

console.log('\n' + ok + '/' + total + ' passed.');
process.exit(ok === total ? 0 : 1);
