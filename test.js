'use strict';
// Uji integrasi end-to-end: node test.js
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'bm-'));
process.env.POW_BITS = '10';
const { server } = require('./bengkel-core.cjs');

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m); };
let base;
const call = async (m, p, body, tok) => {
  const r = await fetch(base + p, { method: m, headers: { 'content-type': 'application/json', ...(tok ? { authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined });
  return { s: r.status, j: await r.json().catch(() => ({})) };
};
const mkKey = () => crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
const sign = (priv, nonce) => crypto.sign('sha256', Buffer.from(nonce), { key: priv, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64');
const pow = (nonce, bits) => { for (let c = 0; ; c++) { const h = crypto.createHash('sha256').update(nonce + c).digest(); let b = 0; for (const x of h) { if (!x) { b += 8; continue; } b += Math.clz32(x) - 24; break; } if (b >= bits) return c; } };
async function register(kp) {
  const ch = (await call('GET', '/api/challenge')).j;
  const pub = kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return call('POST', '/api/auth/register', { publicKey: pub, cid: ch.cid, counter: pow(ch.nonce, ch.bits), sig: sign(kp.privateKey, ch.nonce) });
}

(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + server.address().port;
  const [kOwner, kAdmin, kBuyer, kWeak] = [mkKey(), mkKey(), mkKey(), crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })];

  const owner = (await register(kOwner)).j, adm = (await register(kAdmin)).j, buyer = (await register(kBuyer)).j;
  ok(owner.token && adm.token && buyer.token, 'registrasi tanpa email/telepon (kunci RSA-4096)');
  ok((await register(kWeak)).s === 400, 'kunci RSA-2048 ditolak (minimal 2048x2)');

  // replay / tanda tangan salah
  const ch = (await call('GET', '/api/challenge')).j;
  ok((await call('POST', '/api/auth/login', { userId: buyer.userId, cid: ch.cid, sig: sign(kOwner.privateKey, ch.nonce) })).s === 401, 'login dengan kunci salah ditolak');
  ok((await call('POST', '/api/auth/login', { userId: buyer.userId, cid: ch.cid, sig: sign(kBuyer.privateKey, ch.nonce) })).s === 401, 'challenge sekali pakai (anti replay)');
  const ch2 = (await call('GET', '/api/challenge')).j;
  ok((await call('POST', '/api/auth/login', { userId: buyer.userId, cid: ch2.cid, sig: sign(kBuyer.privateKey, ch2.nonce) })).s === 200, 'login challenge-response sukses');
  ok((await call('GET', '/api/me')).s === 401, 'endpoint privat butuh sesi');

  // bengkel
  const shop = await call('POST', '/api/shops', { name: 'Bengkel Abcd Racing', address: 'Jl. Merdeka 1, Bandung', lat: -6.9175, lng: 107.6191, description: 'Spesialis knalpot' }, owner.token);
  ok(shop.s === 200, 'daftar bengkel + lokasi'); const sid = shop.j.id;
  ok((await call('POST', '/api/shops', { name: 'x', address: 'y', lat: 999, lng: 0 }, owner.token)).s === 400, 'validasi koordinat');
  const today = (await call('GET', '/api/meta')).j.today;
  const p1 = (await call('POST', `/api/shops/${sid}/products`, { name: 'Knalpot Racing 4-2-1', category: 'Knalpot', price: 850000, stock: 5, payment: 'both', date: today }, owner.token)).j;
  const p2 = (await call('POST', `/api/shops/${sid}/products`, { name: 'Lampu LED H4', category: 'Lampu', price: 120000, stock: 3, payment: 'cod', date: today }, owner.token)).j;
  ok(p1.id && p2.id, 'tambah produk jualan hari ini');
  ok((await call('POST', `/api/shops/${sid}/products`, { name: 'Hack', category: 'Knalpot', price: 1, stock: 1, payment: 'both' }, buyer.token)).s === 403, 'pembeli tak bisa tambah produk');
  const list = (await call('GET', '/api/shops?lat=-6.92&lng=107.62&q=knalpot')).j;
  ok(list.length === 1 && list[0].productsToday === 2 && list[0].distanceKm < 1, 'pencarian + jarak + produk hari ini');

  // admin & status
  ok((await call('POST', `/api/shops/${sid}/admins`, { userId: adm.userId, label: 'Admin Budi' }, owner.token)).s === 200, 'pemilik tambah admin ke-2');
  ok((await call('POST', `/api/shops/${sid}/admins`, { userId: adm.userId, label: 'x' }, adm.token)).s === 403, 'admin biasa tak bisa tambah admin');
  await call('POST', `/api/shops/${sid}/status`, { status: 'busy' }, owner.token);
  await call('POST', `/api/shops/${sid}/status`, { status: 'online' }, adm.token);

  // pesanan
  ok((await call('POST', `/api/shops/${sid}/orders`, { items: [{ productId: p2.id, qty: 1 }], payment: 'online' }, buyer.token)).s === 400, 'produk COD-only ditolak untuk bayar online');
  const ord = await call('POST', `/api/shops/${sid}/orders`, { items: [{ productId: p1.id, qty: 2 }, { productId: p2.id, qty: 1 }], payment: 'cod', address: 'Jl. Pembeli 9', note: 'Sore ya' }, buyer.token);
  ok(ord.s === 200 && ord.j.total === 850000 * 2 + 120000, 'pesanan dibuat, total dihitung server');
  ok((await call('POST', `/api/shops/${sid}/orders`, { items: [{ productId: p1.id, qty: 99 }], payment: 'cod' }, buyer.token)).s === 400, 'stok tak cukup ditolak');
  const raw = fs.readFileSync(path.join(process.env.DATA_DIR, 'shops', sid, 'orders.enc'), 'utf8');
  ok(!raw.includes('Jl. Pembeli') && !raw.includes('Knalpot') && !raw.includes('buyerId'), 'orders.enc terenkripsi ARIA-256-GCM (tidak ada plaintext)');
  fs.writeFileSync(path.join(process.env.DATA_DIR, 'shops', sid, 'orders.enc'), raw.slice(0, 40) + (raw[40] === 'A' ? 'B' : 'A') + raw.slice(41));
  ok((await call('GET', `/api/shops/${sid}/orders`, null, adm.token)).s === 500, 'data dirusak -> GCM menolak (integritas)');
  fs.writeFileSync(path.join(process.env.DATA_DIR, 'shops', sid, 'orders.enc'), raw);
  const so = (await call('GET', `/api/shops/${sid}/orders`, null, adm.token)).j;
  ok(so.length === 1 && so[0].buyerAlias.startsWith('P-') && !so[0].buyerId && so[0].address === 'Jl. Pembeli 9', 'admin lihat pesanan dengan alias pembeli');
  ok((await call('GET', `/api/shops/${sid}/orders`, null, buyer.token)).s === 403, 'pembeli tak bisa lihat daftar pesanan');
  ok((await call('POST', `/api/shops/${sid}/orders/${so[0].id}/status`, { status: 'diproses' }, adm.token)).s === 200, 'admin atur status pesanan');
  ok((await call('GET', '/api/my/orders', null, buyer.token)).j.length === 1, 'pembeli lihat pesanannya');
  const after = (await call('GET', `/api/shops/${sid}`)).j.products.find((x) => x.id === p1.id);
  ok(after.stock === 3, 'stok berkurang otomatis');

  // chat
  const th = (await call('POST', `/api/shops/${sid}/chat`, {}, buyer.token)).j;
  ok(th.tid && th.admin.label === 'Admin Budi', 'chat tanpa nomor, auto-assign ke admin online');
  await call('POST', `/api/shops/${sid}/chat/${th.tid}/messages`, { text: 'Ready gan?' }, buyer.token);
  await call('POST', `/api/shops/${sid}/chat/${th.tid}/messages`, { text: 'Ready, silakan' }, adm.token);
  ok((await call('GET', `/api/shops/${sid}/chat/${th.tid}`, null, buyer.token)).j.messages.length === 2, 'pesan bolak-balik');
  ok((await call('GET', `/api/shops/${sid}/chat/${th.tid}`, null, (await register(mkKey())).j.token)).s === 403, 'pihak ketiga tak bisa baca chat');
  const craw = fs.readFileSync(path.join(process.env.DATA_DIR, 'shops', sid, 'chats.enc'), 'utf8');
  ok(!craw.includes('Ready'), 'chats.enc terenkripsi');
  const pub = (await call('GET', `/api/shops/${sid}`)).j.admins.find((a) => a.label === 'Pemilik');
  ok((await call('POST', `/api/shops/${sid}/chat/${th.tid}/transfer`, { alias: pub.alias }, buyer.token)).s === 200, 'pembeli alihkan ke admin lain tanpa tahu nomor');
  ok((await call('GET', `/api/shops/${sid}/threads`, null, owner.token)).j.length === 1, 'admin tujuan melihat thread');

  // keamanan
  ok((await call('POST', '/api/shops', { name: 'a'.repeat(40000) }, owner.token)).s === 413, 'body > 32KB ditolak');
  ok((await fetch(base + '/../server.js')).status !== 200 && (await fetch(base + '/%2e%2e/server.js')).status === 404, 'path traversal diblok');
  const hdr = (await fetch(base + '/')).headers;
  ok(hdr.get('content-security-policy') && hdr.get('x-frame-options') === 'DENY', 'header keamanan (CSP dll)');
  let c429 = 0; for (let i = 0; i < 320; i++) if ((await call('GET', '/api/meta')).s === 429) c429++;
  ok(c429 > 0, 'rate limit aktif (anti flood/botnet)');

  console.log(`\n${pass} lulus, ${fail} gagal`);
  server.close(); process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
