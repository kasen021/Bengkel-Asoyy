'use strict';
/**
 * BengkelMarket — prototipe marketplace bengkel / sparepart / modifikasi motor.
 * Tanpa dependensi (Node >= 18). Jalankan: node server.js
 *
 * - Akun = kunci publik RSA-4096 (2048 x 2). Tanpa email / nomor telepon.
 * - Login = tanda tangan RSA-PSS atas nonce (challenge-response, anti-replay).
 * - Data tiap bengkel disimpan di folder terpisah; pesanan & chat dienkripsi ARIA-256-GCM
 *   dengan kunci unik per-bengkel (HKDF dari master key).
 * - Alias pembeli/admin diturunkan per-bengkel (HMAC) sehingga identitas tak bisa dilacak lintas bengkel.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const PUB = path.join(__dirname, 'public');
const POW_BITS = +process.env.POW_BITS || 16; // biaya komputasi pendaftaran (anti bot massal)
const MIN_RSA_BITS = 4096;

fs.mkdirSync(path.join(DATA, 'shops'), { recursive: true });

/* ------------------------------------------------------------------ kunci master */
let MASTER;
const mkPath = path.join(DATA, 'master.key');
if (process.env.MASTER_KEY) MASTER = Buffer.from(process.env.MASTER_KEY, 'hex');
else if (fs.existsSync(mkPath)) MASTER = Buffer.from(fs.readFileSync(mkPath, 'utf8').trim(), 'hex');
else { MASTER = crypto.randomBytes(32); fs.writeFileSync(mkPath, MASTER.toString('hex'), { mode: 0o600 }); }
if (MASTER.length !== 32) throw new Error('MASTER_KEY harus 32 byte (64 hex)');

/* ------------------------------------------------------------------ ARIA-256-GCM */
const shopKey = (id) => Buffer.from(crypto.hkdfSync('sha256', MASTER, id, 'bengkel-aria256gcm-v1', 32));
function seal(key, obj, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aria-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function unseal(key, b64, aad) {
  const b = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aria-256-gcm', key, b.subarray(0, 12));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(b.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'));
}
const hmac = (...parts) => crypto.createHmac('sha256', MASTER).update(parts.join('|')).digest('hex');
const buyerAlias = (shopId, uid) => 'P-' + hmac('buy', shopId, uid).slice(0, 6);
const adminAlias = (shopId, uid) => 'A-' + hmac('adm', shopId, uid).slice(0, 6);

/* ------------------------------------------------------------------ penyimpanan */
const readJson = (p, def) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return def; } };
const mirror = require('./mirror');
const mirror = require('./mirror');
const mirror = require('./mirror');
const writeAtomic = (p, s) => { const t = p + '.tmp'; fs.writeFileSync(t, s); fs.renameSync(t, p); mirror.put(DATA, p, s); };
const ID_RE = /^[a-f0-9]{16}$/;
const shopDir = (id) => path.join(DATA, 'shops', id);
const encRead = (id, name, def) => {
  const p = path.join(shopDir(id), name + '.enc');
  return fs.existsSync(p) ? unseal(shopKey(id), fs.readFileSync(p, 'utf8'), id + '/' + name) : def;
};
const encWrite = (id, name, obj) => writeAtomic(path.join(shopDir(id), name + '.enc'), seal(shopKey(id), obj, id + '/' + name));
const plainRead = (id, name, def) => readJson(path.join(shopDir(id), name + '.json'), def);
const plainWrite = (id, name, obj) => writeAtomic(path.join(shopDir(id), name + '.json'), JSON.stringify(obj));

const users = readJson(path.join(DATA, 'users.json'), {});
const saveUsers = () => writeAtomic(path.join(DATA, 'users.json'), JSON.stringify(users));
const shops = new Map();
for (const id of fs.readdirSync(path.join(DATA, 'shops'))) {
  if (!ID_RE.test(id)) continue;
  const m = plainRead(id, 'shop', null);
  if (m) shops.set(id, m);
}

/* ------------------------------------------------------------------ util */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (m) => new HttpError(400, m);
const str = (v, max, min = 0) => {
  if (typeof v !== 'string') throw bad('Input teks tidak valid');
  const s = v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
  if (s.length < min || s.length > max) throw bad(`Panjang teks harus ${min}-${max} karakter`);
  return s;
};
const num = (v, min, max, int = false) => {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < min || v > max || (int && !Number.isInteger(v))) throw bad('Angka tidak valid');
  return v;
};
const todayWIB = () => new Date(Date.now() + 7 * 3600e3).toISOString().slice(0, 10);
const rid = (n = 6) => crypto.randomBytes(n).toString('hex');
const CATEGORIES = ['Knalpot', 'Velg & Ban', 'Lampu', 'Suspensi', 'Mesin & Performa', 'Kelistrikan', 'Body & Aksesoris', 'Oli & Cairan', 'Rem', 'Lainnya'];
const ORDER_STATUS = ['baru', 'diproses', 'dikirim', 'selesai', 'ditolak'];
const ADMIN_STATUS = ['online', 'busy', 'offline'];

function haversine(a, b, c, d) {
  const R = 6371, t = (x) => (x * Math.PI) / 180;
  const dLat = t(c - a), dLon = t(d - b);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(t(a)) * Math.cos(t(c)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

/* rate limit sederhana (jendela tetap) */
const buckets = new Map();
function allow(key, max, perMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now - b.t > perMs) { b = { t: now, n: 0 }; buckets.set(key, b); }
  return ++b.n <= max;
}
setInterval(() => { const n = Date.now(); for (const [k, b] of buckets) if (n - b.t > 3700e3) buckets.delete(k); }, 60e3).unref();

/* ------------------------------------------------------------------ autentikasi */
const challenges = new Map();
const sessions = new Map();
setInterval(() => {
  const n = Date.now();
  for (const [k, v] of challenges) if (v.exp < n) challenges.delete(k);
  for (const [k, v] of sessions) if (v.exp < n) sessions.delete(k);
}, 30e3).unref();

function parsePub(b64) {
  if (typeof b64 !== 'string' || b64.length > 2000) throw bad('Kunci publik tidak valid');
  let key;
  try { key = crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' }); } catch { throw bad('Kunci publik tidak valid'); }
  if (key.asymmetricKeyType !== 'rsa' && key.asymmetricKeyType !== 'rsa-pss') throw bad('Harus kunci RSA');
  if (key.asymmetricKeyDetails.modulusLength < MIN_RSA_BITS) throw bad(`Kunci minimal RSA-${MIN_RSA_BITS} (2048 x 2)`);
  return key;
}
function verifySig(key, nonce, sigB64) {
  try {
    return crypto.verify('sha256', Buffer.from(nonce), { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(String(sigB64), 'base64'));
  } catch { return false; }
}
function takeChallenge(cid) {
  const ch = challenges.get(cid);
  if (!ch || ch.exp < Date.now()) throw new HttpError(401, 'Challenge kedaluwarsa, ulangi');
  challenges.delete(cid); // sekali pakai -> anti replay
  return ch;
}
function powOk(nonce, counter) {
  if (!Number.isInteger(counter) || counter < 0 || counter > 1e12) return false;
  const h = crypto.createHash('sha256').update(nonce + counter).digest();
  let bits = 0;
  for (const byte of h) { if (byte === 0) { bits += 8; continue; } bits += Math.clz32(byte) - 24; break; }
  return bits >= POW_BITS;
}
function newSession(uid) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { uid, exp: Date.now() + 12 * 3600e3 });
  return token;
}

/* ------------------------------------------------------------------ router */
const routes = [];
const R = (method, p, handler, auth = false) =>
  routes.push({ method, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), handler, auth });

const shopOf = (id) => {
  if (!ID_RE.test(id) || !shops.has(id)) throw new HttpError(404, 'Bengkel tidak ditemukan');
  return shops.get(id);
};
const admins = (id) => plainRead(id, 'admins', {});
const isAdmin = (id, uid) => !!uid && (shops.get(id).ownerId === uid || !!admins(id)[uid]);
const needAdmin = (id, uid) => { if (!isAdmin(id, uid)) throw new HttpError(403, 'Khusus admin bengkel'); };
const needOwner = (id, uid) => { if (shopOf(id).ownerId !== uid) throw new HttpError(403, 'Khusus pemilik bengkel'); };
const publicAdmins = (id) => Object.entries(admins(id)).map(([uid, a]) => ({ alias: adminAlias(id, uid), label: a.label, status: a.status }));
const sendAdmin = (id, uid) => { const a = admins(id)[uid]; return a ? { alias: adminAlias(id, uid), label: a.label, status: a.status } : null; };

/* --- auth --- */
R('GET', '/api/challenge', () => {
  const cid = rid(16), nonce = rid(32);
  challenges.set(cid, { nonce, exp: Date.now() + 120e3 });
  if (challenges.size > 20000) throw new HttpError(503, 'Server sibuk');
  return { cid, nonce, bits: POW_BITS };
});
R('POST', '/api/auth/register', ({ body, ip }) => {
  if (!allow('reg:' + ip, 10, 3600e3)) throw new HttpError(429, 'Terlalu banyak pendaftaran dari IP ini');
  const key = parsePub(body.publicKey);
  const ch = takeChallenge(body.cid);
  if (!powOk(ch.nonce, body.counter)) throw bad('Bukti kerja (proof-of-work) salah');
  if (!verifySig(key, ch.nonce, body.sig)) throw new HttpError(401, 'Tanda tangan tidak valid');
  const der = key.export({ type: 'spki', format: 'der' });
  const uid = crypto.createHash('sha256').update(der).digest('hex').slice(0, 32);
  if (!users[uid]) { users[uid] = { pub: der.toString('base64'), created: Date.now() }; saveUsers(); }
  return { token: newSession(uid), userId: uid };
});
R('POST', '/api/auth/login', ({ body, ip }) => {
  if (!allow('login:' + ip, 30, 600e3)) throw new HttpError(429, 'Terlalu banyak percobaan login');
  const uid = str(body.userId, 32, 32);
  const ch = takeChallenge(body.cid);
  const u = users[uid];
  if (!u || !verifySig(parsePub(u.pub), ch.nonce, body.sig)) throw new HttpError(401, 'Login gagal');
  return { token: newSession(uid), userId: uid };
});
R('GET', '/api/me', ({ uid }) => ({
  userId: uid,
  shops: [...shops.entries()].filter(([id]) => isAdmin(id, uid)).map(([id, m]) => ({ id, name: m.name, owner: m.ownerId === uid })),
}), true);

/* --- bengkel --- */
R('GET', '/api/meta', () => ({ categories: CATEGORIES, today: todayWIB() }));
R('GET', '/api/shops', ({ url }) => {
  const q = (url.searchParams.get('q') || '').toLowerCase().slice(0, 60);
  const lat = parseFloat(url.searchParams.get('lat')), lng = parseFloat(url.searchParams.get('lng'));
  const geo = Number.isFinite(lat) && Number.isFinite(lng);
  const today = todayWIB();
  let list = [...shops.entries()].map(([id, m]) => {
    const prods = plainRead(id, 'products', []);
    const todays = prods.filter((p) => p.date === today && p.stock > 0);
    return {
      id, name: m.name, address: m.address, lat: m.lat, lng: m.lng, description: m.description,
      productsToday: todays.length,
      adminsOnline: Object.values(admins(id)).filter((a) => a.status === 'online').length,
      distanceKm: geo ? +haversine(lat, lng, m.lat, m.lng).toFixed(2) : null,
      _hay: (m.name + ' ' + m.address + ' ' + prods.map((p) => p.name).join(' ')).toLowerCase(),
    };
  });
  if (q) list = list.filter((s) => s._hay.includes(q));
  list.forEach((s) => delete s._hay);
  list.sort((a, b) => (geo ? a.distanceKm - b.distanceKm : b.productsToday - a.productsToday));
  return list.slice(0, 200);
});
R('POST', '/api/shops', ({ body, uid, ip }) => {
  if (!allow('shop:' + ip, 5, 3600e3)) throw new HttpError(429, 'Batas pendaftaran bengkel tercapai');
  if ([...shops.values()].filter((s) => s.ownerId === uid).length >= 3) throw bad('Maksimal 3 bengkel per akun');
  const id = rid(8);
  const meta = {
    id, ownerId: uid, created: Date.now(),
    name: str(body.name, 60, 3), address: str(body.address, 200, 3),
    description: str(body.description ?? '', 300),
    lat: num(body.lat, -90, 90), lng: num(body.lng, -180, 180),
  };
  fs.mkdirSync(shopDir(id), { recursive: true });
  plainWrite(id, 'shop', meta);
  plainWrite(id, 'products', []);
  plainWrite(id, 'admins', { [uid]: { label: 'Pemilik', status: 'online', added: Date.now() } });
  encWrite(id, 'orders', { orders: [] });
  encWrite(id, 'chats', { threads: {} });
  shops.set(id, meta);
  return { id };
}, true);
R('GET', '/api/shops/:id', ({ params, uid }) => {
  const m = shopOf(params.id);
  return {
    id: m.id, name: m.name, address: m.address, description: m.description, lat: m.lat, lng: m.lng,
    products: plainRead(m.id, 'products', []), admins: publicAdmins(m.id),
    isAdmin: isAdmin(m.id, uid), isOwner: m.ownerId === uid, today: todayWIB(),
  };
});

/* --- produk / jualan hari ini --- */
function productFrom(body) {
  const payment = body.payment;
  if (!['cod', 'online', 'both'].includes(payment)) throw bad('Pembayaran harus cod / online / both');
  if (!CATEGORIES.includes(body.category)) throw bad('Kategori tidak valid');
  const date = str(body.date ?? todayWIB(), 10, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date))) throw bad('Tanggal tidak valid');
  return {
    name: str(body.name, 80, 2), category: body.category, price: num(body.price, 0, 1e9, true),
    stock: num(body.stock, 0, 9999, true), payment, date, note: str(body.note ?? '', 200),
  };
}
R('POST', '/api/shops/:id/products', ({ params, body, uid }) => {
  needAdmin(params.id, uid);
  const prods = plainRead(params.id, 'products', []);
  if (prods.length >= 300) throw bad('Maksimal 300 produk');
  const p = { id: rid(4), ...productFrom(body) };
  prods.push(p); plainWrite(params.id, 'products', prods);
  return p;
}, true);
R('POST', '/api/shops/:id/products/:pid', ({ params, body, uid }) => {
  needAdmin(params.id, uid);
  const prods = plainRead(params.id, 'products', []);
  const i = prods.findIndex((p) => p.id === params.pid);
  if (i < 0) throw new HttpError(404, 'Produk tidak ditemukan');
  prods[i] = { id: prods[i].id, ...productFrom({ ...prods[i], ...body }) };
  plainWrite(params.id, 'products', prods);
  return prods[i];
}, true);
R('DELETE', '/api/shops/:id/products/:pid', ({ params, uid }) => {
  needAdmin(params.id, uid);
  plainWrite(params.id, 'products', plainRead(params.id, 'products', []).filter((p) => p.id !== params.pid));
  return { ok: true };
}, true);

/* --- admin bengkel --- */
R('POST', '/api/shops/:id/admins', ({ params, body, uid }) => {
  needOwner(params.id, uid);
  const target = str(body.userId, 32, 32);
  if (!users[target]) throw bad('Akun belum terdaftar (minta ia membuat akun dulu)');
  const a = admins(params.id);
  if (Object.keys(a).length >= 10) throw bad('Maksimal 10 admin');
  a[target] = { label: str(body.label, 30, 2), status: 'offline', added: Date.now() };
  plainWrite(params.id, 'admins', a);
  return { alias: adminAlias(params.id, target) };
}, true);
R('DELETE', '/api/shops/:id/admins/:alias', ({ params, uid }) => {
  needOwner(params.id, uid);
  const a = admins(params.id);
  const target = Object.keys(a).find((u) => adminAlias(params.id, u) === params.alias);
  if (!target) throw new HttpError(404, 'Admin tidak ditemukan');
  if (target === shops.get(params.id).ownerId) throw bad('Pemilik tidak bisa dihapus');
  delete a[target]; plainWrite(params.id, 'admins', a);
  return { ok: true };
}, true);
R('POST', '/api/shops/:id/status', ({ params, body, uid }) => {
  needAdmin(params.id, uid);
  if (!ADMIN_STATUS.includes(body.status)) throw bad('Status harus online / busy / offline');
  const a = admins(params.id);
  if (!a[uid]) a[uid] = { label: 'Pemilik', added: Date.now() };
  a[uid].status = body.status; plainWrite(params.id, 'admins', a);
  return sendAdmin(params.id, uid);
}, true);

/* --- pesanan (terenkripsi ARIA-256-GCM) --- */
R('POST', '/api/shops/:id/orders', ({ params, body, uid }) => {
  const id = params.id; shopOf(id);
  if (isAdmin(id, uid)) throw bad('Admin tidak bisa memesan di bengkelnya sendiri');
  if (!Array.isArray(body.items) || !body.items.length || body.items.length > 20) throw bad('Item pesanan tidak valid');
  if (!['cod', 'online'].includes(body.payment)) throw bad('Pilih pembayaran cod / online');
  const prods = plainRead(id, 'products', []);
  const items = []; let total = 0;
  for (const it of body.items) {
    const p = prods.find((x) => x.id === it.productId);
    if (!p) throw bad('Produk tidak ditemukan');
    const qty = num(it.qty, 1, 99, true);
    if (p.stock < qty) throw bad(`Stok "${p.name}" tidak cukup`);
    if (p.payment !== 'both' && p.payment !== body.payment) throw bad(`"${p.name}" tidak tersedia untuk pembayaran ${body.payment.toUpperCase()}`);
    items.push({ productId: p.id, name: p.name, price: p.price, qty });
    total += p.price * qty;
  }
  for (const it of items) prods.find((x) => x.id === it.productId).stock -= it.qty;
  plainWrite(id, 'products', prods);
  const db = encRead(id, 'orders', { orders: [] });
  const order = {
    id: rid(6), buyerId: uid, items, total, payment: body.payment,
    address: str(body.address ?? '', 200), note: str(body.note ?? '', 300),
    status: 'baru', created: Date.now(),
  };
  db.orders.push(order); encWrite(id, 'orders', db);
  return { id: order.id, total, status: order.status };
}, true);
R('GET', '/api/shops/:id/orders', ({ params, uid }) => {
  needAdmin(params.id, uid);
  return encRead(params.id, 'orders', { orders: [] }).orders.slice().reverse()
    .map((o) => ({ ...o, buyerId: undefined, buyerAlias: buyerAlias(params.id, o.buyerId) }));
}, true);
R('POST', '/api/shops/:id/orders/:oid/status', ({ params, body, uid }) => {
  needAdmin(params.id, uid);
  if (!ORDER_STATUS.includes(body.status)) throw bad('Status pesanan tidak valid');
  const db = encRead(params.id, 'orders', { orders: [] });
  const o = db.orders.find((x) => x.id === params.oid);
  if (!o) throw new HttpError(404, 'Pesanan tidak ditemukan');
  if (body.status === 'ditolak' && o.status !== 'ditolak') { // kembalikan stok
    const prods = plainRead(params.id, 'products', []);
    for (const it of o.items) { const p = prods.find((x) => x.id === it.productId); if (p) p.stock += it.qty; }
    plainWrite(params.id, 'products', prods);
  }
  o.status = body.status; encWrite(params.id, 'orders', db);
  return { ok: true };
}, true);
R('GET', '/api/my/orders', ({ uid }) => {
  const out = [];
  for (const [id, m] of shops) {
    for (const o of encRead(id, 'orders', { orders: [] }).orders) {
      if (o.buyerId === uid) out.push({ ...o, buyerId: undefined, shopId: id, shopName: m.name });
    }
  }
  return out.sort((a, b) => b.created - a.created);
}, true);

/* --- chat privat tanpa nomor (pembeli <-> admin, bisa dialihkan ke admin lain) --- */
function pickAdmin(id) {
  const a = admins(id);
  const threads = encRead(id, 'chats', { threads: {} }).threads;
  const load = (u) => Object.values(threads).filter((t) => t.adminId === u).length;
  for (const st of ['online', 'busy', 'offline']) {
    const c = Object.keys(a).filter((u) => a[u].status === st).sort((x, y) => load(x) - load(y));
    if (c.length) return c[0];
  }
  return shops.get(id).ownerId;
}
function loadThread(id, tid, uid) {
  const db = encRead(id, 'chats', { threads: {} });
  const t = db.threads[tid];
  if (!t) throw new HttpError(404, 'Percakapan tidak ditemukan');
  const buyer = t.buyerId === uid;
  if (!buyer && !(t.adminId === uid || shops.get(id).ownerId === uid)) throw new HttpError(403, 'Bukan percakapan Anda');
  return { db, t, role: buyer ? 'buyer' : 'admin' };
}
R('POST', '/api/shops/:id/chat', ({ params, uid }) => {
  const id = params.id; shopOf(id);
  if (isAdmin(id, uid)) throw bad('Admin membuka chat dari dasbor');
  const db = encRead(id, 'chats', { threads: {} });
  let t = Object.values(db.threads).find((x) => x.buyerId === uid);
  if (!t) {
    if (Object.keys(db.threads).length > 5000) throw new HttpError(503, 'Bengkel sedang penuh');
    t = { id: rid(6), buyerId: uid, adminId: pickAdmin(id), msgs: [], created: Date.now() };
    db.threads[t.id] = t; encWrite(id, 'chats', db);
  }
  return { tid: t.id, admin: sendAdmin(id, t.adminId) };
}, true);
R('GET', '/api/shops/:id/chat/:tid', ({ params, url, uid }) => {
  const { t, role } = loadThread(params.id, params.tid, uid);
  const after = parseInt(url.searchParams.get('after') || '0', 10) || 0;
  return {
    role, admin: sendAdmin(params.id, t.adminId), buyerAlias: buyerAlias(params.id, t.buyerId),
    messages: t.msgs.filter((m) => m.n > after),
  };
}, true);
R('POST', '/api/shops/:id/chat/:tid/messages', ({ params, body, uid }) => {
  const { db, t, role } = loadThread(params.id, params.tid, uid);
  if (t.msgs.length >= 1000) throw bad('Percakapan penuh');
  const m = { n: (t.msgs.at(-1)?.n || 0) + 1, from: role, text: str(body.text, 1000, 1), t: Date.now() };
  t.msgs.push(m); encWrite(params.id, 'chats', db);
  return m;
}, true);
R('POST', '/api/shops/:id/chat/:tid/transfer', ({ params, body, uid }) => {
  const { db, t } = loadThread(params.id, params.tid, uid);
  const a = admins(params.id);
  const target = Object.keys(a).find((u) => adminAlias(params.id, u) === body.alias);
  if (!target) throw new HttpError(404, 'Admin tidak ditemukan');
  t.adminId = target;
  t.msgs.push({ n: (t.msgs.at(-1)?.n || 0) + 1, from: 'system', text: `Percakapan dialihkan ke ${a[target].label}`, t: Date.now() });
  encWrite(params.id, 'chats', db);
  return sendAdmin(params.id, target);
}, true);
R('GET', '/api/shops/:id/threads', ({ params, uid }) => {
  needAdmin(params.id, uid);
  const owner = shops.get(params.id).ownerId === uid;
  return Object.values(encRead(params.id, 'chats', { threads: {} }).threads)
    .filter((t) => owner || t.adminId === uid)
    .map((t) => ({
      tid: t.id, buyerAlias: buyerAlias(params.id, t.buyerId), admin: sendAdmin(params.id, t.adminId),
      count: t.msgs.length, last: t.msgs.at(-1) || null,
    })).sort((a, b) => (b.last?.t || 0) - (a.last?.t || 0));
}, true);

/* ------------------------------------------------------------------ HTTP server */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function secHeaders(res) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' https://unpkg.com; img-src 'self' data: https://*.tile.openstreetmap.org https://unpkg.com; connect-src 'self' https://nominatim.openstreetmap.org; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(self), camera=(), microphone=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method tidak diizinkan');
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { throw bad('Path tidak valid'); }
  if (rel === '/' || rel === '') rel = '/index.html';
  const file = path.normalize(path.join(PUB, rel));
  if (!file.startsWith(PUB + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) throw new HttpError(404, 'Tidak ditemukan');
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(file).pipe(res);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0, over = false; const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (over) return; // buang sisa data (dibatasi requestTimeout), jangan simpan
      if (n > 32768) { over = true; chunks.length = 0; reject(new HttpError(413, 'Body terlalu besar')); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (over) return;
      if (!chunks.length) return resolve({});
      try {
        const o = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (o === null || typeof o !== 'object' || Array.isArray(o)) throw 0;
        resolve(o);
      } catch { reject(bad('JSON tidak valid')); }
    });
    req.on('error', reject);
  });
}
const send = (res, status, obj) => {
  const b = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(b);
};

const server = http.createServer(async (req, res) => {
  secHeaders(res);
  try {
    const ip = (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
    const url = new URL(req.url, 'http://localhost');
    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
    if (!allow('g:' + ip, 300, 60e3)) throw new HttpError(429, 'Terlalu banyak permintaan, pelan-pelan');
    const route = routes.find((r) => r.method === req.method && r.re.test(url.pathname));
    if (!route) throw new HttpError(404, 'Endpoint tidak ada');
    const params = { ...url.pathname.match(route.re).groups };
    const tok = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization || '');
    const sess = tok && sessions.get(tok[1]);
    const uid = sess && sess.exp > Date.now() ? sess.uid : null;
    if (route.auth) {
      if (!uid) throw new HttpError(401, 'Silakan login dengan kunci Anda');
      if (!allow('u:' + uid, 240, 60e3)) throw new HttpError(429, 'Terlalu banyak permintaan akun ini');
    }
    const body = req.method === 'POST' ? await readBody(req) : {};
    send(res, 200, await route.handler({ params, body, url, uid, ip }));
  } catch (e) {
    if (e instanceof HttpError) {
      if (res.headersSent) return res.destroy();
      return send(res, e.status, { error: e.message });
    }
    console.error('[ERR]', e);
    if (!res.headersSent) send(res, 500, { error: 'Kesalahan server' });
  }
});
server.headersTimeout = 10e3;
server.requestTimeout = 15e3;
server.keepAliveTimeout = 5e3;
server.maxHeadersCount = 50;

if (require.main === module) {
  server.listen(PORT, HOST, () => console.log(`BengkelMarket jalan di http://${HOST}:${PORT}  (data: ${DATA})`));
}
module.exports = { server };
