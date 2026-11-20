'use strict';
/* BengkelMarket — frontend. Tanpa framework. Semua teks pengguna di-escape (anti XSS). */
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rp = (n) => 'Rp ' + Number(n).toLocaleString('id-ID');
const app = $('#app');
const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const LS = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch {} }, del: (k) => { try { localStorage.removeItem(k); } catch {} } };

let token = null, me = null, timers = [], map = null, cart = {}, userPos = null, meta = { categories: [], today: '' };
const clearTimers = () => { timers.forEach(clearInterval); timers = []; };

function toast(msg, err) {
  const t = $('#toast'); t.textContent = msg; t.className = 'toast' + (err ? ' err' : '');
  clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.add('hidden'), 3500);
}
async function api(path, method = 'GET', body) {
  const r = await fetch(path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'Kesalahan ' + r.status);
  return j;
}
const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

/* ------------------------------------------------------------ kripto akun (RSA-4096 = 2048 x 2) */
async function solvePow(nonce, bits) {
  for (let c = 0; ; c++) {
    const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(nonce + c)));
    let z = 0;
    for (const x of h) { if (!x) { z += 8; continue; } z += Math.clz32(x) - 24; break; }
    if (z >= bits) return c;
    if (c % 3000 === 2999) await new Promise((r) => setTimeout(r));
  }
}
async function signNonce(nonce) {
  const k = await crypto.subtle.importKey('pkcs8', unb64(LS.get('bk.priv')), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, k, enc.encode(nonce)));
}
async function createAccount(setMsg) {
  setMsg('Membuat kunci RSA-4096… (bisa 5–30 detik)');
  const kp = await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  LS.set('bk.priv', b64(await crypto.subtle.exportKey('pkcs8', kp.privateKey)));
  LS.set('bk.pub', b64(await crypto.subtle.exportKey('spki', kp.publicKey)));
  setMsg('Menghitung bukti kerja anti-bot…');
  const ch = await api('/api/challenge');
  const counter = await solvePow(ch.nonce, ch.bits);
  const r = await api('/api/auth/register', 'POST', { publicKey: LS.get('bk.pub'), cid: ch.cid, counter, sig: await signNonce(ch.nonce) });
  LS.set('bk.uid', r.userId); token = r.token; me = r.userId;
}
async function login() {
  if (!LS.get('bk.priv') || !LS.get('bk.uid')) return false;
  const ch = await api('/api/challenge');
  const r = await api('/api/auth/login', 'POST', { userId: LS.get('bk.uid'), cid: ch.cid, sig: await signNonce(ch.nonce) });
  token = r.token; me = r.userId; return true;
}
async function requireLogin() {
  if (token) return true;
  if (LS.get('bk.priv')) { await login(); return true; }
  toast('Buat/impor akun dulu di menu Akun', true); location.hash = '#/account'; return false;
}
function updateNav() { $('#nav-account').textContent = me ? '🔑 ' + me.slice(0, 6) : 'Akun'; }

/* ------------------------------------------------------------ helpers tampilan */
const stBadge = (s) => `<span class="badge b-${esc(s)}">${s === 'online' ? '● online' : s === 'busy' ? '● sibuk' : '○ offline'}</span>`;
const payBadge = (p) => p === 'both' ? '<span class="badge b-cod">COD</span> <span class="badge b-online-pay">Online</span>' : p === 'cod' ? '<span class="badge b-cod">COD</span>' : '<span class="badge b-online-pay">Online</span>';
const fmtDate = (d) => d === meta.today ? 'Hari ini' : d;
const fmtTime = (t) => new Date(t).toLocaleString('id-ID', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: 'short' });
const hasLeaflet = () => typeof L !== 'undefined';
function getPos() {
  return new Promise((res) => navigator.geolocation ? navigator.geolocation.getCurrentPosition((p) => res({ lat: p.coords.latitude, lng: p.coords.longitude }), () => res(null), { timeout: 8000 }) : res(null));
}
async function geocode(q) { // pencarian alamat real-time (OpenStreetMap Nominatim)
  const r = await fetch('https://nominatim.openstreetmap.org/search?format=json&limit=5&countrycodes=id&q=' + encodeURIComponent(q));
  return r.json();
}
function mkMap(el, lat, lng, zoom) {
  if (map) { map.remove(); map = null; }
  map = L.map(el).setView([lat, lng], zoom);
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '© OpenStreetMap' }).addTo(map);
  return map;
}

/* ------------------------------------------------------------ router */
async function route() {
  clearTimers();
  const [, view, a] = location.hash.replace(/^#/, '').split('/');
  try {
    if (!view) await viewHome();
    else if (view === 'shop') await viewShop(a);
    else if (view === 'account') await viewAccount();
    else if (view === 'new-shop') await viewNewShop();
    else if (view === 'dash') await viewDash(a);
    else if (view === 'orders') await viewMyOrders();
    else app.innerHTML = '<p>Halaman tidak ada.</p>';
  } catch (e) { toast(e.message, true); }
}
window.addEventListener('hashchange', route);

/* ------------------------------------------------------------ beranda: peta + daftar */
async function viewHome() {
  app.innerHTML = `<h1>Cari bengkel & sparepart terdekat</h1>
  <div class="row card"><input id="q" placeholder="Cari bengkel / alamat / barang (mis. knalpot)" class="grow"><button id="go">Cari</button><button class="sec" id="loc">📍 Lokasi saya</button></div>
  <div id="map" class="map"></div><div id="list" class="grid"></div>`;
  let shops = [];
  const load = async () => {
    const p = new URLSearchParams({ q: $('#q').value });
    if (userPos) { p.set('lat', userPos.lat); p.set('lng', userPos.lng); }
    shops = await api('/api/shops?' + p);
    $('#list').innerHTML = shops.length ? shops.map((s) => `<a class="card" href="#/shop/${s.id}"><h3>${esc(s.name)}</h3>
      <div class="mut">${esc(s.address)}</div><div class="row">
      ${s.distanceKm != null ? `<span class="badge">${s.distanceKm} km</span>` : ''}
      <span class="badge">${s.productsToday} jualan hari ini</span>${s.adminsOnline ? '<span class="badge b-online">admin online</span>' : '<span class="badge b-offline">admin offline</span>'}</div></a>`).join('') : '<p class="mut">Belum ada bengkel. Jadilah yang pertama mendaftar!</p>';
    if (hasLeaflet()) {
      const c = userPos || (shops[0] ? { lat: shops[0].lat, lng: shops[0].lng } : { lat: -6.2, lng: 106.82 });
      mkMap('map', c.lat, c.lng, userPos || shops.length ? 12 : 5);
      shops.forEach((s) => L.marker([s.lat, s.lng]).addTo(map).bindPopup(`<b>${esc(s.name)}</b><br>${s.productsToday} jualan hari ini<br><a href="#/shop/${s.id}">Buka</a>`));
      if (userPos) L.circleMarker([userPos.lat, userPos.lng], { radius: 8 }).addTo(map).bindPopup('Lokasi Anda');
    } else $('#map').outerHTML = '<p class="mut">Peta tidak termuat (butuh internet ke unpkg/OSM). Daftar bengkel tetap bisa dipakai.</p>';
  };
  $('#go').onclick = guard(load);
  $('#q').onkeydown = (e) => e.key === 'Enter' && load().catch((x) => toast(x.message, true));
  $('#loc').onclick = guard(async () => { userPos = await getPos(); if (!userPos) return toast('Lokasi tidak diizinkan', true); await load(); });
  await load();
}

/* ------------------------------------------------------------ detail bengkel + beli + chat */
async function viewShop(id) {
  const s = await api('/api/shops/' + id);
  const todays = s.products.filter((p) => p.date === meta.today);
  const shareText = () => `🏍️ ${s.name} — jualan ${fmtDate(meta.today)} (${meta.today})\n` + (todays.length ? todays.map((p) => `• ${p.name} — ${rp(p.price)} (${p.payment === 'both' ? 'COD/Online' : p.payment.toUpperCase()})`).join('\n') : '(belum ada jualan hari ini)') + `\n📍 ${s.address}\n💬 Chat tanpa nomor: ${location.origin}/#/shop/${s.id}`;
  app.innerHTML = `<div class="row"><h1>${esc(s.name)}</h1></div>
  <div class="mut">${esc(s.address)} • <a target="_blank" rel="noopener" href="https://www.openstreetmap.org/?mlat=${s.lat}&mlon=${s.lng}#map=17/${s.lat}/${s.lng}">lihat peta</a></div>
  <p>${esc(s.description)}</p>
  <div class="row"><button id="share" class="sec">📤 Bagikan jualan hari ini</button>${s.isAdmin ? `<a href="#/dash/${s.id}"><button>Dasbor bengkel</button></a>` : ''}</div>
  <div class="split"><div>
    <h2>Jualan</h2><div class="row"><label><input type="checkbox" id="onlyToday" checked style="width:auto"> hanya hari ini (${esc(meta.today)})</label></div>
    <div id="prods"></div></div>
  <div><h2>Admin & chat</h2><div class="card" id="admins">${s.admins.map((a) => `<div class="row"><b>${esc(a.label)}</b> ${stBadge(a.status)}</div>`).join('')}</div>
    <div id="chatbox"></div>
    <h2>Keranjang</h2><div class="card" id="cart"></div></div></div>`;
  const renderProds = () => {
    const only = $('#onlyToday').checked;
    const list = s.products.filter((p) => !only || p.date === meta.today);
    $('#prods').innerHTML = list.length ? list.map((p) => `<div class="card"><div class="row"><h3>${esc(p.name)}</h3><span class="badge">${esc(p.category)}</span></div>
      <div><span class="price">${rp(p.price)}</span> ${payBadge(p.payment)} <span class="badge">${esc(fmtDate(p.date))}</span></div>
      <div class="mut">Stok ${p.stock}${p.note ? ' • ' + esc(p.note) : ''}</div>
      ${p.stock > 0 && !s.isAdmin ? `<button data-add="${p.id}">+ Keranjang</button>` : '<span class="mut">habis</span>'}</div>`).join('') : '<p class="mut">Belum ada jualan.</p>';
    document.querySelectorAll('[data-add]').forEach((b) => b.onclick = () => { cart[s.id] = cart[s.id] || {}; cart[s.id][b.dataset.add] = (cart[s.id][b.dataset.add] || 0) + 1; renderCart(); });
  };
  const renderCart = () => {
    const items = Object.entries(cart[s.id] || {}).map(([pid, q]) => ({ p: s.products.find((x) => x.id === pid), q })).filter((x) => x.p);
    if (!items.length) { $('#cart').innerHTML = '<span class="mut">Kosong</span>'; return; }
    const allow = (m) => items.every((x) => x.p.payment === 'both' || x.p.payment === m);
    const total = items.reduce((t, x) => t + x.p.price * x.q, 0);
    $('#cart').innerHTML = items.map((x) => `<div class="row">${esc(x.p.name)} × ${x.q} <button class="sec" data-dec="${x.p.id}">−</button></div>`).join('') + `<p><b>Total ${rp(total)}</b></p>
      <label>Pembayaran</label><select id="pay">${allow('cod') ? '<option value="cod">COD (bayar di tempat)</option>' : ''}${allow('online') ? '<option value="online">Online (transfer)</option>' : ''}</select>
      <label>Alamat / titik temu (dienkripsi ARIA-256-GCM)</label><input id="addr" maxlength="200"><label>Catatan</label><textarea id="note" maxlength="300"></textarea>
      <button id="order">Kirim pesanan</button><p class="mut">Pembayaran online di prototipe ini hanya dicatat; integrasikan payment gateway untuk produksi.</p>`;
    document.querySelectorAll('[data-dec]').forEach((b) => b.onclick = () => { const k = b.dataset.dec; cart[s.id][k]--; if (cart[s.id][k] <= 0) delete cart[s.id][k]; renderCart(); });
    if ($('#order')) $('#order').onclick = guard(async () => {
      if (!(await requireLogin())) return;
      if (!$('#pay').value) return toast('Barang di keranjang tidak punya metode bayar yang sama', true);
      const r = await api(`/api/shops/${s.id}/orders`, 'POST', { items: items.map((x) => ({ productId: x.p.id, qty: x.q })), payment: $('#pay').value, address: $('#addr').value, note: $('#note').value });
      cart[s.id] = {}; toast('Pesanan terkirim! Total ' + rp(r.total)); location.hash = '#/orders';
    });
  };
  $('#onlyToday').onchange = renderProds; renderProds(); renderCart();
  $('#share').onclick = guard(async () => {
    const t = shareText();
    if (navigator.share) { try { await navigator.share({ text: t }); return; } catch { /* batal */ } }
    await navigator.clipboard.writeText(t); toast('Teks jualan hari ini disalin — tempel ke WhatsApp/Telegram/dll');
  });
  /* chat */
  const box = $('#chatbox');
  if (s.isAdmin) { box.innerHTML = '<p class="mut">Kelola chat dari dasbor bengkel.</p>'; return; }
  box.innerHTML = '<button id="openchat">💬 Chat bengkel (tanpa nomor)</button>';
  $('#openchat').onclick = guard(async () => {
    if (!(await requireLogin())) return;
    const t = await api(`/api/shops/${s.id}/chat`, 'POST', {});
    chatUI(box, s.id, t.tid, 'buyer', s.admins);
  });
}

/* UI chat bersama (pembeli & admin) */
function chatUI(box, sid, tid, role, admins) {
  box.innerHTML = `<div class="card"><div class="row"><b id="peer"></b><span id="peerst"></span></div><div class="chat" id="msgs"></div>
    <div class="row"><input id="txt" maxlength="1000" placeholder="Tulis pesan…" class="grow"><button id="send">Kirim</button></div>
    <div class="row"><select id="xfer"><option value="">Alihkan ke admin lain…</option>${admins.map((a) => `<option value="${esc(a.alias)}">${esc(a.label)} (${esc(a.status)})</option>`).join('')}</select><button class="sec" id="xgo">Alihkan</button></div>
    <p class="mut">Tersimpan terenkripsi ARIA-256-GCM. Identitas Anda hanya tampil sebagai alias.</p></div>`;
  let last = 0; const msgs = $('#msgs', box);
  const poll = async () => {
    const r = await api(`/api/shops/${sid}/chat/${tid}?after=${last}`);
    $('#peer', box).textContent = role === 'buyer' ? (r.admin?.label || '—') : r.buyerAlias; $('#peerst', box).innerHTML = role === 'buyer' && r.admin ? stBadge(r.admin.status) : '';
    for (const m of r.messages) {
      last = m.n; const d = document.createElement('div');
      d.className = 'msg ' + (m.from === 'system' ? 'sys' : m.from === role ? 'me' : ''); d.textContent = m.text; msgs.appendChild(d);
    }
    if (r.messages.length) msgs.scrollTop = msgs.scrollHeight;
  };
  const send = guard(async () => { const v = $('#txt', box).value.trim(); if (!v) return; $('#txt', box).value = ''; await api(`/api/shops/${sid}/chat/${tid}/messages`, 'POST', { text: v }); await poll(); });
  $('#send', box).onclick = send; $('#txt', box).onkeydown = (e) => e.key === 'Enter' && send();
  $('#xgo', box).onclick = guard(async () => { const v = $('#xfer', box).value; if (!v) return; const a = await api(`/api/shops/${sid}/chat/${tid}/transfer`, 'POST', { alias: v }); toast('Dialihkan ke ' + a.label); await poll(); });
  poll().catch((e) => toast(e.message, true)); timers.push(setInterval(() => poll().catch(() => {}), 3000));
}

/* ------------------------------------------------------------ akun */
async function viewAccount() {
  const has = !!LS.get('bk.priv');
  app.innerHTML = `<h1>Akun (kunci kriptografi)</h1><div class="card">
  <p>Akun Anda adalah pasangan kunci <b>RSA-4096 (2048 × 2)</b> yang dibuat di perangkat ini. Tanpa email, tanpa nomor telepon. Kunci privat <b>tidak pernah</b> dikirim ke server — login memakai tanda tangan RSA-PSS atas nonce sekali pakai.</p>
  ${has ? `<p>ID akun (bagikan ke pemilik bengkel bila ingin dijadikan admin):</p><pre class="key">${esc(LS.get('bk.uid'))}</pre>
  <div class="row"><button id="login">Login</button><button class="sec" id="exp">⬇ Cadangkan kunci</button><button class="danger" id="del">Hapus dari perangkat</button></div>
  <p class="mut">⚠ Kunci tersimpan di browser ini. Simpan cadangan; bila hilang, akun tidak bisa dipulihkan.</p>`
    : `<div class="row"><button id="create">Buat akun baru</button><label class="row"><span>atau impor cadangan:</span><input type="file" id="imp" accept=".json"></label></div><p id="msg" class="mut"></p>`}
  </div>`;
  if (has) {
    $('#login').onclick = guard(async () => { await login(); updateNav(); toast('Login berhasil'); });
    $('#exp').onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify({ uid: LS.get('bk.uid'), pub: LS.get('bk.pub'), priv: LS.get('bk.priv') })], { type: 'application/json' })); a.download = 'bengkelmarket-kunci.json'; a.click(); };
    $('#del').onclick = () => { if (confirm('Hapus kunci dari perangkat ini? Pastikan sudah punya cadangan.')) { ['bk.priv', 'bk.pub', 'bk.uid'].forEach(LS.del); token = me = null; updateNav(); viewAccount(); } };
  } else {
    $('#create').onclick = guard(async () => { $('#create').disabled = true; try { await createAccount((m) => $('#msg').textContent = m); updateNav(); toast('Akun dibuat'); viewAccount(); } finally { $('#create') && ($('#create').disabled = false); } });
    $('#imp').onchange = guard(async (e) => { const j = JSON.parse(await e.target.files[0].text()); if (!j.priv || !j.pub || !j.uid) throw new Error('Berkas tidak valid'); LS.set('bk.priv', j.priv); LS.set('bk.pub', j.pub); LS.set('bk.uid', j.uid); await login(); updateNav(); viewAccount(); });
  }
}

/* ------------------------------------------------------------ daftar bengkel baru (lokasi real-time) */
async function viewNewShop() {
  app.innerHTML = `<h1>Daftarkan bengkel</h1><div class="split"><div class="card">
  <label>Nama bengkel</label><input id="n" maxlength="60"><label>Deskripsi singkat</label><input id="d" maxlength="300">
  <label>Cari alamat (real-time, OpenStreetMap)</label><div class="row"><input id="sq" placeholder="mis. Jl. Asia Afrika Bandung" class="grow"><button class="sec" id="sgo">Cari</button><button class="sec" id="sloc">📍</button></div>
  <div id="res"></div><label>Alamat lengkap</label><input id="a" maxlength="200">
  <div class="row"><div><label>Lat</label><input id="lat"></div><div><label>Lng</label><input id="lng"></div></div>
  <p class="mut">Klik peta untuk menggeser titik lokasi.</p><button id="save">Daftarkan</button></div>
  <div><div id="pmap" class="map small"></div></div></div>`;
  let marker = null;
  const setPt = (lat, lng, addr) => {
    $('#lat').value = (+lat).toFixed(6); $('#lng').value = (+lng).toFixed(6); if (addr) $('#a').value = addr;
    if (hasLeaflet()) { if (marker) marker.setLatLng([lat, lng]); else marker = L.marker([lat, lng]).addTo(map); map.setView([lat, lng], 16); }
  };
  if (hasLeaflet()) { mkMap('pmap', -2.5, 118, 5); map.on('click', (e) => setPt(e.latlng.lat, e.latlng.lng)); }
  else $('#pmap').outerHTML = '<p class="mut">Peta tidak termuat — isi Lat/Lng manual.</p>';
  $('#sgo').onclick = guard(async () => {
    const r = await geocode($('#sq').value);
    $('#res').innerHTML = r.length ? r.map((x, i) => `<div class="card"><a href="#" data-i="${i}">${esc(x.display_name)}</a></div>`).join('') : '<p class="mut">Tidak ketemu</p>';
    document.querySelectorAll('[data-i]').forEach((a) => a.onclick = (e) => { e.preventDefault(); const x = r[+a.dataset.i]; setPt(+x.lat, +x.lon, x.display_name.slice(0, 200)); $('#res').innerHTML = ''; });
  });
  $('#sloc').onclick = guard(async () => { const p = await getPos(); if (!p) return toast('Lokasi tidak diizinkan', true); setPt(p.lat, p.lng); });
  $('#save').onclick = guard(async () => {
    if (!(await requireLogin())) return;
    const r = await api('/api/shops', 'POST', { name: $('#n').value, description: $('#d').value, address: $('#a').value, lat: parseFloat($('#lat').value), lng: parseFloat($('#lng').value) });
    toast('Bengkel terdaftar'); location.hash = '#/dash/' + r.id;
  });
}

/* ------------------------------------------------------------ dasbor bengkel (admin) */
async function viewDash(id) {
  if (!(await requireLogin())) return;
  let tab = 'prod';
  const draw = async () => {
    const s = await api('/api/shops/' + id);
    if (!s.isAdmin) { app.innerHTML = '<p>Anda bukan admin bengkel ini.</p>'; return; }
    const mine = s.admins; // status sendiri: ambil dari /api/me tidak memuat status, jadi tampilkan tombol set
    app.innerHTML = `<h1>Dasbor: ${esc(s.name)}</h1><div class="row"><a href="#/shop/${id}">← halaman publik</a>
      <span class="mut">Status saya:</span><button class="sec" data-st="online">● Online</button><button class="sec" data-st="busy">● Sibuk</button><button class="sec" data-st="offline">○ Offline</button></div>
      <div class="tabs">${[['prod', 'Produk'], ['ord', 'Pesanan'], ['chat', 'Chat'], ['adm', 'Admin']].map(([k, l]) => `<button data-tab="${k}" class="${tab === k ? 'on' : ''}">${l}</button>`).join('')}</div><div id="pane"></div>`;
    document.querySelectorAll('[data-st]').forEach((b) => b.onclick = guard(async () => { await api(`/api/shops/${id}/status`, 'POST', { status: b.dataset.st }); toast('Status: ' + b.dataset.st); draw(); }));
    document.querySelectorAll('[data-tab]').forEach((b) => b.onclick = () => { tab = b.dataset.tab; clearTimers(); draw(); });
    const pane = $('#pane');
    if (tab === 'prod') await paneProd(pane, s, draw);
    if (tab === 'ord') await paneOrders(pane, id);
    if (tab === 'chat') await paneChat(pane, id, s);
    if (tab === 'adm') paneAdmins(pane, s, draw);
  };
  await draw();
}
async function paneProd(pane, s, redraw) {
  pane.innerHTML = `<div class="card"><h3>Tambah jualan</h3><div class="grid">
  <div><label>Nama barang</label><input id="pn" maxlength="80"></div>
  <div><label>Kategori</label><select id="pc">${meta.categories.map((c) => `<option>${esc(c)}</option>`).join('')}</select></div>
  <div><label>Harga (Rp)</label><input id="pp" type="number" min="0"></div><div><label>Stok</label><input id="ps" type="number" min="0" value="1"></div>
  <div><label>Pembayaran</label><select id="py"><option value="both">COD & Online</option><option value="cod">COD saja</option><option value="online">Online saja</option></select></div>
  <div><label>Tanggal jual</label><input id="pd" type="date" value="${esc(meta.today)}"></div></div>
  <label>Catatan</label><input id="pt" maxlength="200"><p><button id="padd">Tambah</button></p></div>
  <table>${s.products.map((p) => `<tr><td><b>${esc(p.name)}</b><div class="mut">${esc(p.category)} • ${esc(fmtDate(p.date))}</div></td><td>${rp(p.price)}</td><td>${payBadge(p.payment)}</td>
  <td><input type="number" min="0" value="${p.stock}" data-stock="${p.id}"></td><td><button class="danger" data-del="${p.id}">Hapus</button></td></tr>`).join('')}</table>`;
  $('#padd').onclick = guard(async () => {
    await api(`/api/shops/${s.id}/products`, 'POST', { name: $('#pn').value, category: $('#pc').value, price: parseInt($('#pp').value, 10), stock: parseInt($('#ps').value, 10), payment: $('#py').value, date: $('#pd').value, note: $('#pt').value });
    toast('Produk ditambahkan'); redraw();
  });
  document.querySelectorAll('[data-del]').forEach((b) => b.onclick = guard(async () => { await api(`/api/shops/${s.id}/products/${b.dataset.del}`, 'DELETE'); redraw(); }));
  document.querySelectorAll('[data-stock]').forEach((i) => i.onchange = guard(async () => { await api(`/api/shops/${s.id}/products/${i.dataset.stock}`, 'POST', { stock: parseInt(i.value, 10) }); toast('Stok diperbarui'); }));
}
async function paneOrders(pane, id) {
  const list = await api(`/api/shops/${id}/orders`);
  pane.innerHTML = list.length ? list.map((o) => `<div class="card"><div class="row"><b>#${esc(o.id)}</b><span class="badge">${esc(o.buyerAlias)}</span>${payBadge(o.payment)}<span class="badge">${esc(o.status)}</span><span class="mut">${esc(fmtTime(o.created))}</span></div>
    <div>${o.items.map((i) => `${esc(i.name)} × ${i.qty}`).join(', ')}</div><div class="price">${rp(o.total)}</div>
    ${o.address ? `<div class="mut">📍 ${esc(o.address)}</div>` : ''}${o.note ? `<div class="mut">📝 ${esc(o.note)}</div>` : ''}
    <div class="row">${['diproses', 'dikirim', 'selesai', 'ditolak'].map((st) => `<button class="${st === 'ditolak' ? 'danger' : 'sec'}" data-o="${o.id}" data-s="${st}">${st}</button>`).join('')}</div></div>`).join('') : '<p class="mut">Belum ada pesanan.</p>';
  document.querySelectorAll('[data-o]').forEach((b) => b.onclick = guard(async () => { await api(`/api/shops/${id}/orders/${b.dataset.o}/status`, 'POST', { status: b.dataset.s }); toast('Status pesanan diubah'); paneOrders(pane, id); }));
}
async function paneChat(pane, id, s) {
  const draw = async () => {
    const th = await api(`/api/shops/${id}/threads`);
    pane.innerHTML = `<div class="split"><div>${th.length ? th.map((t) => `<div class="card"><div class="row"><b>${esc(t.buyerAlias)}</b><span class="badge">${esc(t.admin?.label || '')}</span></div><div class="mut">${esc(t.last ? t.last.text.slice(0, 60) : '')}</div><button class="sec" data-t="${t.tid}">Buka</button></div>`).join('') : '<p class="mut">Belum ada chat masuk.</p>'}</div><div id="cbox"></div></div>`;
    document.querySelectorAll('[data-t]').forEach((b) => b.onclick = () => { clearTimers(); chatUI($('#cbox'), id, b.dataset.t, 'admin', s.admins); });
  };
  await draw();
}
function paneAdmins(pane, s, redraw) {
  pane.innerHTML = `<div class="card">${s.admins.map((a) => `<div class="row"><b>${esc(a.label)}</b> ${stBadge(a.status)} ${s.isOwner && a.label !== 'Pemilik' ? `<button class="danger" data-rm="${esc(a.alias)}">Hapus</button>` : ''}</div>`).join('')}</div>
  ${s.isOwner ? `<div class="card"><h3>Tambah admin</h3><p class="mut">Minta calon admin membuat akun, lalu salin ID akunnya dari menu Akun. Dengan 2+ admin, pembeli bisa dialihkan antar admin tanpa melihat nomor siapa pun.</p>
  <label>ID akun admin</label><input id="au" maxlength="32"><label>Nama tampilan</label><input id="al" maxlength="30"><p><button id="aadd">Tambah</button></p></div>` : ''}`;
  if (s.isOwner) {
    $('#aadd').onclick = guard(async () => { await api(`/api/shops/${s.id}/admins`, 'POST', { userId: $('#au').value.trim(), label: $('#al').value }); toast('Admin ditambahkan'); redraw(); });
    document.querySelectorAll('[data-rm]').forEach((b) => b.onclick = guard(async () => { await api(`/api/shops/${s.id}/admins/${b.dataset.rm}`, 'DELETE'); redraw(); }));
  }
}

/* ------------------------------------------------------------ pesanan saya */
async function viewMyOrders() {
  if (!(await requireLogin())) return;
  const list = await api('/api/my/orders');
  app.innerHTML = '<h1>Pesanan saya</h1>' + (list.length ? list.map((o) => `<div class="card"><div class="row"><b>${esc(o.shopName)}</b><span class="badge">${esc(o.status)}</span>${payBadge(o.payment)}<span class="mut">${esc(fmtTime(o.created))}</span></div>
    <div>${o.items.map((i) => `${esc(i.name)} × ${i.qty}`).join(', ')}</div><div class="price">${rp(o.total)}</div><a href="#/shop/${esc(o.shopId)}">Buka bengkel / chat</a></div>`).join('') : '<p class="mut">Belum ada pesanan.</p>');
}

/* ------------------------------------------------------------ start */
(async () => {
  try { meta = await api('/api/meta'); } catch {}
  try { await login(); } catch {}
  updateNav(); route();
})();
