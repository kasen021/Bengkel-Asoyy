# BengkelMarket (prototipe)

Marketplace bengkel / sparepart / modifan motor. Tanpa dependensi, butuh Node >= 18.

```bash
node server.js          # http://127.0.0.1:3000
node test.js            # 33 uji integrasi (auth, enkripsi, pesanan, chat, keamanan)
```
Produksi: pasang di belakang HTTPS (nginx/Caddy), set `HOST=0.0.0.0 TRUST_PROXY=1`, simpan `MASTER_KEY` (64 hex) di secret manager.

## Fitur
- **Bengkel + lokasi real-time**: cari alamat (OpenStreetMap Nominatim), klik peta, atau GPS; daftar & peta bengkel terdekat (Leaflet).
- **Jualan per hari**: tiap bengkel punya daftar sendiri (nama, harga, stok, tanggal, COD / Online / keduanya). Tombol **Bagikan** menghasilkan teks "jualan hari ini" + link untuk rekomendasi.
- **Akun tanpa email/telepon**: kunci RSA-4096 (2048 × 2) dibuat di browser; login = tanda tangan RSA-PSS atas nonce sekali pakai. Pendaftaran butuh proof-of-work (anti bot massal).
- **Data terpisah per bengkel**: `data/shops/<id>/`. Pesanan & chat dienkripsi **ARIA-256-GCM** dengan kunci unik per bengkel (HKDF dari master key), AAD terikat ke bengkel/berkas, jadi data yang dirusak/dipindah ditolak.
- **Identitas terjaga**: bengkel hanya melihat alias pembeli (`P-xxxxxx`) yang berbeda di tiap bengkel; pembeli hanya melihat nama tampilan admin.
- **Chat tanpa nomor**; **2+ admin** per bengkel, status online / sibuk / offline, auto-assign ke admin online paling sepi, pembeli/admin bisa mengalihkan ke admin lain.
- **Pertahanan**: rate limit (IP & akun), batas body 32 KB, validasi semua input, CSP + header keamanan, anti path-traversal, anti-replay, timeout request, escape XSS.

## Batasan jujur
- "Stream cipher 2048×2" bukan konstruksi standar. Yang dipakai: RSA-4096 untuk identitas + ARIA-256-GCM (AEAD) untuk data.
- Enkripsi pesanan/chat dilakukan **server** (at-rest). Bukan end-to-end: server bisa membaca saat memproses. E2E penuh perlu pertukaran kunci di klien (mis. ECDH) — langkah lanjutan.
- Tidak ada sistem yang bisa "mencegah semua serangan siber". Ini mitigasi dasar; untuk produksi tambahkan HTTPS, WAF/CDN anti-DDoS, backup, audit, dan payment gateway sungguhan (pembayaran online di sini hanya dicatat).
- "Turing-complete" tidak dibutuhkan untuk sistem ini dan justru memperbesar risiko, jadi tidak dibuat.
- Kunci privat disimpan di localStorage browser: cadangkan lewat menu Akun.
