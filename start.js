'use strict';
const path = require('path');
const mirror = require('./mirror');
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
(async () => {
  if (mirror.enabled) console.log('Memulihkan data dari Upstash:', await mirror.hydrate(DATA), 'berkas');
  else console.log('Cermin Upstash mati (data hanya di disk lokal).');
  if (process.env.PORT && !process.env.HOST) process.env.HOST = '0.0.0.0';
  const { server } = require('./app.cjs');
  const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '127.0.0.1';
  server.listen(PORT, HOST, () => console.log(`BengkelMarket jalan di ${HOST}:${PORT}`));
})().catch((e) => { console.error(e); process.exit(1); });
