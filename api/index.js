'use strict';
// Satu-satunya fungsi Vercel. Jika gagal dimuat, tampilkan penyebabnya (tanpa membuka nilai rahasia).
let handler, loadErr;
try { handler = require('./_core.cjs').handle; } catch (e) { loadErr = e; }
const has = (k) => (process.env[k] ? 'ada (' + process.env[k].length + ' karakter)' : 'KOSONG');
module.exports = (req, res) => {
  if ((req.url || '').startsWith('/api/diag') || loadErr) {
    res.statusCode = loadErr ? 500 : 200;
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    return res.end([
      loadErr ? 'GAGAL MEMUAT: ' + loadErr.message : 'Server termuat dengan baik.',
      'MASTER_KEY (harus 64 karakter): ' + has('MASTER_KEY'),
      'UPSTASH_REDIS_REST_URL: ' + has('UPSTASH_REDIS_REST_URL'),
      'UPSTASH_REDIS_REST_TOKEN: ' + has('UPSTASH_REDIS_REST_TOKEN'),
      'VERCEL: ' + has('VERCEL'),
      'Node: ' + process.version,
    ].join('\n'));
  }
  return handler(req, res);
};
