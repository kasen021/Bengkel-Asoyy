'use strict';
// Pintu masuk Vercel. Jika gagal memuat, tampilkan penyebabnya (sementara, untuk diagnosa).
let handler, loadErr;
try { handler = require('../bengkel-core.cjs').handle; } catch (e) { loadErr = e; }
module.exports = (req, res) => {
  if (loadErr || typeof handler !== 'function') {
    res.statusCode = 500; res.setHeader('content-type', 'text/plain; charset=utf-8');
    return res.end('GAGAL MEMUAT: ' + ((loadErr && loadErr.message) || 'handle bukan fungsi'));
  }
  return handler(req, res);
};
