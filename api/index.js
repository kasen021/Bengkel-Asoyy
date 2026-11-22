'use strict';

module.exports = async function (req, res) {
  try {
    const { handle } = require('../server');
    return await handle(req, res);
  } catch (e) {
    console.error('[VERCEL_BOOT_ERROR]', e && e.stack ? e.stack : e);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'Server initialization failed' }));
  }
};
