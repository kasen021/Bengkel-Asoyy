'use strict';
const fs = require('fs');
const path = require('path');
const URL_ = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, '');
const TOK = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const enabled = !!(URL_ && TOK);
const P = 'bm:';
async function cmd(args) {
  const r = await fetch(URL_, { method: 'POST', headers: { authorization: 'Bearer ' + TOK, 'content-type': 'application/json' }, body: JSON.stringify(args) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
const pending = new Map();
let busy = false;
async function flush() {
  if (busy) return; busy = true;
  try {
    while (pending.size) {
      const [rel, val] = pending.entries().next().value;
      try { await cmd(['SET', P + rel, val]); if (pending.get(rel) === val) pending.delete(rel); }
      catch (e) { console.error('mirror gagal:', e.message); await new Promise((r) => setTimeout(r, 3000)); }
    }
  } finally { busy = false; }
}
function put(dataDir, file, content) {
  if (!enabled) return;
  pending.set(path.relative(dataDir, file).split(path.sep).join('/'), content);
  flush();
}
async function hydrate(dataDir) {
  if (!enabled) return 0;
  const keys = await cmd(['KEYS', P + '*']);
  let n = 0;
  for (const k of keys) {
    const rel = k.slice(P.length);
    if (rel.includes('..') || rel.startsWith('/')) continue;
    const val = await cmd(['GET', k]);
    const f = path.join(dataDir, rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, val); n++;
  }
  return n;
}
module.exports = { enabled, put, hydrate };
