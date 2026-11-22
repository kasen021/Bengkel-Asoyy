'use strict';
// Penyimpanan Upstash Redis (REST) untuk hosting serverless (Vercel). Tanpa dependensi.
const URL_ = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, '');
const TOK = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const HASH = 'bm:data';
async function cmd(args) {
  if (!URL_ || !TOK) throw new Error('UPSTASH_REDIS_REST_URL / _TOKEN belum diisi');
  const r = await fetch(URL_, { method: 'POST', headers: { authorization: 'Bearer ' + TOK, 'content-type': 'application/json' }, body: JSON.stringify(args) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
const hgetall = async () => cmd(['HGETALL', HASH]) || [];
const hset = (flat) => cmd(['HSET', HASH, ...flat]);
const claim = async (key, ttl) => (await cmd(['SET', 'bm:used:' + key, '1', 'NX', 'EX', String(ttl)])) === 'OK';
module.exports = { hgetall, hset, claim };
