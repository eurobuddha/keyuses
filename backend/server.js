'use strict';
/*
 * KeyUses audit backend.
 *
 * Serves on-chain key-usage lookups for the KeyUses MiniDapp. The heavy work
 * (scanning the whole archive for every signature) is done offline by the Java
 * KeyUseScanner, which writes a small JSON index (the chain is sparse, so the set
 * of distinct signing keys is modest). This service loads that index into memory
 * and answers fast point lookups. A cron refreshes the JSON; we hot-reload it.
 *
 * Endpoint:
 *   GET /keyaudit?keys=0xPK1,0xPK2,...   ->  { status:true, keys:[ {publickey,usecount,maxleafindex,firstblock,lastblock} ] }
 *   GET /keyaudit/health                 ->  { status:true, indexed:N, generated:<mtime> }
 *
 * Misses are zero-filled (usecount:0, maxleafindex:-1) so the dapp always gets a
 * row per requested key. Only PUBLIC keys are ever involved — no wallet data here.
 */

const express = require('express');
const fs = require('fs');
const path = require('path');

const PORT = process.env.KEYUSES_PORT || 3010;
const INDEX_FILE = process.env.KEYUSES_INDEX || path.join(__dirname, 'key_usage.json');
const MAX_KEYS = 256; // generous: a node has 64, allow headroom

let INDEX = new Map();       // UPPERCASE publickey -> usage object
let INDEX_MTIME = 0;
let INDEX_COUNT = 0;

function loadIndex() {
  try {
    const stat = fs.statSync(INDEX_FILE);
    if (stat.mtimeMs === INDEX_MTIME) return; // unchanged
    const raw = JSON.parse(fs.readFileSync(INDEX_FILE, 'utf8'));
    const arr = Array.isArray(raw) ? raw : (raw.keys || []);
    const m = new Map();
    for (const u of arr) {
      if (u && u.publickey) m.set(String(u.publickey).toUpperCase(), u);
    }
    INDEX = m;
    INDEX_MTIME = stat.mtimeMs;
    INDEX_COUNT = m.size;
    console.log(`[keyuses] loaded index: ${m.size} keys (mtime ${new Date(stat.mtimeMs).toISOString()})`);
  } catch (e) {
    console.error('[keyuses] index load failed:', e.message);
  }
}

loadIndex();
setInterval(loadIndex, 60 * 1000); // hot-reload at most once a minute

const app = express();

// CORS — the MiniDapp fetches cross-origin from the node.
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/health', (req, res) => {
  loadIndex();
  res.json({ status: true, indexed: INDEX_COUNT, generated: INDEX_MTIME });
});

app.get('/', (req, res) => {
  const raw = (req.query.keys || '').trim();
  if (!raw) return res.json({ status: false, error: 'no keys parameter' });

  const pks = raw.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
  if (pks.length === 0) return res.json({ status: false, error: 'empty keys' });
  if (pks.length > MAX_KEYS) return res.json({ status: false, error: 'too many keys (max ' + MAX_KEYS + ')' });

  loadIndex();
  const out = pks.map(pk => {
    const u = INDEX.get(pk);
    if (u) {
      return {
        publickey: pk,
        usecount: u.usecount,
        maxleafindex: u.maxleafindex,
        firstblock: u.firstblock,
        lastblock: u.lastblock,
      };
    }
    // zero-fill miss: never signed on-chain
    return { publickey: pk, usecount: 0, maxleafindex: -1, firstblock: -1, lastblock: -1 };
  });

  res.json({ status: true, keys: out });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[keyuses] audit backend on 127.0.0.1:${PORT}, index=${INDEX_FILE}`);
});
