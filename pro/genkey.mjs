#!/usr/bin/env node
// Mint AI Personal Firewall Pro license keys.
// Usage:  node pro/genkey.mjs [count]      (default 1)
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
require('../pro-lib.js');
const pro = globalThis.AIFW.pro;

const count = parseInt(process.argv[2] || '1', 10);
if (!count || count < 1 || count > 100) {
  console.error('Usage: node pro/genkey.mjs [1-100]');
  process.exit(1);
}

for (let i = 0; i < count; i++) {
  const key = pro.generate();
  console.log(key);
}
console.log(`\n${count} key(s) minted. Hand these to Pro buyers; they unlock the docs at /pro/docs.html`);
console.log('Validation matches pro-lib.js (FNV-1a checksum, salt in pro-lib.js).');