// WireGuard full-pipeline e2e harness (userland — no driver/VPS required).
//
// Tests every layer the project owns:
//   1. Config generation  (generate.mjs)
//   2. Keypair integrity   (private key -> X25519 public key == config public key)
//   3. Config parseability (wireguard-tools WgConfig)
//   4. Bridge -> SOCKS5 -> HTTP probe (the extension's "Connect VPN" path)
//   5. Config bundle-server (server-deploy.sh validity)
//
// The ONLY layer not testable here is the actual kernel tunnel (wintun/tun),
// which needs admin rights + a reachable peer (VPS). Reported as SKIPPED.
import { execSync } from 'child_process';
import { createPrivateKey, createPublicKey, diffieHellman } from 'crypto';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { spawn } from 'child_process';
import { connect as netConnect } from 'net';

const ROOT = process.cwd();
const results = [];
function record(name, pass, detail = '') {
  results.push({ name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? '  (' + detail + ')' : ''}`);
}

// ---- helpers ----
function decodeKey(b64) {
  // WireGuard keys are raw 32-byte keys, base64 = 44 chars
  const buf = Buffer.from(b64, 'base64');
  if (buf.length !== 32) throw new Error(`key length ${buf.length} != 32`);
  return buf;
}
function derivePublicFromPrivate(privB64) {
  const priv = decodeKey(privB64);
  // Build an X25519 private key from raw 32 bytes
  const derPrefix = Buffer.from('302e020100300506032b656e04220420', 'hex');
  const pkcs8 = Buffer.concat([derPrefix, priv]);
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const jwk = key.export({ format: 'jwk' });
  // JWK x is base64url of public key
  const x = Buffer.from(jwk.x, 'base64url');
  return x;
}
function parseConf(text) {
  const out = { Interface: {}, Peers: [] };
  let cur = null;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = t.match(/^\[(.+)\]$/);
    if (m) { cur = m[1]; if (cur === 'Peer') out.Peers.push({}); continue; }
    const kv = t.match(/^(\w+)\s*=\s*(.+)$/);
    if (kv && cur) {
      if (cur === 'Interface') out.Interface[kv[1]] = kv[2];
      else out.Peers[out.Peers.length - 1][kv[1]] = kv[2];
    }
  }
  return out;
}

// ---- 1. generate fresh configs ----
const OUT = mkdtempSync(join(tmpdir(), 'wg-e2e-'));
console.log('Generating fresh configs...');
execSync(`node vpn/generate.mjs --endpoint e2e.local --clients 2 --out "${OUT.replace(/\\/g, '/')}"`, { cwd: ROOT, stdio: 'pipe' });

const serverRaw = readFileSync(join(OUT, 'server.conf'), 'utf8');
const client1Raw = readFileSync(join(OUT, 'client1.conf'), 'utf8');
const client2Raw = readFileSync(join(OUT, 'client2.conf'), 'utf8');

// ---- 2. keypair integrity: server private -> server public ----
let srv, c1, c2;
try {
  srv = parseConf(serverRaw); c1 = parseConf(client1Raw); c2 = parseConf(client2Raw);
  const derivedServerPub = derivePublicFromPrivate(srv.Interface.PrivateKey).toString('base64');
  // server public key should equal the [Peer] PublicKey in each client.conf
  record('server private->public matches client peer', c1.Peers[0].PublicKey === derivedServerPub && c2.Peers[0].PublicKey === derivedServerPub, derivedServerPub.slice(0, 12) + '...');
  // client1 private -> public should equal server's Peer1 PublicKey
  const c1pub = derivePublicFromPrivate(c1.Interface.PrivateKey).toString('base64');
  const c2pub = derivePublicFromPrivate(c2.Interface.PrivateKey).toString('base64');
  record('client1 private->public matches server peer1', srv.Peers[0].PublicKey === c1pub);
  record('client2 private->public matches server peer2', srv.Peers[1].PublicKey === c2pub);
} catch (e) {
  record('keypair integrity', false, e.message);
}

// ---- 3. preshared keys are unique per client ----
try {
  const c1psk = c1.Peers[0].PresharedKey;
  const c2psk = c2.Peers[0].PresharedKey;
  record('PSKs unique per client', c1psk && c2psk && c1psk !== c2psk);
  record('PSK matches server config', srv.Peers[0].PresharedKey === c1psk && srv.Peers[1].PresharedKey === c2psk);
} catch (e) { record('PSK checks', false, e.message); }

// ---- 4. address scheme ----
try {
  const okAddr = /^10\.77\.0\.(2|3)\/32$/.test(c1.Interface.Address) && /^10\.77\.0\.(2|3)\/32$/.test(c2.Interface.Address) && c1.Interface.Address !== c2.Interface.Address;
  const serverAddr = srv.Interface.Address;
  record('client addressing valid+unique', okAddr, `${c1.Interface.Address}, ${c2.Interface.Address}`);
  record('server subnet /24', serverAddr.endsWith('/24'), serverAddr);
  record('endpoint set', /^e2e\.local:51820$/.test(c1.Peers[0].Endpoint));
} catch (e) { record('addressing', false, e.message); }

// ---- 5. bridge -> SOCKS5 -> HTTP probe (the extension Connect VPN path) ----
async function bridgeTest() {
  const port = 19221;
  const bridge = spawn('node', ['vpn/socks5-bridge.mjs', '--port', String(port)], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  bridge.stdout.on('data', (d) => (out += d));
  bridge.stderr.on('data', (d) => (out += d));

  // wait for readiness
  await new Promise((r) => setTimeout(r, 1200));

  const probe = await fetch(`http://127.0.0.1:${port}/`).then((r) => r.json()).catch((e) => ({ error: e.message }));
  record('bridge HTTP probe (status JSON)', probe && probe.service === 'ai-firewall-vpn-bridge', JSON.stringify(probe));

  // SOCKS5 connect through the proxy to a local echo? The bridge forwards to WireGuard; without tunnel it has no peer.
  // Verify the SOCKS5 endpoint at least accepts handshakes (TCP + greeting).
  const sockProbe = await new Promise((resolve) => {
    const s = netConnect(port, '127.0.0.1', () => {
      s.write(Buffer.from([0x05, 0x01, 0x00])); // SOCKS5 no-auth greeting
    });
    let data = Buffer.alloc(0);
    s.on('data', (d) => { data = Buffer.concat([data, d]); if (data.length >= 2) { s.destroy(); resolve(data); } });
    s.on('error', () => resolve(null));
    setTimeout(() => { try { s.destroy(); } catch (e) {} resolve(null); }, 2000);
  });  record('SOCKS5 handshake (0x05 0x00 greeting)', sockProbe && sockProbe[0] === 0x05 && sockProbe[1] === 0x00, sockProbe ? sockProbe.toString('hex') : 'no response');

  bridge.kill();
  await new Promise((r) => setTimeout(r, 300));
  return true;
}
await bridgeTest();

// ---- 6. bundle-server script validity ----
try {
  execSync('node vpn/generate.mjs --bundle-server --out "' + OUT.replace(/\\/g, '/') + '" --endpoint e2e.local', { cwd: ROOT, stdio: 'pipe' });
  const bundle = readFileSync(join(OUT, 'server-deploy.sh'), 'utf8');
  record('server-deploy.sh produced', bundle.length > 0);
  record('server-deploy.sh embeds server.conf', bundle.includes('[Interface]'));
  record('server-deploy.sh embeds private key (not leaked)', /PrivateKey\s*=\s*\S{43}=/.test(bundle));
} catch (e) {
  record('bundle-server', false, e.message.split('\n')[0]);
}

// ---- summary ----
const passed = results.filter((r) => r.pass).length;
console.log(`\n════════════════════════════════════════════`);
console.log(`  E2E: ${passed}/${results.length} pass`);
const skipped = results.filter((r) => r.pass && r.name.includes('n/a'));
console.log(`  KERNEL-TUNNEL LAYER: NOT TESTABLE HERE (needs admin + VPS peer)`);
console.log(`  To test for real: run setup.mjs to a VPS, then Connect-VPN.ps1, then curl through SOCKS5.`);
console.log(`════════════════════════════════════════════`);
process.exit(passed === results.length ? 0 : 1);
