#!/usr/bin/env node
// AI Firewall VPN — all-in-one installer wizard
//
// One command that:
//   1. Generates WireGuard keys + configs (vpn/generate.mjs)
//   2. Deploys the server to your VPS over SSH (scp + ssh)
//   3. Imports a client config locally (WireGuard CLI or app)
//   4. Starts the SOCKS5 bridge for the extension
//   5. Prints "open the popup -> Connect VPN"
//
// Prerequisites:
//   - A rented Ubuntu/Debian VPS with SSH access (user + password/key)
//   - ssh and scp on your PATH
//   - Node.js 16+
//
// Usage:
//   node vpn/setup.mjs                        # interactive prompts
//   node vpn/setup.mjs --host 1.2.3.4 --user root --clients 2
//
// The server's private keys stay local; nothing is ever uploaded to a
// public URL. The VPS receives only server.conf (via scp).

import { spawnSync, spawn } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VPN = join(ROOT, 'vpn');

function ask(question, def) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question + (def ? ' [' + def + '] ' : ' '), (ans) => {
      rl.close();
      resolve(ans.trim() || def || '');
    });
  });
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: opts.silent ? 'pipe' : 'inherit', shell: opts.shell });
  if (r.error) {
    console.error('ERROR: could not run ' + cmd + ': ' + r.error.message);
    process.exit(1);
  }
  return r;
}

async function main() {
  const argv = process.argv.slice(2);
  let host = null, user = null, clients = 3, port = 51820, noPsk = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--host') host = argv[++i];
    if (argv[i] === '--user') user = argv[++i];
    if (argv[i] === '--clients') clients = parseInt(argv[++i], 10);
    if (argv[i] === '--port') port = parseInt(argv[++i], 10);
    if (argv[i] === '--no-preshared') noPsk = true;
    if (argv[i] === '--help') {
      console.log('AI Firewall VPN — all-in-one installer');
      console.log('Usage: node vpn/setup.mjs [--host <vps-ip>] [--user <ssh-user>] [--clients n] [--port n]');
      console.log('No VPS yet? There are permanently FREE servers — see vpn/FREE_VPS.md (Oracle Cloud / Google Cloud).');
      process.exit(0);
    }
  }

  console.log('');
  console.log('  AI Firewall VPN — all-in-one installer');
  console.log('  ' + '─'.repeat(48));
  console.log('');

  if (!host) host = await ask('VPS public IP or hostname (required):');
  if (!host) { console.error('ERROR: VPS host is required.'); process.exit(1); }
  if (!user) user = (await ask('SSH user', 'root')) || 'root';

  const psk = noPsk ? '--no-preshared' : '';

  // 1. Generate keys + configs
  console.log('');
  console.log('==> [1/4] Generating keys + configs (local, X25519)...');
  const gen = run(process.execPath, [join(VPN, 'generate.mjs'), '--endpoint', host, '--port', String(port), '--clients', String(clients), '--bundle-server', psk]);
  if (gen.status !== 0) { console.error('ERROR: key generation failed.'); process.exit(1); }

  const outDir = join(ROOT, 'vpn-out');
  const serverConf = join(outDir, 'server.conf');
  const deploySh = join(outDir, 'server-deploy.sh');
  if (!existsSync(serverConf)) { console.error('ERROR: ' + serverConf + ' missing.'); process.exit(1); }

  // 2. Deploy server over SSH
  console.log('');
  console.log('==> [2/4] Deploying to VPS (' + user + '@' + host + ')...');
  console.log('    (enter your SSH password when prompted)');
  if (existsSync(deploySh)) {
    const scp = spawnSync('scp', [deploySh, user + '@' + host + ':/tmp/server-deploy.sh'], { stdio: 'inherit' });
    if (scp.status !== 0) { console.error('ERROR: scp failed.'); process.exit(1); }
    const sshDeploy = spawnSync('ssh', [user + '@' + host, 'sudo bash /tmp/server-deploy.sh'], { stdio: 'inherit' });
    if (sshDeploy.status !== 0) { console.error('ERROR: remote deploy failed.'); process.exit(1); }
  } else {
    console.error('ERROR: bundled server-deploy.sh not found (regenerate with --bundle-server).');
    process.exit(1);
  }

  // 3. Import client config locally
  console.log('');
  console.log('==> [3/4] Setting up local client...');
  const wg = spawnSync('wg', ['--version'], { stdio: 'pipe' });
  const clientConf = join(outDir, 'client1.conf');
  if (wg.status === 0 && wg.stdout.toString().trim()) {
    const up = spawnSync('wg-quick', ['up', clientConf], { stdio: 'inherit' });
    if (up.status !== 0) console.log('    (wg-quick could not auto-connect — open client1.conf in the WireGuard app instead)');
  } else {
    console.log('    WireGuard CLI not found on this machine.');
    console.log('    On Windows: run  powershell -File vpn/client/install.ps1  then import: ' + clientConf);
    console.log('    Else: import ' + clientConf + ' into the official WireGuard app.');
  }

  // 4. Start the SOCKS5 bridge
  console.log('');
  console.log('==> [4/4] Starting SOCKS5 bridge on 127.0.0.1:1080 ...');
  console.log('    (leave this terminal running)');
  const bridge = spawn(process.execPath, [join(VPN, 'socks5-bridge.mjs')], { stdio: 'inherit' });
  bridge.on('error', (e) => { console.error('ERROR: could not start bridge: ' + e.message); });
  bridge.on('exit', (code) => { console.log('Bridge stopped (exit ' + code + ').'); });

  console.log('');
  console.log('  ' + '─'.repeat(48));
  console.log('  DONE. Now open the extension popup and hit  Connect VPN');
  console.log('  host: 127.0.0.1  port: 1080  protocol: SOCKS5');
  console.log('');
}

main().catch((e) => { console.error(e); process.exit(1); });
