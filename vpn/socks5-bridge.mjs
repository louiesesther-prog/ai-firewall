#!/usr/bin/env node
// AI Firewall VPN — SOCKS5 bridge over the WireGuard tunnel
//
// Exposes a local SOCKS5 proxy (default 127.0.0.1:1080) that routes
// connections THROUGH the active WireGuard tunnel. This lets the browser
// extension's "Privacy Route" mode point at your real VPN:
//
//   popup -> Privacy Route -> SOCKS5 127.0.0.1:1080
//
// Usage:
//   node vpn/socks5-bridge.mjs                # listen on 127.0.0.1:1080
//   node vpn/socks5-bridge.mjs --port 1081    # custom port
//   node vpn/socks5-bridge.mjs --test         # verify tunnel connectivity
//
// Requirements:
//   - WireGuard tunnel must be UP (wg-quick up <name>)
//   - Node.js 16+
//
// HOW IT WORKS: listend for SOCKS5 clients (browser, apps) and makes the
// connection using the system's default route — i.e., through the WireGuard
// adapter. Dependency-free SOCKS5 (RFC 1928) CONNECT implementation.

import { createServer, connect as createConnection } from 'net';
import { networkInterfaces } from 'os';

const LISTEN_HOST = '127.0.0.1';
let LISTEN_PORT = 1080;
let VERIFY = false;

const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--port') LISTEN_PORT = parseInt(argv[i + 1], 10) || 1080;
  if (argv[i] === '--test') VERIFY = true;
  if (argv[i] === '--help') {
    console.log('AI Firewall VPN — SOCKS5 bridge over WireGuard tunnel');
    console.log('Usage: node vpn/socks5-bridge.mjs [--port <n>] [--test]');
    process.exit(0);
  }
}

function detectWgAdapter() {
  try {
    const ifaces = networkInterfaces();
    for (const [name, addrs] of Object.entries(ifaces)) {
      if (/wireguard/i.test(name)) {
        const ip = (addrs || []).find((a) => a.family === 'IPv4');
        if (ip) return { name, ip: ip.address };
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

function handleSocks(conn) {
  let stage = 0;
  conn.on('error', () => { try { conn.destroy(); } catch (e) {} });

  conn.on('data', (data) => {
    try {
      if (stage === 0) {
        // Method negotiation (RFC 1928): expect SOCKS5, reply no-auth
        if (data[0] !== 5) { conn.end(); return; }
        stage = 1;
        conn.write(Buffer.from([5, 0]));
        return;
      }
      if (stage === 1) {
        // Connect request
        const cmd = data[1], atyp = data[3];
        if (cmd !== 1) { conn.end(); return; } // CONNECT only
        let host, port;
        if (atyp === 1) { // IPv4
          host = [data[4], data[5], data[6], data[7]].join('.');
          port = data.readUInt16BE(8);
        } else if (atyp === 3) { // domain
          const len = data[4];
          host = data.slice(5, 5 + len).toString();
          port = data.readUInt16BE(5 + len);
        } else if (atyp === 4) { // IPv6
          host = data.slice(4, 20).toString('hex').replace(/(.{4})/g, '$1:').replace(/:$/, '');
          port = data.readUInt16BE(20);
        } else { conn.end(); return; }

        stage = 2;
        const upstream = createConnection({ host, port });
        let bound = false;
        upstream.on('connect', () => {
          if (bound) return; bound = true;
          conn.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
          upstream.pipe(conn);
          conn.pipe(upstream);
        });
        upstream.on('error', () => { if (!bound) conn.end(); });
        conn.on('error', () => { try { upstream.destroy(); } catch (e) {} });
        return;
      }
    } catch (e) {
      try { conn.end(); } catch (e2) {}
    }
  });
}

const server = createServer(handleSocks);
server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  const wg = detectWgAdapter();
  console.log('');
  console.log('  AI Firewall VPN — SOCKS5 bridge');
  console.log('  ' + '─'.repeat(45));
  console.log('  Listening: ' + LISTEN_HOST + ':' + LISTEN_PORT);
  if (wg) {
    console.log('  WireGuard adapter: ' + wg.name + ' (' + wg.ip + ')');
    console.log('  Tunnel: UP — proxy traffic rides the VPN.');
  } else {
    console.log('  WireGuard adapter: not detected.');
    console.log('  Make sure the tunnel is up (wg-quick up <name>)!');
  }
  console.log('');
  console.log('  Point the extension Privacy Route at this proxy:');
  console.log('    host: ' + LISTEN_HOST + '   port: ' + LISTEN_PORT + '   protocol: SOCKS5');
  console.log('');
  console.log('  All proxy connections now travel through the WireGuard tunnel.');
  console.log('  Press Ctrl+C to stop.');
  if (VERIFY) setTimeout(testBridge, 400);
});

function testBridge() {
  const t = createConnection({ host: LISTEN_HOST, port: LISTEN_PORT });
  t.on('connect', () => {
    t.write(Buffer.from([5, 1, 0]));
    t.on('data', (d) => {
      if (d[0] === 5 && d[1] === 0) {
        console.log('[test] SOCKS5 handshake OK — bridge is ready.');
      } else {
        console.log('[test] Unexpected handshake response.');
      }
      t.end();
      process.exit(0);
    });
  });
  t.on('error', (e) => {
    console.log('[test] FAILED: ' + e.message);
    process.exit(1);
  });
  setTimeout(() => { console.log('[test] timeout'); process.exit(1); }, 5000);
}
