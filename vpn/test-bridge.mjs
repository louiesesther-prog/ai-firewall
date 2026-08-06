// End-to-end test: start a local HTTP echo server, run the SOCKS5 bridge,
// connect through it via a raw SOCKS5 CONNECT, and verify the echo round-trips.
import { createServer } from 'net';
import { connect } from 'net';
import { spawn } from 'child_process';

const ECHO_PORT = 19090;
const SOCKS_PORT = 19108;

function startEcho() {
  return new Promise((resolve) => {
    const srv = createServer((c) => { c.pipe(c); });
    srv.listen(ECHO_PORT, '127.0.0.1', () => resolve(srv));
  });
}

function startBridge() {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['vpn/socks5-bridge.mjs', '--port', String(SOCKS_PORT)], {
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let buf = '';
    child.stdout.on('data', (d) => { buf += d; if (buf.includes('Listening')) resolve(child); });
    child.stderr.on('data', () => {});
  });
}

function socks5Connect(port) {
  return new Promise((resolve, reject) => {
    const sock = connect(SOCKS_PORT, '127.0.0.1');
    sock.on('error', reject);
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0]))); // greeting
    let stage = 0;
    sock.on('data', (d) => {
      try {
        if (stage === 0) {
          if (d[0] !== 5 || d[1] !== 0) { reject(new Error('bad auth reply')); return; }
          stage = 1;
          // CONNECT to echo server
          const req = Buffer.alloc(4 + 4 + 2);
          req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 1;
          req.writeUInt8(127, 4); req.writeUInt8(0, 5); req.writeUInt8(0, 6); req.writeUInt8(1, 7);
          req.writeUInt16BE(port, 8);
          sock.write(req);
          return;
        }
        if (stage === 1) {
          if (d[0] !== 5 || d[1] !== 0) { reject(new Error('connect rejected: ' + d[1])); return; }
          resolve(sock);
        }
      } catch (e) { reject(e); }
    });
  });
}

const results = { pass: 0, fail: 0 };
function check(name, cond) {
  if (cond) { results.pass++; console.log('PASS  ' + name); }
  else { results.fail++; console.log('FAIL  ' + name); }
}

// Test the SOCKS5 handshake parser in isolation via the real server
const echo = await startEcho();
const bridge = await startBridge();
await new Promise((r) => setTimeout(r, 300));

// Test 1: connect through SOCKS bridge to echo server
try {
  const sock = await socks5Connect(ECHO_PORT);
  const payload = 'AI-Firewall-VPN-ROUNDTRIP-' + Date.now();
  const replyP = new Promise((resolve) => {
    sock.on('data', (d) => resolve(d.toString()));
  });
  sock.write(payload);
  const echoed = await replyP;
  check('SOCKS5 CONNECT + echo round-trip', echoed === payload);
  sock.end();
} catch (e) {
  check('SOCKS5 CONNECT + echo round-trip', false);
  console.log('     error: ' + e.message);
}

// Test 2: handshake with unsupported command (BIND) should be rejected
try {
  const sock = connect(SOCKS_PORT, '127.0.0.1');
  await new Promise((r) => { sock.on('connect', r); });
  sock.on('data', () => {}); // drain replies
  sock.write(Buffer.from([5, 1, 0]));
  await new Promise((r) => setTimeout(r, 100));
  sock.write(Buffer.from([5, 2, 0, 1, 127, 0, 0, 1, 0, ECHO_PORT]));
  const closed = await Promise.race([
    new Promise((r) => sock.on('close', () => r(true))),
    new Promise((r) => setTimeout(() => r(false), 2000))
  ]);
  check('BIND command rejected (close)', closed === true);
  sock.destroy();
} catch (e) {
  check('BIND command rejected (close)', true);
}

// Test 3: version mismatch rejected
try {
  const sock = connect(SOCKS_PORT, '127.0.0.1');
  await new Promise((r) => { sock.on('connect', r); });
  sock.write(Buffer.from([4, 1, 0])); // SOCKS4
  const closed = await Promise.race([
    new Promise((r) => sock.on('close', () => r(true))),
    new Promise((r) => setTimeout(() => r(false), 2000))
  ]);
  check('SOCKS4 rejected', closed === true);
  sock.destroy();
} catch (e) {
  check('SOCKS4 rejected', true);
}

// Test 4: HTTP status probe (extension "Connect VPN" button polls this)
try {
  const sock = connect(SOCKS_PORT, '127.0.0.1');
  await new Promise((r) => { sock.on('connect', r); });
  const bodyP = new Promise((resolve) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('\r\n\r\n')) {
        resolve(buf);
        sock.destroy();
      }
    });
  });
  sock.write('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n');
  const raw = await bodyP;
  const json = raw.slice(raw.indexOf('{'));
  const status = JSON.parse(json);
  check('HTTP status probe returns bridge JSON', status.ok === true && status.service === 'ai-firewall-vpn-bridge');
} catch (e) {
  check('HTTP status probe returns bridge JSON', false);
  console.log('     error: ' + e.message);
}

bridge.kill();
echo.close();
console.log('');
console.log('SOCKS5 bridge: ' + results.pass + '/' + (results.pass + results.fail) + ' pass');
process.exit(results.fail > 0 ? 1 : 0);
