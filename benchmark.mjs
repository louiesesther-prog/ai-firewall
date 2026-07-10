import { scrub, BUILTIN_RULES } from './cli.js';

const SIZES = [
  { label: '1 KB',     bytes: 1_000 },
  { label: '10 KB',    bytes: 10_000 },
  { label: '100 KB',   bytes: 100_000 },
  { label: '250 KB',   bytes: 250_000 },
];

function genText(n) {
  const items = ['email: user@example.com ','phone: 555-123-4567 ','ssn: 123-45-6789 ','card: 4111-1111-1111-1111 ','ip: 192.168.1.1 ','wallet: 0x71C7656EC7ab9b618e7dD32a6D9C6e1f3B3b6C6e ','mac: aa:bb:cc:dd:ee:ff ','password: secret123 ','api_key: sk-test123 ','dob: 01/15/1990 '];
  const filler = 'Lorem ipsum dolor sit amet consectetur adipiscing elit. ';
  let s = '';
  while (s.length < n) { s += Math.random() < 0.3 ? items[Math.floor(Math.random()*items.length)] : filler; }
  return s.substring(0, n);
}

let cached = {};
function getText(n) {
  if (!cached[n]) cached[n] = genText(n);
  return cached[n];
}

console.log('='.repeat(65));
console.log('AI Firewall - Performance Benchmark');
console.log('='.repeat(65));
console.log('');
console.log('Input Size    | Scrub (ms) | Scrub MB/s | Scan (ms) | Scan MB/s');
console.log('-'.repeat(65));

for (const size of SIZES) {
  const text = getText(size.bytes);
  const iter = size.bytes <= 100_000 ? 5 : 2;

  const s0 = process.hrtime.bigint();
  for (let i = 0; i < iter; i++) scrub(text, { mode: 'placeholder', rules: BUILTIN_RULES });
  const s1 = process.hrtime.bigint();
  const sMs = Number(s1 - s0) / 1e6 / iter;
  const sMB = (size.bytes / sMs / 1e4) * 1e4;

  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iter; i++) {
    for (const rule of BUILTIN_RULES) {
      const re = new RegExp(rule.regex.source, 'g' + (rule.regex.flags.includes('i') ? 'i' : ''));
      re.exec(text);
    }
  }
  const t1 = process.hrtime.bigint();
  const tMs = Number(t1 - t0) / 1e6 / iter;
  const tMB = (size.bytes / tMs / 1e4) * 1e4;

  console.log(
    String(size.label).padEnd(14) + '| ' +
    String(sMs.toFixed(2)).padStart(9) + ' | ' +
    String(sMB.toFixed(2)).padStart(10) + ' | ' +
    String(tMs.toFixed(2)).padStart(8) + ' | ' +
    String(tMB.toFixed(2)).padStart(9)
  );
  delete cached[size.bytes];
}

console.log('-'.repeat(65));
console.log('');
console.log('Tested with ' + BUILTIN_RULES.length + ' PII rules across ' + SIZES.length + ' sizes.');
console.log('='.repeat(65));
