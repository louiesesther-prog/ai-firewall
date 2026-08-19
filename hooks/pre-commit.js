#!/usr/bin/env node
'use strict';
const { execSync } = require('child_process');

let files;
try {
  files = execSync('git diff --cached --name-only --diff-filter=ACM', { encoding: 'utf8' })
    .trim().split('\n').filter(f => /\.(js|ts|jsx|tsx|json|md|txt|env|yml|yaml|toml|ini|cfg|conf|py|rb|go|rs|java|c|cpp|h)$/i.test(f));
} catch { process.exit(0); }

if (!files.length) process.exit(0);

console.log('[AI Firewall] Scanning ' + files.length + ' staged files for PII...');

let totalPII = 0;
const issues = [];

for (const file of files) {
  try {
    const output = execSync('node cli.js ci --file "' + file + '" --format json --fail-threshold 9999', { encoding: 'utf8', timeout: 30000 });
    const result = JSON.parse(output);
    if (result.totalPII > 0) {
      totalPII += result.totalPII;
      for (const m of result.matches) {
        issues.push('  ' + file + ':' + m.line + ' [' + m.type + '] ' + m.original.substring(0, 50));
      }
    }
  } catch (e) {
    if (e.stdout) {
      try {
        const result = JSON.parse(e.stdout);
        if (result.totalPII > 0) {
          totalPII += result.totalPII;
          for (const m of result.matches) {
            issues.push('  ' + file + ':' + m.line + ' [' + m.type + '] ' + m.original.substring(0, 50));
          }
        }
      } catch {}
    }
  }
}

if (totalPII > 0) {
  console.error('\n[AI Firewall] BLOCKED: ' + totalPII + ' PII items found in staged files:\n');
  issues.forEach(i => console.error(i));
  console.error('\nRemove or mask PII before committing.');
  console.error('To bypass: git commit --no-verify\n');
  process.exit(1);
} else {
  console.log('[AI Firewall] No PII detected. Commit OK.');
}
