#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const rules = require(path.join(ROOT, 'rules.cjs'));

// ── Generate browser-compatible rules array (no require, no regex literals) ──
function generateBrowserRules() {
  const lines = rules.BUILTIN_RULES.map(r => {
    const regexStr = r.regex.toString();
    return `  { id:'${r.id}', name:'${r.name.replace(/'/g, "\\'")}', label:'${r.label}', regex:${regexStr}, conf:${r.conf}${r.luhn ? ', luhn:true' : ''} }`;
  });
  return '[\n' + lines.join(',\n') + '\n]';
}

function generateBrowserFakers() {
  const lines = Object.entries(rules.FAKERS).map(([label, fn]) => {
    const fnStr = fn.toString();
    return `  ${label}: ${fnStr}`;
  });
  return '{\n' + lines.join(',\n') + '\n}';
}

// ── Replace rules section in a file ──
function replaceSection(content, startPattern, endPattern, newContent) {
  const startIdx = content.indexOf(startPattern);
  if (startIdx === -1) return null;
  const afterStart = content.indexOf(endPattern, startIdx + startPattern.length);
  if (afterStart === -1) return null;
  const endIdx = afterStart + endPattern.length;
  return content.substring(0, startIdx) + newContent + content.substring(endIdx);
}

// ── Update extension/content.js ──
function updateContentJS() {
  const filePath = path.join(ROOT, 'extension', 'content.js');
  let content = fs.readFileSync(filePath, 'utf8');
  const browserRules = generateBrowserRules();
  const browserFakers = generateBrowserFakers();

  const newPatterns = 'var patterns = ' + browserRules + ';';
  const newFakerBlock = '  function fakeFor(label) {\n    var fakers = ' + browserFakers + ';\n    var fn = fakers[label];\n    return fn ? fn() : \'[FAKE_\' + label + \']\';\n  }';

  // Replace patterns array
  const patternsMatch = content.match(/var patterns = \[[\s\S]*?\];/);
  if (patternsMatch) {
    content = content.replace(patternsMatch[0], newPatterns);
  }

  // Replace fakeFor function
  const fakeForMatch = content.match(/function fakeFor\(label\) \{[\s\S]*?return fn \? fn\(\) : '\[FAKE_' \+ label \+ '\]';[\s\S]*?\}/);
  if (fakeForMatch) {
    content = content.replace(fakeForMatch[0], newFakerBlock);
  }

  fs.writeFileSync(filePath, content, 'utf8');
  console.log('  Updated extension/content.js (' + rules.BUILTIN_RULES.length + ' rules)');
}

// ── Update extension/background.js ──
function updateBackgroundJS() {
  const filePath = path.join(ROOT, 'extension', 'background.js');
  let content = fs.readFileSync(filePath, 'utf8');
  const browserRules = generateBrowserRules();
  const browserFakers = generateBrowserFakers();

  // Replace PII_RULES array
  const rulesMatch = content.match(/const PII_RULES = \[[\s\S]*?\];/);
  if (rulesMatch) {
    content = content.replace(rulesMatch[0], 'const PII_RULES = ' + browserRules + ';');
  }

  // Replace FAKERS object
  const fakersMatch = content.match(/const FAKERS = \{[\s\S]*?\};/);
  if (fakersMatch) {
    content = content.replace(fakersMatch[0], 'const FAKERS = ' + browserFakers + ';');
  }

  fs.writeFileSync(filePath, content, 'utf8');
  console.log('  Updated extension/background.js (' + rules.BUILTIN_RULES.length + ' rules)');
}

// ── Update .vscode-ext/extension.js ──
function updateVSCodeExtension() {
  const filePath = path.join(ROOT, '.vscode-ext', 'extension.js');
  let content = fs.readFileSync(filePath, 'utf8');
  const vscodeRules = generateBrowserRules().replace(/\n/g, '\n');
  const vscodeFakers = generateBrowserFakers();

  // Replace PII_RULES array
  const rulesMatch = content.match(/const PII_RULES = \[[\s\S]*?\];/);
  if (rulesMatch) {
    content = content.replace(rulesMatch[0], 'const PII_RULES = ' + vscodeRules + ';');
  }

  // Replace FAKERS object
  const fakersMatch = content.match(/const FAKERS = \{[\s\S]*?\};/);
  if (fakersMatch) {
    content = content.replace(fakersMatch[0], 'const FAKERS = ' + vscodeFakers + ';');
  }

  fs.writeFileSync(filePath, content, 'utf8');
  console.log('  Updated .vscode-ext/extension.js (' + rules.BUILTIN_RULES.length + ' rules)');
}

// ── Update index.html PWA ──
function updateIndexHTML() {
  const filePath = path.join(ROOT, 'index.html');
  let content = fs.readFileSync(filePath, 'utf8');
  const browserRules = generateBrowserRules();
  const browserFakers = generateBrowserFakers();

  // Replace PII_RULES array in index.html
  const rulesMatch = content.match(/const PII_RULES = \[[\s\S]*?\];/);
  if (rulesMatch) {
    content = content.replace(rulesMatch[0], 'const PII_RULES = ' + browserRules + ';');
  }

  // Replace FAKERS object in index.html
  const fakersMatch = content.match(/const FAKERS = \{[\s\S]*?\};/);
  if (fakersMatch) {
    content = content.replace(fakersMatch[0], 'const FAKERS = ' + browserFakers + ';');
  }

  fs.writeFileSync(filePath, content, 'utf8');
  console.log('  Updated index.html (' + rules.BUILTIN_RULES.length + ' rules)');
}

// ── Main ──
console.log('Syncing rules from rules.cjs to all surfaces...');
console.log('  Rules: ' + rules.BUILTIN_RULES.length + ' PII types');
console.log('  Fakers: ' + Object.keys(rules.FAKERS).length + ' functions');
console.log('');

try { updateContentJS(); } catch (e) { console.error('  Error updating content.js:', e.message); }
try { updateBackgroundJS(); } catch (e) { console.error('  Error updating background.js:', e.message); }
try { updateVSCodeExtension(); } catch (e) { console.error('  Error updating VS Code extension:', e.message); }
try { updateIndexHTML(); } catch (e) { console.error('  Error updating index.html:', e.message); }

console.log('\nDone. Run tests to verify: node test-report.mjs');
