#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ── PII RULES (canonical source: rules.cjs) ─────────────────────
const { BUILTIN_RULES, FAKERS, COMPLIANCE_PROFILES, RISK_WEIGHTS, luhnCheck } = require('./rules.cjs');
const { analyzeDocument, contextScore, detectMissingPII } = require('./context.cjs');

function fakeFor(label, extraFakers) { const fn = (extraFakers && extraFakers[label]) || FAKERS[label]; return fn ? fn() : '[FAKE_' + label + ']'; }

// ── PLUGIN SYSTEM ─────────────────────────────────────────────────
function loadPlugins(pluginPaths) {
  const plugins = { rules: [], fakers: {}, formatters: {} };
  if (!pluginPaths || !pluginPaths.length) return plugins;
  for (const p of pluginPaths) {
    try {
      const resolved = path.resolve(p);
      const mod = require(resolved);
      if (mod.rules && Array.isArray(mod.rules)) plugins.rules.push(...mod.rules);
      if (mod.fakers) Object.assign(plugins.fakers, mod.fakers);
      if (mod.formatters) Object.assign(plugins.formatters, mod.formatters);
      console.log('  Plugin loaded: ' + resolved);
    } catch (e) {
      console.error('  Plugin error (' + p + '): ' + e.message);
    }
  }
  return plugins;
}

function resolveRules(config, profile, pluginRules) {
  const activeProfile = COMPLIANCE_PROFILES[profile] || COMPLIANCE_PROFILES.none;

  let rules = BUILTIN_RULES;

  if (config && config.rules && config.rules.length) {
    const disabled = new Set(config.rules.filter(r => r.enabled === false).map(r => r.id));
    const overrides = {};
    for (const r of config.rules) {
      if (r.conf) overrides[r.id] = r.conf;
    }
    rules = BUILTIN_RULES.map(r => {
      if (disabled.has(r.id)) return null;
      const copy = { ...r };
      if (overrides[r.id] !== undefined) copy.conf = overrides[r.id];
      return copy;
    }).filter(Boolean);
  }

  rules = rules.filter(r => activeProfile.match(r.id));

  if (pluginRules && pluginRules.length) {
    for (const pr of pluginRules) {
      if (pr.enabled === false) continue;
      try {
        const reFlags = pr.flags || 'g';
        const re = new RegExp(pr.regex, reFlags.includes('g') ? reFlags : reFlags + 'g');
        rules.push({
          id: pr.id || ('plugin_' + rules.length),
          name: pr.name || pr.id,
          label: pr.label || (pr.id ? pr.id.toUpperCase() : 'PLUGIN'),
          regex: re,
          conf: pr.conf || 0.7,
          luhn: !!pr.luhn,
          custom: true,
          plugin: true,
        });
      } catch (e) {
        console.error('Invalid plugin rule ("' + (pr.id || 'unknown') + '"): ' + e.message);
      }
    }
  }

  if (config && config.customRules && config.customRules.length) {
    for (const cr of config.customRules) {
      if (cr.enabled === false) continue;
      try {
        const reFlags = cr.flags || 'g';
        const re = new RegExp(cr.regex, reFlags.includes('g') ? reFlags : reFlags + 'g');
        rules.push({
          id: cr.id || ('custom_' + rules.length),
          name: cr.name || cr.id,
          label: cr.label || (cr.id ? cr.id.toUpperCase() : 'CUSTOM'),
          regex: re,
          conf: cr.conf || 0.7,
          luhn: !!cr.luhn,
          custom: true,
        });
      } catch (e) {
        console.error('Invalid custom rule regex for "' + (cr.id || 'unknown') + '": ' + e.message);
      }
    }
  }

  return rules;
}

function getCustomFakers(config, allowUnsafe) {
  const fakers = {};
  if (config && config.customRules && config.customRules.length) {
    for (const cr of config.customRules) {
      const label = cr.label || (cr.id ? cr.id.toUpperCase() : 'CUSTOM');
      if (cr.faker) {
        try {
          if (typeof cr.faker === 'function') {
            fakers[label] = cr.faker;
          } else if (typeof cr.faker === 'string') {
            if (!allowUnsafe) {
              console.error('Skipping string-based faker for "' + (cr.id || 'unknown') + '": requires --unsafe flag (executes arbitrary code)');
              fakers[label] = () => '[FAKE_' + label + ']';
            } else {
              const fn = new Function('return ' + cr.faker)();
              if (typeof fn === 'function') {
                console.warn('WARNING: String-based faker for "' + (cr.id || 'unknown') + '" executes arbitrary code.');
                fakers[label] = fn;
              }
            }
          }
        } catch (e) {
          console.error('Invalid faker for "' + (cr.id || 'unknown') + '": ' + e.message);
        }
      } else {
        fakers[label] = () => '[FAKE_' + label + ']';
      }
    }
  }
  return fakers;
}

// ── SCRUB ───────────────────────────────────────────────────────
function scrub(text, options = {}) {
  const mode = options.mode || 'placeholder';
  const rules = options.rules || BUILTIN_RULES;
  const extraFakers = options.fakers || {};
  let counter = 1;
  let result = text;
  const matches = [];

  const docStats = analyzeDocument(text);

  for (const rule of rules) {
    const regex = new RegExp(rule.regex.source, rule.regex.flags);
    let match;
    while ((match = regex.exec(result)) !== null) {
      const raw = match[0];
      let conf = rule.conf;

      if (rule.luhn) {
        const clean = raw.replace(/[-\s]/g, '');
        if (clean.length >= 13 && clean.length <= 19) {
          conf = luhnCheck(clean) ? 0.95 : 0.3;
        }
      }

      conf = applyHeuristics(rule, raw, match.index, result, conf);
      conf = contextScore(rule, raw, match.index, result, conf, docStats, matches);

      let replacement;
      if (mode === 'realistic') {
        replacement = fakeFor(rule.label, extraFakers);
      } else {
        replacement = '[' + rule.label + '_' + counter + ']';
      }

      matches.push({ type: rule.label, name: rule.name, original: raw, replacement, confidence: conf, _index: match.index });
      result = result.split(raw).join(replacement);
      counter++;
    }
  }

  // Detect additional PII that regex misses (names, etc.)
  const extraMatches = detectMissingPII(result, docStats);
  for (const em of extraMatches) {
    let replacement;
    if (mode === 'realistic') {
      replacement = fakeFor(em.type, extraFakers) || 'John Smith';
    } else {
      replacement = '[PERSON_NAME_' + counter + ']';
    }
    matches.push({ type: em.type, name: em.name, original: em.match, replacement, confidence: em.confidence });
    result = result.split(em.match).join(replacement);
    counter++;
  }

  return { scrubbed: result, matches };
}

function applyHeuristics(rule, raw, idx, text, conf) {
  const start = Math.max(0, idx - 35);
  const end = Math.min(text.length, idx + raw.length + 35);
  const before = text.substring(Math.max(0, idx - 25), idx);
  const after = text.substring(idx + raw.length, Math.min(text.length, idx + raw.length + 25));
  const ctx = before + ' ' + after;

  // Token-boundary: match is part of longer token (embedded in alphanumeric)
  const prev = idx > 0 ? text[idx - 1] : '';
  const next = idx + raw.length < text.length ? text[idx + raw.length] : '';
  if ((prev && /\w/.test(prev)) || (next && /\w/.test(next))) return 0.2;

  // SSN in math or SKU/code context
  if (rule.id === 'ssn') {
    if (/[+\-*=]/.test(ctx) || /\b(SKU|Part\s*#|Product\s*Code)\b/i.test(ctx)) return 0.2;
    if (/^\s*(Number|ID|Code)\s*[#:]?\s*$/i.test(before) && !/\b(SSN|social|security|tax|employee)\b/i.test(ctx)) return 0.2;
  }

  // Passport in code/spec context
  if (rule.id === 'passport') {
    if (/\b(Code|SKU|spec|Ref)\b/i.test(ctx)) return 0.2;
  }

  // Phone in order/product context (no "call" or "dial" nearby)
  if (rule.id === 'phone') {
    if (/\b(Order|Product|Item)\s*[#:]/i.test(ctx) && !/\b(call|dial|phone|tel|ring|reach|contact)\b/i.test(ctx)) return 0.2;
  }

  // Routing number preceded by generic label without "routing"
  if (rule.id === 'routing') {
    if (/^\s*(Number|ID|Code|Ref)\s*[#:]?\s*$/i.test(before) && !/\b(routing|ABA|transit|bank)\b/i.test(ctx)) return 0.15;
  }

  // Statistical classifier: digit-heavy context with no letters = unnatural text
  if ((rule.id === 'phone' || rule.id === 'uk-nhs') && conf > 0.5) {
    const letters = (ctx.match(/[a-zA-Z]/g) || []).length;
    const digits = (ctx.match(/\d/g) || []).length;
    const total = ctx.replace(/\s/g, '').length || 1;
    if (digits / total > 0.6 && letters < 3) return 0.2;
  }

  // DE_TAX: reduce if preceded by +CC phone prefix
  if (rule.id === 'de-tax') {
    const prefix = text.substring(Math.max(0, idx - 15), idx);
    if (/\+\d{2,4}\s/.test(prefix)) return 0.15;
  }

  return conf;
}

function computeRiskScore(matches) {
  if (matches.length === 0) return 0;
  let score = 0;
  for (const m of matches) {
    score += (RISK_WEIGHTS[m.type] || 5) * m.confidence;
  }
  return Math.min(100, Math.round(score));
}

// ── CONFIG ───────────────────────────────────────────────────────
function findConfig(startDir) {
  let dir = path.resolve(startDir || '.');
  while (true) {
    const p = path.join(dir, '.ai-firewallrc');
    if (fs.existsSync(p)) return p;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function loadConfig(configPath) {
  if (!configPath) {
    configPath = findConfig(process.cwd());
    if (!configPath) return {};
  }
  try {
    const raw = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Error loading config:', e.message);
    return {};
  }
}

const DEFAULT_CONFIG = {
  mode: 'placeholder',
  format: 'text',
  risk: false,
  exclude: ['node_modules', '.git', '__pycache__', '*.pyc', '.vscode', 'dist', 'build', '.opencode'],
  include: ['*.js', '*.ts', '*.py', '*.json', '*.txt', '*.md', '*.html', '*.css', '*.yml', '*.yaml', '*.env', '*.cfg', '*.ini', '*.conf', '*.pdf', '*.docx', '*.png', '*.jpg', '*.jpeg'],
  rules: [],
};

// ── DOCUMENT SCAN ───────────────────────────────────────────────
const DOC_EXTS = ['.pdf', '.docx', '.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif', '.webp'];

function isDocumentFile(filePath) {
  return DOC_EXTS.includes(path.extname(filePath).toLowerCase());
}

async function scanFileAsync(filePath, rules, options) {
  const ext = path.extname(filePath).toLowerCase();
  if (!DOC_EXTS.includes(ext)) {
    return scanFile(filePath, rules);
  }
  try {
    const { extractText } = require('./scanners/index');
    const text = await extractText(filePath, { ocr: !!(options && options.ocr) });
    if (!text) return [];
    const findings = [];
    for (const rule of rules) {
      const regex = new RegExp(rule.regex.source, 'g' + (rule.regex.flags.includes('i') ? 'i' : ''));
      let m;
      while ((m = regex.exec(text)) !== null) {
        const raw = m[0];
        let conf = rule.conf;
        if (rule.luhn) {
          const clean = raw.replace(/[-\s]/g, '');
          if (clean.length >= 13 && clean.length <= 19) {
            conf = luhnCheck(clean) ? 0.95 : 0.3;
          }
        }
        findings.push({
          type: rule.label,
          name: rule.name,
          match: raw,
          confidence: conf,
          line: findLineNumber(text, m.index),
          column: findColumn(text, m.index),
        });
      }
    }
    findings.sort((a, b) => a.line - b.line || a.column - b.column);
    return findings;
  } catch (e) {
    console.error('  Document scan error (' + filePath + '): ' + e.message);
    return [];
  }
}

async function scanDirAsync(dirPath, config, profile, plugins, options) {
  const rules = resolveRules(config, profile, (plugins && plugins.rules) || []);
  const exclude = config.exclude || DEFAULT_CONFIG.exclude;
  const include = config.include || DEFAULT_CONFIG.include;
  const results = {};

  async function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir); } catch (e) { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry);
      if (shouldExclude(full, exclude)) continue;
      let stat;
      try { stat = fs.statSync(full); } catch (e) { continue; }
      if (stat.isDirectory()) {
        await walk(full);
      } else if (stat.isFile() && shouldInclude(full, include)) {
        const findings = await scanFileAsync(full, rules, options);
        if (findings.length > 0) {
          results[full] = findings;
        }
        if (options && options.onFile) options.onFile(full);
      }
    }
  }

  await walk(dirPath);
  return results;
}

// ── SCAN ─────────────────────────────────────────────────────────
function matchesGlob(filePath, pattern) {
  const name = path.basename(filePath);
  const rel = filePath.replace(/\\/g, '/');
  if (pattern.includes('*')) {
    const re = new RegExp('^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$', 'i');
    return re.test(name) || re.test(rel);
  }
  return rel.includes(pattern) || name === pattern;
}

function shouldExclude(filePath, excludePatterns) {
  const rel = filePath.replace(/\\/g, '/');
  for (const p of excludePatterns || []) {
    if (matchesGlob(rel, p)) return true;
  }
  return false;
}

function shouldInclude(filePath, includePatterns) {
  if (!includePatterns || includePatterns.length === 0) return true;
  const rel = filePath.replace(/\\/g, '/');
  for (const p of includePatterns) {
    if (matchesGlob(rel, p)) return true;
  }
  return false;
}

function findLineNumber(text, index) {
  if (index <= 0) return 1;
  return (text.substring(0, index).match(/\n/g) || []).length + 1;
}

function findColumn(text, index) {
  if (index <= 0) return 1;
  const lastNewline = text.lastIndexOf('\n', index - 1);
  return index - lastNewline;
}

function scanFile(filePath, rules) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const findings = [];
    for (const rule of rules) {
      const regex = new RegExp(rule.regex.source, 'g' + (rule.regex.flags.includes('i') ? 'i' : ''));
      let m;
      while ((m = regex.exec(content)) !== null) {
        const raw = m[0];
        let conf = rule.conf;
        if (rule.luhn) {
          const clean = raw.replace(/[-\s]/g, '');
          if (clean.length >= 13 && clean.length <= 19) {
            conf = luhnCheck(clean) ? 0.95 : 0.3;
          }
        }
        findings.push({
          type: rule.label,
          name: rule.name,
          match: raw,
          confidence: conf,
          line: findLineNumber(content, m.index),
          column: findColumn(content, m.index),
        });
      }
    }
    findings.sort((a, b) => a.line - b.line || a.column - b.column);
    return findings;
  } catch (e) {
    return [];
  }
}

function scanDir(dirPath, config, profile, plugins) {
  const rules = resolveRules(config, profile, (plugins && plugins.rules) || []);
  const exclude = config.exclude || DEFAULT_CONFIG.exclude;
  const include = config.include || DEFAULT_CONFIG.include;
  const results = {};

  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir); } catch (e) { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry);
      if (shouldExclude(full, exclude)) continue;
      let stat;
      try { stat = fs.statSync(full); } catch (e) { continue; }
      if (stat.isDirectory()) {
        walk(full);
      } else if (stat.isFile() && shouldInclude(full, include)) {
        const findings = scanFile(full, rules);
        if (findings.length > 0) {
          results[full] = findings;
        }
      }
    }
  }

  walk(dirPath);
  return results;
}

// ── INIT ─────────────────────────────────────────────────────────
function initProject() {
  const cfgPath = path.join(process.cwd(), '.ai-firewallrc');
  if (fs.existsSync(cfgPath)) {
    console.log('.ai-firewallrc already exists.');
  } else {
    try {
      fs.writeFileSync(cfgPath, JSON.stringify(DEFAULT_CONFIG, null, 2) + '\n', 'utf8');
      console.log('Created .ai-firewallrc');
    } catch (e) { console.error('Failed to create .ai-firewallrc:', e.message); process.exit(1); }
  }

  const gitDir = path.join(process.cwd(), '.git');
  if (fs.existsSync(gitDir)) {
    const hooksDir = path.join(gitDir, 'hooks');
    const hookPath = path.join(hooksDir, 'pre-commit');
    if (fs.existsSync(hookPath)) {
      console.log('Pre-commit hook already exists at', hookPath);
      console.log('To install: merge scripts/pre-commit with your existing hook.');
    } else {
      const hookContent = `#!/bin/sh
# AI Firewall pre-commit hook — prevents committing PII
echo "[AI Firewall] Scanning staged files for PII..."
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(js|ts|py|json|txt|md|html|css|yml|yaml|env|cfg|ini|conf)$' || true)
if [ -z "$FILES" ]; then
  echo "[AI Firewall] No eligible files staged."
  exit 0
fi
PASS=1
for f in $FILES; do
  if [ -f "$f" ]; then
    RESULT=$(node "$(dirname "$0")/../../cli.js" scan --file "$f" --format json 2>/dev/null)
    COUNT=$(echo "$RESULT" | node -e "let d=[];try{d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'))}catch(e){};let c=0;for(const[k,v]of Object.entries(d)){c+=v.length};process.stdout.write(String(c))" 2>/dev/null)
    if [ -n "$COUNT" ] && [ "$COUNT" -gt 0 ]; then
      echo "[AI Firewall] PII found in $f ($COUNT matches)"
      PASS=0
    fi
  fi
done
if [ "$PASS" -eq 0 ]; then
  echo "[AI Firewall] Commit blocked. Remove PII or use --no-verify to bypass."
  exit 1
fi
echo "[AI Firewall] No PII detected."
exit 0
`;
      const scriptsDir = path.join(process.cwd(), 'scripts');
      if (!fs.existsSync(scriptsDir)) fs.mkdirSync(scriptsDir, { recursive: true });
      try {
        fs.writeFileSync(hookPath, hookContent, 'utf8');
        try { fs.chmodSync(hookPath, '755'); } catch (e) { /* chmod not available on all platforms */ }
        console.log('Installed pre-commit hook at', hookPath);
      } catch (e) { console.error('Failed to install pre-commit hook:', e.message); }
    }
  } else {
    console.log('No .git directory found. Skipping pre-commit hook installation.');
  }

  console.log('Run \`node cli.js scan\` to scan all files in the project.');
}

// ── HTML REPORT ──────────────────────────────────────────────────
function generateHtmlReport(results, riskScore) {
  const escape = s => (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const fileCount = Object.keys(results).length;
  let totalMatches = 0;
  for (const f of Object.keys(results)) totalMatches += results[f].length;

  const entries = Object.entries(results).sort((a, b) => b[1].length - a[1].length);
  let body = '';
  for (const [file, findings] of entries) {
    const types = [...new Set(findings.map(m => m.type))].sort();
    body += `<div class="file">`;
    body += `<h2 onclick="this.nextElementSibling.classList.toggle('hidden')">&#9654; ${escape(file)} <span class="badge">${findings.length} matches</span></h2>`;
    body += `<div><table><tr><th>Line</th><th>Column</th><th>Type</th><th>Confidence</th><th>Match Preview</th></tr>`;
    for (const m of findings) {
      const preview = m.match.length > 80 ? escape(m.match.substring(0, 77)) + '...' : escape(m.match);
      const confPct = Math.round(m.confidence * 100);
      const confClass = confPct >= 85 ? 'high' : confPct >= 50 ? 'med' : 'low';
      body += `<tr class="conf-${confClass}"><td>${m.line}</td><td>${m.column}</td><td>${escape(m.type)}</td><td>${confPct}%</td><td><code>${preview}</code></td></tr>`;
    }
    body += `</table></div></div>`;
  }

  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Firewall - PII Scan Report</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:1200px;margin:0 auto;padding:20px;background:#0f172a;color:#e2e8f0}
  h1{color:#818cf8;border-bottom:2px solid #334155;padding-bottom:10px}
  .summary{background:#1e293b;border-radius:8px;padding:16px;margin:16px 0;display:flex;gap:24px}
  .summary div{text-align:center}
  .summary .num{font-size:28px;font-weight:700;color:#818cf8}
  .summary .lbl{font-size:12px;text-transform:uppercase;color:#94a3b8}
  .risk{font-size:20px;font-weight:700;text-align:center}
  .risk-high{color:#ef4444}.risk-med{color:#f59e0b}.risk-low{color:#22c55e}
  .file{background:#1e293b;border-radius:8px;margin:12px 0;overflow:hidden}
  .file h2{margin:0;padding:12px 16px;background:#334155;cursor:pointer;font-size:14px;display:flex;justify-content:space-between;align-items:center}
  .file h2:hover{background:#3b4f6b}
  .badge{background:#6366f1;color:#fff;border-radius:12px;padding:2px 10px;font-size:12px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#1e293b;padding:8px 12px;text-align:left;color:#94a3b8;text-transform:uppercase;font-size:11px;border-bottom:1px solid #334155}
  td{padding:6px 12px;border-bottom:1px solid #1e293b}
  code{color:#f472b6;font-size:12px;word-break:break-all}
  .hidden{display:none}
  .conf-high td:nth-child(4){color:#ef4444;font-weight:600}
  .conf-med td:nth-child(4){color:#f59e0b}
  .conf-low td:nth-child(4){color:#22c55e}
  tr:hover{background:#1a2332}
  footer{text-align:center;color:#64748b;font-size:12px;margin-top:32px}
</style></head><body>
<h1>AI Firewall - PII Scan Report</h1>
<div class="summary">
  <div><div class="num">${fileCount}</div><div class="lbl">Files</div></div>
  <div><div class="num">${totalMatches}</div><div class="lbl">PII Matches</div></div>
  <div><div class="num risk-${riskScore >= 50 ? 'high' : riskScore >= 20 ? 'med' : 'low'}">${riskScore}</div><div class="lbl">Risk Score</div></div>
</div>
${body}
<footer>Generated by AI Firewall &mdash; ${new Date().toISOString()}</footer>
<script>document.querySelectorAll('.file h2').forEach(h=>h.nextElementSibling.classList.add('hidden'))</script>
</body></html>`;
}

// ── DIFF REPORT (inline highlighted) ─────────────────────────────
function generateDiffReport(results, origContents, scrubbedContents) {
  const escape = s => (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  function highlightInline(orig, scrubbed) {
    const oLines = orig.split('\n');
    const sLines = scrubbed.split('\n');
    let html = '<table class="diff-inline">';
    for (let i = 0; i < Math.max(oLines.length, sLines.length); i++) {
      const o = oLines[i] || '';
      const s = sLines[i] || '';
      const lineNum = i + 1;
      if (o === s) {
        html += '<tr class="same"><td class="ln">' + lineNum + '</td><td class="line" colspan="2">' + escape(o) + '</td></tr>';
      } else {
        html += '<tr class="del"><td class="ln">' + lineNum + '</td><td class="mark">-</td><td class="line">' + escape(o) + '</td></tr>';
        html += '<tr class="add"><td class="ln">' + lineNum + '</td><td class="mark">+</td><td class="line">' + escape(s) + '</td></tr>';
      }
    }
    html += '</table>';
    return html;
  }

  const fileCount = Object.keys(results).length;
  let totalMatches = 0;
  for (const f of Object.keys(results)) totalMatches += results[f].length;

  const entries = Object.entries(results).sort((a, b) => b[1].length - a[1].length);
  let body = '';
  for (const [file, findings] of entries) {
    const orig = origContents[file] || '';
    const scrubbed = scrubbedContents[file] || '';
    body += `<div class="file">`;
    body += `<h2 onclick="this.nextElementSibling.classList.toggle('hidden')">&#9654; ${escape(file)} <span class="badge">${findings.length} changes</span></h2>`;
    body += `<div class="inline-diff">${highlightInline(orig, scrubbed)}</div></div>`;
  }

  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Firewall - PII Diff Report</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:1200px;margin:0 auto;padding:20px;background:#0f172a;color:#e2e8f0}
  h1{color:#818cf8;border-bottom:2px solid #334155;padding-bottom:10px}
  .summary{background:#1e293b;border-radius:8px;padding:16px;margin:16px 0;display:flex;gap:24px}
  .summary div{text-align:center}
  .summary .num{font-size:28px;font-weight:700;color:#818cf8}
  .summary .lbl{font-size:12px;text-transform:uppercase;color:#94a3b8}
  .file{background:#1e293b;border-radius:8px;margin:12px 0;overflow:hidden}
  .file h2{margin:0;padding:12px 16px;background:#334155;cursor:pointer;font-size:14px;display:flex;justify-content:space-between;align-items:center}
  .file h2:hover{background:#3b4f6b}
  .badge{background:#6366f1;color:#fff;border-radius:12px;padding:2px 10px;font-size:12px}
  .diff-inline{width:100%;border-collapse:collapse;font-family:monospace;font-size:12px;line-height:1.5}
  .diff-inline td{padding:2px 8px;vertical-align:top}
  .ln{color:#64748b;text-align:right;width:40px;user-select:none;border-right:1px solid #334155}
  .mark{width:20px;text-align:center;font-weight:700;user-select:none}
  .same .line{color:#e2e8f0;background:transparent}
  .del .line{background:#2d1b1b;color:#f87171}
  .del .mark{color:#f87171;background:#2d1b1b}
  .add .line{background:#0d2818;color:#4ade80}
  .add .mark{color:#4ade80;background:#0d2818}
  .same .ln,.del .ln,.add .ln{background:#0f172a}
  .hidden{display:none}
  footer{text-align:center;color:#64748b;font-size:12px;margin-top:32px}
</style></head><body>
<h1>AI Firewall - PII Diff Report (inline)</h1>
<div class="summary">
  <div><div class="num">${fileCount}</div><div class="lbl">Files</div></div>
  <div><div class="num">${totalMatches}</div><div class="lbl">PII Changes</div></div>
</div>
${body}
<footer>Generated by AI Firewall &mdash; ${new Date().toISOString()}</footer>
<script>document.querySelectorAll('.file h2').forEach(h=>h.nextElementSibling.classList.add('hidden'))</script>
</body></html>`;
}

// ── ENCRYPT MODE ─────────────────────────────────────────────────
function encryptValue(text, keyObj) {
  const key = (keyObj && keyObj.key) ? keyObj.key : keyObj;
  const outerSalt = (keyObj && keyObj.salt) ? keyObj.salt : null;
  const innerSalt = crypto.randomBytes(32);
  const derived = crypto.pbkdf2Sync(key, innerSalt, 100000, 32, 'sha256');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', derived, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  if (outerSalt) {
    return outerSalt.toString('hex') + ':' + innerSalt.toString('hex') + ':' + iv.toString('hex') + ':' + authTag + ':' + encrypted;
  }
  return innerSalt.toString('hex') + ':' + iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

function decryptValue(encoded, passphraseOrKey) {
  try {
    const parts = encoded.split(':');
    if (parts.length !== 4 && parts.length !== 5) return null;
    let outerSalt, innerSalt, iv, authTag, encrypted;
    if (parts.length === 5) {
      outerSalt = Buffer.from(parts[0], 'hex');
      innerSalt = Buffer.from(parts[1], 'hex');
      iv = Buffer.from(parts[2], 'hex');
      authTag = parts[3];
      encrypted = parts[4];
    } else {
      innerSalt = Buffer.from(parts[0], 'hex');
      iv = Buffer.from(parts[1], 'hex');
      authTag = parts[2];
      encrypted = parts[3];
    }
    let outerKey;
    if (typeof passphraseOrKey === 'string') {
      const salt = outerSalt || Buffer.from('legacy-context');
      outerKey = crypto.pbkdf2Sync(passphraseOrKey, salt, 100000, 32, 'sha256');
    } else {
      outerKey = (passphraseOrKey && passphraseOrKey.key) ? passphraseOrKey.key : passphraseOrKey;
    }
    const derived = crypto.pbkdf2Sync(outerKey, innerSalt, 100000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', derived, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    return null;
  }
}

function deriveKey(passphrase, salt) {
  if (!salt) salt = crypto.randomBytes(32);
  const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
  return { key, salt };
}

// ── WATCH MODE ────────────────────────────────────────────────────
function watchDir(watchPath, config, plugins) {
  const include = config.include || DEFAULT_CONFIG.include;
  const rules = resolveRules(config, undefined, (plugins && plugins.rules) || []);

  console.log('Watching ' + path.resolve(watchPath) + ' for changes...');
  console.log('Press Ctrl+C to stop.\n');

  fs.watch(watchPath, { recursive: true }, (eventType, filename) => {
    if (!filename) return;
    const fullPath = path.join(watchPath, filename);
    try {
      if (!fs.statSync(fullPath).isFile()) return;
    } catch (e) { return; }
    if (!shouldInclude(fullPath, include)) return;
    const findings = scanFile(fullPath, rules);
    if (findings.length > 0) {
      const types = [...new Set(findings.map(m => m.type))].join(', ');
      console.log('[' + new Date().toLocaleTimeString() + '] ' + fullPath + ': ' + findings.length + ' PII match(es) (' + types + ')');
      for (const m of findings) {
        console.log('  Ln ' + m.line + ' [' + m.type + '] ' + (m.match.length > 60 ? m.match.substring(0,57)+'...' : m.match));
      }
    }
  });
}

// ── HELP ─────────────────────────────────────────────────────────
function printHelp() {
  console.log(`
AI Firewall CLI v2 - PII Detection & Masking Tool (` + BUILTIN_RULES.length + ` PII types)

Usage:
  cli.js [command] [options]

Commands:
  scan [dir]             Recursively scan directory for PII (default: .)
  ci [dir]               CI/CD scan — exits with code 1 if PII found above threshold
  watch <dir>            Watch directory for changes and report PII
  serve [port]           Start REST API server (default port: 3000)
    --port, -p <port>    Port to listen on (default: 3000)
    --config, -c <path>  Path to .ai-firewallrc config
    --profile <name>     Compliance profile: none (default), gdpr, hipaa, pci-dss, ccpa
    --analytics          Enable analytics dashboard & API
  bot                    Start Slack/Discord bot (--slack or --discord)
  init                   Create .ai-firewallrc config + pre-commit hook
  --help, -h             Show this help
  --list                 List supported PII types

Scrub Options (default command when piping text):
  --file, -f <path>      Input file (stdin if not provided)
  --out, -o <path>       Output file (stdout if not provided)
  --mode, -m <mode>      Mask mode: placeholder (default) or realistic
  --format, -F <fmt>     Output format: text (default), json, csv
  --config, -c <path>    Path to .ai-firewallrc config
  --risk                 Show risk score
  --summary              Show summary only (scan command)
  --profile <name>       Compliance profile: none (default), gdpr, hipaa, pci-dss, ccpa
  --unsafe               Allow string-based custom fakers (executes arbitrary code)

Scan Options:
  --config, -c <path>    Path to .ai-firewallrc config
  --format, -F <fmt>     Output: text (default), json, csv-summary, html
  --file <path>          Scan single file only
  --fix                  Auto-scrub PII in-place (modifies files)
  --dry-run              Preview --fix changes without writing (implies --fix)
  --diff                 Show before/after diff of PII changes
  --progress             Show progress bar during directory scan
  --ocr                  Enable OCR for image files (requires tesseract.js)
  --report <path>        Save report to file
  --encrypt <passphrase> Replace PII with AES-256-GCM encrypted tokens
  --summary              Show per-file summary with counts only
  --profile <name>       Compliance profile: none (default), gdpr, hipaa, pci-dss, ccpa
  --plugin <path>        Load external plugin module (repeatable)

Custom Rules:
  Define custom PII patterns in .ai-firewallrc via "customRules":
    { "customRules": [{ "id": "my-rule", "name": "My Rule", "regex": "pattern", "conf": 0.8, "flags": "gi", "faker": "() => '[FAKE]'" }] }

Plugins:
  Load external JS modules with rules/fakers/formatters:
    --plugin <path>       Load a plugin module (can be used multiple times)
    Plugin modules export: { rules, fakers, formatters }

Decrypt:
  node cli.js --decrypt <file> <passphrase>  Decrypt a file with [ENC:...] tokens

Examples:
  echo "email: test@test.com" | node cli.js
  node cli.js --file input.txt --out output.txt --mode realistic
  node cli.js scan                           # scan entire project
  node cli.js scan ./src --format json       # scan ./src as JSON
  node cli.js scan ./src --format html       # generate HTML report
  node cli.js scan --fix                     # scan & auto-scrub PII
  node cli.js init                           # create config + hook
  node cli.js scan --file deploy.env         # scan single file
  node cli.js watch ./src                    # watch for changes
  node cli.js serve                          # start REST API on :3000
  node cli.js serve --port 4000              # start REST API on :4000
  node cli.js serve --analytics              # start with analytics dashboard
  node cli.js scan --profile gdpr            # scan with GDPR profile
  node cli.js scan --diff                    # show before/after diff
  node cli.js scan --encrypt mykey           # encrypt PII found in files
  node cli.js scan --progress                # show progress bar
  node cli.js scan --report report.html      # save report to file
  node cli.js ci                             # CI/CD scan (exit 1 if PII found)
  node cli.js ci --fail-threshold 5          # fail only if >=5 PII items
  node cli.js bot --slack                    # start Slack bot
  node cli.js bot --discord                  # start Discord bot
  node cli.js bot --slack --token xoxb-...   # start with token override
`);
}

function printTypes() {
  console.log('Supported PII Types (' + BUILTIN_RULES.length + '):\n');
  const rows = BUILTIN_RULES.map(r => [r.id.padEnd(16), r.name.padEnd(24), (r.conf * 100 + '').padStart(2) + '%', r.luhn ? 'Luhn' : '']);
  console.log('  ID               Name                      Confidence  Validation');
  console.log('  ' + '-'.repeat(70));
  for (const r of rows) {
    console.log('  ' + r[0] + r[1] + r[2].padStart(12) + '  ' + (r[3] ? '(Luhn)' : ''));
  }
  console.log('\nCompliance Profiles:\n');
  for (const [name, p] of Object.entries(COMPLIANCE_PROFILES)) {
    if (name === 'none') continue;
    console.log('  ' + name.padEnd(12) + p.desc);
  }
}

// ── MAIN ─────────────────────────────────────────────────────────
async function main() {
  process.on('uncaughtException', (err) => { console.error('Uncaught exception:', err.message || err); process.exit(1); });
  process.on('unhandledRejection', (err) => { console.error('Unhandled rejection:', err && err.message ? err.message : err); process.exit(1); });
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h') || args.length === 0 && process.stdin.isTTY) {
    printHelp();
    process.exit(0);
  }
  if (args.includes('--list')) { printTypes(); process.exit(0); }

  if (args[0] === 'init') { initProject(); return; }

  if (args[0] === '--decrypt') {
    const filePath = args[1];
    const passphrase = args[2];
    if (!filePath || !passphrase) { console.error('Usage: node cli.js --decrypt <file> <passphrase>'); process.exit(1); }
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const decrypted = content.replace(/\[ENC:([^\]]+)\]/g, (_, enc) => {
        const val = decryptValue(enc, passphrase);
        return val !== null ? val : '[DECRYPT_FAILED]';
      });
      console.log(decrypted);
    } catch (e) { console.error('Decrypt error:', e.message); process.exit(1); }
    return;
  }

  // ── RESPONSE-SCAN COMMAND ────────────────────────────────────
  if (args[0] === 'response-scan') {
    let service = 'unknown';
    let mode = 'warn';
    let format = 'text';
    let profile = 'none';
    let inputFile = null;
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--service') service = args[++i] || 'unknown';
      else if (args[i] === '--mode') mode = args[++i] || 'warn';
      else if (args[i] === '--format') format = args[++i] || 'text';
      else if (args[i] === '--profile') profile = args[++i] || 'none';
      else if (!args[i].startsWith('-')) inputFile = args[i];
    }

    const { scanResponse } = require('./scanners/response.cjs');
    const config = inputFile ? loadConfig() : {};
    const configRules = resolveRules(config, profile);

    function processInput(text) {
      const result = scanResponse(text, { service, mode, profile, rules: configRules });
      if (format === 'json') {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.findings.length === 0) {
          console.log('No PII detected in AI response.');
        } else {
          console.log('PII detected in AI response (' + result.actionTaken + '):');
          for (const f of result.findings) {
            console.log('  [' + f.type + '] ' + f.name + ' (conf: ' + f.confidence.toFixed(2) + '): "' + f.match.substring(0, 50) + '"');
          }
          console.log('Risk Score: ' + result.riskScore + '/100');
        }
      }
    }

    if (inputFile) {
      const text = fs.readFileSync(inputFile, 'utf8');
      processInput(text);
    } else if (!process.stdin.isTTY) {
      const chunks = [];
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (c) => chunks.push(c));
      process.stdin.on('end', () => processInput(chunks.join('')));
    } else {
      console.error('Usage: ai-firewall response-scan [--service chatgpt] [--mode warn|scrub] [--format text|json] [file]');
      console.error('       cat ai-output.txt | ai-firewall response-scan --service claude');
      process.exit(1);
    }
    return;
  }

  function getArgVal(anArgs, flag) {
    const idx = anArgs.indexOf(flag);
    return idx !== -1 && anArgs[idx + 1] ? anArgs[idx + 1] : null;
  }

  // ── AUDIT COMMAND ────────────────────────────────────────────
  if (args[0] === 'audit') {
    const subcmd = args[1] || 'events';
    let reportType = 'gdpr_art30';
    let periodStart = '';
    let periodEnd = '';
    let limit = 50;
    let format = 'json';
    let retentionDays = 365;
    for (let i = 2; i < args.length; i++) {
      if (args[i] === '--type') reportType = args[++i] || 'gdpr_art30';
      else if (args[i] === '--from') periodStart = args[++i] || '';
      else if (args[i] === '--to') periodEnd = args[++i] || '';
      else if (args[i] === '--limit') limit = parseInt(args[++i], 10) || 50;
      else if (args[i] === '--format') format = args[++i] || 'json';
      else if (args[i] === '--retention-days') retentionDays = parseInt(args[++i], 10) || 365;
      else if (args[i] === '--older-than') retentionDays = parseInt(args[++i], 10) || 365;
    }

    const { getDb } = require('./analytics/db.cjs');
    const db = getDb();

    if (subcmd === 'export') {
      try {
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const { init: initAudit, getEvents } = require('./enterprise/audit/audit.cjs');
        initAudit(db);
        const { init: initExport, generateReport } = require('./enterprise/audit/compliance-export.cjs');
        initExport(db);

        if (!periodStart || !periodEnd) {
          periodStart = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
          periodEnd = new Date().toISOString().split('T')[0];
        }

        const report = generateReport({ reportType, periodStart, periodEnd, generatedBy: 'cli' });
        if (format === 'json') {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log('Compliance Report: ' + reportType.toUpperCase());
          console.log('Period: ' + periodStart + ' to ' + periodEnd);
          console.log('Events: ' + report.eventCount);
          console.log('Generated: ' + report.generatedAt);
        }
      } catch (e) {
        console.error('Audit export error:', e.message);
        process.exit(1);
      }
    } else if (subcmd === 'retention') {
      try {
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const { init: initRetention, cleanupExpired, getRetentionStats } = require('./enterprise/audit/retention.cjs');
        initRetention(db);
        const stats = getRetentionStats();
        console.log('Audit Retention Stats:');
        console.log('  Audit events: ' + (stats.auditEvents || 0));
        console.log('  Compliance reports: ' + (stats.complianceReports || 0));
        console.log('  Oldest event: ' + (stats.oldestEvent || 'none'));
        console.log('  Newest event: ' + (stats.newestEvent || 'none'));

        if (args.includes('--cleanup')) {
          const result = cleanupExpired(retentionDays);
          console.log('\nCleanup completed (retention: ' + retentionDays + ' days)');
          console.log('  Deleted: ' + result.deleted + ' events');
        }
      } catch (e) {
        console.error('Audit retention error:', e.message);
        process.exit(1);
      }
    } else {
      // Default: list events
      try {
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const { init: initAudit, getEvents, getEventCount } = require('./enterprise/audit/audit.cjs');
        initAudit(db);
        const total = getEventCount({ limit: 999999 });
        const events = getEvents({ limit });
        if (format === 'json') {
          console.log(JSON.stringify({ total, events }, null, 2));
        } else {
          console.log('Audit Events (' + events.length + ' of ' + total + '):');
          for (const e of events) {
            console.log('  [' + e.timestamp + '] ' + e.action + ' by ' + (e.user_id || 'system') + ' - risk:' + (e.risk_score || 0));
          }
        }
      } catch (e) {
        console.error('Audit events error:', e.message);
        process.exit(1);
      }
    }
    return;
  }

  // ── API-KEY COMMAND ──────────────────────────────────────────
  if (args[0] === 'api-key') {
    const subcmd = args[1] || 'list';
    const teamId = getArgVal(args, '--team') || null;
    if (subcmd === 'generate' || subcmd === 'create') {
      if (!teamId) { console.error('Usage: ai-firewall api-key generate --team <teamId> [--name "My Key"]'); process.exit(1); }
      const name = getArgVal(args, '--name') || 'API Key';
      const quota = parseInt(getArgVal(args, '--quota'), 10) || 10000;
      try {
        const { getDb } = require('./analytics/db.cjs');
        const db = getDb();
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const apiKeys = require('./enterprise/auth/api-keys.cjs');
        apiKeys.init(db);
        const key = apiKeys.generateKey(teamId, { name: name, quotaDaily: quota, createdBy: 'cli' });
        console.log('API Key generated:');
        console.log('  ID:     ' + key.id);
        console.log('  Key:    ' + key.key);
        console.log('  Name:   ' + key.name);
        console.log('  Quota:  ' + key.quotaDaily + ' requests/day');
        console.log('\n⚠  Save this key now — it will not be shown again.');
      } catch (e) { console.error('Error:', e.message); process.exit(1); }
    } else if (subcmd === 'list') {
      if (!teamId) { console.error('Usage: ai-firewall api-key list --team <teamId>'); process.exit(1); }
      try {
        const { getDb } = require('./analytics/db.cjs');
        const db = getDb();
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const apiKeys = require('./enterprise/auth/api-keys.cjs');
        apiKeys.init(db);
        const keys = apiKeys.listKeys(teamId);
        if (keys.length === 0) { console.log('No API keys for this team.'); return; }
        console.log('API Keys (' + keys.length + '):');
        for (const k of keys) {
          console.log('  [' + k.id + '] ' + k.name + ' (' + k.key_prefix + '...) ' + (k.revoked_at ? 'REVOKED' : k.enabled ? 'Active' : 'Disabled'));
        }
      } catch (e) { console.error('Error:', e.message); process.exit(1); }
    } else if (subcmd === 'revoke') {
      const keyId = args[2];
      if (!keyId) { console.error('Usage: ai-firewall api-key revoke <keyId>'); process.exit(1); }
      try {
        const { getDb } = require('./analytics/db.cjs');
        const db = getDb();
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const apiKeys = require('./enterprise/auth/api-keys.cjs');
        apiKeys.init(db);
        apiKeys.revokeKey(keyId);
        console.log('API key ' + keyId + ' revoked.');
      } catch (e) { console.error('Error:', e.message); process.exit(1); }
    } else {
      console.error('Usage: ai-firewall api-key <generate|list|revoke> [options]');
      process.exit(1);
    }
    return;
  }

  // ── TEAM COMMAND ─────────────────────────────────────────────
  if (args[0] === 'team') {
    const subcmd = args[1] || 'list';

    if (subcmd === 'create') {
      const name = args[2];
      if (!name) { console.error('Usage: ai-firewall team create <name> [--plan pro]'); process.exit(1); }
      const plan = getArgVal(args, '--plan') || 'free';
      try {
        const { getDb } = require('./analytics/db.cjs');
        const db = getDb();
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const teams = require('./enterprise/auth/teams.cjs');
        teams.init(db);
        const team = teams.createTeam({ name: name, plan: plan, creatorId: 'cli' });
        console.log('Team created:');
        console.log('  ID:   ' + team.id);
        console.log('  Name: ' + team.name);
        console.log('  Slug: ' + team.slug);
        console.log('  Plan: ' + team.plan);
      } catch (e) { console.error('Error:', e.message); process.exit(1); }
    } else if (subcmd === 'list') {
      try {
        const { getDb } = require('./analytics/db.cjs');
        const db = getDb();
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const teams = require('./enterprise/auth/teams.cjs');
        teams.init(db);
        const teamList = teams.listTeams();
        if (teamList.length === 0) { console.log('No teams yet.'); return; }
        console.log('Teams (' + teamList.length + '):');
        for (const t of teamList) {
          console.log('  [' + t.id + '] ' + t.name + ' (' + t.slug + ') — ' + t.plan);
        }
      } catch (e) { console.error('Error:', e.message); process.exit(1); }
    } else if (subcmd === 'members') {
      const teamId = args[2];
      if (!teamId) { console.error('Usage: ai-firewall team members <teamId>'); process.exit(1); }
      try {
        const { getDb } = require('./analytics/db.cjs');
        const db = getDb();
        const { initEnterpriseSchema } = require('./enterprise/db.cjs');
        initEnterpriseSchema(db);
        const teams = require('./enterprise/auth/teams.cjs');
        teams.init(db);
        const members = teams.listMembers(teamId);
        if (members.length === 0) { console.log('No members in this team.'); return; }
        console.log('Team Members (' + members.length + '):');
        for (const m of members) {
          console.log('  ' + m.user_id + ' (' + m.role + ')' + (m.email ? ' <' + m.email + '>' : ''));
        }
      } catch (e) { console.error('Error:', e.message); process.exit(1); }
    } else {
      console.error('Usage: ai-firewall team <create|list|members> [options]');
      process.exit(1);
    }
    return;
  }

  // ── SSO COMMAND ──────────────────────────────────────────────
  if (args[0] === 'sso') {
    const subcmd = args[1] || 'status';
    const teamId = getArgVal(args, '--team') || null;
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const sso = require('./enterprise/identity/sso.cjs');
      sso.init(db);
      if (subcmd === 'token') {
        if (!teamId) { console.error('Usage: ai-firewall sso token --team <teamId> [--user userId] [--email e]'); process.exit(1); }
        const userId = getArgVal(args, '--user') || 'cli-user';
        const email = getArgVal(args, '--email') || null;
        const token = sso.issueToken(teamId, { subject: userId, email: email, scopes: ['scrub', 'scan'] });
        console.log('SSO Token issued:');
        console.log('  sessionId: ' + token.sessionId);
        console.log('  expiresAt: ' + token.expiresAt);
        console.log('  token:');
        console.log('    ' + token.token);
      } else if (subcmd === 'sessions') {
        if (!teamId) { console.error('Usage: ai-firewall sso sessions --team <teamId>'); process.exit(1); }
        const sessions = sso.listSessions(teamId);
        if (sessions.length === 0) { console.log('No active sessions.'); return; }
        console.log('SSO Sessions (' + sessions.length + '):');
        for (const s of sessions) console.log('  [' + s.id + '] ' + (s.email || s.user_id) + ' (' + s.token_type + ') issued ' + s.issued_at);
      } else {
        console.log('SSO module active. Commands: token, sessions');
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── SCIM COMMAND ─────────────────────────────────────────────
  if (args[0] === 'scim') {
    const subcmd = args[1] || 'users';
    const teamId = getArgVal(args, '--team') || null;
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const scim = require('./enterprise/identity/scim.cjs');
      scim.init(db);
      if (subcmd === 'user-create') {
        const userName = getArgVal(args, '--username');
        const email = getArgVal(args, '--email');
        if (!userName) { console.error('Usage: ai-firewall scim user-create --username <name> [--email e]'); process.exit(1); }
        const user = scim.createUser(teamId, { userName: userName, emails: [{ value: email }], displayName: userName });
        console.log('SCIM User created: ' + user.id + ' (' + user.userName + ')');
      } else if (subcmd === 'users') {
        const result = scim.listUsers(teamId);
        console.log('SCIM Users (' + result.totalResults + '):');
        for (const u of result.Resources) console.log('  [' + u.id + '] ' + u.userName + (u.active ? ' (active)' : ' (inactive)'));
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── POLICY COMMAND ───────────────────────────────────────────
  if (args[0] === 'policy') {
    const subcmd = args[1] || 'list';
    const teamId = getArgVal(args, '--team') || null;
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const policy = require('./enterprise/policy/policy-engine.cjs');
      policy.init(db);
      if (subcmd === 'list') {
        const policies = policy.listPolicies(teamId, { includeDisabled: true });
        if (policies.length === 0) { console.log('No policies defined.'); return; }
        console.log('Policies (' + policies.length + '):');
        for (const p of policies) console.log('  [' + p.id + '] ' + p.name + ' -> ' + p.action + ' [' + p.scope + '] ' + (p.enabled ? 'enabled' : 'disabled') + ' priority ' + p.priority);
      } else if (subcmd === 'create') {
        const name = getArgVal(args, '--name');
        const action = getArgVal(args, '--action') || 'deny';
        if (!name) { console.error('Usage: ai-firewall policy create --name <name> [--action allow|deny|redact|quarantine]'); process.exit(1); }
        const p = policy.createPolicy({ name: name, action: action, teamId: teamId, conditions: { piiTypes: ['*'] } });
        console.log('Policy created: ' + p.id + ' (' + p.name + ', ' + p.action + ')');
      } else if (subcmd === 'evaluate') {
        const text = getArgVal(args, '--text');
        if (!text) { console.error('Usage: ai-firewall policy evaluate --text "..."'); process.exit(1); }
        const decision = policy.evaluate({ teamId: teamId, text: text, piiTypes: ['*'], riskScore: 80, scope: 'outbound', channel: 'all' });
        console.log('Decision: ' + (decision.action || 'allow') + (decision.matched ? ' (matched policy)' : ' (no match)'));
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── ALERT COMMAND ────────────────────────────────────────────
  if (args[0] === 'alert') {
    const subcmd = args[1] || 'list';
    const teamId = getArgVal(args, '--team') || null;
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const alertService = require('./enterprise/alerts/alerts.cjs');
      alertService.init(db, null);
      if (subcmd === 'list') {
        const alerts = alertService.listAlerts(teamId);
        if (alerts.length === 0) { console.log('No alerts.'); return; }
        console.log('Alerts (' + alerts.length + '):');
        for (const a of alerts) console.log('  [' + a.id + '] ' + a.severity.toUpperCase() + ' ' + a.title + ' (' + a.status + ')');
      } else if (subcmd === 'rules') {
        const rules = alertService.listRules(teamId, { includeDisabled: true });
        if (rules.length === 0) { console.log('No alert rules.'); return; }
        console.log('Alert Rules (' + rules.length + '):');
        for (const r of rules) console.log('  [' + r.id + '] ' + r.name + ' on:' + r.event_type + ' sev:' + r.severity + ' ' + (r.enabled ? 'enabled' : 'disabled'));
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── SHADOW COMMAND ───────────────────────────────────────────
  if (args[0] === 'shadow') {
    const teamId = getArgVal(args, '--team') || null;
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const shadow = require('./enterprise/observability/shadow-mode.cjs');
      shadow.init(db);
      if (args[1] === 'discover') {
        const byService = shadow.discoverShadowAI(teamId);
        console.log('Shadow AI discovery:');
        for (const s of byService) console.log('  ' + s.ai_service + ': ' + s.events + ' events' + (s.pii_events ? ' (' + s.pii_events + ' with PII)' : ''));
      } else {
        const summary = shadow.getSummary(teamId);
        console.log('Shadow Mode summary:');
        console.log('  Events: ' + summary.totalEvents);
        console.log('  With PII: ' + summary.piiEvents);
        console.log('  Distinct AI services: ' + summary.distinctServices);
        console.log('  Distinct users: ' + summary.distinctUsers);
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── NETWORK COMMAND ──────────────────────────────────────────
  if (args[0] === 'network') {
    const teamId = getArgVal(args, '--team') || null;
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const agent = require('./enterprise/observability/network-agent.cjs');
      agent.init(db);
      if (args[1] === 'analyze') {
        const payload = getArgVal(args, '--payload');
        if (!payload) { console.error('Usage: ai-firewall network analyze --payload "..."'); process.exit(1); }
        const result = agent.analyzePayload(payload);
        console.log('Payload analysis: ' + (result.piiTypes.length ? result.piiTypes.join(', ') : 'no PII') + ' (risk ' + result.riskScore + ')');
      } else {
        const summary = agent.getSummary(teamId);
        console.log('Network Agent summary:');
        console.log('  Status: ' + summary.status);
        console.log('  Connections: ' + summary.totalConnections);
        console.log('  AI service connections: ' + summary.aiServiceConnections);
        console.log('  PII payloads: ' + summary.piiPayloads);
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── ORG COMMAND (multi-tenancy) ──────────────────────────────
  if (args[0] === 'org') {
    const subcmd = args[1] || 'list';
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const orgs = require('./enterprise/tenancy/organizations.cjs');
      orgs.init(db);
      if (subcmd === 'create') {
        const name = getArgVal(args, '--name');
        if (!name) { console.error('Usage: ai-firewall org create --name <name> [--plan pro]'); process.exit(1); }
        const org = orgs.createOrganization({ name: name, plan: getArgVal(args, '--plan') || 'free', createdBy: 'cli', creatorId: getArgVal(args, '--owner') || 'cli-admin' });
        console.log('Organization created:');
        console.log('  ID:   ' + org.id);
        console.log('  Name: ' + org.name);
        console.log('  Slug: ' + org.slug);
        console.log('  Plan: ' + org.plan);
      } else if (subcmd === 'list') {
        const list = orgs.listOrganizations();
        if (list.length === 0) { console.log('No organizations.'); return; }
        console.log('Organizations (' + list.length + '):');
        for (const o of list) console.log('  [' + o.id + '] ' + o.name + ' (' + o.slug + ') plan:' + o.plan + ' status:' + o.status);
      } else if (subcmd === 'link-team') {
        const orgId = args[2], teamId = getArgVal(args, '--team');
        if (!orgId || !teamId) { console.error('Usage: ai-firewall org link-team <orgId> --team <teamId>'); process.exit(1); }
        orgs.addTeamToOrg(orgId, teamId);
        console.log('Team ' + teamId + ' linked to org ' + orgId);
      } else if (subcmd === 'teams') {
        const orgId = args[2];
        if (!orgId) { console.error('Usage: ai-firewall org teams <orgId>'); process.exit(1); }
        const teams = orgs.listOrgTeams(orgId);
        if (teams.length === 0) { console.log('No teams in this org.'); return; }
        console.log('Org Teams (' + teams.length + '):');
        for (const t of teams) console.log('  [' + t.id + '] ' + t.name + ' (' + t.slug + ')');
      } else {
        console.error('Usage: ai-firewall org <create|list|link-team|teams>');
        process.exit(1);
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── RBAC / PERMISSION COMMAND ────────────────────────────────
  if (args[0] === 'perm' || args[0] === 'rbac') {
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const rbac = require('./enterprise/auth/rbac.cjs');
      rbac.init(db);
      const subcmd = args[1] || 'seed';
      if (subcmd === 'seed') {
        rbac.ensureSeedPermissions();
        console.log('RBAC permissions & role mappings seeded.');
      } else if (subcmd === 'grant') {
        const teamId = getArgVal(args, '--team');
        const user = getArgVal(args, '--user');
        const perm = getArgVal(args, '--perm');
        if (!teamId || !user || !perm) { console.error('Usage: ai-firewall perm grant --team <t> --user <u> --perm <p.read> [--deny]'); process.exit(1); }
        const deny = getArgVal(args, '--deny') === 'true' ? false : true;
        rbac.setMemberPermission(teamId, user, perm, deny);
        console.log((deny ? 'Granted' : 'Denied') + ' ' + perm + ' to ' + user + ' in ' + teamId);
      } else if (subcmd === 'check') {
        const teamId = getArgVal(args, '--team');
        const user = getArgVal(args, '--user');
        const perm = getArgVal(args, '--perm');
        if (!teamId || !user || !perm) { console.error('Usage: ai-firewall perm check --team <t> --user <u> --perm <p.read>'); process.exit(1); }
        const allowed = rbac.hasPermission(teamId, user, perm);
        console.log((allowed ? 'ALLOWED' : 'DENIED') + ': ' + user + ' ' + perm + ' in ' + teamId);
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── MARKETPLACE COMMAND ──────────────────────────────────────
  if (args[0] === 'marketplace' || args[0] === 'market') {
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const market = require('./enterprise/marketplace/marketplace.cjs');
      market.init(db, null);
      market.seedBuiltins();
      const subcmd = args[1] || 'packs';
      if (subcmd === 'packs') {
        const packs = market.listPacks();
        if (packs.length === 0) { console.log('No rule packs.'); return; }
        console.log('Rule Packs (' + packs.length + '):');
        for (const p of packs) console.log('  [' + p.slug + '] ' + p.name + ' (' + p.category + ') ' + p.rules_count + ' rules ' + (p.installed === 1 ? 'INSTALLED' : ''));
      } else if (subcmd === 'templates') {
        const templates = market.listTemplates();
        if (templates.length === 0) { console.log('No templates.'); return; }
        console.log('Policy Templates (' + templates.length + '):');
        for (const t of templates) console.log('  [' + t.slug + '] ' + t.name + ' -> ' + t.action + ' (' + t.category + ')');
      } else if (subcmd === 'install') {
        const slug = args[2];
        if (!slug) { console.error('Usage: ai-firewall marketplace install <slug>'); process.exit(1); }
        const result = market.installPack(slug);
        console.log(result.error || ('Installed ' + slug + ' (' + result.rulesInstalled + ' rules)'));
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  // ── REPORT COMMAND (advanced analytics) ──────────────────────
  if (args[0] === 'report') {
    const teamId = getArgVal(args, '--team') || null;
    const period = getArgVal(args, '--period') || '30d';
    try {
      const { getDb } = require('./analytics/db.cjs');
      const db = getDb();
      const { initEnterpriseSchema } = require('./enterprise/db.cjs');
      initEnterpriseSchema(db);
      const reporting = require('./enterprise/analytics/advanced-reporting.cjs');
      reporting.init(db, null, null);
      if (args[1] === 'summary') {
        const md = reporting.generateSummaryReport(teamId, period);
        console.log(md);
      } else if (args[1] === 'pii-types') {
        const types = reporting.piiTypeDistribution(teamId, period);
        if (types.length === 0) { console.log('No PII detected in period.'); return; }
        console.log('PII type distribution (' + period + '):');
        for (const t of types) console.log('  ' + t.piiType + ': ' + t.count);
      } else {
        const d = reporting.dashboard(teamId, period);
        console.log('Analytics dashboard (' + period + '):');
        console.log('  Detections: ' + d.detections.length + ' days of data');
        console.log('  Top services: ' + (d.topServices.length ? d.topServices.map(s => s.service + '(' + s.events + ')').join(', ') : 'none'));
        console.log('  PII types: ' + (d.piiTypes.length ? d.piiTypes.slice(0, 5).map(p => p.piiType + ':' + p.count).join(', ') : 'none'));
      }
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
    return;
  }

  if (args[0] === 'license') {
    const lic = require('./enterprise/license.cjs');
    const sub = args[1] || 'status';
    if (sub === 'generate') {
      const tier = getArgVal(args, '--tier') || 'enterprise';
      const org = getArgVal(args, '--org') || process.env.AIFW_LICENSE_ORG || 'Acme';
      const seats = parseInt(getArgVal(args, '--seats') || '0', 10) || 0;
      const expDays = parseInt(getArgVal(args, '--days') || '365', 10) || 365;
      try {
        const key = lic.createKey({ tier, org, seats, expDays });
        console.log(key);
      } catch (e) { console.error('Error:', e.message); process.exit(1); }
      return;
    }
    if (sub === 'verify') {
      const k = getArgVal(args, '--key') || lic.loadKey();
      if (!k) { console.log('No license key configured (community tier).'); return; }
      try {
        const lic2 = lic.verifyKey(k);
        console.log('Tier      : ' + lic2.tier);
        console.log('Org       : ' + lic2.org);
        console.log('Seats     : ' + lic2.seats);
        console.log('Issued    : ' + new Date(lic2.issued).toISOString());
        console.log('Expires   : ' + (lic2.exp ? new Date(lic2.exp).toISOString() : 'never'));
        console.log('Status    : valid');
      } catch (e) { console.log('Status    : ' + (e.code || 'invalid')); console.log('Reason    : ' + e.message); process.exit(1); }
      return;
    }
    // status
    const lic2 = lic.current();
    console.log('Tier      : ' + lic2.tier);
    console.log('Unlocked  : ' + (lic2.unlocked ? 'yes' : 'no'));
    if (lic2.license) {
      console.log('Org       : ' + lic2.license.org);
      console.log('Seats     : ' + lic2.license.seats);
      console.log('Expires   : ' + (lic2.license.exp ? new Date(lic2.license.exp).toISOString() : 'never'));
    } else {
      console.log('Reason    : ' + (lic2.reason || 'no-key') + (lic2.error ? ' — ' + lic2.error : ''));
    }
    const ff = require('./enterprise/feature-flags.cjs');
    const enabled = Object.keys(ff.getAllFlags()).filter(f => ff.isEnabled(f));
    console.log('Enabled   : ' + (enabled.length ? enabled.join(', ') : 'none (community tier)'));
    return;
  }

  if (args[0] === 'serve' || args[0] === 'server') {
    const { startServer } = require('./server.js');
    let port = parseInt(process.env.PORT, 10) || 3000;
    let configPath = null;
    let profile = 'none';
    let analytics = false;
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--port' || args[i] === '-p') {
        const p = parseInt(args[++i], 10);
        port = isNaN(p) || p < 1 || p > 65535 ? 3000 : p;
      }
      if (args[i] === '--config' || args[i] === '-c') configPath = args[++i];
      if (args[i] === '--profile') profile = args[++i] || 'none';
      if (args[i] === '--analytics') analytics = true;
    }
    startServer(port, { config: configPath, profile, analytics });
    return;
  }

  if (args[0] === 'watch') {
    const watchTarget = args[1] || '.';
    const config = loadConfig(null);
    const configPluginPaths = (config && config.plugins && Array.isArray(config.plugins)) ? config.plugins : [];
    const plugins = loadPlugins(configPluginPaths);
    watchDir(watchTarget, config, plugins);
    return;
  }

  if (args[0] === 'bot') {
    let platform = null;
    let botConfig = null;
    let configPath = null;

    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--slack') platform = 'slack';
      if (args[i] === '--discord') platform = 'discord';
      if (args[i] === '--config' || args[i] === '-c') configPath = args[++i];
      if (args[i] === '--token') {
        if (!botConfig) botConfig = {};
        botConfig.token = args[++i];
      }
    }

    const config = loadConfig(configPath);
    if (config && config.bot) {
      botConfig = Object.assign(botConfig || {}, config.bot);
    }

    if (!platform && botConfig) {
      platform = botConfig.platform;
    }

    if (!platform) {
      console.error('Usage: node cli.js bot --slack | --discord');
      console.error('Configure bot tokens in .ai-firewallrc or pass --token');
      process.exit(1);
    }

    if (platform === 'slack') {
      const slackConfig = (botConfig && botConfig.slack) || botConfig || {};
      if (!slackConfig.token) {
        console.error('Slack token required. Set in .ai-firewallrc or pass --token');
        process.exit(1);
      }
      const { startSlackBot } = require('./bot/slack.cjs');
      console.log('Starting Slack bot...');
      startSlackBot(slackConfig);
    } else if (platform === 'discord') {
      const discordConfig = (botConfig && botConfig.discord) || botConfig || {};
      if (!discordConfig.token) {
        console.error('Discord token required. Set in .ai-firewallrc or pass --token');
        process.exit(1);
      }
      const { startDiscordBot } = require('./bot/discord.cjs');
      console.log('Starting Discord bot...');
      startDiscordBot(discordConfig);
    } else {
      console.error('Unknown platform: ' + platform + '. Use --slack or --discord');
      process.exit(1);
    }
    return;
  }

  if (args[0] === 'scan') {
    let scanTarget = '.';
    let format = 'text';
    let configPath = null;
    let singleFile = null;
    let summaryOnly = false;
    let fixMode = false;
    let dryRun = false;
    let diffMode = false;
    let encryptMode = false;
    let encryptKey = null;
    let showProgress = false;
    let reportPath = null;
    let profile = 'none';
    let ocrMode = false;
    let unsafeMode = false;
    const pluginPaths = [];

    for (let i = 1; i < args.length; i++) {
      switch (args[i]) {
        case '--config': case '-c': configPath = args[++i]; break;
        case '--format': case '-F': format = args[++i]; break;
        case '--file': singleFile = args[++i]; break;
        case '--fix': fixMode = true; break;
        case '--dry-run': dryRun = true; fixMode = true; break;
        case '--diff': diffMode = true; break;
        case '--encrypt': encryptMode = true; encryptKey = args[++i]; break;
        case '--progress': showProgress = true; break;
        case '--report': reportPath = args[++i]; break;
        case '--summary': summaryOnly = true; break;
        case '--profile': profile = args[++i] || 'none'; break;
        case '--ocr': ocrMode = true; break;
        case '--unsafe': unsafeMode = true; break;
        case '--plugin': pluginPaths.push(args[++i]); break;
        default:
          if (!args[i].startsWith('-')) scanTarget = args[i];
      }
    }

    const config = loadConfig(configPath);
    const configPluginPaths = (config && config.plugins && Array.isArray(config.plugins)) ? config.plugins : [];
    const plugins = loadPlugins([...configPluginPaths, ...pluginPaths]);
    const configRules = resolveRules(config, profile, plugins.rules);
    const customFakers = Object.assign({}, getCustomFakers(config, unsafeMode), plugins.fakers);
    const encKey = encryptMode && encryptKey ? deriveKey(encryptKey) : null;

    // ── --progress scan ─────────────────────────────────────
    let progressCount = 0;
    let progressTotal = 0;

    function showProgressBar() {
      if (!showProgress) return;
      const pct = progressTotal > 0 ? Math.round((progressCount / progressTotal) * 100) : 0;
      const bar = '█'.repeat(Math.floor(pct / 5)) + '░'.repeat(20 - Math.floor(pct / 5));
      process.stdout.write('\r  [' + bar + '] ' + pct + '% (' + progressCount + ' files)' + ' '.repeat(10));
    }

    let results;
    if (singleFile) {
      const findings = await scanFileAsync(singleFile, configRules, { ocr: ocrMode });
      results = findings.length > 0 ? { [singleFile]: findings } : {};
    } else {
      if (showProgress) {
        try {
          function countFiles(d) {
            let e;
            try { e = fs.readdirSync(d); } catch(ex) { return; }
            for (const en of e) {
              const f = path.join(d, en);
              if (shouldExclude(f, config.exclude || DEFAULT_CONFIG.exclude)) continue;
              try {
                const s = fs.statSync(f);
                if (s.isDirectory()) countFiles(f);
                else if (s.isFile() && shouldInclude(f, config.include || DEFAULT_CONFIG.include)) progressTotal++;
              } catch(ex) {}
            }
          }
          countFiles(scanTarget);
        } catch(e) {}
        console.log('Scanning ' + progressTotal + ' files...');
        results = await scanDirAsync(scanTarget, config, profile, plugins, {
          ocr: ocrMode,
          onFile: function() { progressCount++; showProgressBar(); }
        });
      } else {
        results = await scanDirAsync(scanTarget, config, profile, plugins, {
          ocr: ocrMode,
          onFile: showProgress ? function() { progressCount++; showProgressBar(); } : undefined
        });
      }
    }

    const fileCount = Object.keys(results).length;
    let totalMatches = 0;
    for (const f of Object.keys(results)) totalMatches += results[f].length;

    // ── --diff mode: show before/after ───────────────────────
    if (diffMode && totalMatches > 0) {
      const origContents = {};
      const scrubbedContents = {};
      for (const f of Object.keys(results)) {
        let content;
        try {
          content = fs.readFileSync(f, 'utf8');
        } catch (e) {
          console.error('Warning: Could not read ' + f + ': ' + e.message);
          continue;
        }
        origContents[f] = content;
        const r = scrub(content, { mode: encryptMode && encKey ? 'encrypt' : 'placeholder', rules: configRules, fakers: customFakers });
        scrubbedContents[f] = r.scrubbed;
      }
      if (format === 'html') {
        console.log(generateDiffReport(results, origContents, scrubbedContents));
      } else {
        for (const [f, findings] of Object.entries(results)) {
          console.log('\n=== ' + f + ' (' + findings.length + ' changes) ===');
          let content;
          try {
            content = fs.readFileSync(f, 'utf8');
          } catch (e) {
            console.error('  Warning: Could not read ' + f + ': ' + e.message);
            continue;
          }
          const r = scrub(content, { mode: 'placeholder', rules: configRules, fakers: customFakers });
          const lines = content.split('\n');
          const scrubbedLines = r.scrubbed.split('\n');
          for (let i = 0; i < Math.max(lines.length, scrubbedLines.length); i++) {
            const o = lines[i] || '';
            const s = scrubbedLines[i] || '';
            if (o !== s) {
              console.log('  - Ln ' + (i + 1) + ': ' + (o.length > 60 ? o.substring(0,57)+'...' : o));
              console.log('  + Ln ' + (i + 1) + ': ' + (s.length > 60 ? s.substring(0,57)+'...' : s));
            }
          }
        }
      }
      if (!format || format === 'text' || format === 'html') return;
    }

    // ── --encrypt mode: replace PII with encrypted tokens ───
    if (encryptMode && encKey && totalMatches > 0 && !diffMode) {
      let encryptedCount = 0;
      for (const [f, findings] of Object.entries(results)) {
        try {
          let content = fs.readFileSync(f, 'utf8');
          for (const m of findings) {
            const encrypted = encryptValue(m.match, encKey);
            content = content.split(m.match).join('[ENC:' + encrypted + ']');
            encryptedCount++;
          }
          if (fixMode) {
            fs.writeFileSync(f, content, 'utf8');
            console.log('Encrypted in-place: ' + f + ' (' + findings.length + ' items)');
          }
        } catch (e) {
          console.error('Error encrypting ' + f + ': ' + e.message);
        }
      }
      if (encryptKey) {
        console.log('\nEncryption key (SAVE THIS to decrypt later): ' + encryptKey);
        console.log('To decrypt: node cli.js --decrypt <file> <key>');
      }
      if (fixMode) return;
    }

    // ── --fix mode: auto-scrub files in-place ──────────────────
    if (fixMode && totalMatches > 0 && !encryptMode) {
      let fixedCount = 0;
      for (const [f, findings] of Object.entries(results)) {
        try {
          const content = fs.readFileSync(f, 'utf8');
          const scrubbed = scrub(content, { mode: 'placeholder', rules: configRules, fakers: customFakers });
          if (dryRun) {
            console.log('\n=== DRY RUN: ' + f + ' (' + scrubbed.matches.length + ' changes) ===');
            const lines = content.split('\n');
            const scrubbedLines = scrubbed.scrubbed.split('\n');
            for (let i = 0; i < Math.max(lines.length, scrubbedLines.length); i++) {
              if ((lines[i] || '') !== (scrubbedLines[i] || '')) {
                console.log('  - Ln ' + (i + 1) + ': ' + (lines[i] || '').substring(0, 60));
                console.log('  + Ln ' + (i + 1) + ': ' + (scrubbedLines[i] || '').substring(0, 60));
              }
            }
          } else {
            fs.writeFileSync(f, scrubbed.scrubbed, 'utf8');
            console.log('Fixed: ' + f + ' (' + scrubbed.matches.length + ' PII items masked)');
          }
          fixedCount++;
        } catch (e) {
          console.error('Error fixing ' + f + ': ' + e.message);
        }
      }
      console.log('\n' + (dryRun ? 'Dry run:' : 'Fixed ') + fixedCount + ' file(s), ' + totalMatches + ' match(es) ' + (dryRun ? 'would be scrubbed.' : 'scrubbed.'));
      return;
    }

    let output = '';
    if (format === 'html') {
      const allMatches = [];
      for (const f of Object.keys(results)) allMatches.push(...results[f]);
      const score = computeRiskScore(allMatches.map(m => ({ type: m.type, confidence: m.confidence })));
      output = generateHtmlReport(results, score);
      console.log(output);
      if (reportPath) {
        try {
          fs.writeFileSync(reportPath, output, 'utf8');
          console.log('Report saved to ' + reportPath);
        } catch (e) { console.error('Failed to write report:', e.message); }
      }
      return;
    }

    if (format === 'json') {
      output = JSON.stringify(results, null, 2);
    } else if (format === 'csv-summary') {
      output += 'File,Matches,Types\n';
      for (const [f, findings] of Object.entries(results)) {
        const types = [...new Set(findings.map(m => m.type))].join(';');
        output += '"' + f + '",' + findings.length + ',"' + types + '"\n';
      }
      output += '\nTotal: ' + fileCount + ' files, ' + totalMatches + ' matches';
    } else {
      if (totalMatches === 0) {
        console.log('No PII detected.');
        return;
      }
      for (const [f, findings] of Object.entries(results)) {
        if (summaryOnly) {
          const types = [...new Set(findings.map(m => m.type))].join(', ');
          output += f + ': ' + findings.length + ' matches (' + types + ')\n';
        } else {
          output += '\n' + f + ' (' + findings.length + ' matches):\n';
          for (const m of findings) {
            const preview = m.match.length > 60 ? m.match.substring(0, 57) + '...' : m.match;
            output += '  Ln ' + String(m.line).padStart(4) + ' [' + m.type + '] ' + preview + ' (conf: ' + m.confidence + ')\n';
          }
        }
      }
      output += '\n' + fileCount + ' file(s), ' + totalMatches + ' match(es)\n';
    }

    if (output) {
      if (reportPath) {
        try {
          fs.writeFileSync(reportPath, output, 'utf8');
          console.log('Report saved to ' + reportPath);
        } catch (e) { console.error('Failed to write report:', e.message); }
      } else {
        console.log(output);
      }
    }

    if (totalMatches > 0) {
      const allMatches = [];
      for (const f of Object.keys(results)) allMatches.push(...results[f]);
      const score = computeRiskScore(allMatches.map(m => ({ type: m.type, confidence: m.confidence })));
      if (!reportPath) console.log('Risk Score: ' + score + '/100');
    }
    return;
  }

  if (args[0] === 'ci') {
    let scanTarget = '.';
    let failThreshold = 1;
    let format = 'json';
    let configPath = null;
    let profile = 'none';

    for (let i = 1; i < args.length; i++) {
      switch (args[i]) {
        case '--fail-threshold': {
          const t = parseInt(args[++i], 10);
          failThreshold = isNaN(t) || t < 1 ? 1 : t;
          break;
        }
        case '--format': case '-F': format = args[++i]; break;
        case '--config': case '-c': configPath = args[++i]; break;
        case '--profile': profile = args[++i] || 'none'; break;
        default:
          if (!args[i].startsWith('-')) scanTarget = args[i];
      }
    }

    const config = loadConfig(configPath);
    const configRules = resolveRules(config, profile);
    const isFile = fs.existsSync(scanTarget) && fs.statSync(scanTarget).isFile();

    let results;
    if (isFile) {
      const findings = scanFile(scanTarget, configRules);
      results = findings.length > 0 ? [{ file: scanTarget, matches: findings }] : [];
    } else {
      const dirResults = scanDir(scanTarget, config, profile);
      results = Object.entries(dirResults).map(([file, matches]) => ({ file, matches }));
    }

    const totalPII = results.reduce((sum, r) => sum + r.matches.length, 0);
    const highConf = results.reduce((sum, r) => sum + r.matches.filter(m => m.confidence >= 0.8).length, 0);
    const failed = totalPII >= failThreshold;

      if (format === 'json') {
        const report = { timestamp: new Date().toISOString(), scanTarget, totalFiles: results.length, totalPII, highConfidencePII: highConf, failed, matches: [] };
        for (const r of results) {
          for (const m of r.matches) {
            report.matches.push({ file: r.file, line: m.line, column: m.column, type: m.type, original: m.original, confidence: m.confidence });
          }
        }
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log('AI Firewall CI Scan Results');
        console.log('==========================');
        console.log('Target:    ' + scanTarget);
        console.log('Files:     ' + results.length);
        console.log('PII Found: ' + totalPII + ' (' + highConf + ' high confidence)');
        console.log('Status:    ' + (failed ? 'FAIL' : 'PASS'));
        if (results.length > 0) {
          console.log('');
          for (const r of results) {
            if (r.matches.length > 0) {
              console.log('  ' + r.file + ':');
              for (const m of r.matches) {
                console.log('    L' + m.line + ':' + m.column + ' [' + m.type + '] ' + (m.match || m.original || '').substring(0, 40) + ((m.match || m.original || '').length > 40 ? '...' : '') + ' (conf: ' + m.confidence.toFixed(2) + ')');
              }
            }
          }
        }
      }
      process.exit(failed ? 1 : 0);
    return;
  }

  // ── SCRUB MODE ────────────────────────────────────────────────
  let filePath = null;
  let outPath = null;
  let mode = 'placeholder';
  let format = 'text';
  let showRisk = false;
  let configPath = null;
  let profile = 'none';
  let unsafeMode = false;
  const pluginPaths = [];

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--file': case '-f': filePath = args[++i]; break;
      case '--out': case '-o': outPath = args[++i]; break;
      case '--mode': case '-m': mode = args[++i]; break;
      case '--format': case '-F': format = args[++i]; break;
      case '--config': case '-c': configPath = args[++i]; break;
      case '--risk': showRisk = true; break;
      case '--profile': profile = args[++i] || 'none'; break;
      case '--unsafe': unsafeMode = true; break;
      case '--plugin': pluginPaths.push(args[++i]); break;
    }
  }

  const config = loadConfig(configPath);
  const configPluginPaths = (config && config.plugins && Array.isArray(config.plugins)) ? config.plugins : [];
  const plugins = loadPlugins([...configPluginPaths, ...pluginPaths]);
  const configRules = resolveRules(config, profile, plugins.rules);
  const customFakers = Object.assign({}, getCustomFakers(config, unsafeMode), plugins.fakers);

  function processText(input) {
    const result = scrub(input, { mode, rules: configRules, fakers: customFakers });
    const risk = showRisk ? computeRiskScore(result.matches) : null;

    if (format === 'json') {
      const output = {
        timestamp: new Date().toISOString(),
        inputLength: input.length,
        matchesFound: result.matches.length,
        riskScore: risk,
        mode,
        scrubbed: result.scrubbed,
        matches: result.matches
      };
      return JSON.stringify(output, null, 2);
    } else if (format === 'csv') {
      const header = 'Type,Name,Confidence,Original,Replacement\n';
      const rows = result.matches.map(m =>
        '"' + m.type + '","' + m.name + '",' + m.confidence + ',"' + m.original.replace(/"/g,'""') + '","' + m.replacement.replace(/"/g,'""') + '"'
      ).join('\n');
      return header + rows;
    } else {
      let out = result.scrubbed;
      if (result.matches.length > 0) {
        out += '\n\n-- PII Detected: ' + result.matches.length + ' items --\n';
        for (const m of result.matches) {
          out += '  [' + m.type + '] ' + m.name + ' (conf: ' + m.confidence + '): "' + m.original.substring(0, 40) + '" -> "' + m.replacement.substring(0, 40) + '"\n';
        }
        if (risk !== null) out += '\nRisk Score: ' + risk + '/100\n';
      }
      return out;
    }
  }

  if (filePath) {
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) { console.error('Error reading file:', err.message); process.exit(1); }
      const output = processText(data);
      if (outPath) {
        fs.writeFile(outPath, output, 'utf8', (err2) => {
          if (err2) { console.error('Error writing file:', err2.message); process.exit(1); }
        });
      } else {
        console.log(output);
      }
    });
  } else {
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => input += chunk);
    process.stdin.on('end', () => {
      const output = processText(input);
      if (outPath) {
        fs.writeFile(outPath, output, 'utf8', (err2) => {
          if (err2) { console.error('Error writing file:', err2.message); process.exit(1); }
        });
      } else {
        console.log(output);
      }
    });
  }
}

if (require.main === module) main().catch(err => { console.error('Fatal:', err.message || err); process.exit(1); });
module.exports = { scrub, scanFile, scanDir, loadConfig, resolveRules, computeRiskScore, luhnCheck, generateHtmlReport, generateDiffReport, watchDir, encryptValue, decryptValue, deriveKey, loadPlugins, BUILTIN_RULES, FAKERS, COMPLIANCE_PROFILES, RISK_WEIGHTS, getCustomFakers };
