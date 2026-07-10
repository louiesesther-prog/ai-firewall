const vscode = require('vscode');

const PII_RULES = [
  { id:'crypto',  name:'Crypto Wallet',   label:'CRYPTO',   regex:/0x[a-fA-F0-9]{40}/g,                       conf:0.95 },
  { id:'mac',     name:'MAC Address',     label:'MAC_ADDR', regex:/[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}/g, conf:0.95 },
  { id:'cc',      name:'Credit Card',     label:'CC_NUM',   regex:/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, conf:0.9, luhn:true },
  { id:'ssn',     name:'SSN',             label:'SSN_NUM',  regex:/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,            conf:0.85 },
  { id:'apikey',  name:'API Key',         label:'APIKEY',   regex:/(?:api[_-]?key|api key)[=:\s]+\S+/gi,         conf:0.85 },
  { id:'pwd',     name:'Password',        label:'PWD_VAL',  regex:/(?:password|passwd|pass)[=:\s]+\S+/gi,        conf:0.8 },
  { id:'dob',     name:'Date of Birth',   label:'DOB',      regex:/(?:DOB|date\s*of\s*birth|birth\s*date)[=:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}/gi, conf:0.9 },
  { id:'passport',name:'Passport',        label:'PASSPORT', regex:/\b[A-Z]\d{8}\b/g,                             conf:0.85 },
  { id:'phone',   name:'Phone Number',    label:'PHONE_NUM',regex:/\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, conf:0.8 },
  { id:'ip',      name:'IP Address',      label:'IP_ADDR',  regex:/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,   conf:0.65 },
  { id:'routing', name:'Routing Number',  label:'ROUTING',  regex:/\b\d{9}\b/g,                                  conf:0.4 },
  { id:'email',   name:'Email Address',   label:'EMAIL_ADDR',regex:/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, conf:0.95 },
  { id:'license', name:'Driver License',  label:'LICENSE',  regex:/(?:driver'?s?\s*license|dl|license)[=:\s]*[A-Z0-9]{5,14}/gi, conf:0.7 },
  { id:'address', name:'Street Address',  label:'ADDRESS',  regex:/\b\d{1,5}\s+[\w\s]{2,}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Circle|Cir|Place|Pl)\.?\b/gi, conf:0.6 },
  { id:'bank',    name:'Bank Account',    label:'BANK_ACCT',regex:/(?:account|acct|acc)\s*(?:#|number|num|no)?[=:\s]+\d{5,17}/gi, conf:0.7 },
  { id:'uk-ni',   name:'UK National Insurance', label:'UK_NI', regex:/\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b/gi, conf:0.85 },
  { id:'uk-nhs',  name:'UK NHS Number',          label:'UK_NHS', regex:/\b\d{3}\s?\d{3}\s?\d{4}\b/g, conf:0.7 },
  { id:'in-aadhaar',name:'India Aadhaar',        label:'IN_AADHAAR', regex:/\b\d{4}\s?\d{4}\s?\d{4}\b/g, conf:0.85 },
  { id:'in-pan',  name:'India PAN',              label:'IN_PAN', regex:/\b[A-Z]{5}\d{4}[A-Z]\b/gi, conf:0.9 },
  { id:'cn-id',   name:'China ID (18位)',        label:'CN_ID', regex:/\b\d{6}\d{8}[\dXx]\b/g, conf:0.85 },
  { id:'ca-sin',  name:'Canada SIN',             label:'CA_SIN', regex:/\b\d{3}\s?\d{3}\s?\d{3}\b/g, conf:0.7 },

  // ── Token / infrastructure ─────────────────────────────────
  { id:'jwt',     name:'JWT Token',           label:'JWT',      regex:/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, conf:0.95 },
  { id:'aws-key', name:'AWS Access Key',      label:'AWS_KEY',  regex:/\bAKIA[0-9A-Z]{16}\b/g,                          conf:0.95 },
  { id:'github',  name:'GitHub Token',        label:'GITHUB',   regex:/\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}\b/g, conf:0.95 },
  { id:'slack',   name:'Slack Token',         label:'SLACK',    regex:/\bxox[baprs]-[a-zA-Z0-9-]{10,}\b/g,               conf:0.95 },

  // ── More i18n ──────────────────────────────────────────────
  { id:'au-tfn',  name:'Australia TFN',       label:'AU_TFN',   regex:/\b\d{3}\s?\d{3}\s?\d{3}\b/g,                     conf:0.4 },
  { id:'jp-my',   name:'Japan My Number',     label:'JP_MY',    regex:/\b\d{4}-\d{4}-\d{4}\b/g,                          conf:0.85 },
  { id:'br-cpf',  name:'Brazil CPF',          label:'BR_CPF',   regex:/\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g,              conf:0.8 },
  { id:'br-cnpj', name:'Brazil CNPJ',         label:'BR_CNPJ',  regex:/\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g,      conf:0.85 },
  { id:'fr-insee',name:'France INSEE',        label:'FR_INSEE', regex:/\b\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\b/g, conf:0.7 },
];

const FAKERS = {
  EMAIL_ADDR: () => 'user' + (Math.floor(Math.random() * 9000) + 1000) + '@example.com',
  PHONE_NUM: () => '555-' + (Math.floor(Math.random() * 900) + 100) + '-' + (Math.floor(Math.random() * 9000) + 1000),
  CC_NUM: () => '4111' + Array(12).fill(0).map(() => Math.floor(Math.random() * 10)).join(''),
  SSN_NUM: () => (Math.floor(Math.random() * 900) + 100) + '-' + (Math.floor(Math.random() * 90) + 10) + '-' + (Math.floor(Math.random() * 9000) + 1000),
  IP_ADDR: () => Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256),
  PWD_VAL: () => '[REDACTED]',
  APIKEY: () => 'sk-' + Array(24).fill(0).map(() => 'abcdef0123456789'[Math.floor(Math.random() * 16)]).join(''),
  CRYPTO: () => '0x' + Array(40).fill(0).map(() => 'abcdef0123456789'[Math.floor(Math.random() * 16)]).join(''),
  MAC_ADDR: () => Array(6).fill(0).map(() => ('0' + Math.floor(Math.random() * 256).toString(16)).slice(-2)).join(':'),
  DOB: () => (Math.floor(Math.random() * 12) + 1).toString().padStart(2,'0') + '/' + (Math.floor(Math.random() * 28) + 1).toString().padStart(2,'0') + '/' + (Math.floor(Math.random() * 30 + 1970)),
  PASSPORT: () => String.fromCharCode(65 + Math.floor(Math.random() * 26)) + Math.floor(Math.random() * 100000000).toString().padStart(8, '0'),
  LICENSE: () => 'DL' + Math.floor(Math.random() * 10000000).toString().padStart(7, '0'),
  ADDRESS: () => Math.floor(Math.random() * 9999) + 1 + ' ' + ['Main','Oak','Elm','Pine','Maple','Cedar'][Math.floor(Math.random()*6)] + ' ' + ['Street','Avenue','Road','Drive','Lane'][Math.floor(Math.random()*5)],
  BANK_ACCT: () => '****' + Math.floor(Math.random() * 100000).toString().padStart(5, '0'),
  ROUTING: () => Math.floor(Math.random() * 1000000000).toString().padStart(9, '0'),
  UK_NI: () => 'AB' + Math.floor(Math.random() * 1000000).toString().padStart(6, '0') + 'C',
  UK_NHS: () => Math.floor(Math.random() * 10000000000).toString().padStart(10, '0'),
  IN_AADHAAR: () => Math.floor(Math.random() * 10000).toString().padStart(4,'0') + ' ' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + ' ' + Math.floor(Math.random() * 10000).toString().padStart(4,'0'),
  IN_PAN: () => 'ABCDE' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + 'Z',
  CN_ID: () => Math.floor(Math.random() * 100000000000000000).toString().padStart(18, '0'),
  CA_SIN: () => Math.floor(Math.random() * 1000000000).toString().padStart(9, '0'),
  JWT: () => 'eyJhbGciOiJIUzI1NiJ9.' + Array(43).fill(0).map(() => 'abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 64)]).join('') + '.' + Array(43).fill(0).map(() => 'abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 64)]).join(''),
  AWS_KEY: () => 'AKIA' + Array(16).fill(0).map(() => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random() * 36)]).join(''),
  GITHUB: () => 'ghp_' + Array(36).fill(0).map(() => 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 62)]).join(''),
  SLACK: () => 'xoxb-' + Array(16).fill(0).map(() => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 36)]).join('') + '-' + Array(10).fill(0).map(() => '0123456789'[Math.floor(Math.random() * 10)]).join(''),
  AU_TFN: () => Math.floor(Math.random() * 1000000000).toString().padStart(9, '0'),
  JP_MY: () => Math.floor(Math.random() * 10000).toString().padStart(4,'0') + '-' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + '-' + Math.floor(Math.random() * 10000).toString().padStart(4,'0'),
  BR_CPF: () => Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '.' + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '.' + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '-' + Math.floor(Math.random() * 100).toString().padStart(2,'0'),
  BR_CNPJ: () => Math.floor(Math.random() * 100).toString().padStart(2,'0') + '.' + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '.' + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '/' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + '-' + Math.floor(Math.random() * 100).toString().padStart(2,'0'),
  FR_INSEE: () => Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 1000).toString().padStart(3,'0'),
};

function fakeFor(label) { const fn = FAKERS[label]; return fn ? fn() : '[FAKE_' + label + ']'; }

function luhnCheck(num) {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

function scrub(text, mode) {
  let counter = 1;
  let result = text;
  const matches = [];
  const map = {};

  for (const rule of PII_RULES) {
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

      let replacement;
      if (mode === 'realistic') {
        replacement = fakeFor(rule.label);
      } else {
        replacement = '[' + rule.label + '_' + counter + ']';
      }

      map[replacement] = raw;
      matches.push({ type: rule.label, name: rule.name, original: raw, replacement, confidence: conf });
      result = result.replace(raw, replacement);
      counter++;
    }
  }

  return { scrubbed: result, map, matches };
}

function restore(text, map) {
  if (!text || !map) return text;
  let restored = text;
  const sorted = Object.entries(map).sort((a, b) => b[0].length - a[0].length);
  for (const [ph, orig] of sorted) {
    restored = restored.split(ph).join(orig);
  }
  return restored;
}

let lastMap = {};

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('ai-firewall.scrubSelection', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const selection = editor.selection;
      const text = editor.document.getText(selection);
      if (!text) { vscode.window.showInformationMessage('No text selected.'); return; }
      const config = vscode.workspace.getConfiguration('ai-firewall');
      const mode = config.get('maskMode', 'placeholder');
      const result = scrub(text, mode);
      editor.edit(editBuilder => editBuilder.replace(selection, result.scrubbed));
      lastMap = result.map;
      if (result.matches.length > 0) {
        vscode.window.showInformationMessage('AI Firewall: Masked ' + result.matches.length + ' PII items');
      } else {
        vscode.window.showInformationMessage('AI Firewall: No PII detected in selection');
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('ai-firewall.scrubDocument', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const text = editor.document.getText();
      if (!text) return;
      const config = vscode.workspace.getConfiguration('ai-firewall');
      const mode = config.get('maskMode', 'placeholder');
      const result = scrub(text, mode);
      const fullRange = new vscode.Range(0, 0, editor.document.lineCount, 0);
      editor.edit(editBuilder => editBuilder.replace(fullRange, result.scrubbed));
      lastMap = result.map;
      vscode.window.showInformationMessage('AI Firewall: Document scrubbed (' + result.matches.length + ' PII items masked)');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('ai-firewall.restoreDocument', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || Object.keys(lastMap).length === 0) {
        vscode.window.showInformationMessage('No PII to restore.');
        return;
      }
      const text = editor.document.getText();
      const restored = restore(text, lastMap);
      const fullRange = new vscode.Range(0, 0, editor.document.lineCount, 0);
      editor.edit(editBuilder => editBuilder.replace(fullRange, restored));
      lastMap = {};
      vscode.window.showInformationMessage('AI Firewall: Original text restored.');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('ai-firewall.toggleMode', () => {
      const config = vscode.workspace.getConfiguration('ai-firewall');
      const current = config.get('maskMode', 'placeholder');
      const next = current === 'placeholder' ? 'realistic' : 'placeholder';
      config.update('maskMode', next, vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage('AI Firewall: Mask mode set to "' + next + '"');
    })
  );

  console.log('[AI Firewall] VS Code extension activated (' + PII_RULES.length + ' PII types)');
}

function deactivate() {}

module.exports = { activate, deactivate };
