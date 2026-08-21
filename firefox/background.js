const PII_RULES = [
  { id:'crypto', name:'Crypto Wallet', label:'CRYPTO', regex:/0x[a-fA-F0-9]{40}/g, conf:0.95 },
  { id:'mac', name:'MAC Address', label:'MAC_ADDR', regex:/[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}/g, conf:0.95 },
  { id:'cc', name:'Credit Card', label:'CC_NUM', regex:/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, conf:0.9, luhn:true },
  { id:'ssn', name:'SSN', label:'SSN_NUM', regex:/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, conf:0.85 },
  { id:'apikey', name:'API Key', label:'APIKEY', regex:/(?:api[_-]?key|api key)[=:\s]+\S+/gi, conf:0.85 },
  { id:'pwd', name:'Password', label:'PWD_VAL', regex:/(?:password|passwd|pass)[=:\s]+\S+/gi, conf:0.8 },
  { id:'dob', name:'Date of Birth', label:'DOB', regex:/(?:DOB|date\s*of\s*birth|birth\s*date)[=:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}/gi, conf:0.9 },
  { id:'de-id', name:'Germany Personalausweis', label:'DE_ID', regex:/\b[A-Z]\d{8}\b/g, conf:0.8 },
  { id:'passport', name:'Passport', label:'PASSPORT', regex:/\b[A-Z]\d{8}\b/g, conf:0.85 },
  { id:'phone', name:'Phone Number', label:'PHONE_NUM', regex:/\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, conf:0.8 },
  { id:'ip', name:'IP Address', label:'IP_ADDR', regex:/(?<!\b[vV]ersion\s)\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g, conf:0.65 },
  { id:'routing', name:'Routing Number', label:'ROUTING', regex:/\b\d{9}\b/g, conf:0.4 },
  { id:'email', name:'Email Address', label:'EMAIL_ADDR', regex:/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, conf:0.95 },
  { id:'license', name:'Driver License', label:'LICENSE', regex:/(?:driver'?s?\s*license|dl|license)[=:\s]*[A-Z0-9]{5,14}/gi, conf:0.7 },
  { id:'address', name:'Street Address', label:'ADDRESS', regex:/\b\d{1,5}\s+(?:[\w]\s?){0,25}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Circle|Cir|Place|Pl)\.?\b/gi, conf:0.6 },
  { id:'bank', name:'Bank Account', label:'BANK_ACCT', regex:/(?:account|acct|acc)\s*(?:#|number|num|no)?[=:\s]+\d{5,17}/gi, conf:0.7 },
  { id:'uk-ni', name:'UK National Insurance', label:'UK_NI', regex:/\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b/gi, conf:0.85 },
  { id:'uk-nhs', name:'UK NHS Number', label:'UK_NHS', regex:/\b\d{3}\s?\d{3}\s?\d{4}\b/g, conf:0.7 },
  { id:'in-aadhaar', name:'India Aadhaar', label:'IN_AADHAAR', regex:/\b\d{4}\s?\d{4}\s?\d{4}\b/g, conf:0.85 },
  { id:'in-pan', name:'India PAN', label:'IN_PAN', regex:/\b[A-Z]{5}\d{4}[A-Z]\b/gi, conf:0.9 },
  { id:'cn-id', name:'China ID (18位)', label:'CN_ID', regex:/\b\d{6}\d{8}\d{3}[\dXx]\b/g, conf:0.85 },
  { id:'ca-sin', name:'Canada SIN', label:'CA_SIN', regex:/\b\d{3}\s?\d{3}\s?\d{3}\b/g, conf:0.7 },
  { id:'jwt', name:'JWT Token', label:'JWT', regex:/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, conf:0.95 },
  { id:'aws-key', name:'AWS Access Key', label:'AWS_KEY', regex:/\bAKIA[0-9A-Z]{16}\b/g, conf:0.95 },
  { id:'github', name:'GitHub Token', label:'GITHUB', regex:/\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}\b/g, conf:0.95 },
  { id:'slack', name:'Slack Token', label:'SLACK', regex:/\bxox[baprs]-[a-zA-Z0-9-]{10,}\b/g, conf:0.95 },
  { id:'au-tfn', name:'Australia TFN', label:'AU_TFN', regex:/\b\d{3}\s?\d{3}\s?\d{3}\b/g, conf:0.4 },
  { id:'jp-my', name:'Japan My Number', label:'JP_MY', regex:/\b\d{4}-\d{4}-\d{4}\b/g, conf:0.85 },
  { id:'br-cpf', name:'Brazil CPF', label:'BR_CPF', regex:/\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g, conf:0.8 },
  { id:'br-cnpj', name:'Brazil CNPJ', label:'BR_CNPJ', regex:/\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g, conf:0.85 },
  { id:'fr-insee', name:'France INSEE', label:'FR_INSEE', regex:/\b\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\b/g, conf:0.7 },
  { id:'de-tax', name:'Germany Tax ID (Steuernummer)', label:'DE_TAX', regex:/(?<!\+)(?<!\d)\b\d{2,3}\s\d{3,4}\s\d{3,4}(\s\d{1,2})?\b/g, conf:0.4 },
  { id:'kr-rrn', name:'Korea Resident Registration', label:'KR_RRN', regex:/\b\d{6}-[1-4]\d{6}\b/g, conf:0.9 },
  { id:'mx-curp', name:'Mexico CURP', label:'MX_CURP', regex:/\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b/g, conf:0.95 },
  { id:'mx-rfc', name:'Mexico RFC', label:'MX_RFC', regex:/\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b/g, conf:0.85 },
  { id:'se-pn', name:'Sweden Personnummer', label:'SE_PN', regex:/\b\d{6}[-+]\d{4}\b/g, conf:0.8 },
  { id:'it-cf', name:'Italy Codice Fiscale', label:'IT_CF', regex:/\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b/g, conf:0.95 }
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
  PERSON_NAME: () => ['John Smith','Jane Doe','Alex Johnson','Sam Wilson','Taylor Brown'][Math.floor(Math.random() * 5)],
  DE_ID: () => String.fromCharCode(65 + Math.floor(Math.random() * 26)) + Math.floor(Math.random() * 100000000).toString().padStart(8, '0'),
  DE_TAX: () => Math.floor(Math.random() * 300).toString().padStart(3,'0') + ' ' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + ' ' + Math.floor(Math.random() * 10000).toString().padStart(4,'0'),
  KR_RRN: () => Math.floor(Math.random() * 1000000).toString().padStart(6,'0') + '-' + (Math.floor(Math.random() * 4) + 1) + Math.floor(Math.random() * 1000000).toString().padStart(6,'0'),
  MX_CURP: () => { const c = 'AEIOU'; const v = 'AEIOU'; const letters = Array(4).fill(0).map(() => c[Math.floor(Math.random() * c.length)]).join(''); const consonants = Array(5).fill(0).map(() => 'BCDFGHJKLMNPQRSTVWXYZ'[Math.floor(Math.random() * 21)]).join(''); return letters + Math.floor(Math.random() * 1000000).toString().padStart(6,'0') + (Math.random() > 0.5 ? 'H' : 'M') + consonants + '0' + Math.floor(Math.random() * 10).toString(); },
  MX_RFC: () => { const c = 'AEIOUX'; const letters = Array(3).fill(0).map(() => c[Math.floor(Math.random() * c.length)]).join(''); const letters4 = letters[0] + Array(3).fill(0).map(() => 'AEIOUX'[Math.floor(Math.random() * 6)]).join(''); const use4 = Math.random() > 0.5; return (use4 ? letters4 : letters) + Math.floor(Math.random() * 1000000).toString().padStart(6,'0') + Array(3).fill(0).map(() => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random() * 36)]).join(''); },
  SE_PN: () => Math.floor(Math.random() * 1000000).toString().padStart(6,'0') + Math.floor(Math.random() * 10000).toString().padStart(4,'0'),
  IT_CF: () => { const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; const letters = Array(6).fill(0).map(() => c[Math.floor(Math.random() * 26)]).join(''); return letters + Math.floor(Math.random() * 100).toString().padStart(2,'0') + c[Math.floor(Math.random() * 26)] + Math.floor(Math.random() * 100).toString().padStart(2,'0') + c[Math.floor(Math.random() * 26)] + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + c[Math.floor(Math.random() * 26)]; }
};

function fakeFor(label) { const fn = FAKERS[label]; return fn ? fn() : '[FAKE_' + label + ']'; }

function luhnCheck(num) {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  const clean = num.replace(/[-\s]/g, '');
  if (/^0+$/.test(clean)) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

let piiMap = {};
let counter = 1;
let isEnabled = true;
let maskMode = 'placeholder';
let stats = { requests: 0, piiDetected: 0, piiTypes: {} };

// ── VPN / Privacy Route ─────────────────────────────────────
const AI_DOMAINS = [
  'chat.openai.com', 'chatgpt.com', 'copilot.microsoft.com', 'gemini.google.com',
  'claude.ai', 'perplexity.ai', 'poe.com', 'groq.com', 'mistral.ai', 'cohere.ai',
  'meta.ai', 'deepseek.com', 'you.com', 'kimi.ai', 'qwen.ai', 'jina.ai',
  'phind.com', 'chat.google.com', 'ai.google.dev'
];

let vpnConfig = { enabled: false, host: '', port: 1080, protocol: 'socks5', leakProtect: true };

function proxySupported() {
  return !!(browser.proxy && browser.proxy.settings && browser.proxy.settings.set);
}

function buildPacScript(cfg) {
  const scheme = cfg.protocol === 'https' ? 'HTTPS' : 'SOCKS5';
  const host = cfg.host || '127.0.0.1';
  const port = cfg.port || 1080;
  const lines = AI_DOMAINS.map((d) => "  '" + d + "',").join('\n');
  return [
    'function FindProxyForURL(url, host) {',
    '  var protectedHosts = [',
    lines,
    '  ];',
    '  var h = host.toLowerCase();',
    '  for (var i = 0; i < protectedHosts.length; i++) {',
    '    var p = protectedHosts[i];',
    '    if (h === p) return "' + scheme + ' ' + host + ':' + port + '";',
    '    if (h.indexOf(p) === h.length - p.length && h.charAt(h.length - p.length - 1) === ".") return "' + scheme + ' ' + host + ':' + port + '";',
    '  }',
    '  return "DIRECT";',
    '}'
  ].join('\n');
}

function applyVpn() {
  if (proxySupported()) {
    if (vpnConfig.enabled && vpnConfig.host) {
      browser.proxy.settings.set({
        value: { mode: 'pac_script', pacScript: { data: buildPacScript(vpnConfig) } },
        scope: 'regular'
      }).catch(() => {});
    } else {
      browser.proxy.settings.set({ value: { mode: 'direct' }, scope: 'regular' }).catch(() => {});
    }
    if (vpnConfig.leakProtect && browser.privacy && browser.privacy.network && browser.privacy.network.webRTCIPHandlingPolicy) {
      browser.privacy.network.webRTCIPHandlingPolicy.set({
        value: vpnConfig.enabled ? 'disable_non_proxied_udp' : 'default'
      }).catch(() => {});
    }
  }
  browser.storage.local.set({ vpnConfig });
}

function vpnStatus() {
  return {
    enabled: vpnConfig.enabled,
    host: vpnConfig.host,
    port: vpnConfig.port,
    protocol: vpnConfig.protocol,
    leakProtect: vpnConfig.leakProtect,
    supported: proxySupported(),
    domains: AI_DOMAINS.length
  };
}

browser.storage.local.get(['vpnConfig']).then((res) => {
  if (res.vpnConfig) vpnConfig = Object.assign({}, vpnConfig, res.vpnConfig);
  applyVpn();
});

function scrub(text) {
  if (!isEnabled || !text) return { text, map: {}, matches: [] };

  piiMap = {};
  counter = 1;
  let scrubbed = text;
  let allMatches = [];
  let detectedTypes = [];

  for (const rule of PII_RULES) {
    const regex = new RegExp(rule.regex.source, rule.regex.flags);
    let match;
    while ((match = regex.exec(scrubbed)) !== null) {
      const raw = match[0];
      let conf = rule.conf;

      if (rule.luhn) {
        const clean = raw.replace(/[-\s]/g, '');
        if (clean.length >= 13 && clean.length <= 19) {
          conf = luhnCheck(clean) ? 0.95 : 0.3;
        }
      }

      let replacement;
      if (maskMode === 'realistic') {
        replacement = fakeFor(rule.label);
      } else {
        replacement = '[' + rule.label + '_' + counter + ']';
      }

      piiMap[replacement] = raw;
      allMatches.push({ type: rule.label, original: raw, placeholder: replacement, confidence: conf, name: rule.name });
      scrubbed = scrubbed.split(raw).join(replacement);

      if (!detectedTypes.includes(rule.label)) detectedTypes.push(rule.label);
      stats.piiDetected++;
      stats.piiTypes[rule.label] = (stats.piiTypes[rule.label] || 0) + 1;
      counter++;
      if (counter > 1000) break;
    }
  }

  return { text: scrubbed, map: piiMap, matches: allMatches, detected: detectedTypes };
}

function restore(text, map) {
  if (!text || !map) return text;
  let restored = text;
  const sorted = Object.entries(map).sort((a, b) => b[0].length - a[0].length);
  for (const [placeholder, original] of sorted) {
    restored = restored.split(placeholder).join(original);
  }
  return restored;
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {
    case 'SCRUB':
      const result = scrub(msg.text);
      stats.requests++;
      sendResponse(result);
      break;
    case 'RESTORE':
      sendResponse({ text: restore(msg.text, msg.map) });
      break;
    case 'GET_STATS':
      sendResponse({ stats, isEnabled, maskMode });
      break;
    case 'TOGGLE':
      isEnabled = !isEnabled;
      browser.storage.local.set({ isEnabled });
      sendResponse({ isEnabled });
      break;
    case 'SET_MASK_MODE':
      maskMode = msg.mode || 'placeholder';
      browser.storage.local.set({ maskMode });
      sendResponse({ maskMode });
      break;
    case 'GET_ENABLED':
      sendResponse({ isEnabled });
      break;
    case 'GET_MAP':
      sendResponse({ map: piiMap });
      break;
    case 'SET_SOUND':
      sendResponse({ success: true });
      break;
    case 'SET_MASKED_TEXT':
      sendResponse({ success: true });
      break;
    case 'VPN_GET':
      sendResponse(vpnStatus());
      break;
    case 'VPN_SET':
      if (msg.config) {
        const allowedProtocols = ['http', 'https', 'socks4', 'socks5'];
        const safeConfig = {};
        if (msg.config.enabled !== undefined) safeConfig.enabled = !!msg.config.enabled;
        if (msg.config.leakProtect !== undefined) safeConfig.leakProtect = !!msg.config.leakProtect;
        if (typeof msg.config.host === 'string' && /^[a-zA-Z0-9._-]+$/.test(msg.config.host)) {
          safeConfig.host = msg.config.host.substring(0, 255);
        }
        if (typeof msg.config.port === 'number' && msg.config.port >= 1 && msg.config.port <= 65535) {
          safeConfig.port = msg.config.port;
        }
        if (allowedProtocols.includes(msg.config.protocol)) {
          safeConfig.protocol = msg.config.protocol;
        }
        vpnConfig = Object.assign({}, vpnConfig, safeConfig);
      }
      applyVpn();
      sendResponse(vpnStatus());
      break;
    case 'VPN_TOGGLE':
      vpnConfig.enabled = !!msg.enabled;
      applyVpn();
      sendResponse(vpnStatus());
      break;
    default:
      sendResponse({ error: 'Unknown message type' });
  }
  return true;
});

browser.storage.local.get(['isEnabled', 'maskMode']).then((result) => {
  if (result.isEnabled !== undefined) isEnabled = result.isEnabled;
  if (result.maskMode !== undefined) maskMode = result.maskMode;
});

console.log('[AI Firewall] Safari background loaded (' + PII_RULES.length + ' PII types, Luhn, confidence)');
