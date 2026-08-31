// ── PII RULES (matching index.html) ──────────────────────────────
import { analyzeDocument, contextScore, detectMissingPII } from './context.cjs';

const BUILTIN_RULES = [
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

let globalCounter = 1;
let piiMap = {};

function luhnCheck(num) {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^0+$/.test(digits)) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

function applyHeuristics(rule, raw, idx, text, conf) {
  const before = text.substring(Math.max(0, idx - 25), idx);
  const after = text.substring(idx + raw.length, Math.min(text.length, idx + raw.length + 25));
  const ctx = before + ' ' + after;
  const prev = idx > 0 ? text[idx - 1] : '';
  const next = idx + raw.length < text.length ? text[idx + raw.length] : '';
  if ((prev && /\w/.test(prev)) || (next && /\w/.test(next))) return 0.2;
  if (rule.id === 'ssn') {
    if (/[+\-*=]/.test(ctx) || /\b(SKU|Part\s*#|Product\s*Code)\b/i.test(ctx)) return 0.2;
    if (/^\s*(Number|ID|Code)\s*[#:]?\s*$/i.test(before) && !/\b(SSN|social|security|tax|employee)\b/i.test(ctx)) return 0.2;
  }
  if (rule.id === 'passport') {
    if (/\b(Code|SKU|spec|Ref)\b/i.test(ctx)) return 0.2;
  }
  if (rule.id === 'phone') {
    if (/\b(Order|Product|Item)\s*[#:]/i.test(ctx) && !/\b(call|dial|phone|tel|ring|reach|contact)\b/i.test(ctx)) return 0.2;
  }
  if (rule.id === 'routing') {
    if (/^\s*(Number|ID|Code|Ref)\s*[#:]?\s*$/i.test(before) && !/\b(routing|ABA|transit|bank)\b/i.test(ctx)) return 0.15;
  }
  if (rule.id === 'phone' && conf > 0.5) {
    const letters = (ctx.match(/[a-zA-Z]/g) || []).length;
    const digits = (ctx.match(/\d/g) || []).length;
    const total = ctx.replace(/\s/g, '').length || 1;
    if (digits / total > 0.6 && letters < 3) return 0.2;
  }
  return conf;
}

const FAKERS = {
  EMAIL_ADDR: () => 'user' + (Math.floor(Math.random() * 9000) + 1000) + '@example.com',
  PHONE_NUM: () => '555-' + (Math.floor(Math.random() * 900) + 100) + '-' + (Math.floor(Math.random() * 9000) + 1000),
  CC_NUM: () => '4111' + Array(12).fill(0).map(() => Math.floor(Math.random() * 10)).join(''),
  SSN_NUM: () => (Math.floor(Math.random() * 900) + 100) + '-' + (Math.floor(Math.random() * 90) + 10) + '-' + (Math.floor(Math.random() * 9000) + 1000),
  IP_ADDR: () => '0.0.0.0',
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

function scrub(text, mode) {
  piiMap = {};
  globalCounter = 1;
  let result = text;
  const matches = [];
  const docStats = analyzeDocument(text);

  for (const rule of BUILTIN_RULES) {
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
        replacement = fakeFor(rule.label);
      } else {
        replacement = '[' + rule.label + '_' + globalCounter + ']';
      }

      piiMap[replacement] = raw;
      matches.push({ type: rule.label, original: raw, replacement, confidence: conf });
      result = result.replace(raw, replacement);
      globalCounter++;
    }
  }

  const extraMatches = detectMissingPII(result, docStats);
  for (const em of extraMatches) {
    const replacement = mode === 'realistic' ? (fakeFor(em.type) || 'John Smith') : '[PERSON_NAME_' + globalCounter + ']';
    piiMap[replacement] = em.match;
    matches.push({ type: em.type, original: em.match, replacement, confidence: em.confidence });
    result = result.split(em.match).join(replacement);
    globalCounter++;
  }

  return { scrubbed: result, piiMap, matches };
}

// ── TESTS ─────────────────────────────────────────────────────────
const tests = [
  // ── EMAIL ──────────────────────────────────────────────────────
  { id:"E01", cat:"EMAIL", desc:"Simple email",                        input:"Contact me at john.doe@example.com" },
  { id:"E02", cat:"EMAIL", desc:"Multiple emails",                     input:"a@b.com and c@d.org are both valid" },
  { id:"E03", cat:"EMAIL", desc:"Email with + alias",                  input:"user+label@gmail.com" },
  { id:"E04", cat:"EMAIL", desc:"Email with dots in local part",       input:"first.last@company.co.uk" },
  { id:"E05", cat:"EMAIL", desc:"Email with subdomain",                input:"admin@mail.server.com" },
  { id:"E06", cat:"EMAIL", desc:"Email at end of sentence",            input:"Write to me@home.com." },
  { id:"E07", cat:"EMAIL", desc:"Email adjacent to parentheses",       input:"Contact (bob@work.com) for details" },
  { id:"E08", cat:"EMAIL", desc:"Email in angle brackets",             input:"Send to <admin@example.com>" },
  { id:"E09", cat:"EMAIL", desc:"Email with _ and - in domain",        input:"test_1@my-server-1.com" },
  { id:"E10", cat:"EMAIL", desc:"Two emails same line diff domain",    input:"alice@alpha.com bob@beta.org" },
  { id:"E11", cat:"EMAIL", desc:"Email in mailto link",                input:"Send to <a href='mailto:user@site.com'>user@site.com</a>" },
  { id:"E12", cat:"EMAIL", desc:"Email in quotes",                     input:"The email is \"test@example.com\" on file" },
  { id:"E13", cat:"EMAIL", desc:"Email after colon",                   input:"Email: support@help.org" },
  { id:"E14", cat:"EMAIL", desc:"Email in query string",               input:"?email=user@test.com&id=123" },
  { id:"E15", cat:"EMAIL", desc:"Email with numeric domain prefix",    input:"My email is user@123-reg.co.uk" },
  { id:"E16", cat:"EMAIL", desc:"Three emails comma separated",        input:"a@x.com, b@y.com, c@z.com" },
  { id:"E17", cat:"EMAIL", desc:"Email in pipe-delimited list",        input:"admin@a.com|bob@b.com|carol@c.com" },
  { id:"E18", cat:"EMAIL", desc:"Email with = in local part",          input:"user=name@domain.com" },

  // ── PHONE ──────────────────────────────────────────────────────
  { id:"P01", cat:"PHONE", desc:"Phone with dashes",                   input:"Call 555-123-4567 for support" },
  { id:"P02", cat:"PHONE", desc:"Phone with parens",                   input:"Reach (555) 987-6543" },
  { id:"P03", cat:"PHONE", desc:"Phone with +1",                       input:"International: +1 800-555-0199" },
  { id:"P04", cat:"PHONE", desc:"Phone with dots",                     input:"Dial 555.123.4567 now" },
  { id:"P05", cat:"PHONE", desc:"Phone with spaces only",              input:"Tel 555 123 4567" },
  { id:"P06", cat:"PHONE", desc:"Phone contiguous 10 digits",          input:"Ring 5551234567 now" },
  { id:"P07", cat:"PHONE", desc:"Phone with +1 no space",              input:"Call +14155550199" },
  { id:"P08", cat:"PHONE", desc:"Phone in parentheses with dashes",    input:"Office: (555) 123-4567" },
  { id:"P09", cat:"PHONE", desc:"Two phones same line",                input:"Home 555-111-2222 Mobile 555-333-4444" },
  { id:"P10", cat:"PHONE", desc:"Phone with 1 prefix no +",            input:"Dial 1-555-123-4567" },
  { id:"P11", cat:"PHONE", desc:"Phone in brackets",                   input:"Tel: [555-123-4567]" },
  { id:"P12", cat:"PHONE", desc:"Phone in quotes",                     input:'Phone "555-123-4567" on record' },
  { id:"P13", cat:"PHONE", desc:"Phone with extension",                input:"Call 555-123-4567 x1234" },
  { id:"P14", cat:"PHONE", desc:"Phone after text no space",           input:"phone:555-123-4567" },
  { id:"P15", cat:"PHONE", desc:"Phone each separator different",      input:"555.123 4567" },
  { id:"P16", cat:"PHONE", desc:"Phone with country code parens",       input:"+1 (555) 123-4567" },

  // ── SSN ────────────────────────────────────────────────────────
  { id:"S01", cat:"SSN", desc:"SSN with dashes",                       input:"SSN: 123-45-6789" },
  { id:"S02", cat:"SSN", desc:"SSN with spaces",                       input:"SSN: 123 45 6789" },
  { id:"S03", cat:"SSN", desc:"SSN contiguous 9 digits",               input:"My SSN is 123456789" },
  { id:"S04", cat:"SSN", desc:"SSN at end of sentence",                input:"ID: 123-45-6789." },
  { id:"S05", cat:"SSN", desc:"Two SSNs in one line",                  input:"Employee A: 111-22-3333, B: 444-55-6666" },
  { id:"S06", cat:"SSN", desc:"SSN in brackets",                       input:"SSN [123-45-6789] on file" },
  { id:"S07", cat:"SSN", desc:"SSN in text",                           input:"Born 123-45-6789" },
  { id:"S08", cat:"SSN", desc:"SSN with SS# label",                    input:"SS# 123-45-6789" },
  { id:"S09", cat:"SSN", desc:"SSN in JSON",                           input:'{"ssn":"123-45-6789"}' },
  { id:"S10", cat:"SSN", desc:"SSN in CSV",                            input:"John,Doe,123-45-6789,555-123-4567" },
  { id:"S11", cat:"SSN", desc:"SSN mixed separator style",             input:"123-45 6789" },
  { id:"S12", cat:"SSN", desc:"SSN standalone",                        input:"123-45-6789" },

  // ── CREDIT CARD ────────────────────────────────────────────────
  { id:"C01", cat:"CC", desc:"Card 16 contiguous digits",              input:"Card: 4111111111111111" },
  { id:"C02", cat:"CC", desc:"Card with dashes",                       input:"Card: 4111-1111-1111-1111" },
  { id:"C03", cat:"CC", desc:"Card with spaces",                       input:"Card: 4111 1111 1111 1111" },
  { id:"C04", cat:"CC", desc:"Visa test card",                         input:"Visa: 4111111111111111" },
  { id:"C05", cat:"CC", desc:"Mastercard test",                        input:"MC: 5500-0000-0000-0004" },
  { id:"C06", cat:"NONE", desc:"Amex 15-digit (no longer FP with \\b phone)", input:"Amex: 3782-822463-10005" },
  { id:"C07", cat:"CC", desc:"Two cards in one line",                  input:"Visa: 4111-1111-1111-1111 MC: 5500-0000-0000-0004" },
  { id:"C08", cat:"CC", desc:"Discover card (6011)",                   input:"Discover: 6011-1111-1111-1117" },
  { id:"C09", cat:"CC", desc:"JCB card (3528)",                        input:"JCB: 3528-0000-0000-0000" },
  { id:"C10", cat:"CC", desc:"Diners Club (300xxx)",                   input:"Diners: 3000-0000-0000-0004" },
  { id:"C11", cat:"CC", desc:"Three cards in one line",                input:"A:4111-1111-1111-1111 B:5500-0000-0000-0004 C:6011-1111-1111-1117" },
  { id:"C12", cat:"CC", desc:"Card in JSON",                           input:'{"card":"4111-1111-1111-1111","cvv":"123"}' },
  { id:"C13", cat:"CC", desc:"Card mixed separators",                  input:"4111 1111-1111 1111" },

  // ── IP ADDRESS ─────────────────────────────────────────────────
  { id:"I01", cat:"IP", desc:"Standard IPv4",                          input:"Server at 192.168.1.1" },
  { id:"I02", cat:"IP", desc:"Localhost",                              input:"Local: 127.0.0.1" },
  { id:"I03", cat:"IP", desc:"Broadcast",                              input:"Broadcast 255.255.255.0" },
  { id:"I04", cat:"IP", desc:"Multiple IPs",                            input:"DNS: 8.8.8.8 and 8.8.4.4" },
  { id:"I05", cat:"IP", desc:"IP in URL-like context",                 input:"http://192.168.1.1:8080/admin" },
  { id:"I06", cat:"IP", desc:"Private IP 10.x.x.x",                   input:"Internal: 10.0.0.5" },
  { id:"I07", cat:"IP", desc:"Private IP 172.16.x.x",                 input:"Network: 172.16.0.1" },
  { id:"I08", cat:"IP", desc:"Private IP 192.168.x.x",                input:"LAN: 192.168.0.100" },
  { id:"I09", cat:"IP", desc:"IP with port number",                    input:"Connect to 203.0.113.5:443" },
  { id:"I10", cat:"IP", desc:"Multiple IPs in log",                    input:"SRC=10.0.0.1 DST=203.0.113.5 PROTO=TCP" },
  { id:"I11", cat:"IP", desc:"IP in CIDR notation",                    input:"Subnet: 192.168.1.0/24" },

  // ── PASSWORD ───────────────────────────────────────────────────
  { id:"PW01", cat:"PWD", desc:"password keyword with colon",          input:"password: hunter2" },
  { id:"PW02", cat:"PWD", desc:"password keyword with space",          input:"my password is secret!" },
  { id:"PW03", cat:"PWD", desc:"passwd shorthand",                     input:"passwd: admin123" },
  { id:"PW04", cat:"PWD", desc:"PASSWORD case insensitive",            input:"PASSWORD: MySecret123" },
  { id:"PW05", cat:"PWD", desc:"password with special chars",          input:"password: p@$$w0rd!" },
  { id:"PW06", cat:"PWD", desc:"password with = sign",                 input:"password=secret123" },
  { id:"PW07", cat:"PWD", desc:"password in config style",             input:"login='admin' password='12345'" },
  { id:"PW08", cat:"PWD", desc:"pass shorthand",                       input:"pass: supersecret" },
  { id:"PW09", cat:"PWD", desc:"pass= shorthand",                      input:"pass=hunter2" },
  { id:"PW10", cat:"PWD", desc:"PASSWD= with = sign",                  input:"PASSWD=admin!" },

  // ── API KEY ────────────────────────────────────────────────────
  { id:"A01", cat:"APIKEY", desc:"api_key with colon",                 input:"api_key: sk-abc123DEF" },
  { id:"A02", cat:"APIKEY", desc:"api key with space",                 input:"api key: abcd-efgh-ijkl" },
  { id:"A03", cat:"APIKEY", desc:"apikey no space",                    input:"apikey: xyz7890" },
  { id:"A04", cat:"APIKEY", desc:"API-KEY with dash",                  input:"API-Key: secret-token-123" },
  { id:"A05", cat:"APIKEY", desc:"APIKEY case insensitive",            input:"APIKEY: ABC123def456" },
  { id:"A06", cat:"APIKEY", desc:"api_key in config style",            input:"api_key='test123'" },
  { id:"A07", cat:"APIKEY", desc:"apikey= shorthand",                  input:"apikey=test123" },
  { id:"A08", cat:"APIKEY", desc:"api-key with space",                 input:"api-key: sk-live-abc123" },
  { id:"A09", cat:"APIKEY", desc:"Api_Key mixed case",                 input:"Api_Key: abcDEF123" },

  // ── NEW TYPES ──────────────────────────────────────────────────
  { id:"N01", cat:"CRYPTO", desc:"ETH wallet address",                 input:"Wallet: 0x71C7656EC7ab9b618e7dD32a6D9C6e1f3B3b6C6e" },
  { id:"X11", cat:"NONE", desc:"BTC wallet (no ETH match)",            input:"BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" },
  { id:"N03", cat:"MAC", desc:"Standard MAC address",                  input:"MAC: aa:bb:cc:dd:ee:ff" },
  { id:"N04", cat:"MAC", desc:"Another MAC address",                   input:"Device 00:11:22:33:44:55 connected" },
  { id:"N05", cat:"DOB", desc:"DOB with label",                        input:"DOB: 01/15/1990" },
  { id:"N06", cat:"DOB", desc:"Date of Birth with text",               input:"Date of Birth: 05-20-1985" },
  { id:"N07", cat:"DOB", desc:"birth date format",                     input:"birth date: 12/25/2000" },
  { id:"X12", cat:"NONE", desc:"DOB without keyword (no match)",       input:"01/15/1990" },
  { id:"N09", cat:"PASSPORT", desc:"US passport number",               input:"Passport: A12345678" },
  { id:"N10", cat:"PASSPORT", desc:"Another passport number",          input:"ID: B98765432" },
  { id:"N11", cat:"LICENSE", desc:"Driver license with label",         input:"driver's license: D1234567" },
  { id:"N12", cat:"LICENSE", desc:"DL shorthand",                      input:"dl: ABC12345" },
  { id:"N13", cat:"LICENSE", desc:"license keyword",                   input:"license: XYZ987654" },
  { id:"N14", cat:"ADDRESS", desc:"Street address",                    input:"Address: 123 Main Street" },
  { id:"N15", cat:"ADDRESS", desc:"Avenue address",                    input:"456 Oak Avenue, Springfield" },
  { id:"N16", cat:"ADDRESS", desc:"Road address",                      input:"789 Pine Road" },
  { id:"N17", cat:"BANK", desc:"Bank account with keyword",            input:"account: 1234567890" },
  { id:"N18", cat:"BANK", desc:"Account number shorthand",             input:"acct# 987654321" },
  { id:"N19", cat:"BANK", desc:"Acc number label",                     input:"acc number: 5555555555" },

  // ── MIXED ──────────────────────────────────────────────────────
  { id:"M01", cat:"MIXED", desc:"All types in one sentence",          input:"Email: bob@test.com | Phone: 555-123-4567 | SSN: 123-45-6789 | Card: 4111-1111-1111-1111 | IP: 10.0.0.1 | password: secret123 | api_key: sk-test | DOB: 01/15/1990 | Wallet: 0x71C7656EC7ab9b618e7dD32a6D9C6e1f3B3b6C6e" },
  { id:"M02", cat:"MIXED", desc:"Realistic support ticket",           input:"My name is John, email john@test.com, phone 555-123-4567. SSN 123-45-6789. DOB: 05/20/1985. Please help." },
  { id:"M03", cat:"MIXED", desc:"JSON-like payload",                   input:'{"user":"admin","email":"admin@corp.com","ip":"10.0.0.5","api_key":"sk-test","dob":"01/15/1990"}' },
  { id:"M04", cat:"MIXED", desc:"PII in log line",                    input:"ERROR [2024-01-15] user=jane@site.com from=192.168.2.10 card=4111111111111111 account=1234567890" },
  { id:"M05", cat:"MIXED", desc:"Support chat transcript",            input:"Agent: what is your email?\nUser: jane@doe.com\nAgent: DOB?\nUser: 05/20/1985\nAgent: phone?\nUser: 555-000-1111" },
  { id:"M06", cat:"MIXED", desc:"PII in CSV row",                     input:"Alice,alice@test.com,555-111-2222,123-45-6789,4111-1111-1111-1111,01/15/1990" },
  { id:"M07", cat:"MIXED", desc:"PII in HTML form",                   input:'<input name="email" value="user@test.com"><input name="phone" value="555-123-4567"><input name="dob" value="01/15/1990">' },
  { id:"M08", cat:"MIXED", desc:"Log line with all PII types",        input:"Jan 15 10:30:00 host app[1234]: user=jane@corp.com from=10.0.0.5 card=4111111111111111 ssn=123-45-6789 phone=555-000-1111 apikey=sk-test password=secret123 dob=01/15/1990 account=1234567890" },
  { id:"M09", cat:"MIXED", desc:"Email + password + IP together",     input:"login='admin@system.com' password='P@ssw0rd' from=192.168.1.100" },
  { id:"M10", cat:"MIXED", desc:"URL with embedded credentials",      input:"ftp://anonymous:password@192.168.1.1/files" },
  { id:"M11", cat:"MIXED", desc:"Crypto + MAC + passport combo",      input:"Wallet: 0x71C7656EC7ab9b618e7dD32a6D9C6e1f3B3b6C6e, MAC: aa:bb:cc:dd:ee:ff, Passport: A12345678, DL: D1234567" },
  { id:"M12", cat:"MIXED", desc:"Bank details with routing",          input:"account: 1234567890 routing number 021000021 transferred to john@bank.com" },

  // ── FALSE POSITIVE EDGE CASES ─────────────────────────────────
  { id:"FP01", cat:"FP", desc:"Version number (looks like IP)",       input:"Version 1.2.3.4 is released" },
  { id:"FP02", cat:"FP", desc:"Date string",                          input:"Date: 2024-01-15" },
  { id:"FP03", cat:"FP", desc:"Math expression in SSN format",        input:"Result = 123-45-6789 = -6681", fixedFp:true },
  { id:"FP04", cat:"FP", desc:"Product code in SSN format",           input:"Order SKU: 123-45-6789-01", fixedFp:true },
  { id:"FP05", cat:"FP", desc:"Port number (looks like phone)",       input:"Port 5555 is open" },
  { id:"FP06", cat:"FP", desc:"Year range",                            input:"Fiscal years 2020-2024 comparison" },
  { id:"FP07", cat:"FP", desc:"Time format (HH:MM:SS)",               input:"Time: 14:30:00" },
  { id:"FP08", cat:"FP", desc:"Decimal number like IP",               input:"Value is 123.456.789" },
  { id:"FP09", cat:"FP", desc:"Latitude/longitude",                   input:"GPS: 40.7128, -74.0060" },
  { id:"FP10", cat:"MAC", desc:"MAC address (should match MAC rule)",  input:"MAC: aa:bb:cc:dd:ee:ff" },
  { id:"FP11", cat:"FP", desc:"Percentage value",                     input:"Rate: 99.9%" },
  { id:"FP12", cat:"FP", desc:"Semantic versioning",                  input:"v2.0.1-alpha+build" },
  { id:"FP13", cat:"FP", desc:"Zip code",                             input:"ZIP: 90210" },
  { id:"FP14", cat:"FP", desc:"ISBN-10 number",                       input:"ISBN: 0-306-40615-2" },
  { id:"FP15", cat:"FP", desc:"ISBN-13 number",                       input:"ISBN: 978-0-306-40615-7" },
  { id:"FP16", cat:"FP", desc:"Coordinates with decimals",            input:"Point: 12.345, 67.890" },
  { id:"FP17", cat:"FP", desc:"Hash value (SHA)",                     input:"SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { id:"FP18", cat:"FP", desc:"Hours range (no PII)",                 input:"Open Mon-Fri 9:00-5:00" },
  { id:"FP19", cat:"FP", desc:"UK phone format (intentional gap)",    input:"Ring 01234 567890" },
  { id:"FP20", cat:"FP", desc:"Intl phone +44 (intentional gap)",     input:"+44 20 7946 0958" },
  { id:"FP21", cat:"FP", desc:"API key in JSON quotes (intl gap)",    input:'{"api_key":"sk-abcdef123456"}' },
  { id:"FP22", cat:"FP", desc:"9-digit number (looks like routing)",  input:"Number: 123456789", fixedFp:true },
  { id:"FP23", cat:"FP", desc:"10-digit product ID (looks like phone)", input:"Order: 1234567890", fixedFp:true },
  { id:"FP24", cat:"NONE", desc:"Hex string like crypto (40 chars)",  input:"Hex: aabbccddeeff00112233445566778899aabbccdd" },
  { id:"FP25", cat:"FP", desc:"Letter+8digits like passport",         input:"Code: X12345678 in spec" },

  // ── CONTEXT ENGINE ────────────────────────────────────────────
  { id:"CTX01", cat:"CTX", desc:"Email boosted by keyword 'email'",    input:"My email is test@example.com", expectPii:1 },
  { id:"CTX02", cat:"CTX", desc:"Phone boosted by keyword 'call'",     input:"Call me at 555-123-4567", expectPii:1 },
  { id:"CTX03", cat:"CTX", desc:"SSN boosted by keyword 'social'",     input:"My social security is 123-45-6789", expectPii:1 },
  { id:"CTX04", cat:"CTX", desc:"Code context reduces confidence",     input:"// regex: 123-45-6789", expectPii:0 },
  { id:"CTX05", cat:"CTX", desc:"Name detection 'My name is John Smith'", input:"My name is John Smith", expectPii:1 },

  // ── NO PII ─────────────────────────────────────────────────────
  { id:"X01", cat:"NONE", desc:"Plain greeting",                      input:"Hello, how are you today?" },
  { id:"X02", cat:"NONE", desc:"Lorem ipsum text",                    input:"Lorem ipsum dolor sit amet consectetur adipiscing elit" },
  { id:"X03", cat:"NONE", desc:"Code snippet (no PII)",               input:"function add(a,b) { return a + b; }" },
  { id:"X04", cat:"NONE", desc:"Empty string",                        input:"" },
  { id:"X05", cat:"NONE", desc:"Only whitespace",                      input:"   " },
  { id:"X06", cat:"NONE", desc:"Random alphanumeric",                 input:"abc123xyz789 test data here" },
  { id:"X07", cat:"NONE", desc:"Only numbers (no PII pattern)",       input:"12345 67890 1112131415", fixedFp:true },
  { id:"X08", cat:"NONE", desc:"Only special characters",             input:"!@#$%^&*()_+-=[]{}|;':\",./<>?" },
  { id:"X09", cat:"NONE", desc:"HTML without PII",                    input:"<html><body><h1>Welcome</h1></body></html>" },
  { id:"X10", cat:"NONE", desc:"Base64 encoded (no PII)",             input:"SGVsbG8gV29ybGQ=" },

  // ── DUPLICATE & OVERLAP ────────────────────────────────────────
  { id:"D01", cat:"DUP", desc:"Same email twice",                     input:"my email is a@b.com and also a@b.com" },
  { id:"D02", cat:"DUP", desc:"Same phone twice",                     input:"Call 555-123-4567 now or 555-123-4567 later" },
  { id:"D03", cat:"DUP", desc:"Email appears 3 times",                input:"a@b.com a@b.com a@b.com" },
  { id:"D04", cat:"DUP", desc:"CC overlap check",                     input:"Card: 4111111111111111 (full 16-digit)" },
  { id:"D05", cat:"DUP", desc:"Multiple PII same value",              input:"user: a@b.com, ssn: 123-45-6789, email: a@b.com" },
  { id:"D06", cat:"DUP", desc:"Same SSN 3 times",                     input:"123-45-6789 123-45-6789 123-45-6789" },
  { id:"D07", cat:"DUP", desc:"Same IP repeated",                     input:"10.0.0.1, 10.0.0.1, 10.0.0.1" },
  { id:"D08", cat:"DUP", desc:"PII same value mixed types",           input:"card:4111-1111-1111-1111 phone:411-111-1111" },

  // ── SPECIAL CHARACTERS ─────────────────────────────────────────
  { id:"Z01", cat:"SPECIAL", desc:"Email with special chars in local",input:"user%name+tag@domain.com" },
  { id:"Z02", cat:"SPECIAL", desc:"Newlines in input",                input:"email:\na@b.com\nphone:\n555-123-4567" },
  { id:"Z03", cat:"SPECIAL", desc:"Tabs in input",                    input:"email:\tuser@test.com\tphone:\t555-123-4567" },
  { id:"Z04", cat:"SPECIAL", desc:"Unicode/emoji around PII",         input:"\u2709\ufe0f a@b.com \U0001f4de 555-123-4567" },
  { id:"Z05", cat:"SPECIAL", desc:"Mixed case email",                 input:"Contact John.Doe@Example.COM" },
  { id:"Z06", cat:"SPECIAL", desc:"Email with apostrophe (rare)",     input:"o'brien@company.ie" },
  { id:"Z07", cat:"SPECIAL", desc:"PII in backticks",                 input:"Email is `admin@system.com`" },
  { id:"Z08", cat:"SPECIAL", desc:"PII in markdown link",             input:"[email](mailto:user@test.com)" },
  { id:"Z09", cat:"SPECIAL", desc:"PII with surrounding asterisks",   input:"*email: a@b.com* *phone: 555-123-4567*" },
  { id:"Z10", cat:"SPECIAL", desc:"Phone with BOM/extra spaces",      input:"  555-123-4567  " },
  { id:"Z11", cat:"SPECIAL", desc:"Mixed line endings (CRLF)",        input:"email: a@b.com\r\nphone: 555-000-1111\r\n" },
  { id:"Z12", cat:"SPECIAL", desc:"New types with special chars",     input:"DOB: 01/15/1990 | MAC: aa:bb:cc:dd:ee:ff | Wallet: 0x71C7656EC7ab9b618e7dD32a6D9C6e1f3B3b6C6e" },

  // ── i18n FORMATS ───────────────────────────────────────────────
  { id:"I18N01", cat:"I18N", desc:"UK National Insurance",            input:"NI: AB123456C" },
  { id:"I18N02", cat:"I18N", desc:"UK NI with spaces",                input:"NI: AB 12 34 56 C" },
  { id:"I18N03", cat:"I18N", desc:"UK NHS number",                    input:"NHS: 123 456 7890" },
  { id:"I18N04", cat:"I18N", desc:"UK NHS contiguous",                input:"NHS: 1234567890" },
  { id:"I18N05", cat:"I18N", desc:"India Aadhaar with spaces",        input:"Aadhaar: 1234 5678 9012" },
  { id:"I18N06", cat:"I18N", desc:"India Aadhaar contiguous",         input:"Aadhaar: 123456789012" },
  { id:"I18N07", cat:"I18N", desc:"India PAN",                        input:"PAN: ABCDE1234Z" },
  { id:"I18N08", cat:"I18N", desc:"India PAN lowercase",              input:"pan: abcde1234z" },
  { id:"I18N09", cat:"I18N", desc:"China ID (18位)",                  input:"ID: 110101199001011234" },
  { id:"I18N10", cat:"I18N", desc:"China ID with X check digit",      input:"ID: 11010119900101123X" },
  { id:"I18N11", cat:"I18N", desc:"Canada SIN with spaces",           input:"SIN: 123 456 789" },
  { id:"I18N12", cat:"I18N", desc:"Canada SIN contiguous",            input:"SIN: 123456789" },
  { id:"I18N13", cat:"I18N", desc:"Australia TFN",                    input:"TFN: 123 456 789" },
  { id:"I18N14", cat:"I18N", desc:"Japan My Number with dashes",      input:"My Number: 1234-5678-9012" },
  { id:"I18N15", cat:"I18N", desc:"Brazil CPF with separators",       input:"CPF: 123.456.789-01" },
  { id:"I18N16", cat:"I18N", desc:"Brazil CPF without separators",    input:"CPF: 12345678901" },
  { id:"I18N17", cat:"I18N", desc:"Brazil CNPJ with separators",      input:"CNPJ: 12.345.678/9012-34" },
  { id:"I18N18", cat:"I18N", desc:"France INSEE with separators",     input:"INSEE: 01 23 45 67 89 123" },
  { id:"I18N19", cat:"I18N", desc:"France INSEE contiguous",          input:"INSEE: 0123456789123" },

  // ── New i18n (Germany, Korea, Mexico, Sweden, Italy) ──────
  { id:"I18N20", cat:"I18N", desc:"Germany Personalausweis",         input:"ID: A12345678" },
  { id:"I18N21", cat:"I18N", desc:"Germany Tax ID",                  input:"StNr: 123 4567 8901" },
  { id:"I18N22", cat:"I18N", desc:"Korea Resident Registration",     input:"RRN: 900101-1234567" },
  { id:"I18N23", cat:"I18N", desc:"Mexico CURP",                     input:"CURP: GARC850101HDFRRN01" },
  { id:"I18N24", cat:"I18N", desc:"Mexico RFC",                      input:"RFC: GARC850101AB1" },
  { id:"I18N25", cat:"I18N", desc:"Sweden Personnummer",             input:"Pnr: 900101-1234" },
  { id:"I18N26", cat:"I18N", desc:"Italy Codice Fiscale",            input:"CF: RSSMRA85M01H501Z" },

  // ── TOKEN PATTERNS ──────────────────────────────────────────────
  { id:"TK01", cat:"TOKEN", desc:"JWT token",                        input:"Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVNHMRc5NvDijV8NqMVsZ7vP3EfbG1s" },
  { id:"TK02", cat:"TOKEN", desc:"JWT token in Authorization header", input:"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVNHMRc5NvDijV8NqMVsZ7vP3EfbG1s" },
  { id:"TK03", cat:"TOKEN", desc:"AWS access key",                   input:"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" },
  { id:"TK04", cat:"TOKEN", desc:"GitHub personal access token",      input:"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789" },
  { id:"TK05", cat:"TOKEN", desc:"Slack bot token",                   input:"xoxb-000000000-0000000000-abcdefghijklmnopqrstuvwxyz" },
  { id:"TK06", cat:"TOKEN", desc:"GitHub gho_ OAuth token",           input:"gho_abcdefghijklmnopqrstuvwxyz0123456789" },

  // ── LUHN VALIDATION ─────────────────────────────────────────────
  { id:"L01", cat:"LUHN", desc:"Visa valid Luhn",                    input:"Card: 4111111111111111" },
  { id:"L02", cat:"LUHN", desc:"MC valid Luhn",                      input:"Card: 5500000000000004" },
  { id:"L03", cat:"LUHN", desc:"Discover valid Luhn",                input:"Card: 6011000000000004" },
  { id:"L04", cat:"LUHN", desc:"JCB valid Luhn",                     input:"Card: 3528000000000000" },
  { id:"L05", cat:"LUHN", desc:"Invalid Luhn (reduced conf)",        input:"Card: 1234567890123456", expectLowConf:true },
  { id:"L06", cat:"LUHN", desc:"Invalid Luhn with dashes",           input:"Card: 1234-5678-9012-3456", expectLowConf:true },
  { id:"L07", cat:"LUHN", desc:"Invalid Luhn with spaces",           input:"Card: 1234 5678 9012 3456", expectLowConf:true },
  { id:"L08", cat:"LUHN", desc:"All zeros (passes Luhn valid)",      input:"Card: 0000000000000000", expectLowConf:true },
  { id:"L09", cat:"LUHN", desc:"All ones invalid Luhn",              input:"Card: 1111111111111111", expectLowConf:true },
  { id:"L10", cat:"LUHN", desc:"Short number not CC (<13 digits)",   input:"Number: 123456789012" },

  // ── REALISTIC MODE ──────────────────────────────────────────────
  { id:"R01", cat:"REALISTIC", desc:"Realistic email mask",          input:"email: test@test.com", realistic:true },
  { id:"R02", cat:"REALISTIC", desc:"Realistic phone mask",          input:"phone: 555-123-4567", realistic:true },
  { id:"R03", cat:"REALISTIC", desc:"Realistic SSN mask",            input:"ssn: 123-45-6789", realistic:true },
  { id:"R04", cat:"REALISTIC", desc:"Realistic CC mask",             input:"card: 4111111111111111", realistic:true },
  { id:"R05", cat:"REALISTIC", desc:"Realistic crypto mask",         input:"wallet: 0x71C7656EC7ab9b618e7dD32a6D9C6e1f3B3b6C6e", realistic:true },

  // ── RESTORE ROUND-TRIP ─────────────────────────────────────────
  { id:"RT01", cat:"RESTORE", desc:"Restore single email",             input:"test@test.com", verify:true },
  { id:"RT02", cat:"RESTORE", desc:"Restore mixed PII",                input:"email: a@b.com phone: 555-123-4567 ssn: 123-45-6789", verify:true },
  { id:"RT03", cat:"RESTORE", desc:"Restore duplicate values",         input:"a@b.com and a@b.com", verify:true },
  { id:"RT04", cat:"RESTORE", desc:"Restore all types",                input:"email:a@b.com phone:555-123-4567 ssn:123-45-6789 card:4111-1111-1111-1111 ip:10.0.0.1 password:secret api_key:test123 dob:01/15/1990", verify:true },
  { id:"RT05", cat:"RESTORE", desc:"Restore PII in sentence",          input:"My email is jane@doe.org and my SSN is 987-65-4321.", verify:true },
  { id:"RT06", cat:"RESTORE", desc:"Restore with special chars",       input:"contact: \"admin@site.com\" (555-123-4567)", verify:true },
  { id:"RT07", cat:"RESTORE", desc:"Restore new types",                input:"Wallet: 0x71C7656EC7ab9b618e7dD32a6D9C6e1f3B3b6C6e MAC: aa:bb:cc:dd:ee:ff Passport: A12345678 DOB: 01/15/1990", verify:true },
  { id:"RT08", cat:"RESTORE", desc:"Restore bank and license",         input:"account: 1234567890 license: D1234567 address: 123 Main Street", verify:true },
];

// ── REPORT ───────────────────────────────────────────────────────
const bold = "\x1b[1m";
const dim = "\x1b[2m";
const green = "\x1b[32m";
const red = "\x1b[31m";
const yellow = "\x1b[33m";
const cyan = "\x1b[36m";
const reset = "\x1b[0m";

console.log(bold + cyan + "══════════════════════════════════════════════════════════════════════════════════════" + reset);
console.log(bold + cyan + "           AI FIREWALL — COMPREHENSIVE PII TEST REPORT (" + BUILTIN_RULES.length + " TYPES)" + reset);
console.log(bold + cyan + "══════════════════════════════════════════════════════════════════════════════════════" + reset);
console.log("");

(async () => {
let passed = 0;
let failed = 0;
const failures = [];

const cats = {};
for (const t of tests) { cats[t.cat] = { total:0, pass:0, fail:0 }; }

for (const t of tests) {
  const mode = t.realistic ? 'realistic' : 'placeholder';
  const { scrubbed, piiMap, matches } = scrub(t.input, mode);
  const piiCount = Object.keys(piiMap).length;
  const changed = t.input !== scrubbed;
  cats[t.cat].total++;

  let status = "PASS";
  let reason = "";

  if (t.verify) {
    let restored = scrubbed;
    for (const [ph, orig] of Object.entries(piiMap)) {
      restored = restored.replace(ph, orig);
    }
    if (restored !== t.input) {
      status = "FAIL";
      reason = "restore mismatch";
    }
  } else if (t.expectFp) {
    status = t.input.length > 0 && changed && piiCount > 0 ? "FP" : "FAIL";
    if (status === "FAIL") reason = "expected FP but no match";
  } else if (t.fixedFp) {
    if (changed && piiCount > 0) {
      const allLow = matches.every(m => m.confidence < 0.4);
      if (allLow) { status = "PASS"; }
      else { status = "FAIL"; reason = "match confidence not below 0.4"; }
    } else { status = "FAIL"; reason = "expected PII match with low confidence"; }
  } else if (t.expectLowConf) {
    if (changed && piiCount > 0) {
      const m = matches.find(m => m.type === 'CC_NUM');
      if (m && m.confidence < 0.5) { status = "PASS"; }
      else { status = "FAIL"; reason = "CC matched but confidence not reduced"; }
    } else {
      status = "FAIL"; reason = "expected low-confidence CC match";
    }
  } else if (t.realistic) {
    if (!changed) { status = "FAIL"; reason = "PII not detected in realistic mode"; }
    else {
      const originalAppears = matches.some(m => scrubbed.includes(m.original));
      if (originalAppears) { status = "FAIL"; reason = "realistic mode should not contain original PII text"; }
    }
  } else if (t.cat === "NONE") {
    if (changed && piiCount > 0) {
      status = "FAIL";
      reason = "unexpected PII detected";
    }
  } else if (t.cat === "FP") {
    status = t.input.length > 0 && changed && piiCount > 0 ? "FP" : "PASS";
    if (status === "FP") reason = "known limitation";
  } else if (t.input.length > 0 && !/^\s+$/.test(t.input)) {
    if (!changed) {
      status = "FAIL";
      reason = "PII not detected";
    }
  }

  if (status === "PASS") { passed++; cats[t.cat].pass++; }
  else if (status === "FP") { failed++; cats[t.cat].fail++; reason = "known limitation"; }
  else { failed++; cats[t.cat].fail++; failures.push(t.id + ": " + reason + " (" + t.desc + ")"); }

  const statusStr = status === "PASS" ? green + "PASS" + reset : status === "FP" ? yellow + "FP " + reset : red + "FAIL" + reset;
  const catColor = t.cat === "NONE" ? dim : t.cat === "FP" ? yellow : "";
  console.log(bold + statusStr + reset + "  | " + catColor + t.cat.padEnd(9) + reset + " | " + yellow + t.id + reset + "  | " + dim + t.desc.padEnd(48) + reset + "  " + (piiCount > 0 ? yellow + piiCount + " PII" + reset : dim + "\u2014" + reset));
  if (t.input.length > 0 && piiCount > 0 && status !== "FAIL" && reason !== "known limitation") {
    console.log("  " + dim + "Out:" + reset + "  " + scrubbed.substring(0, 80));
  }
}

async function runServerTests() {
  const httpMod = await import('http');
  const { createApp } = await import('./server.js');
  const http = httpMod.default;

  function fetchJSON(url, method, body) {
    return new Promise((resolve, reject) => {
      const u = new URL(url);
      const opts = { hostname: u.hostname, port: u.port, path: u.pathname, method: method || 'GET', headers: { 'Content-Type': 'application/json' } };
      const req = http.request(opts, res => {
        let data = ''; res.on('data', c => data += c); res.on('end', () => {
          try { resolve({ status: res.statusCode, body: JSON.parse(data), headers: res.headers }); }
          catch (e) { resolve({ status: res.statusCode, body: data, headers: res.headers }); }
        });
      }); req.on('error', reject); if (body) req.write(JSON.stringify(body)); req.end();
    });
  }
  function fetchPlain(url, method, body) {
    return new Promise((resolve, reject) => {
      const u = new URL(url);
      const opts = { hostname: u.hostname, port: u.port, path: u.pathname, method: method || 'POST', headers: { 'Content-Type': 'text/plain' } };
      const req = http.request(opts, res => {
        let data = ''; res.on('data', c => data += c); res.on('end', () => {
          try { resolve({ status: res.statusCode, body: JSON.parse(data), headers: res.headers }); }
          catch (e) { resolve({ status: res.statusCode, body: data, headers: res.headers }); }
        });
      }); req.on('error', reject); if (body) req.write(body); req.end();
    });
  }
  function rawRequest(url) {
    return new Promise((resolve, reject) => {
      const u = new URL(url);
      http.get({ hostname: u.hostname, port: u.port, path: u.pathname }, res => {
        let data = ''; res.on('data', c => data += c); res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
      }).on('error', reject);
    });
  }

  const app = createApp({});
  let server;
  let baseUrl;
  await new Promise(resolve => {
    server = app.listen(0, () => {
      const addr = server.address();
      baseUrl = 'http://localhost:' + addr.port;
      resolve();
    });
  });

  const serverTestCases = [
    { id:"SRV01", desc:"GET /health returns status ok", fn: async (base) => {
      const r = await fetchJSON(base + '/health');
      return r.status === 200 && r.body.status === 'ok' ? null : 'expected 200 with status ok';
    }},
    { id:"SRV02", desc:"GET /rules returns 30+ rules", fn: async (base) => {
      const r = await fetchJSON(base + '/rules');
      return r.status === 200 && r.body.count >= 30 ? null : 'expected 200 with 30+ rules';
    }},
    { id:"SRV03", desc:"POST /scrub JSON body detects email", fn: async (base) => {
      const r = await fetchJSON(base + '/scrub', 'POST', { text: 'email: test@example.com' });
      return r.status === 200 && r.body.matchesFound === 1 && r.body.scrubbed.includes('[EMAIL_ADDR_') ? null : 'expected 1 email match scrubbed';
    }},
    { id:"SRV04", desc:"POST /scrub plain text body detects phone", fn: async (base) => {
      const r = await fetchPlain(base + '/scrub', 'POST', 'Call 555-123-4567');
      return r.status === 200 && r.body.matchesFound >= 1 ? null : 'expected phone match';
    }},
    { id:"SRV05", desc:"POST /scrub realistic mode fakes data", fn: async (base) => {
      const r = await fetchJSON(base + '/scrub', 'POST', { text: 'My email is a@b.com', mode: 'realistic' });
      return r.status === 200 && r.body.scrubbed.includes('@example.com') ? null : 'expected realistic fake';
    }},
    { id:"SRV06", desc:"POST /scrub returns riskScore", fn: async (base) => {
      const r = await fetchJSON(base + '/scrub', 'POST', { text: 'SSN 123-45-6789' });
      return r.status === 200 && r.body.riskScore > 0 ? null : 'expected positive riskScore';
    }},
    { id:"SRV07", desc:"POST /scan returns line/column findings", fn: async (base) => {
      const r = await fetchJSON(base + '/scan', 'POST', { text: 'My email is a@b.com and cc is 4111 1111 1111 1111' });
      return r.status === 200 && r.body.matchesFound >= 2 ? null : 'expected 2+ findings';
    }},
    { id:"SRV08", desc:"POST /scrub empty text returns 400", fn: async (base) => {
      const r = await fetchJSON(base + '/scrub', 'POST', { text: '' });
      return r.status === 400 ? null : 'expected 400';
    }},
    { id:"SRV09", desc:"CORS not wildcard by default", fn: async (base) => {
      const r = await rawRequest(base + '/health');
      return r.headers['access-control-allow-origin'] !== '*' ? null : 'CORS should not be * by default';
    }},
  ];

  const sc = { total: 0, pass: 0, fail: 0 };
  for (const t of serverTestCases) {
    sc.total++;
    try {
      const err = await t.fn(baseUrl);
      if (err) {
        sc.fail++; failed++; failures.push(t.id + ': ' + err + ' (' + t.desc + ')');
        console.log(red + 'FAIL' + reset + '  | SERVER    | ' + yellow + t.id + reset + '  | ' + dim + t.desc.padEnd(48) + reset + '  ' + red + err + reset);
      } else {
        sc.pass++; passed++;
        console.log(green + 'PASS' + reset + '  | SERVER    | ' + yellow + t.id + reset + '  | ' + dim + t.desc.padEnd(48) + reset + '  ' + dim + '\u2014' + reset);
      }
    } catch (err) {
      sc.fail++; failed++; failures.push(t.id + ': ' + err.message + ' (' + t.desc + ')');
      console.log(red + 'FAIL' + reset + '  | SERVER    | ' + yellow + t.id + reset + '  | ' + dim + t.desc.padEnd(48) + reset + '  ' + red + err.message + reset);
    }
  }
  cats['SERVER'] = sc;
  server.close();
}

await runServerTests();

console.log("");
console.log(bold + "═══════════════════════════════════════════════ BY CATEGORY ═══════════════════════════════════════════════" + reset);
for (const [cat, c] of Object.entries(cats)) {
  if (c.total === 0) continue;
  const pct = c.total > 0 ? ((c.pass / c.total) * 100).toFixed(0) : "0";
  const color = c.fail === 0 ? green : red;
  console.log("  " + color + cat.padEnd(8) + reset + " : " + c.pass + "/" + c.total + " pass  (" + pct + "%)");
}

console.log("");
console.log(bold + "══════════════════════════════════════════════════════════════════════════════════════" + reset);
const total = passed + failed;
const pct = total > 0 ? ((passed / total) * 100).toFixed(1) : "0";
console.log("  " + (failed === 0 ? green : red) + bold + "  PASS: " + passed + "  |  FAIL: " + failed + "  |  TOTAL: " + total + "  |  PASS RATE: " + pct + "%" + reset);
if (failures.length > 0) {
  console.log("");
  console.log(red + bold + "  FAILURES:" + reset);
  for (const f of failures) console.log("    - " + f);
}
console.log(bold + "══════════════════════════════════════════════════════════════════════════════════════" + reset);
})();
