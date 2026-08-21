(function() {
  'use strict';

  var indicator = document.createElement('div');
  indicator.id = 'ai-firewall-indicator';
  Object.assign(indicator.style, {
    position: 'fixed', top: '0', left: '0', zIndex: '2147483647',
    background: '#6366f1', color: 'white', padding: '8px 16px',
    fontFamily: 'monospace', fontSize: '12px', fontWeight: 'bold',
    boxShadow: '0 2px 10px rgba(0,0,0,0.3)', borderRadius: '0 0 8px 0',
    transition: 'all 0.2s ease'
  });
  indicator.textContent = '[AI Firewall] Initializing...';
  document.documentElement.appendChild(indicator);

  var maskMode = 'placeholder';
  var isEnabled = true;
  var enableSound = true;
  var blockedSites = [];
  var piiMap = {};
  var undoStack = [];
  var highlightOverlay = null;
  var stats = { requests: 0, piiDetected: 0, types: {} };

  var patterns = [
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

  function luhnCheck(num) {
    var digits = num.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    var clean = num.replace(/[-\s]/g, '');
    if (/^0+$/.test(clean)) return false;
    var sum = 0, alt = false;
    for (var i = digits.length - 1; i >= 0; i--) {
      var n = parseInt(digits[i], 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }

  var CONTEXT_KEYWORDS_BOOST = {
    email: ['email', 'e-mail', 'mail', 'inbox', 'address'],
    phone: ['phone', 'call', 'mobile', 'cell', 'number', 'dial', 'contact'],
    ssn: ['ssn', 'social', 'security', 'tax', 'identity'],
    cc: ['credit', 'card', 'payment', 'billing', 'visa', 'mastercard', 'amex'],
    address: ['address', 'street', 'location', 'live', 'residence', 'home'],
    dob: ['birth', 'born', 'dob', 'birthday', 'age'],
    password: ['password', 'passwd', 'pass', 'secret', 'credential', 'auth'],
    apikey: ['api', 'key', 'token', 'secret', 'credential'],
    bank: ['bank', 'account', 'routing', 'iban', 'swift', 'financial'],
    passport: ['passport', 'travel', 'visa'],
    license: ['license', 'driver', 'dl', 'driving'],
    crypto: ['wallet', 'crypto', 'bitcoin', 'ethereum', '0x'],
  };

  var CONTEXT_KEYWORDS_REDUCE = {
    phone: ['example', 'fake', 'dummy', 'test', 'sample', '000-000'],
    email: ['example', 'fake', 'dummy', 'test', 'sample', '@test'],
    ssn: ['000', '123', 'example', 'fake'],
    cc: ['4111', '0000', 'example', 'test'],
  };

  function getContextWindow(text, matchIndex, matchLength, windowSize) {
    windowSize = windowSize || 60;
    var start = Math.max(0, matchIndex - windowSize);
    var end = Math.min(text.length, matchIndex + matchLength + windowSize);
    return text.substring(start, end).toLowerCase();
  }

  function isPartOfLongerToken(text, matchIndex, matchLength) {
    var beforeChar = matchIndex > 0 ? text[matchIndex - 1] : '';
    var afterChar = matchIndex + matchLength < text.length ? text[matchIndex + matchLength] : '';
    var wordCharRe = /[a-zA-Z0-9_]/;
    if ((beforeChar && wordCharRe.test(beforeChar)) || (afterChar && wordCharRe.test(afterChar))) {
      return true;
    }
    return false;
  }

  function contextScore(pattern, text, matchIndex, matchValue, baseConf) {
    var conf = baseConf;
    var label = pattern.label.toLowerCase();
    var id = pattern.id;
    var contextWindow = getContextWindow(text, matchIndex, matchValue.length);

    var boostWords = [];
    for (var key in CONTEXT_KEYWORDS_BOOST) {
      if (label.indexOf(key) !== -1 || id.indexOf(key) !== -1) {
        boostWords = CONTEXT_KEYWORDS_BOOST[key];
        break;
      }
    }
    if (boostWords.length > 0) {
      for (var i = 0; i < boostWords.length; i++) {
        if (contextWindow.indexOf(boostWords[i]) !== -1) {
          conf = Math.min(1.0, conf + 0.08);
          break;
        }
      }
    }

    var reduceWords = [];
    for (var key2 in CONTEXT_KEYWORDS_REDUCE) {
      if (label.indexOf(key2) !== -1 || id.indexOf(key2) !== -1) {
        reduceWords = CONTEXT_KEYWORDS_REDUCE[key2];
        break;
      }
    }
    if (reduceWords.length > 0) {
      for (var j = 0; j < reduceWords.length; j++) {
        if (contextWindow.indexOf(reduceWords[j]) !== -1) {
          conf = Math.max(0.1, conf - 0.15);
          break;
        }
      }
    }

    if (isPartOfLongerToken(text, matchIndex, matchValue.length)) {
      conf = Math.max(0.1, conf - 0.12);
    }

    return Math.round(conf * 100) / 100;
  }

  function fakeFor(label) {
    var fakers = {
      EMAIL_ADDR: 'user' + (Math.floor(Math.random() * 9000) + 1000) + '@example.com',
      PHONE_NUM: '555-' + (Math.floor(Math.random() * 900) + 100) + '-' + (Math.floor(Math.random() * 9000) + 1000),
      CC_NUM: '4111' + Array(12).fill(0).map(function(){return Math.floor(Math.random()*10)}).join(''),
      SSN_NUM: (Math.floor(Math.random() * 900) + 100) + '-' + (Math.floor(Math.random() * 90) + 10) + '-' + (Math.floor(Math.random() * 9000) + 1000),
      IP_ADDR: Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256),
      PWD_VAL: '[REDACTED]',
      APIKEY: 'sk-' + Array(24).fill(0).map(function(){return 'abcdef0123456789'[Math.floor(Math.random()*16)]}).join(''),
      CRYPTO: '0x' + Array(40).fill(0).map(function(){return 'abcdef0123456789'[Math.floor(Math.random()*16)]}).join(''),
      MAC_ADDR: Array(6).fill(0).map(function(){return ('0'+Math.floor(Math.random()*256).toString(16)).slice(-2)}).join(':'),
      DOB: (Math.floor(Math.random() * 12) + 1).toString().padStart(2,'0') + '/' + (Math.floor(Math.random() * 28) + 1).toString().padStart(2,'0') + '/' + (Math.floor(Math.random() * 30 + 1970)),
      PASSPORT: String.fromCharCode(65 + Math.floor(Math.random() * 26)) + Math.floor(Math.random() * 100000000).toString().padStart(8, '0'),
      LICENSE: 'DL' + Math.floor(Math.random() * 10000000).toString().padStart(7, '0'),
      ADDRESS: Math.floor(Math.random() * 9999) + 1 + ' ' + ['Main','Oak','Elm','Pine','Maple','Cedar'][Math.floor(Math.random()*6)] + ' ' + ['Street','Avenue','Road','Drive','Lane'][Math.floor(Math.random()*5)],
      BANK_ACCT: '****' + Math.floor(Math.random() * 100000).toString().padStart(5, '0'),
      ROUTING: Math.floor(Math.random() * 1000000000).toString().padStart(9, '0'),
      UK_NI: 'AB' + Math.floor(Math.random() * 1000000).toString().padStart(6, '0') + 'C',
      UK_NHS: Math.floor(Math.random() * 10000000000).toString().padStart(10, '0'),
      IN_AADHAAR: Math.floor(Math.random() * 10000).toString().padStart(4,'0') + ' ' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + ' ' + Math.floor(Math.random() * 10000).toString().padStart(4,'0'),
      IN_PAN: 'ABCDE' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + 'Z',
      CN_ID: Math.floor(Math.random() * 100000000000000000).toString().padStart(18, '0'),
      CA_SIN: Math.floor(Math.random() * 1000000000).toString().padStart(9, '0'),
      JWT: 'eyJhbGciOiJIUzI1NiJ9.' + Array(43).fill(0).map(function(){return 'abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random()*64)]}).join('') + '.' + Array(43).fill(0).map(function(){return 'abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random()*64)]}).join(''),
      AWS_KEY: 'AKIA' + Array(16).fill(0).map(function(){return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random()*36)]}).join(''),
      GITHUB: 'ghp_' + Array(36).fill(0).map(function(){return 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random()*62)]}).join(''),
      SLACK: 'xoxb-' + Array(16).fill(0).map(function(){return 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random()*36)]}).join('') + '-' + Array(10).fill(0).map(function(){return '0123456789'[Math.floor(Math.random()*10)]}).join(''),
      AU_TFN: Math.floor(Math.random() * 1000000000).toString().padStart(9, '0'),
      JP_MY: Math.floor(Math.random() * 10000).toString().padStart(4,'0') + '-' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + '-' + Math.floor(Math.random() * 10000).toString().padStart(4,'0'),
      BR_CPF: Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '.' + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '.' + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '-' + Math.floor(Math.random() * 100).toString().padStart(2,'0'),
      BR_CNPJ: Math.floor(Math.random() * 100).toString().padStart(2,'0') + '.' + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '.' + Math.floor(Math.random() * 1000).toString().padStart(3,'0') + '/' + Math.floor(Math.random() * 10000).toString().padStart(4,'0') + '-' + Math.floor(Math.random() * 100).toString().padStart(2,'0'),
      FR_INSEE: Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 100).toString().padStart(2,'0') + ' ' + Math.floor(Math.random() * 1000).toString().padStart(3,'0'),
    };
    return fakers[label] || '[FAKE_' + label + ']';
  }

  function detect(text) {
    var found = [];
    patterns.forEach(function(p) {
      if (p.regex.test(text)) found.push(p.name + '(' + p.label + ')');
      p.regex.lastIndex = 0;
    });
    return found;
  }

  function mask(text) {
    var result = text;
    piiMap = {};
    var n = 1;

    patterns.forEach(function(p) {
      var regex = new RegExp(p.regex.source, p.regex.flags);
      var lastIndex = 0;
      var parts = [];
      var match;
      while ((match = regex.exec(text)) !== null) {
        var conf = p.conf;
        if (p.luhn) {
          var clean = match[0].replace(/[-\s]/g, '');
          if (clean.length >= 13 && clean.length <= 19) {
            conf = luhnCheck(clean) ? 0.95 : 0.3;
          }
        }
        conf = contextScore(p, text, match.index, match[0], conf);
        var key = '[' + p.label + '_' + n + ']';
        var replacement = maskMode === 'realistic' ? fakeFor(p.label) : key;
        piiMap[key] = { original: match[0], replacement: replacement, confidence: conf, type: p.label };
        stats.types[p.label] = (stats.types[p.label] || 0) + 1;
        parts.push(text.substring(lastIndex, match.index));
        parts.push(replacement);
        lastIndex = match.index + match[0].length;
        n++;
      }
      if (parts.length > 0) {
        parts.push(text.substring(lastIndex));
        result = parts.join('');
      }
    });

    return result;
  }

  var TYPE_COLORS = {
    EMAIL_ADDR: '#ef4444', PHONE_NUM: '#f59e0b', SSN_NUM: '#ef4444',
    CC_NUM: '#dc2626', IP_ADDR: '#6366f1', APIKEY: '#8b5cf6',
    PWD_VAL: '#dc2626', CRYPTO: '#6366f1', MAC_ADDR: '#6366f1',
    DOB: '#f59e0b', PASSPORT: '#f59e0b', LICENSE: '#f59e0b',
    ADDRESS: '#f59e0b', BANK_ACCT: '#dc2626', ROUTING: '#f59e0b',
    UK_NI: '#f59e0b', UK_NHS: '#f59e0b', IN_AADHAAR: '#f59e0b',
    IN_PAN: '#f59e0b', CN_ID: '#f59e0b', CA_SIN: '#f59e0b',
    JWT: '#8b5cf6', AWS_KEY: '#8b5cf6', GITHUB: '#8b5cf6', SLACK: '#8b5cf6',
    AU_TFN: '#f59e0b', JP_MY: '#f59e0b', BR_CPF: '#f59e0b',
    BR_CNPJ: '#f59e0b', FR_INSEE: '#f59e0b',
  };

  function detectPII(text) {
    var results = [];
    patterns.forEach(function(p) {
      var regex = new RegExp(p.regex.source, p.regex.flags);
      var m;
      while ((m = regex.exec(text)) !== null) {
        var conf = contextScore(p, text, m.index, m[0], p.conf);
        results.push({ type: p.label, name: p.name, value: m[0], index: m.index, conf: conf });
      }
    });
    return results.sort(function(a, b) { return a.index - b.index; });
  }

  function createHighlightOverlay(input) {
    if (highlightOverlay) highlightOverlay.remove();
    highlightOverlay = document.createElement('div');
    var rect = input.getBoundingClientRect();
    Object.assign(highlightOverlay.style, {
      position: 'absolute', left: rect.left + 'px', top: rect.top + 'px',
      width: rect.width + 'px', height: rect.height + 'px',
      pointerEvents: 'none', zIndex: '2147483646',
      overflow: 'hidden', fontFamily: getComputedStyle(input).fontFamily,
      fontSize: getComputedStyle(input).fontSize,
      lineHeight: getComputedStyle(input).lineHeight,
      padding: getComputedStyle(input).padding,
      whiteSpace: 'pre-wrap', wordWrap: 'break-word',
      border: '2px solid transparent', borderRadius: getComputedStyle(input).borderRadius,
      boxSizing: 'border-box', color: 'transparent',
    });
    document.body.appendChild(highlightOverlay);
    return highlightOverlay;
  }

  function updateHighlight(input) {
    if (!highlightOverlay || !isEnabled) {
      if (highlightOverlay) highlightOverlay.style.borderColor = 'transparent';
      return;
    }
    var text = input.value || input.textContent || '';
    if (!text.trim()) {
      highlightOverlay.style.borderColor = 'transparent';
      highlightOverlay.innerHTML = '';
      return;
    }
    var pii = detectPII(text);
    if (pii.length === 0) {
      highlightOverlay.style.borderColor = 'transparent';
      highlightOverlay.innerHTML = '';
      return;
    }

    var maxConf = Math.max.apply(null, pii.map(function(p) { return p.conf; }));
    if (maxConf > 0.8) {
      highlightOverlay.style.borderColor = '#ef4444';
    } else if (maxConf > 0.6) {
      highlightOverlay.style.borderColor = '#f59e0b';
    } else {
      highlightOverlay.style.borderColor = '#6366f1';
    }

    var html = '';
    var lastIdx = 0;
    pii.forEach(function(p) {
      html += escapeHtml(text.substring(lastIdx, p.index));
      var color = TYPE_COLORS[p.type] || '#f59e0b';
      html += '<mark style="background:' + color + '22;color:' + color + ';border-bottom:2px solid ' + color + ';border-radius:2px;padding:0 1px;">' + escapeHtml(p.value) + '</mark>';
      lastIdx = p.index + p.value.length;
    });
    html += escapeHtml(text.substring(lastIdx));
    highlightOverlay.innerHTML = html;
  }

  function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function playNotificationSound() {
    if (!enableSound) return;
    try {
      var audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      var oscillator = audioCtx.createOscillator();
      var gainNode = audioCtx.createGain();
      oscillator.connect(gainNode);
      gainNode.connect(audioCtx.destination);
      oscillator.type = 'sine';
      oscillator.frequency.setValueAtTime(880, audioCtx.currentTime);
      oscillator.frequency.setValueAtTime(660, audioCtx.currentTime + 0.08);
      gainNode.gain.setValueAtTime(0.3, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.2);
      oscillator.start(audioCtx.currentTime);
      oscillator.stop(audioCtx.currentTime + 0.2);
    } catch (e) {}
  }

  function undoMask() {
    if (undoStack.length === 0) return false;
    var last = undoStack.pop();
    var input = last.input;
    if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
      input.value = last.original;
    } else {
      input.textContent = last.original;
    }
    input.dispatchEvent(new Event('input', { bubbles: true }));
    indicator.textContent = '[AI Firewall] Undone (' + undoStack.length + ' remaining)';
    indicator.style.background = '#8b5cf6';
    return true;
  }

  function saveStats() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['fw_stats'], function(data) {
        var existing = data.fw_stats || { requests: 0, piiDetected: 0, types: {} };
        existing.requests = (existing.requests || 0) + stats.requests;
        existing.piiDetected = (existing.piiDetected || 0) + stats.piiDetected;
        for (var t in stats.types) {
          existing.types[t] = (existing.types[t] || 0) + stats.types[t];
        }
        chrome.storage.local.set({ fw_stats: existing });
      });
    }
  }

  function findInputs() {
    var selectors = [
      'textarea[id*="prompt"]', 'textarea[id*="message"]', 'textarea[id*="input"]',
      'textarea[name*="prompt"]', 'textarea[name*="message"]',
      'textarea[placeholder*="message"]', 'textarea[placeholder*="Ask"]',
      'textarea[rows="4"]', 'textarea[rows="5"]', 'textarea',
      'div[contenteditable="true"][role="textbox"]', 'div[contenteditable="true"]',
      'input[type="text"]'
    ];
    for (var i = 0; i < selectors.length; i++) {
      var el = document.querySelector(selectors[i]);
      if (el && el.offsetParent !== null && el.clientWidth > 50) {
        return el;
      }
    }
    return null;
  }

  function attach(input) {
    if (input._aiFw) return;
    input._aiFw = true;

    indicator.textContent = '[AI Firewall] Input found';
    indicator.style.background = '#22c55e';

    var overlay = createHighlightOverlay(input);

    input.addEventListener('input', function() {
      if (!isEnabled) {
        indicator.textContent = '[AI Firewall] Disabled';
        indicator.style.background = '#6b7280';
        if (highlightOverlay) highlightOverlay.style.borderColor = 'transparent';
        return;
      }
      var text = input.value || input.textContent || '';
      var found = detect(text);
      updateHighlight(input);
      if (found.length > 0) {
        indicator.textContent = '[AI Firewall] PII: ' + found.join(',');
        indicator.style.background = '#f59e0b';
      } else {
        indicator.textContent = '[AI Firewall] Active';
        indicator.style.background = '#22c55e';
      }
    });

    input.addEventListener('keydown', function(e) {
      if (!isEnabled) return;

      if (e.key === 'z' && (e.ctrlKey || e.metaKey) && !e.shiftKey) {
        if (undoStack.length > 0) {
          e.preventDefault();
          e.stopPropagation();
          undoMask();
          return;
        }
      }

      if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
        var text = input.value || input.textContent || '';
        var masked = mask(text);
        if (Object.keys(piiMap).length > 0) {
          undoStack.push({ input: input, original: text, masked: masked });
          if (undoStack.length > 10) undoStack.shift();
          if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
            input.value = masked;
          } else {
            input.textContent = masked;
          }
          indicator.textContent = '[AI Firewall] Masked ' + Object.keys(piiMap).length + ' PII (Ctrl+Z to undo)';
          indicator.style.background = '#3b82f6';
          if (highlightOverlay) highlightOverlay.style.borderColor = '#22c55e';
          stats.requests++;
          stats.piiDetected += Object.keys(piiMap).length;
          saveStats();
          playNotificationSound();
        }
      }
    });

    input.addEventListener('focus', function() { updateHighlight(input); });
    input.addEventListener('blur', function() {
      if (highlightOverlay) highlightOverlay.style.borderColor = 'transparent';
    });
  }

  function check() {
    var input = findInputs();
    if (input) { attach(input); return true; }
    return false;
  }

  if (!check()) {
    setTimeout(check, 500);
    setTimeout(check, 1500);
    setTimeout(check, 3000);
  }
  setInterval(check, 5000);
  var observer = new MutationObserver(check);
  observer.observe(document.body, { childList: true, subtree: true });

  chrome.storage.local.get(['maskMode', 'isEnabled', 'enableSound', 'blockedSites'], function(r) {
    if (r.maskMode) maskMode = r.maskMode;
    if (r.isEnabled !== undefined) {
      isEnabled = r.isEnabled;
    }
    if (r.enableSound !== undefined) {
      enableSound = r.enableSound;
    }
    if (r.blockedSites) {
      blockedSites = r.blockedSites;
    }

    if (isSiteBlocked(window.location.hostname)) {
      isEnabled = false;
      indicator.textContent = '[AI Firewall] Disabled for this site';
      indicator.style.background = '#6b7280';
    } else {
      indicator.textContent = isEnabled ? '[AI Firewall] Ready' : '[AI Firewall] Disabled';
      indicator.style.background = isEnabled ? '#6366f1' : '#6b7280';
    }

    if (isEnabled) {
      setupResponseScanner();
    }
  });

  chrome.storage.onChanged.addListener(function(changes, area) {
    if (area === 'local') {
      if (changes.isEnabled !== undefined) {
        isEnabled = changes.isEnabled.newValue;
        if (isSiteBlocked(window.location.hostname)) {
          isEnabled = false;
          indicator.textContent = '[AI Firewall] Disabled for this site';
          indicator.style.background = '#6b7280';
        } else {
          indicator.textContent = isEnabled ? '[AI Firewall] Ready' : '[AI Firewall] Disabled';
          indicator.style.background = isEnabled ? '#6366f1' : '#6b7280';
        }
      }
      if (changes.maskMode !== undefined) {
        maskMode = changes.maskMode.newValue;
      }
      if (changes.enableSound !== undefined) {
        enableSound = changes.enableSound.newValue;
      }
      if (changes.blockedSites !== undefined) {
        blockedSites = changes.blockedSites.newValue || [];
        if (isSiteBlocked(window.location.hostname)) {
          isEnabled = false;
          indicator.textContent = '[AI Firewall] Disabled for this site';
          indicator.style.background = '#6b7280';
        }
      }
    }
  });

  var vpnEnabled = false;

  function loadVpnState() {
    chrome.storage.local.get(['vpnConfig'], function(r) {
      if (r.vpnConfig) {
        vpnEnabled = !!r.vpnConfig.enabled && r.vpnConfig.leakProtect !== false;
      }
    });
  }
  chrome.storage.onChanged.addListener(function(changes) {
    if (changes.vpnConfig !== undefined) {
      var cfg = changes.vpnConfig.newValue || {};
      vpnEnabled = !!cfg.enabled && cfg.leakProtect !== false;
    }
  });
  loadVpnState();

  function isSiteBlocked(hostname) {
    for (var i = 0; i < blockedSites.length; i++) {
      var site = blockedSites[i].trim().toLowerCase();
      if (!site) continue;
      if (hostname === site || hostname.endsWith('.' + site)) {
        return true;
      }
    }
    return false;
  }

  var RESPONSE_SELECTORS = [
    '[data-message-author-role="assistant"]',
    '.markdown', '.markdown-body', '.prose',
    '.response-content', '.assistant-message',
    '[class*="response"]', '[class*="assistant"]',
    '[class*="answer"]', '[class*="output"]',
    '.chat-message', '.message-content',
    '[data-message]', '.turn-content',
  ];

  var responseOverlay = null;
  var lastScannedNode = null;

  function createResponseWarningOverlay(container, piiItems) {
    if (responseOverlay) responseOverlay.remove();
    responseOverlay = document.createElement('div');
    var rect = container.getBoundingClientRect();
    Object.assign(responseOverlay.style, {
      position: 'absolute',
      left: rect.left + window.scrollX + 'px',
      top: rect.top + window.scrollY + 'px',
      width: Math.min(rect.width, 500) + 'px',
      background: 'rgba(220, 38, 38, 0.95)',
      color: 'white', padding: '10px 14px', borderRadius: '8px',
      fontFamily: 'monospace', fontSize: '12px', zIndex: '2147483646',
      boxShadow: '0 4px 20px rgba(0,0,0,0.4)', cursor: 'pointer',
    });
    var types = piiItems.map(function(p) { return p.name; });
    var uniqueTypes = types.filter(function(t, i) { return types.indexOf(t) === i; });
    responseOverlay.innerHTML =
      '<div style="font-weight:bold;margin-bottom:4px">[AI Firewall] PII detected in response</div>' +
      '<div style="opacity:0.9">Types: ' + uniqueTypes.join(', ') + '</div>' +
      '<div style="opacity:0.7;font-size:10px;margin-top:4px">Click to dismiss</div>';
    responseOverlay.addEventListener('click', function() { responseOverlay.remove(); responseOverlay = null; });
    document.body.appendChild(responseOverlay);
  }

  function scanNodeForPII(node) {
    if (!isEnabled) return;
    if (!node || node === lastScannedNode) return;
    if (node.nodeType !== 1 && node.nodeType !== 3) return;

    var text = '';
    if (node.nodeType === 3) {
      text = node.textContent;
    } else {
      text = node.textContent || '';
    }
    if (!text || text.trim().length < 10) return;

    var pii = detectPII(text);
    var highConf = pii.filter(function(p) { return p.conf >= 0.6; });
    if (highConf.length > 0) {
      var target = node.nodeType === 3 ? node.parentElement : node;
      if (target) {
        createResponseWarningOverlay(target, highConf);
        lastScannedNode = node;
      }
    }
  }

  function setupResponseScanner() {
    var responseObserver = new MutationObserver(function(mutations) {
      if (!isEnabled) return;
      for (var i = 0; i < mutations.length; i++) {
        var added = mutations[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var node = added[j];
          if (node.nodeType === 3) {
            scanNodeForPII(node);
          } else if (node.nodeType === 1) {
            for (var k = 0; k < RESPONSE_SELECTORS.length; k++) {
              if (node.matches && node.matches(RESPONSE_SELECTORS[k])) {
                scanNodeForPII(node);
                break;
              }
            }
            (function(n) {
              setTimeout(function() { scanNodeForPII(n); }, 500);
            })(node);
          }
        }
      }
    });
    responseObserver.observe(document.body, { childList: true, subtree: true });
    return responseObserver;
  }

  console.log('[AI Firewall] v2 loaded (' + patterns.length + ' PII types, Luhn, confidence scoring)');
  indicator.textContent = '[AI Firewall] Ready';
})();
