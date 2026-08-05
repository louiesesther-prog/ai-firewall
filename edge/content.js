(function() {
  'use strict';

  var indicator = document.createElement('div');
  indicator.id = 'ai-firewall-indicator';
  Object.assign(indicator.style, {
    position: 'fixed', top: '0', left: '0', zIndex: '2147483647',
    background: '#6366f1', color: 'white', padding: '8px 16px',
    fontFamily: 'monospace', fontSize: '12px', fontWeight: 'bold',
    boxShadow: '0 2px 10px rgba(0,0,0,0.3)', borderRadius: '0 0 8px 0'
  });
  indicator.textContent = '[AI Firewall] Initializing...';
  document.documentElement.appendChild(indicator);

  var maskMode = 'placeholder';
  var isEnabled = true;
  var piiMap = {};
  var stats = { requests: 0, piiDetected: 0, types: {} };

  var patterns = [
    { name: 'EMAIL', label:'EMAIL_ADDR', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, conf:0.95 },
    { name: 'PHONE', label:'PHONE_NUM', regex: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, conf:0.8 },
    { name: 'SSN',   label:'SSN_NUM',   regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, conf:0.85 },
    { name: 'CC',    label:'CC_NUM',    regex: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, conf:0.9, luhn:true },
    { name: 'IP',    label:'IP_ADDR',   regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, conf:0.65 },
    { name: 'APIKEY',label:'APIKEY',    regex: /(?:api[_-]?key|api key)[=:\s]+\S+/gi, conf:0.85 },
    { name: 'PWD',   label:'PWD_VAL',   regex: /(?:password|passwd|pass)[=:\s]+\S+/gi, conf:0.8 },
    { name: 'CRYPTO',label:'CRYPTO',    regex: /0x[a-fA-F0-9]{40}/g, conf:0.95 },
    { name: 'MAC',   label:'MAC_ADDR',  regex: /[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}/g, conf:0.95 },
    { name: 'DOB',   label:'DOB',       regex: /(?:DOB|date\s*of\s*birth|birth\s*date)[=:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}/gi, conf:0.9 },
    { name: 'PASSPORT',label:'PASSPORT',regex: /\b[A-Z]\d{8}\b/g, conf:0.85 },
    { name: 'LICENSE',label:'LICENSE',  regex: /(?:driver'?s?\s*license|dl|license)[=:\s]*[A-Z0-9]{5,14}/gi, conf:0.7 },
    { name: 'ADDRESS',label:'ADDRESS',  regex: /\b\d{1,5}\s+[\w\s]{2,}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Circle|Cir|Place|Pl)\.?\b/gi, conf:0.6 },
    { name: 'BANK',  label:'BANK_ACCT', regex: /(?:account|acct|acc)\s*(?:#|number|num|no)?[=:\s]+\d{5,17}/gi, conf:0.7 },
    { name: 'ROUTING',label:'ROUTING',  regex: /\b\d{9}\b/g, conf:0.4 },
    { name: 'UK_NI', label:'UK_NI',     regex: /\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b/gi, conf:0.85 },
    { name: 'UK_NHS',label:'UK_NHS',    regex: /\b\d{3}\s?\d{3}\s?\d{4}\b/g, conf:0.7 },
    { name: 'IN_AADHAAR',label:'IN_AADHAAR', regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/g, conf:0.85 },
    { name: 'IN_PAN',label:'IN_PAN',    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/gi, conf:0.9 },
    { name: 'CN_ID', label:'CN_ID',     regex: /\b\d{6}\d{8}[\dXx]\b/g, conf:0.85 },
    { name: 'CA_SIN',label:'CA_SIN',    regex: /\b\d{3}\s?\d{3}\s?\d{3}\b/g, conf:0.7 },

    { name: 'JWT',   label:'JWT',       regex: /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, conf:0.95 },
    { name: 'AWS_KEY',label:'AWS_KEY',  regex: /\bAKIA[0-9A-Z]{16}\b/g, conf:0.95 },
    { name: 'GITHUB',label:'GITHUB',    regex: /\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}\b/g, conf:0.95 },
    { name: 'SLACK', label:'SLACK',     regex: /\bxox[baprs]-[a-zA-Z0-9-]{10,}\b/g, conf:0.95 },
    { name: 'AU_TFN',label:'AU_TFN',    regex: /\b\d{3}\s?\d{3}\s?\d{3}\b/g, conf:0.4 },
    { name: 'JP_MY', label:'JP_MY',     regex: /\b\d{4}-\d{4}-\d{4}\b/g, conf:0.85 },
    { name: 'BR_CPF',label:'BR_CPF',    regex: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g, conf:0.8 },
    { name: 'BR_CNPJ',label:'BR_CNPJ',  regex: /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g, conf:0.85 },
    { name: 'FR_INSEE',label:'FR_INSEE',regex: /\b\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\b/g, conf:0.7 },
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
      result = result.replace(p.regex, function(m) {
        var conf = p.conf;
        if (p.luhn) {
          var clean = m.replace(/[-\s]/g, '');
          if (clean.length >= 13 && clean.length <= 19) {
            conf = luhnCheck(clean) ? 0.95 : 0.3;
          }
        }
        var key = '[' + p.label + '_' + n + ']';
        var replacement = maskMode === 'realistic' ? fakeFor(p.label) : key;
        piiMap[key] = { original: m, replacement: replacement, confidence: conf, type: p.label };
        stats.types[p.label] = (stats.types[p.label] || 0) + 1;
        n++;
        return replacement;
      });
    });

    return result;
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

    input.addEventListener('input', function() {
      if (!isEnabled) {
        indicator.textContent = '[AI Firewall] Disabled';
        indicator.style.background = '#6b7280';
        return;
      }
      var text = input.value || input.textContent || '';
      var found = detect(text);
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
      if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
        var text = input.value || input.textContent || '';
        var masked = mask(text);
        if (Object.keys(piiMap).length > 0) {
          if (input.tagName === 'TEXTAREA' || input.tagName === 'INPUT') {
            input.value = masked;
          } else {
            input.textContent = masked;
          }
          indicator.textContent = '[AI Firewall] Masked ' + Object.keys(piiMap).length + ' PII';
          indicator.style.background = '#3b82f6';
          stats.requests++;
          stats.piiDetected += Object.keys(piiMap).length;
          saveStats();
        }
      }
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

  chrome.storage.local.get(['maskMode', 'isEnabled'], function(r) {
    if (r.maskMode) maskMode = r.maskMode;
    if (r.isEnabled !== undefined) {
      isEnabled = r.isEnabled;
      indicator.textContent = isEnabled ? '[AI Firewall] Ready' : '[AI Firewall] Disabled';
      indicator.style.background = isEnabled ? '#6366f1' : '#6b7280';
    }
  });

  chrome.storage.onChanged.addListener(function(changes, area) {
    if (area === 'local') {
      if (changes.isEnabled !== undefined) {
        isEnabled = changes.isEnabled.newValue;
        indicator.textContent = isEnabled ? '[AI Firewall] Ready' : '[AI Firewall] Disabled';
        indicator.style.background = isEnabled ? '#6366f1' : '#6b7280';
      }
      if (changes.maskMode !== undefined) {
        maskMode = changes.maskMode.newValue;
      }
    }
  });

  // ── WebRTC / DNS leak protection (main-world injection) ──
  var vpnEnabled = false;
  var LEAK_PROTECT_SRC = '(' + function() {
    if (window.__aiFwLeakProtected) return;
    window.__aiFwLeakProtected = true;
    try {
      var RTP = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
      if (!RTP) return;
      var proto = RTP.prototype;
      var addIce = proto.addIceCandidate;
      proto.addIceCandidate = function(candidate) {
        if (candidate && typeof candidate.candidate === 'string') {
          var c = candidate.candidate;
          // Block host candidates that reveal a real IP (allow mDNS .local only)
          if (/a=candidate:/.test(c) && /typ\s+host\b/.test(c) && !/\.local\b/.test(c)) {
            return Promise.resolve();
          }
        }
        return addIce.call(this, candidate);
      };
      Object.defineProperty(proto, 'iceTransportPolicy', {
        configurable: true,
        get: function() { return 'relay'; },
        set: function() {}
      });
    } catch (e) {}
  }.toString() + ')();';

  function applyLeakProtect() {
    try {
      var s = document.createElement('script');
      s.textContent = LEAK_PROTECT_SRC;
      (document.head || document.documentElement).appendChild(s);
      s.remove();
    } catch (e) {}
  }

  function loadVpnState() {
    chrome.storage.local.get(['vpnConfig'], function(r) {
      if (r.vpnConfig) {
        vpnEnabled = !!r.vpnConfig.enabled && r.vpnConfig.leakProtect !== false;
        if (vpnEnabled) applyLeakProtect();
      }
    });
  }
  chrome.storage.onChanged.addListener(function(changes) {
    if (changes.vpnConfig !== undefined) {
      var cfg = changes.vpnConfig.newValue || {};
      var shouldEnable = !!cfg.enabled && cfg.leakProtect !== false;
      if (shouldEnable && !vpnEnabled) applyLeakProtect();
      vpnEnabled = shouldEnable;
    }
  });
  loadVpnState();

  console.log('[AI Firewall] v2 loaded (' + patterns.length + ' PII types, Luhn, confidence scoring)');
  indicator.textContent = '[AI Firewall] Ready';
})();
