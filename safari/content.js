// ── Cookie Blocking: Override document.cookie in page context (if enabled) ──
(function() {
  if (window.__aiFwCookieBlocked) return;
  try {
    chrome.runtime.sendMessage({ type: 'BLOCK_COOKIES_GET' }, (res) => {
      if (!res || res.cookieBlockMode === 'off') return;
      const hostname = location.hostname;
      const shouldBlock = res.cookieBlockMode === 'global' ||
        (res.cookieBlockMode === 'per-domain' && res.blockedDomains && res.blockedDomains.some(d => hostname === d || hostname.endsWith('.' + d)));
      if (!shouldBlock) return;

      window.__aiFwCookieBlocked = true;
      const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                         Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
      if (cookieDesc && cookieDesc.configurable) {
        Object.defineProperty(document, 'cookie', {
          get: function() { return ''; },
          set: function() { /* blocked */ },
          configurable: true
        });
      }
    });
  } catch (e) {}
})();

let currentApp = null;
let inputElement = null;
let sendButton = null;
let isObserving = false;
let lastValue = '';
let enableSound = true;
let showMaskedText = true;

const APP_CONFIGS = {
  'chat.openai.com': {
    name: 'ChatGPT',
    getInput: () => document.querySelector('textarea[data-id="root"]') || document.querySelector('textarea'),
    getSendBtn: () => document.querySelector('button[data-testid="send-button"]') || document.querySelector('button[aria-label="Send"]'),
  },
  'chatgpt.com': {
    name: 'ChatGPT',
    getInput: () => document.querySelector('textarea[data-id="root"]') || document.querySelector('textarea'),
    getSendBtn: () => document.querySelector('button[data-testid="send-button"]') || document.querySelector('button[aria-label="Send"]'),
  },
  'copilot.microsoft.com': {
    name: 'Copilot',
    getInput: () => document.querySelector('textarea') || document.querySelector('#userInput') || document.querySelector('[aria-label*="Ask"]'),
    getSendBtn: () => document.querySelector('#user-input button') || document.querySelector('button[aria-label*="Submit"]'),
  },
  'gemini.google.com': {
    name: 'Gemini',
    getInput: () => document.querySelector('textarea') || document.querySelector('.input-area textarea') || document.querySelector('[data-testid="gemini-prompt-input"]'),
    getSendBtn: () => document.querySelector('button.send-button') || document.querySelector('.run-button') || document.querySelector('[aria-label="Send"]'),
  },
  'ai.google.dev': {
    name: 'Gemini API',
    getInput: () => document.querySelector('textarea') || document.querySelector('input[type="text"]'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'claude.ai': {
    name: 'Claude',
    getInput: () => document.querySelector('textarea') || document.querySelector('[data-id="chat-input"]') || document.querySelector('[data-testid="prompt-input"]'),
    getSendBtn: () => document.querySelector('button[type="submit"]') || document.querySelector('[aria-label="Send"]'),
  },
  'claude.anthropic.com': {
    name: 'Claude',
    getInput: () => document.querySelector('textarea'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'anthropic.com': {
    name: 'Anthropic',
    getInput: () => document.querySelector('textarea') || document.querySelector('input[type="text"]'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'chat.google.com': {
    name: 'Google AI',
    getInput: () => document.querySelector('textarea') || document.querySelector('[aria-label*="Message"]'),
    getSendBtn: () => document.querySelector('button.send') || document.querySelector('[aria-label*="Send"]'),
  },
  'perplexity.ai': {
    name: 'Perplexity',
    getInput: () => document.querySelector('textarea') || document.querySelector('[data-testid="search-input"]') || document.querySelector('.search-input'),
    getSendBtn: () => document.querySelector('button.submit') || document.querySelector('[aria-label="Search"]'),
  },
  'poe.com': {
    name: 'Poe',
    getInput: () => document.querySelector('textarea') || document.querySelector('[data-testid="ChatContainer-input"]'),
    getSendBtn: () => document.querySelector('button.send') || document.querySelector('[aria-label="Send"]'),
  },
  'groq.com': {
    name: 'Groq',
    getInput: () => document.querySelector('textarea') || document.querySelector('input[type="text"]'),
    getSendBtn: () => document.querySelector('button[type="submit"]') || document.querySelector('button.send'),
  },
  'mistral.ai': {
    name: 'Mistral',
    getInput: () => document.querySelector('textarea') || document.querySelector('input[type="text"]'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'cohere.ai': {
    name: 'Cohere',
    getInput: () => document.querySelector('textarea'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'meta.ai': {
    name: 'Meta AI',
    getInput: () => document.querySelector('textarea') || document.querySelector('[aria-label*="Message"]'),
    getSendBtn: () => document.querySelector('[aria-label="Send"]') || document.querySelector('button[type="submit"]'),
  },
  'you.com': {
    name: 'You.com',
    getInput: () => document.querySelector('textarea') || document.querySelector('input[type="text"]'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'kimi.ai': {
    name: 'Kimi',
    getInput: () => document.querySelector('textarea'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'qwen.ai': {
    name: 'Qwen',
    getInput: () => document.querySelector('textarea'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'deepseek.com': {
    name: 'DeepSeek',
    getInput: () => document.querySelector('textarea') || document.querySelector('input[type="text"]'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'jina.ai': {
    name: 'Jina AI',
    getInput: () => document.querySelector('textarea'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  },
  'phind.com': {
    name: 'Phind',
    getInput: () => document.querySelector('textarea'),
    getSendBtn: () => document.querySelector('button[type="submit"]'),
  }
};

function detectApp() {
  const hostname = window.location.hostname;
  for (const [domain, config] of Object.entries(APP_CONFIGS)) {
    if (hostname.includes(domain.replace('*://', ''))) {
      return { domain, ...config };
    }
  }
  return null;
}

function showNotification(message, type = 'info', details = null) {
  const notification = document.createElement('div');
  notification.className = `ai-firewall-notification ai-firewall-${type}`;
  
  let content = `<span class="icon">🛡️</span><span class="message">${message}</span>`;
  
  if (showMaskedText && details && details.length > 0) {
    content += `<div class="details"><strong>Masked:</strong> ${details.join(', ')}</div>`;
  }
  
  notification.innerHTML = content;
  document.body.appendChild(notification);
  
  setTimeout(() => notification.classList.add('show'), 100);
  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => notification.remove(), 300);
  }, 5000);
}

function playSound(type) {
  if (!enableSound) return;
  
  try {
    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);
    
    if (type === 'detect') {
      oscillator.frequency.value = 800;
      gainNode.gain.value = 0.1;
      oscillator.start();
      oscillator.stop(audioContext.currentTime + 0.1);
    } else if (type === 'send') {
      oscillator.frequency.value = 600;
      gainNode.gain.value = 0.1;
      oscillator.start();
      setTimeout(() => { oscillator.frequency.value = 800; }, 50);
      oscillator.stop(audioContext.currentTime + 0.15);
    }
  } catch (e) {
    console.log('Sound error:', e);
  }
}

async function interceptInput() {
  if (!inputElement) return;
  
  const currentValue = inputElement.value;
  if (currentValue === lastValue) return;
  
  lastValue = currentValue;
  
  if (currentValue.length > 10) {
    try {
      const response = await browser.runtime.sendMessage({ type: 'SCRUB', text: currentValue });
      if (response && response.matches && response.matches.length > 0) {
        playSound('detect');
        
        const maskedTypes = Object.keys(response.map).map(k => {
          const match = k.match(/\[([A-Z_]+)/);
          return match ? match[1] : k;
        });
        
        showNotification(`🛡️ ${response.matches.length} PII item(s) masked`, 'warning', maskedTypes);
      }
    } catch (e) {
      console.log('AI Firewall: Content script error', e);
    }
  }
}

function setupInterceptor() {
  if (!currentApp || isObserving) return;
  
  inputElement = currentApp.getInput();
  sendButton = currentApp.getSendBtn();
  
  if (!inputElement) {
    setTimeout(setupInterceptor, 1000);
    return;
  }
  
  isObserving = true;
  
  inputElement.addEventListener('input', interceptInput);
  inputElement.addEventListener('paste', () => setTimeout(interceptInput, 100));
  
  if (sendButton) {
    sendButton.addEventListener('click', async () => {
      const text = inputElement.value;
      if (text.trim()) {
        try {
          const response = await browser.runtime.sendMessage({ type: 'SCRUB', text });
          if (response && response.matches && response.matches.length > 0) {
            inputElement.value = response.text;
            lastValue = response.text;
            playSound('send');
            showNotification(`✅ Sent with ${response.matches.length} masked PII item(s)`, 'success');
          }
        } catch (e) {
          console.log('AI Firewall: Click handler error', e);
        }
      }
    });
  }
  
  const observer = new MutationObserver(() => {
    const newInput = currentApp.getInput();
    if (newInput && newInput !== inputElement) {
      inputElement = newInput;
      inputElement.addEventListener('input', interceptInput);
      inputElement.addEventListener('paste', () => setTimeout(interceptInput, 100));
    }
  });
  
  observer.observe(document.body, { childList: true, subtree: true });
  
  showNotification('🛡️ AI Personal Firewall Active', 'success');
}

function init() {
  currentApp = detectApp();
  
  if (currentApp) {
    console.log(`AI Firewall: Protecting ${currentApp.name}`);
    setupInterceptor();
  } else {
    console.log('AI Firewall: No supported AI app detected');
  }
}

// ── WebRTC / DNS leak protection (main-world injection) ──
let vpnEnabled = false;
const LEAK_PROTECT_SRC = '(' + function() {
  if (window.__aiFwLeakProtected) return;
  window.__aiFwLeakProtected = true;
  try {
    const RTP = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
    if (!RTP) return;
    const proto = RTP.prototype;
    const addIce = proto.addIceCandidate;
    proto.addIceCandidate = function(candidate) {
      if (candidate && typeof candidate.candidate === 'string') {
        const c = candidate.candidate;
        if (/a=candidate:/.test(c) && /typ\s+host\b/.test(c) && !/\.local\b/.test(c)) {
          return Promise.resolve();
        }
      }
      return addIce.call(this, candidate);
    };
    Object.defineProperty(proto, 'iceTransportPolicy', {
      configurable: true,
      get: () => 'relay',
      set: () => {}
    });
  } catch (e) {}
}.toString() + ')();';

function applyLeakProtect() {
  try {
    const s = document.createElement('script');
    s.textContent = LEAK_PROTECT_SRC;
    (document.head || document.documentElement).appendChild(s);
    s.remove();
  } catch (e) {}
}

function loadVpnState() {
  browser.storage.local.get(['vpnConfig']).then((r) => {
    if (r.vpnConfig) {
      vpnEnabled = !!r.vpnConfig.enabled && r.vpnConfig.leakProtect !== false;
      if (vpnEnabled) applyLeakProtect();
    }
  }).catch(() => {});
}
browser.storage.onChanged.addListener((changes) => {
  if (changes.vpnConfig !== undefined) {
    const cfg = changes.vpnConfig.newValue || {};
    const shouldEnable = !!cfg.enabled && cfg.leakProtect !== false;
    if (shouldEnable && !vpnEnabled) applyLeakProtect();
    vpnEnabled = shouldEnable;
  }
});
loadVpnState();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}