document.addEventListener('DOMContentLoaded', function() {
  var enableToggle = document.getElementById('enableToggle');
  var soundToggle = document.getElementById('soundToggle');
  var maskedTextToggle = document.getElementById('maskedTextToggle');
  var requestsCount = document.getElementById('requestsCount');
  var piiCount = document.getElementById('piiCount');
  var piiList = document.getElementById('piiList');
  var clearStats = document.getElementById('clearStats');
  var vpnSection = document.getElementById('vpnSection');
  var vpnToggle = document.getElementById('vpnToggle');
  var vpnDot = document.getElementById('vpnDot');
  var vpnHost = document.getElementById('vpnHost');
  var vpnPort = document.getElementById('vpnPort');
  var vpnProto = document.getElementById('vpnProto');
  var vpnLeakToggle = document.getElementById('vpnLeakToggle');
  var vpnStatus = document.getElementById('vpnStatus');
  var vpnConnectBtn = document.getElementById('vpnConnectBtn');
  var blockedSiteInput = document.getElementById('blockedSiteInput');
  var addBlockedSite = document.getElementById('addBlockedSite');
  var blockedSitesList = document.getElementById('blockedSitesList');

  function sendVpn(msg) {
    return new Promise(function(resolve) {
      if (typeof browser !== 'undefined' && browser.runtime) {
        browser.runtime.sendMessage(msg).then(resolve).catch(function() { resolve(null); });
      } else {
        chrome.runtime.sendMessage(msg, resolve);
      }
    });
  }

  function setVpnUI(state) {
    if (!state) return;
    if (state.supported === false) {
      vpnToggle.checked = false;
      vpnToggle.disabled = true;
      vpnHost.disabled = true;
      vpnPort.disabled = true;
      vpnProto.disabled = true;
      vpnLeakToggle.disabled = true;
      vpnStatus.className = 'vpn-status err';
      vpnStatus.textContent = 'Privacy Route is not supported by this browser.';
      return;
    }
    vpnToggle.checked = !!state.enabled;
    vpnHost.value = state.host || '';
    vpnPort.value = state.port || '';
    vpnProto.value = state.protocol || 'socks5';
    vpnLeakToggle.checked = state.leakProtect !== false;
    vpnSection.classList.toggle('on', !!state.enabled);
    vpnDot.classList.toggle('on', !!state.enabled);
    if (state.enabled) {
      if (state.host) {
        vpnStatus.className = 'vpn-status ok';
        vpnStatus.textContent = 'Active — ' + state.protocol.toUpperCase() + ' ' + state.host + ':' + state.port + ' (' + state.domains + ' AI sites routed).';
      } else {
        vpnStatus.className = 'vpn-status err';
        vpnStatus.textContent = 'Enabled but no host set — add a proxy/VPN host above.';
      }
    } else {
      vpnStatus.className = 'vpn-status';
      vpnStatus.textContent = 'Reroutes AI chat traffic through your own proxy. Traffic for other sites stays direct.';
    }
  }

  function loadVpn() {
    sendVpn({ type: 'VPN_GET' }).then(setVpnUI);
  }
  
  vpnToggle.addEventListener('change', function() {
    sendVpn({ type: 'VPN_SET', config: { enabled: vpnToggle.checked } }).then(setVpnUI);
  });
  vpnHost.addEventListener('change', function() {
    sendVpn({ type: 'VPN_SET', config: { host: vpnHost.value.trim() } }).then(setVpnUI);
  });
  vpnPort.addEventListener('change', function() {
    sendVpn({ type: 'VPN_SET', config: { port: parseInt(vpnPort.value, 10) || 1080 } }).then(setVpnUI);
  });
  vpnProto.addEventListener('change', function() {
    sendVpn({ type: 'VPN_SET', config: { protocol: vpnProto.value } }).then(setVpnUI);
  });
  vpnLeakToggle.addEventListener('change', function() {
    sendVpn({ type: 'VPN_SET', config: { leakProtect: vpnLeakToggle.checked } }).then(setVpnUI);
  });
  
  function loadStats() {
    chrome.storage.local.get(['fw_stats', 'isEnabled', 'enableSound'], function(data) {
      var stats = data.fw_stats || { requests: 0, piiDetected: 0, types: {} };
      requestsCount.textContent = stats.requests || 0;
      piiCount.textContent = stats.piiDetected || 0;
      
      var types = stats.types || {};
      if (Object.keys(types).length > 0) {
        piiList.innerHTML = '';
        for (var type in types) {
          var item = document.createElement('div');
          item.className = 'pii-item';
          item.innerHTML = '<span class="pii-type">' + type + '</span><span class="pii-count">' + types[type] + '</span>';
          piiList.appendChild(item);
        }
      } else {
        piiList.innerHTML = '<div class="pii-item"><span class="pii-type">No PII detected yet</span></div>';
      }
      
      if (data.isEnabled !== undefined) {
        enableToggle.checked = data.isEnabled;
      }
      if (data.enableSound !== undefined) {
        soundToggle.checked = data.enableSound;
      }
    });
  }
  
  loadStats();
  loadVpn();

  // ── Per-site blocked sites management ──
  var currentBlockedSites = [];

  function renderBlockedSites() {
    blockedSitesList.innerHTML = '';
    if (currentBlockedSites.length === 0) {
      blockedSitesList.innerHTML = '<div style="color:#666;padding:4px 0">No blocked sites</div>';
      return;
    }
    currentBlockedSites.forEach(function(site, idx) {
      var item = document.createElement('div');
      item.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:3px 0;border-bottom:1px solid #1a1a3e';
      item.innerHTML = '<span>' + site + '</span>';
      var removeBtn = document.createElement('button');
      removeBtn.textContent = '✕';
      removeBtn.style.cssText = 'background:none;border:none;color:#e94560;cursor:pointer;font-size:13px;font-weight:bold;padding:0 4px';
      removeBtn.addEventListener('click', function() {
        currentBlockedSites.splice(idx, 1);
        chrome.storage.local.set({ blockedSites: currentBlockedSites });
        renderBlockedSites();
      });
      item.appendChild(removeBtn);
      blockedSitesList.appendChild(item);
    });
  }

  chrome.storage.local.get(['blockedSites'], function(data) {
    currentBlockedSites = data.blockedSites || [];
    renderBlockedSites();
  });

  addBlockedSite.addEventListener('click', function() {
    var site = blockedSiteInput.value.trim().toLowerCase();
    if (!site) return;
    // Strip protocol if user includes it
    site = site.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (currentBlockedSites.indexOf(site) !== -1) return;
    currentBlockedSites.push(site);
    chrome.storage.local.set({ blockedSites: currentBlockedSites });
    blockedSiteInput.value = '';
    renderBlockedSites();
  });

  blockedSiteInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      addBlockedSite.click();
    }
  });
  
  enableToggle.addEventListener('change', function() {
    chrome.storage.local.set({ isEnabled: enableToggle.checked });
  });
  
  soundToggle.addEventListener('change', function() {
    chrome.storage.local.set({ enableSound: soundToggle.checked });
  });
  
  maskedTextToggle.addEventListener('change', function() {
    chrome.storage.local.set({ showMaskedText: maskedTextToggle.checked });
  });
  
  clearStats.addEventListener('click', function(e) {
    e.preventDefault();
    chrome.storage.local.set({ fw_stats: { requests: 0, piiDetected: 0, types: {} } });
    requestsCount.textContent = '0';
    piiCount.textContent = '0';
    piiList.innerHTML = '<div class="pii-item"><span class="pii-type">Statistics cleared</span></div>';
  });

  // ── Connect VPN: probe local bridge, then enable Privacy Route ──
  function probeBridge(host, port) {
    return fetch('http://' + host + ':' + port + '/').then(function(r) {
      return r.json();
    }).catch(function() { return null; });
  }

  vpnConnectBtn.addEventListener('click', function() {
    var host = vpnHost.value.trim() || '127.0.0.1';
    var port = parseInt(vpnPort.value, 10) || 1080;
    vpnConnectBtn.disabled = true;
    vpnStatus.className = 'vpn-status';
    vpnStatus.textContent = 'Probing ' + host + ':' + port + ' ...';

    probeBridge(host, port).then(function(status) {
      vpnConnectBtn.disabled = false;
      if (!status) {
        vpnStatus.className = 'vpn-status err';
        vpnStatus.textContent = 'No bridge at ' + host + ':' + port + '. Start it: node vpn/socks5-bridge.mjs (with your WireGuard tunnel up).';
        return;
      }
      if (status.tunnel === 'down') {
        vpnStatus.className = 'vpn-status err';
        vpnStatus.textContent = 'Bridge found, but WireGuard tunnel is DOWN. Bring it up (wg-quick up <name>) then Connect again.';
        return;
      }
      // Enable Privacy Route pointing at the local bridge
      return sendVpn({ type: 'VPN_SET', config: { host: host, port: port, protocol: 'socks5', enabled: true, leakProtect: true } }).then(function(state) {
        setVpnUI(state);
        vpnStatus.className = 'vpn-status ok';
        vpnStatus.textContent = 'Connected via WireGuard tunnel (' + status.tunnelAdapter + '). AI sites now routed through VPN.';
      });
    });
  });

  setInterval(loadStats, 2000);
});