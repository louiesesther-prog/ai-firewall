document.addEventListener('DOMContentLoaded', () => {
  const enableToggle = document.getElementById('enableToggle');
  const soundToggle = document.getElementById('soundToggle');
  const maskedTextToggle = document.getElementById('maskedTextToggle');
  const requestsCount = document.getElementById('requestsCount');
  const piiCount = document.getElementById('piiCount');
  const piiList = document.getElementById('piiList');
  const clearStats = document.getElementById('clearStats');
  const vpnSection = document.getElementById('vpnSection');
  const vpnToggle = document.getElementById('vpnToggle');
  const vpnDot = document.getElementById('vpnDot');
  const vpnHost = document.getElementById('vpnHost');
  const vpnPort = document.getElementById('vpnPort');
  const vpnProto = document.getElementById('vpnProto');
  const vpnLeakToggle = document.getElementById('vpnLeakToggle');
  const vpnStatus = document.getElementById('vpnStatus');
  const vpnConnectBtn = document.getElementById('vpnConnectBtn');

  function setVpnUI(state) {
    if (!state) return;
    if (state.supported === false) {
      vpnToggle.checked = false;
      vpnToggle.disabled = true;
      vpnHost.disabled = true;
      vpnPort.disabled = true;
      vpnProto.disabled = true;
      vpnLeakToggle.disabled = true;
      vpnConnectBtn.style.display = 'none';
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

  function sendVpn(msg) {
    return browser.runtime.sendMessage(msg).catch(() => null);
  }

  function loadVpn() {
    sendVpn({ type: 'VPN_GET' }).then(setVpnUI);
  }

  vpnToggle.addEventListener('change', () => {
    sendVpn({ type: 'VPN_SET', config: { enabled: vpnToggle.checked } }).then(setVpnUI);
  });
  vpnHost.addEventListener('change', () => {
    sendVpn({ type: 'VPN_SET', config: { host: vpnHost.value.trim() } }).then(setVpnUI);
  });
  vpnPort.addEventListener('change', () => {
    sendVpn({ type: 'VPN_SET', config: { port: parseInt(vpnPort.value, 10) || 1080 } }).then(setVpnUI);
  });
  vpnProto.addEventListener('change', () => {
    sendVpn({ type: 'VPN_SET', config: { protocol: vpnProto.value } }).then(setVpnUI);
  });
  vpnLeakToggle.addEventListener('change', () => {
    sendVpn({ type: 'VPN_SET', config: { leakProtect: vpnLeakToggle.checked } }).then(setVpnUI);
  });

  function updateStats() {
    browser.runtime.sendMessage({ type: 'GET_STATS' }).then((response) => {
      if (response) {
        requestsCount.textContent = response.stats?.requests || 0;
        piiCount.textContent = response.stats?.piiDetected || 0;
        enableToggle.checked = response.isEnabled !== false;
      }
    }).catch(() => {});

    browser.runtime.sendMessage({ type: 'GET_MAP' }).then((response) => {
      if (response && response.map && Object.keys(response.map).length > 0) {
        piiList.innerHTML = '';
        const grouped = {};

        for (const [placeholder] of Object.entries(response.map)) {
          const type = placeholder.match(/\[([A-Z_]+)/)?.[1] || 'UNKNOWN';
          if (!grouped[type]) grouped[type] = 0;
          grouped[type]++;
        }

        for (const [type, count] of Object.entries(grouped)) {
          const item = document.createElement('div');
          item.className = 'pii-item';
          item.innerHTML = `<span class="pii-type">${type}</span><span class="pii-count">${count}</span>`;
          piiList.appendChild(item);
        }
      } else {
        piiList.innerHTML = '<div class="pii-item"><span class="pii-type">No PII detected yet</span></div>';
      }
    }).catch(() => {});
  }

  enableToggle.addEventListener('change', () => {
    browser.runtime.sendMessage({ type: 'TOGGLE' }).then((response) => {
      enableToggle.checked = response?.isEnabled ?? true;
    }).catch(() => {});
  });

  soundToggle.addEventListener('change', () => {
    browser.storage.local.set({ enableSound: soundToggle.checked });
  });

  maskedTextToggle.addEventListener('change', () => {
    browser.storage.local.set({ showMaskedText: maskedTextToggle.checked });
  });

  clearStats.addEventListener('click', (e) => {
    e.preventDefault();
    browser.storage.local.set({ fw_stats: { requests: 0, piiDetected: 0, types: {} } });
    requestsCount.textContent = '0';
    piiCount.textContent = '0';
    piiList.innerHTML = '<div class="pii-item"><span class="pii-type">Statistics cleared</span></div>';
  });

  // ── Connect VPN: probe local bridge, then enable Privacy Route ──
  function probeBridge(host, port) {
    return fetch(`http://${host}:${port}/`).then((r) => r.json()).catch(() => null);
  }

  vpnConnectBtn.addEventListener('click', () => {
    const host = vpnHost.value.trim() || '127.0.0.1';
    const port = parseInt(vpnPort.value, 10) || 1080;
    vpnConnectBtn.disabled = true;
    vpnStatus.className = 'vpn-status';
    vpnStatus.textContent = `Probing ${host}:${port} ...`;

    probeBridge(host, port).then((status) => {
      vpnConnectBtn.disabled = false;
      if (!status) {
        vpnStatus.className = 'vpn-status err';
        vpnStatus.textContent = `No bridge at ${host}:${port}. Start it: node vpn/socks5-bridge.mjs (with your WireGuard tunnel up).`;
        return;
      }
      if (status.tunnel === 'down') {
        vpnStatus.className = 'vpn-status err';
        vpnStatus.textContent = 'Bridge found, but WireGuard tunnel is DOWN. Bring it up (wg-quick up <name>) then Connect again.';
        return;
      }
      sendVpn({ type: 'VPN_SET', config: { host, port, protocol: 'socks5', enabled: true, leakProtect: true } }).then((state) => {
        setVpnUI(state);
        vpnStatus.className = 'vpn-status ok';
        vpnStatus.textContent = `Connected via WireGuard tunnel (${status.tunnelAdapter}). AI sites now routed through VPN.`;
      });
    });
  });

  updateStats();
  loadVpn();
  setInterval(updateStats, 2000);
});
