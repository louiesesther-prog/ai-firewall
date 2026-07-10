document.addEventListener('DOMContentLoaded', () => {
  const enableToggle = document.getElementById('enableToggle');
  const soundToggle = document.getElementById('soundToggle');
  const maskedTextToggle = document.getElementById('maskedTextToggle');
  const requestsCount = document.getElementById('requestsCount');
  const piiCount = document.getElementById('piiCount');
  const piiList = document.getElementById('piiList');
  const clearStats = document.getElementById('clearStats');

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
    browser.runtime.sendMessage({ type: 'SET_SOUND', enabled: soundToggle.checked }).catch(() => {});
  });

  maskedTextToggle.addEventListener('change', () => {
    browser.runtime.sendMessage({ type: 'SET_MASKED_TEXT', enabled: maskedTextToggle.checked }).catch(() => {});
  });

  clearStats.addEventListener('click', (e) => {
    e.preventDefault();
    browser.storage.local.clear();
    requestsCount.textContent = '0';
    piiCount.textContent = '0';
    piiList.innerHTML = '<div class="pii-item"><span class="pii-type">Statistics cleared</span></div>';
  });

  updateStats();
  setInterval(updateStats, 2000);
});
