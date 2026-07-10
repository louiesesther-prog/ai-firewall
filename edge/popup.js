document.addEventListener('DOMContentLoaded', function() {
  var enableToggle = document.getElementById('enableToggle');
  var soundToggle = document.getElementById('soundToggle');
  var maskedTextToggle = document.getElementById('maskedTextToggle');
  var requestsCount = document.getElementById('requestsCount');
  var piiCount = document.getElementById('piiCount');
  var piiList = document.getElementById('piiList');
  var clearStats = document.getElementById('clearStats');
  
  function loadStats() {
    chrome.storage.local.get(['fw_stats', 'isEnabled'], function(data) {
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
    });
  }
  
  loadStats();
  
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
  
  setInterval(loadStats, 2000);
});