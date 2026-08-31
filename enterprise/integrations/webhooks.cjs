// ── Webhook Dispatcher ────────────────────────────────────────────
// Delivers webhook payloads with HMAC signing, retry with exponential
// backoff, and delivery tracking.

const crypto = require('crypto');
const https = require('https');
const http = require('http');

var _db = null;
var _maxRetries = 3;
var _retryDelay = 5000;

function init(database) {
  _db = database;
}

function signPayload(payload, secret) {
  if (!secret) return null;
  return 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function dispatchEvent(eventType, payload) {
  if (!_db) return;

  var webhooks = getWebhooksForEvent(eventType);
  for (var i = 0; i < webhooks.length; i++) {
    deliverWebhook(webhooks[i], eventType, payload);
  }
}

function getWebhooksForEvent(eventType) {
  if (!_db) return [];
  try {
    var stmt = _db.prepare('SELECT * FROM webhooks WHERE enabled = 1');
    var rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();

    return rows.filter(function(wh) {
      try {
        var events = JSON.parse(wh.events);
        return events.indexOf(eventType) !== -1 || events.indexOf('*') !== -1;
      } catch (e) {
        return false;
      }
    });
  } catch (e) {
    return [];
  }
}

function deliverWebhook(webhook, eventType, payload) {
  if (!_db) return;

  var body = JSON.stringify({
    event: eventType,
    timestamp: new Date().toISOString(),
    data: payload,
  });

  var signature = signPayload(body, webhook.secret);

  // Record delivery attempt
  var deliveryId;
  try {
    _db.run(
      `INSERT INTO webhook_deliveries (webhook_id, event_type, payload, status, attempts) VALUES (?, ?, ?, 'pending', 1)`,
      [webhook.id, eventType, body]
    );
    var stmt = _db.prepare('SELECT last_insert_rowid() as id');
    if (stmt.step()) deliveryId = stmt.getAsObject().id;
    stmt.free();
  } catch (e) {
    console.warn('[webhook] Failed to record delivery:', e.message);
    return;
  }

  sendRequest(webhook.url, body, signature, webhook.headers, function(err, statusCode) {
    if (!_db) return;

    var status = (err || statusCode >= 400) ? 'failed' : 'success';
    var errorMsg = err ? err.message : null;

    try {
      _db.run(
        `UPDATE webhook_deliveries SET status = ?, response_code = ?, error_message = ?, delivered_at = datetime('now') WHERE id = ?`,
        [status, statusCode || null, errorMsg, deliveryId]
      );

      // Update webhook last_triggered_at and failure_count
      if (status === 'failed') {
        _db.run(
          `UPDATE webhooks SET failure_count = failure_count + 1, last_triggered_at = datetime('now') WHERE id = ?`,
          [webhook.id]
        );
      } else {
        _db.run(
          `UPDATE webhooks SET failure_count = 0, last_triggered_at = datetime('now') WHERE id = ?`,
          [webhook.id]
        );
      }
    } catch (e) {}

    // Retry on failure
    if (status === 'failed' && deliveryId) {
      scheduleRetry(webhook, eventType, body, signature, deliveryId, 1);
    }
  });
}

function sendRequest(url, body, signature, customHeaders, callback) {
  var urlObj;
  try { urlObj = new (require('url').URL)(url); } catch (e) {
    return callback(new Error('Invalid webhook URL'));
  }

  var mod = urlObj.protocol === 'https:' ? https : http;
  var headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'User-Agent': 'AI-Firewall-Webhook/1.0',
  };

  if (signature) headers['X-Webhook-Signature'] = signature;

  if (customHeaders) {
    try {
      var custom = typeof customHeaders === 'string' ? JSON.parse(customHeaders) : customHeaders;
      Object.keys(custom).forEach(function(k) { headers[k] = custom[k]; });
    } catch (e) {}
  }

  var req = mod.request({
    hostname: urlObj.hostname,
    port: urlObj.port,
    path: urlObj.pathname + urlObj.search,
    method: 'POST',
    headers: headers,
    timeout: 10000,
  }, function(res) {
    callback(null, res.statusCode);
    res.resume();
  });

  req.on('error', function(e) { callback(e); });
  req.on('timeout', function() { req.destroy(); callback(new Error('Timeout')); });
  req.write(body);
  req.end();
}

function scheduleRetry(webhook, eventType, body, signature, deliveryId, attempt) {
  if (attempt > _maxRetries) return;

  var delay = _retryDelay * Math.pow(2, attempt - 1);
  var nextRetry = new Date(Date.now() + delay).toISOString().replace('T', ' ').substring(0, 19);

  try {
    _db.run(
      `UPDATE webhook_deliveries SET attempts = ?, next_retry_at = ? WHERE id = ?`,
      [attempt + 1, nextRetry, deliveryId]
    );
  } catch (e) {}

  setTimeout(function() {
    sendRequest(webhook.url, body, signature, webhook.headers, function(err, statusCode) {
      if (!_db) return;
      var status = (err || statusCode >= 400) ? 'failed' : 'success';
      var errorMsg = err ? err.message : null;

      try {
        _db.run(
          `UPDATE webhook_deliveries SET status = ?, response_code = ?, error_message = ?, delivered_at = CASE WHEN ? = 'success' THEN datetime('now') ELSE delivered_at END WHERE id = ?`,
          [status, statusCode || null, errorMsg, status, deliveryId]
        );
      } catch (e) {}

      if (status === 'failed') {
        scheduleRetry(webhook, eventType, body, signature, deliveryId, attempt + 1);
      }
    });
  }, delay);
}

function getDeliveries(options) {
  if (!_db) return [];
  options = options || {};

  var where = [];
  var params = [];

  if (options.webhookId) { where.push('webhook_id = ?'); params.push(options.webhookId); }
  if (options.status) { where.push('status = ?'); params.push(options.status); }

  var sql = 'SELECT * FROM webhook_deliveries';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(options.limit || 50);

  try {
    var stmt = _db.prepare(sql);
    if (params.length) stmt.bind(params);
    var rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } catch (e) {
    return [];
  }
}

module.exports = { init, dispatchEvent, deliverWebhook, getDeliveries, signPayload };
