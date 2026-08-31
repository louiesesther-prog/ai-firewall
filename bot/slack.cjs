const core = require('./core.cjs');

function startSlackBot(config) {
  let App;
  try {
    App = require('@slack/bolt').App;
  } catch (e) {
    throw new Error(
      'Slack bot requires @slack/bolt: npm install @slack/bolt\n' +
      'Error: ' + e.message
    );
  }

  const app = new App({
    token: config.token,
    signingSecret: config.signingSecret,
    appToken: config.appToken,
    socketMode: !!config.appToken,
  });

  const profile = config.profile || 'none';

  app.command('/scan', async ({ command, ack, respond }) => {
    await ack();
    const text = command.text;
    if (!text) {
      return respond({ text: 'Usage: /scan <text to check for PII>' });
    }
    try {
      const result = core.scanText(text, { profile, platform: 'slack' });
      await respond(core.formatSlackMessage(result));
    } catch (err) {
      await respond({ text: ':x: Scan error: ' + err.message }).catch(() => {});
    }
  });

  app.command('/pii', async ({ command, ack, respond }) => {
    await ack();
    const text = command.text;
    if (!text) {
      return respond({ text: 'Usage: /pii <text to check for PII>' });
    }
    try {
      const result = core.scanText(text, { profile, platform: 'slack' });
      await respond(core.formatSlackMessage(result));
    } catch (err) {
      await respond({ text: ':x: Scan error: ' + err.message }).catch(() => {});
    }
  });

  app.command('/scrub', async ({ command, ack, respond }) => {
    await ack();
    const text = command.text;
    if (!text) {
      return respond({ text: 'Usage: /scrub <text to sanitize>' });
    }
    try {
      const result = core.scrubText(text, { profile });
      if (result.matches.length === 0) {
        return respond({ text: ':white_check_mark: No PII detected. Text is safe.' });
      }
      await respond({ text: ':soap: *Scrubbed text:*\n```\n' + result.scrubbed + '\n```' });
    } catch (err) {
      await respond({ text: ':x: Scrub error: ' + err.message }).catch(() => {});
    }
  });

  app.command('/help', async ({ ack, respond }) => {
    await ack();
    await respond({
      text: [
        '*AI Firewall Bot Commands*',
        '`/scan <text>` - Detect PII in text',
        '`/pii <text>` - Alias for scan',
        '`/scrub <text>` - Detect and return sanitized text',
        '`/help` - Show this message',
        profile !== 'none' ? '*Compliance profile:* ' + profile : '',
      ].filter(Boolean).join('\n')
    });
  });

  if (config.autoScan !== false && config.scanChannels && config.scanChannels.length > 0) {
    const channelSet = new Set(config.scanChannels);
    app.message(async ({ message, say }) => {
      if (message.bot_id || message.subtype) return;
      if (!channelSet.has(message.channel)) return;
      const text = message.text;
      if (!text || text.length < 10) return;
      try {
        const result = core.scanText(text, { profile, platform: 'slack' });
        if (result.matches.length > 0 && config.notifyOnPII !== false) {
          const minConf = config.minConfidence || 0.7;
          const highConfMatches = result.matches.filter(m => m.confidence >= minConf);
          if (highConfMatches.length > 0) {
            await say({
              text: ':warning: PII detected in message (' + highConfMatches.length + ' high-confidence items)',
              thread_ts: message.ts,
            });
          }
        }
      } catch (err) {
        console.error('[AI Firewall Slack] Auto-scan error:', err.message);
      }
    });
  }

  return app;
}

module.exports = { startSlackBot };
