const core = require('./core');

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

  app.command('/scan', async ({ command, ack, respond }) => {
    await ack();
    const text = command.text;
    if (!text) {
      return respond({ text: 'Usage: /scan <text to check for PII>' });
    }
    const result = core.scanText(text);
    await respond(core.formatSlackMessage(result));
  });

  app.command('/pii', async ({ command, ack, respond }) => {
    await ack();
    const text = command.text;
    if (!text) {
      return respond({ text: 'Usage: /pii <text to check for PII>' });
    }
    const result = core.scanText(text);
    await respond(core.formatSlackMessage(result));
  });

  if (config.scanChannels && config.scanChannels.length > 0) {
    const channelSet = new Set(config.scanChannels);
    app.message(async ({ message, say }) => {
      if (message.bot_id || message.subtype) return;
      if (!channelSet.has(message.channel)) return;
      const text = message.text;
      if (!text || text.length < 10) return;
      const result = core.scanText(text);
      if (result.matches.length > 0) {
        const minConf = config.minConfidence || 0.7;
        const highConfMatches = result.matches.filter(m => m.confidence >= minConf);
        if (highConfMatches.length > 0) {
          await say({
            text: ':warning: PII detected in message (' + highConfMatches.length + ' high-confidence items)',
            thread_ts: message.ts,
          });
        }
      }
    });
  }

  return app;
}

module.exports = { startSlackBot };
