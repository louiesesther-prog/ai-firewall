const core = require('./core.cjs');

function startDiscordBot(config) {
  let Client, GatewayIntentBits;
  try {
    const djs = require('discord.js');
    Client = djs.Client;
    GatewayIntentBits = djs.GatewayIntentBits;
  } catch (e) {
    throw new Error(
      'Discord bot requires discord.js: npm install discord.js\n' +
      'Error: ' + e.message
    );
  }

  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,
    ],
  });

  const PREFIX = config.prefix || '!';
  const profile = config.profile || 'none';

  client.on('messageCreate', async (message) => {
    if (message.author.bot) return;

    if (message.content === PREFIX + 'help') {
      const embed = {
        title: 'AI Firewall Bot Commands',
        description: [
          '`' + PREFIX + 'scan <text>` - Detect PII in text',
          '`' + PREFIX + 'pii <text>` - Alias for scan',
          '`' + PREFIX + 'scrub <text>` - Detect and return sanitized text',
          '`' + PREFIX + 'help` - Show this message',
          profile !== 'none' ? '*Compliance profile:* ' + profile : '',
        ].filter(Boolean).join('\n'),
        color: 0x6366f1,
      };
      return message.reply({ embeds: [embed] });
    }

    if (message.content.startsWith(PREFIX + 'scan ') || message.content.startsWith(PREFIX + 'pii ')) {
      const prefixLen = message.content.startsWith(PREFIX + 'scan ') ? (PREFIX + 'scan ').length : (PREFIX + 'pii ').length;
      const text = message.content.slice(prefixLen);
      if (!text.trim()) {
        return message.reply('Usage: ' + PREFIX + 'scan <text to check for PII>');
      }
      try {
        const result = core.scanText(text, { profile, platform: 'discord' });
        const formatted = core.formatDiscordEmbed(result);
        await message.reply(formatted);
      } catch (err) {
        await message.reply(':x: Scan error: ' + err.message).catch(() => {});
      }
    }

    if (message.content.startsWith(PREFIX + 'scrub ')) {
      const text = message.content.slice((PREFIX + 'scrub ').length);
      if (!text.trim()) {
        return message.reply('Usage: ' + PREFIX + 'scrub <text to sanitize>');
      }
      try {
        const result = core.scrubText(text, { profile });
        if (result.matches.length === 0) {
          return message.reply(':white_check_mark: No PII detected. Text is safe.');
        }
        await message.reply(':soap: **Scrubbed text:**\n```\n' + result.scrubbed + '\n```');
      } catch (err) {
        await message.reply(':x: Scrub error: ' + err.message).catch(() => {});
      }
    }

    if (config.autoScan !== false && config.scanChannels && config.scanChannels.length > 0) {
      const channelSet = new Set(config.scanChannels);
      if (channelSet.has(message.channel.id) && message.content.length > 10) {
        try {
          const result = core.scanText(message.content, { profile, platform: 'discord' });
          if (result.matches.length > 0 && config.notifyOnPII !== false) {
            const minConf = config.minConfidence || 0.7;
            const highConfMatches = result.matches.filter(m => m.confidence >= minConf);
            if (highConfMatches.length > 0) {
              await message.reply({
                content: ':warning: **PII detected** in your message (' + highConfMatches.length + ' high-confidence items). Please review before posting.',
              });
            }
          }
        } catch (err) {
          console.error('[AI Firewall Discord] Auto-scan error:', err.message);
        }
      }
    }
  });

  client.on('interactionCreate', async (interaction) => {
    if (!interaction.isChatInputCommand()) return;

    if (interaction.commandName === 'scan') {
      const text = interaction.options.getString('text');
      if (!text) {
        return interaction.reply({ content: 'Usage: /scan <text>', ephemeral: true });
      }
      try {
        const result = core.scanText(text, { profile, platform: 'discord' });
        const formatted = core.formatDiscordEmbed(result);
        await interaction.reply(formatted);
      } catch (err) {
        await interaction.reply({ content: ':x: Scan error: ' + err.message, ephemeral: true }).catch(() => {});
      }
    }
  });

  client.login(config.token);
  return client;
}

module.exports = { startDiscordBot };
