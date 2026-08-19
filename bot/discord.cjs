const core = require('./core');

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

  client.on('messageCreate', async (message) => {
    if (message.author.bot) return;

    if (message.content.startsWith(PREFIX + 'scan ')) {
      const text = message.content.slice((PREFIX + 'scan ').length);
      if (!text.trim()) {
        return message.reply('Usage: ' + PREFIX + 'scan <text to check for PII>');
      }
      const result = core.scanText(text);
      const formatted = core.formatDiscordEmbed(result);
      await message.reply(formatted);
    }

    if (message.content.startsWith(PREFIX + 'pii ')) {
      const text = message.content.slice((PREFIX + 'pii ').length);
      if (!text.trim()) {
        return message.reply('Usage: ' + PREFIX + 'pii <text to check for PII>');
      }
      const result = core.scanText(text);
      const formatted = core.formatDiscordEmbed(result);
      await message.reply(formatted);
    }

    if (config.scanChannels && config.scanChannels.length > 0) {
      const channelSet = new Set(config.scanChannels);
      if (channelSet.has(message.channel.id) && message.content.length > 10) {
        const result = core.scanText(message.content);
        if (result.matches.length > 0) {
          const minConf = config.minConfidence || 0.7;
          const highConfMatches = result.matches.filter(m => m.confidence >= minConf);
          if (highConfMatches.length > 0) {
            await message.reply({
              content: ':warning: **PII detected** in your message (' + highConfMatches.length + ' high-confidence items). Please review before posting.',
            });
          }
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
      const result = core.scanText(text);
      const formatted = core.formatDiscordEmbed(result);
      await interaction.reply(formatted);
    }
  });

  client.login(config.token);
  return client;
}

module.exports = { startDiscordBot };
