const { scrub, computeRiskScore } = require('../cli');
const { BUILTIN_RULES } = require('../rules.cjs');

function scanText(text, options = {}) {
  const rules = options.rules || BUILTIN_RULES;
  const result = scrub(text, { mode: 'placeholder', rules });
  const riskScore = computeRiskScore(result.matches);
  return { ...result, riskScore };
}

function formatSlackMessage(result) {
  if (result.matches.length === 0) {
    return { text: ':white_check_mark: No PII detected.' };
  }
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: ':warning: PII Detected' } },
    { type: 'section', text: { type: 'mrkdwn', text: '*' + result.matches.length + '* PII items found (Risk: ' + result.riskScore + '/100)' } },
    { type: 'divider' },
  ];
  for (const m of result.matches.slice(0, 10)) {
    const confIcon = m.confidence >= 0.8 ? ':red_circle:' : ':large_orange_circle:';
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: '`' + m.type + '` ' + confIcon + ' `' + m.original.substring(0, 30) + (m.original.length > 30 ? '...' : '') + '`' }
    });
  }
  if (result.matches.length > 10) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: '...and ' + (result.matches.length - 10) + ' more items' }] });
  }
  return { blocks };
}

function formatDiscordEmbed(result) {
  if (result.matches.length === 0) {
    return { content: ':white_check_mark: No PII detected.' };
  }
  const color = result.riskScore >= 50 ? 0xff4444 : result.riskScore >= 20 ? 0xffaa00 : 0x44ff44;
  return {
    embeds: [{
      title: ':warning: PII Detected',
      color: color,
      fields: result.matches.slice(0, 10).map(m => ({
        name: m.type,
        value: '`' + m.original.substring(0, 40) + (m.original.length > 40 ? '...' : '') + '`\nConfidence: ' + Math.round(m.confidence * 100) + '%',
        inline: true,
      })),
      footer: { text: 'Risk Score: ' + result.riskScore + '/100 | ' + result.matches.length + ' total items' },
      timestamp: new Date().toISOString(),
    }],
  };
}

function formatPlainText(result) {
  if (result.matches.length === 0) {
    return 'No PII detected.';
  }
  let out = 'PII Detection Results\n';
  out += '=====================\n';
  out += 'Matches: ' + result.matches.length + ' | Risk Score: ' + result.riskScore + '/100\n\n';
  for (const m of result.matches) {
    out += '  [' + m.type + '] ' + m.original.substring(0, 40) + (m.original.length > 40 ? '...' : '') + ' (conf: ' + Math.round(m.confidence * 100) + '%)\n';
  }
  return out;
}

module.exports = { scanText, formatSlackMessage, formatDiscordEmbed, formatPlainText };
