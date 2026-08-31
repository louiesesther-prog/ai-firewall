// ── Response Scanner ──────────────────────────────────────────────
// Scans AI response text for PII. Applies higher thresholds than input
// scanner to reduce false positives on AI "teaching" content.

const { scrub, computeRiskScore } = require('../cli.js');

const RESPONSE_CONFIDENCE_THRESHOLD = 0.65;

function scanResponse(text, options) {
  options = options || {};
  var service = options.service || 'unknown';
  var threshold = options.threshold || RESPONSE_CONFIDENCE_THRESHOLD;
  var mode = options.mode || 'warn';
  var profile = options.profile || 'none';

  if (!text || typeof text !== 'string') {
    return { findings: [], riskScore: 0, actionTaken: 'none', service: service };
  }

  var result = scrub(text, {
    mode: mode === 'scrub' ? (options.realistic ? 'realistic' : 'placeholder') : 'placeholder',
    rules: options.rules || undefined,
    fakers: options.fakers || undefined,
  });

  var findings = result.matches.filter(function(m) {
    return m.confidence >= threshold;
  });

  var riskScore = computeRiskScore(findings.map(function(m) {
    return { type: m.type, confidence: m.confidence };
  }));

  var actionTaken = 'warned';
  if (findings.length === 0) {
    actionTaken = 'none';
  } else if (mode === 'scrub') {
    actionTaken = 'scrubbed';
  } else if (mode === 'block') {
    actionTaken = 'blocked';
  }

  return {
    findings: findings.map(function(m) {
      return {
        type: m.type,
        name: m.name,
        match: m.original,
        replacement: m.replacement,
        confidence: m.confidence,
      };
    }),
    riskScore: riskScore,
    actionTaken: actionTaken,
    service: service,
    inputLength: text.length,
    responseLength: text.length,
    profile: profile,
  };
}

function scrubResponse(text, options) {
  options = options || {};
  var mode = options.mode || 'placeholder';
  var profile = options.profile || 'none';

  if (!text || typeof text !== 'string') {
    return { scrubbed: text, matches: [], actionTaken: 'none' };
  }

  var result = scrub(text, {
    mode: mode,
    rules: options.rules || undefined,
    fakers: options.fakers || undefined,
  });

  return {
    scrubbed: result.scrubbed,
    matches: result.matches,
    matchesFound: result.matches.length,
    actionTaken: result.matches.length > 0 ? 'scrubbed' : 'none',
    inputLength: text.length,
    profile: profile,
  };
}

module.exports = { scanResponse, scrubResponse, RESPONSE_CONFIDENCE_THRESHOLD };
