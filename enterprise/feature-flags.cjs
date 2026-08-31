// ── Enterprise Feature Flags (Open Core) ──────────────────────────
// Enable via env vars, .ai-firewallrc enterprise config, or programmatic.
//
// Open-core gating: flags are only honored when the active license tier
// is high enough AND the flag is enabled. Without a key the tier is
// "community" and every enterprise flag stays off (free core).
//   - team tier      unlocks: apiKeys, quotas, scheduled, sso, teams,
//                     alerts, webhooks, guardrails, responseScan, reporting
//   - enterprise tier: everything (incl. scim, rbac, tenancy, shadow,
//                     networkAgent, marketplace, audit, policy)

const FALSY = new Set(['0', 'false', 'no', 'off', '']);

// Minimum license tier required per module. Lowercase tier names.
const TIER_REQUIREMENTS = {
  audit:        'team',
  sso:          'team',
  scim:         'enterprise',
  policy:       'team',
  alerts:       'team',
  webhooks:     'team',
  guardrails:   'team',
  shadow:       'enterprise',
  responseScan: 'team',
  networkAgent: 'enterprise',
  apiKeys:      'team',
  teams:        'team',
  quotas:       'team',
  scheduled:    'team',
  rbac:         'enterprise',
  tenancy:      'enterprise',
  reporting:    'team',
  marketplace:  'enterprise',
};

function flagKey(flagName) {
  return 'ENTERPRISE_' + flagName.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();
}

// Resolve a flag value: an explicit per-module flag wins, otherwise fall back
// to ENTERPRISE_ALL. Absent → disabled; falsy string ("0"/"false"/"no"/"off")
// → disabled (allows per-module override off even when ENTERPRISE_ALL is set).
function envEnabled(flagName, env) {
  const key = flagKey(flagName);
  if (Object.prototype.hasOwnProperty.call(env, key)) {
    const v = String(env[key]).trim().toLowerCase();
    return v !== '' && !FALSY.has(v);
  }
  if (Object.prototype.hasOwnProperty.call(env, 'ENTERPRISE_ALL')) {
    const v = String(env.ENTERPRISE_ALL).trim().toLowerCase();
    return v !== '' && !FALSY.has(v);
  }
  return false;
}

// Tier of the currently installed license. Lazily imported so tests that
// stub process.env get a fresh read.
function currentTier() {
  try {
    const lic = require('./license.cjs');
    return lic.current().tier;
  } catch (e) {
    return 'community';
  }
}

const TIER_ORDER = { community: 0, team: 1, enterprise: 2 };

function tierAtLeast(actual, min) {
  return (TIER_ORDER[actual] || 0) >= (TIER_ORDER[min] || 0);
}

function resolveFlag(flagName, env) {
  const want = envEnabled(flagName, env);
  if (!want) return false;
  const min = TIER_REQUIREMENTS[flagName] || 'team';
  return tierAtLeast(currentTier(), min);
}

const flags = {
  audit:        resolveFlag('audit', process.env),
  sso:          resolveFlag('sso', process.env),
  scim:         resolveFlag('scim', process.env),
  policy:       resolveFlag('policy', process.env),
  alerts:       resolveFlag('alerts', process.env),
  webhooks:     resolveFlag('webhooks', process.env),
  guardrails:   resolveFlag('guardrails', process.env),
  shadow:       resolveFlag('shadow', process.env),
  responseScan: resolveFlag('responseScan', process.env),
  networkAgent: resolveFlag('networkAgent', process.env),
  apiKeys:      resolveFlag('apiKeys', process.env),
  teams:        resolveFlag('teams', process.env),
  quotas:       resolveFlag('quotas', process.env),
  scheduled:    resolveFlag('scheduled', process.env),
  rbac:         resolveFlag('rbac', process.env),
  tenancy:      resolveFlag('tenancy', process.env),
  reporting:    resolveFlag('reporting', process.env),
  marketplace:  resolveFlag('marketplace', process.env),
};

function isEnabled(flagName) {
  return !!flags[flagName];
}

function enable(flagName) {
  flags[flagName] = true;
}

function disable(flagName) {
  flags[flagName] = false;
}

function getAllFlags() {
  return Object.assign({}, flags);
}

function getTierRequirements() {
  return Object.assign({}, TIER_REQUIREMENTS);
}

module.exports = { isEnabled, enable, disable, getAllFlags, flags, getTierRequirements };
