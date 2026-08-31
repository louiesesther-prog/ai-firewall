// ── Enterprise Database Schema ────────────────────────────────────
// Extends the analytics DB with audit trail, webhooks, response scan,
// API key, team, and quota tables.

const ENTERPRISE_TABLES = `
  -- ── Teams / Organizations ──────────────────────────────────────
  CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'free',
    settings TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Team Members (roles) ──────────────────────────────────────
  CREATE TABLE IF NOT EXISTS team_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'member',
    invited_by TEXT,
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(team_id, user_id)
  );

  -- ── API Keys ──────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    scopes TEXT DEFAULT '["scrub","scan"]',
    rate_limit INTEGER DEFAULT 60,
    quota_daily INTEGER DEFAULT 10000,
    enabled INTEGER DEFAULT 1,
    last_used_at TEXT,
    expires_at TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT
  );

  -- ── API Key Usage (daily aggregates) ──────────────────────────
  CREATE TABLE IF NOT EXISTS api_key_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    date TEXT NOT NULL,
    requests INTEGER DEFAULT 0,
    pii_detections INTEGER DEFAULT 0,
    scrub_operations INTEGER DEFAULT 0,
    scan_operations INTEGER DEFAULT 0,
    response_scans INTEGER DEFAULT 0,
    UNIQUE(key_id, date)
  );

  -- ── Usage Quotas / Limits ─────────────────────────────────────
  CREATE TABLE IF NOT EXISTS usage_quotas (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    quota_type TEXT NOT NULL,
    limit_value INTEGER NOT NULL,
    period TEXT NOT NULL DEFAULT 'monthly',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Scheduled Reports ─────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS scheduled_reports (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    report_type TEXT NOT NULL,
    schedule TEXT NOT NULL,
    recipients TEXT DEFAULT '[]',
    delivery_method TEXT DEFAULT 'webhook',
    last_run_at TEXT,
    next_run_at TEXT,
    enabled INTEGER DEFAULT 1,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Scheduled Report History ───────────────────────────────────
  CREATE TABLE IF NOT EXISTS scheduled_report_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id TEXT NOT NULL REFERENCES scheduled_reports(id) ON DELETE CASCADE,
    report_id TEXT,
    status TEXT DEFAULT 'pending',
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    error_message TEXT,
    delivery_status TEXT
  );

  -- ── Response scan tracking ────────────────────────────────────
  CREATE TABLE IF NOT EXISTS response_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER REFERENCES scan_events(id) ON DELETE SET NULL,
    source_url TEXT,
    ai_service TEXT,
    pii_found INTEGER DEFAULT 0,
    action_taken TEXT DEFAULT 'warned',
    response_length INTEGER,
    user_id TEXT,
    team_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Full audit trail (immutable, append-only) ─────────────────
  CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    user_id TEXT,
    team_id TEXT,
    session_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    pii_types TEXT,
    risk_score INTEGER,
    action_taken TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata TEXT,
    compliance_profile TEXT,
    retention_until TEXT
  );

  -- ── Compliance report generation ──────────────────────────────
  CREATE TABLE IF NOT EXISTS compliance_reports (
    id TEXT PRIMARY KEY,
    team_id TEXT,
    report_type TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    generated_by TEXT,
    status TEXT DEFAULT 'generating',
    file_path TEXT,
    row_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT
  );

  -- ── Webhook configurations ────────────────────────────────────
  CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    team_id TEXT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT,
    events TEXT NOT NULL DEFAULT '["scan"]',
    headers TEXT DEFAULT '{}',
    enabled INTEGER DEFAULT 1,
    failure_count INTEGER DEFAULT 0,
    last_triggered_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Webhook delivery log ──────────────────────────────────────
  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    response_code INTEGER,
    error_message TEXT,
    attempts INTEGER DEFAULT 0,
    next_retry_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    delivered_at TEXT
  );

  -- ═════════════════════════────────────────────────────────────
  -- ── Phase 3: Identity - SSO Providers & Sessions ─────────────
  -- ═════════════════════════────────────────────────────────────
  CREATE TABLE IF NOT EXISTS sso_providers (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL DEFAULT 'generic',   -- generic | jwt | hmac
    issuer TEXT,
    client_id TEXT,
    client_secret TEXT,
    signing_key TEXT,
    metadata_url TEXT,
    enabled INTEGER DEFAULT 1,
    config TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sso_sessions (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    provider_id TEXT REFERENCES sso_providers(id) ON DELETE SET NULL,
    user_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    token TEXT,
    token_type TEXT DEFAULT 'jwt',
    issued_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    revoked_at TEXT,
    last_seen_at TEXT,
    ip_address TEXT,
    user_agent TEXT,
    scopes TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}'
  );

  -- ── SCIM: Users & Groups (provisioned identities) ────────────
  CREATE TABLE IF NOT EXISTS scim_users (
    id TEXT PRIMARY KEY,
    external_id TEXT UNIQUE,
    user_name TEXT,
    display_name TEXT,
    email TEXT,
    given_name TEXT,
    family_name TEXT,
    active INTEGER DEFAULT 1,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    attributes TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    deleted_at TEXT
  );

  CREATE TABLE IF NOT EXISTS scim_groups (
    id TEXT PRIMARY KEY,
    display_name TEXT,
    external_id TEXT UNIQUE,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS scim_group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES scim_users(id) ON DELETE CASCADE,
    UNIQUE(group_id, user_id)
  );

  -- ═════════════════════════────────────────────────────────────
  -- ── Phase 3: Policy Engine (Data Guardrails) ─────────────────
  -- ═════════════════════════────────────────────────────────────
  CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,   -- NULL = global default
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 500,                          -- higher = evaluated first
    action TEXT NOT NULL DEFAULT 'allow',                  -- allow | deny | redact | quarantine
    scope TEXT NOT NULL DEFAULT '*',                       -- engine channels (scrub|scan|outbound|prompt|all)
    conditions TEXT DEFAULT '{}',                          -- JSON condition config
    channel TEXT DEFAULT 'all',                            -- apply-to channel
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS policy_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT REFERENCES policies(id) ON DELETE SET NULL,
    team_id TEXT,
    user_id TEXT,
    action TEXT,                      -- denied | redacted | quarantined
    scope TEXT,
    pii_types TEXT,
    risk_score INTEGER,
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ═════════════════════════────────────────────────────────────
  -- ── Phase 3: Alerts (reactive notifications) ─────────────────
  -- ═════════════════════════────────────────────────────────────
  CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER DEFAULT 1,
    event_type TEXT NOT NULL,          -- high_risk | pii_detected | policy_violation | quota_exceeded | shadow_usage | custom
    condition TEXT DEFAULT '{}',       -- JSON threshold config
    severity TEXT DEFAULT 'medium',    -- info | low | medium | high | critical
    channels TEXT DEFAULT '["webhook"]',  -- webhook | syslog | email | log
    cooldown_seconds INTEGER DEFAULT 0,
    last_fired_at TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT REFERENCES alert_rules(id) ON DELETE SET NULL,
    team_id TEXT,
    event_type TEXT,
    severity TEXT,
    title TEXT,
    message TEXT,
    payload TEXT DEFAULT '{}',
    status TEXT DEFAULT 'open',        -- open | acknowledged | resolved | dismissed
    acknowledged_by TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ═════════════════════════────────────────────────────────────
  -- ── Phase 3: Shadow Mode (log-only AI usage detection) ───────
  -- ═════════════════════════────────────────────────────────────
  CREATE TABLE IF NOT EXISTS shadow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id TEXT,
    user_id TEXT,
    source TEXT,                       -- extension | api | cli | network | browser
    event_type TEXT,                   -- prompt_sent | response_received | ai_service_seen
    ai_service TEXT,                   -- chatgpt | claude | gemini | copilot | custom
    url TEXT,
    prompt_preview TEXT,
    response_preview TEXT,
    pii_detected INTEGER DEFAULT 0,
    pii_types TEXT DEFAULT '[]',
    risk_score INTEGER DEFAULT 0,
    action_taken TEXT DEFAULT 'observed',  -- observed (shadow mode never blocks)
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Network Agent (packet / connection-level detection) ───────
  CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    domain TEXT,
    ai_service TEXT,
    connection_type TEXT,
    payload_preview TEXT,
    pii_detected INTEGER DEFAULT 0,
    pii_types TEXT DEFAULT '[]',
    risk_score INTEGER DEFAULT 0,
    action_taken TEXT DEFAULT 'observed',
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ═════════════════════════────────────────────────────────────
  -- ── Phase 4: Multi-Tenancy (Organizations) ───────────────────
  -- ═════════════════════════────────────────────────────────────
  CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'free',
    status TEXT DEFAULT 'active',
    settings TEXT DEFAULT '{}',
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS org_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'member',   -- owner | admin | member | viewer
    invited_by TEXT,
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(org_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS org_teams (
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (org_id, team_id)
  );

  -- ═════════════════════════────────────────────────────────────
  -- ── Phase 4: RBAC (permissions) ──────────────────────────────
  -- ═════════════════════════────────────────────────────────────
  CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,             -- e.g. api_keys.read, api_keys.write
    resource TEXT NOT NULL,                -- api_keys | policies | teams | alerts | audit | reports ...
    action TEXT NOT NULL,                  -- read | write | delete | manage
    description TEXT
  );

  CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,                    -- admin | member | viewer | owner
    permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE(role, permission_id)
  );

  CREATE TABLE IF NOT EXISTS member_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted INTEGER DEFAULT 1,             -- 1 grant, 0 deny (overrides role)
    UNIQUE(team_id, user_id, permission_id)
  );

  -- ═════════════════════════────────────────────────────────────
  -- ── Phase 4: Rule & Policy Marketplace ───────────────────────
  -- ═════════════════════════────────────────────────────────────
  CREATE TABLE IF NOT EXISTS rule_packs (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    version TEXT DEFAULT '1.0.0',
    category TEXT,                         -- hipaa | pci | gdpr | ccpa | soc2 | general
    author TEXT,
    license TEXT,
    enabled INTEGER DEFAULT 1,
    installed INTEGER DEFAULT 0,
    rules_count INTEGER DEFAULT 0,
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS rule_pack_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pack_id TEXT NOT NULL REFERENCES rule_packs(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_json TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS policy_templates (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT,                         -- compliance | data-loss | ai-guardrails
    action TEXT DEFAULT 'redact',
    conditions TEXT DEFAULT '{}',
    scope TEXT DEFAULT '*',
    enabled INTEGER DEFAULT 1,
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Indexes for performance ───────────────────────────────────
  CREATE INDEX IF NOT EXISTS idx_response_scans_service ON response_scans(ai_service);
  CREATE INDEX IF NOT EXISTS idx_response_scans_user ON response_scans(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_team ON audit_events(team_id);
  CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
  CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
  CREATE INDEX IF NOT EXISTS idx_audit_retention ON audit_events(retention_until);
  CREATE INDEX IF NOT EXISTS idx_compliance_team ON compliance_reports(team_id);
  CREATE INDEX IF NOT EXISTS idx_webhooks_team ON webhooks(team_id);
  CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
  CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);
  CREATE INDEX IF NOT EXISTS idx_teams_slug ON teams(slug);
  CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
  CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_keys_team ON api_keys(team_id);
  CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
  CREATE INDEX IF NOT EXISTS idx_api_key_usage_key ON api_key_usage(key_id);
  CREATE INDEX IF NOT EXISTS idx_api_key_usage_date ON api_key_usage(date);
  CREATE INDEX IF NOT EXISTS idx_usage_quotas_team ON usage_quotas(team_id);
  CREATE INDEX IF NOT EXISTS idx_scheduled_reports_team ON scheduled_reports(team_id);
  CREATE INDEX IF NOT EXISTS idx_scheduled_reports_next ON scheduled_reports(next_run_at);
  CREATE INDEX IF NOT EXISTS idx_scheduled_report_history_schedule ON scheduled_report_history(schedule_id);
  CREATE INDEX IF NOT EXISTS idx_sso_sessions_team ON sso_sessions(team_id);
  CREATE INDEX IF NOT EXISTS idx_sso_sessions_user ON sso_sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sso_sessions_token ON sso_sessions(token);
  CREATE INDEX IF NOT EXISTS idx_scim_users_email ON scim_users(email);
  CREATE INDEX IF NOT EXISTS idx_scim_users_active ON scim_users(active);
  CREATE INDEX IF NOT EXISTS idx_scim_group_members_group ON scim_group_members(group_id);
  CREATE INDEX IF NOT EXISTS idx_policies_team ON policies(team_id);
  CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies(scope);
  CREATE INDEX IF NOT EXISTS idx_policy_events_policy ON policy_events(policy_id);
  CREATE INDEX IF NOT EXISTS idx_policy_events_team ON policy_events(team_id);
  CREATE INDEX IF NOT EXISTS idx_alert_rules_team ON alert_rules(team_id);
  CREATE INDEX IF NOT EXISTS idx_alert_rules_event ON alert_rules(event_type);
  CREATE INDEX IF NOT EXISTS idx_alerts_team ON alerts(team_id);
  CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
  CREATE INDEX IF NOT EXISTS idx_shadow_events_team ON shadow_events(team_id);
  CREATE INDEX IF NOT EXISTS idx_shadow_events_service ON shadow_events(ai_service);
  CREATE INDEX IF NOT EXISTS idx_network_events_team ON network_events(team_id);
  CREATE INDEX IF NOT EXISTS idx_network_events_ip ON network_events(source_ip);
  CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
  CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id);
  CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id);
  CREATE INDEX IF NOT EXISTS idx_org_teams_org ON org_teams(org_id);
  CREATE INDEX IF NOT EXISTS idx_org_teams_team ON org_teams(team_id);
  CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
  CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role);
  CREATE INDEX IF NOT EXISTS idx_member_permissions_team ON member_permissions(team_id);
  CREATE INDEX IF NOT EXISTS idx_rule_packs_category ON rule_packs(category);
  CREATE INDEX IF NOT EXISTS idx_rule_pack_rules_pack ON rule_pack_rules(pack_id);
  CREATE INDEX IF NOT EXISTS idx_policy_templates_category ON policy_templates(category);
`;

function initEnterpriseSchema(database) {
  try {
    database.exec(ENTERPRISE_TABLES);
    return true;
  } catch (e) {
    console.warn('[enterprise-db] Schema init failed:', e.message);
    return false;
  }
}

module.exports = { initEnterpriseSchema, ENTERPRISE_TABLES };
