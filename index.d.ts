// ── PII Rule Types ──────────────────────────────────────────────

export interface PIIRule {
  id: string;
  name: string;
  label: string;
  regex: RegExp;
  conf: number;
  luhn?: boolean;
  custom?: boolean;
}

export interface CustomRuleConfig {
  id: string;
  name?: string;
  label?: string;
  regex: string;
  conf?: number;
  flags?: string;
  luhn?: boolean;
  enabled?: boolean;
  faker?: string;
}

export interface PIIMatch {
  type: string;
  name: string;
  original: string;
  replacement: string;
  confidence: number;
}

export interface ScanFinding {
  type: string;
  name: string;
  match: string;
  confidence: number;
  line: number;
  column: number;
}

export interface ScrubResult {
  scrubbed: string;
  matches: PIIMatch[];
}

export interface ScrubOptions {
  mode?: 'placeholder' | 'realistic';
  rules?: PIIRule[];
  fakers?: Record<string, () => string>;
}

// ── Config Types ────────────────────────────────────────────────

export interface AiFirewallConfig {
  mode?: 'placeholder' | 'realistic';
  format?: 'text' | 'json' | 'csv' | 'html';
  risk?: boolean;
  exclude?: string[];
  include?: string[];
  rules?: Array<{ id: string; enabled?: boolean; conf?: number }>;
  customRules?: CustomRuleConfig[];
}

export type ComplianceProfile = 'none' | 'gdpr' | 'hipaa' | 'pci-dss' | 'ccpa';

// ── Functions ──────────────────────────────────────────────────

export function scrub(text: string, options?: ScrubOptions): ScrubResult;

export function scanFile(filePath: string, rules: PIIRule[]): ScanFinding[];

export function scanDir(dirPath: string, config: AiFirewallConfig): Record<string, ScanFinding[]>;

export function loadConfig(configPath?: string | null): AiFirewallConfig;

export function resolveRules(config?: AiFirewallConfig, profile?: ComplianceProfile): PIIRule[];

export function computeRiskScore(matches: Array<{ type: string; confidence: number }>): number;

export function luhnCheck(num: string): boolean;

export function generateHtmlReport(results: Record<string, ScanFinding[]>, riskScore: number): string;

export function watchDir(watchPath: string, config: AiFirewallConfig): void;

export function getCustomFakers(config?: AiFirewallConfig): Record<string, () => string>;

// ── Encryption ─────────────────────────────────────────────────

export function encryptValue(text: string, keyObj: { key: Buffer; salt: Buffer } | Buffer): string;

export function decryptValue(encoded: string, passphraseOrKey: string | { key: Buffer; salt: Buffer } | Buffer): string | null;

export function deriveKey(passphrase: string, salt?: Buffer): { key: Buffer; salt: Buffer };

// ── Diff Report ────────────────────────────────────────────────

export function generateDiffReport(results: Record<string, ScanFinding[]>, origContents: Record<string, string>, scrubbedContents: Record<string, string>): string;

// ── Response Scanning ──────────────────────────────────────────

export interface ResponseFinding {
  type: string;
  name: string;
  match: string;
  confidence: number;
}

export interface ResponseScanResult {
  findings: ResponseFinding[];
  actionTaken: 'warn' | 'scrubbed';
  riskScore: number;
}

export function scanResponse(text: string, options?: {
  service?: string;
  mode?: 'warn' | 'scrub';
  profile?: string;
  rules?: any[];
}): ResponseScanResult;

export function scrubResponse(text: string, options?: {
  service?: string;
  profile?: string;
  rules?: any[];
}): { scrubbed: string; findings: ResponseFinding[]; riskScore: number };

// ── Enterprise Audit ───────────────────────────────────────────

export interface AuditEvent {
  id: number;
  timestamp: string;
  action: string;
  user_id?: string;
  resource_type?: string;
  resource_id?: string;
  risk_score?: number;
  details?: string;
}

export function getAuditEvents(options?: { limit?: number; action?: string; since?: string }): AuditEvent[];
export function logAuditEvent(event: { action: string; user_id?: string; resource_type?: string; resource_id?: string; risk_score?: number; details?: any }): void;

// ── Enterprise Compliance Export ────────────────────────────────

export interface ComplianceReport {
  reportType: string;
  periodStart: string;
  periodEnd: string;
  eventCount: number;
  generatedAt: string;
  generatedBy: string;
  report: any;
}

export function generateComplianceReport(options: {
  reportType: 'gdpr_art30' | 'soc2' | 'hipaa';
  periodStart: string;
  periodEnd: string;
  generatedBy?: string;
}): ComplianceReport;

// ── Enterprise API Keys ──────────────────────────────────────────

export interface ApiKey {
  id: string;
  key?: string;
  keyPrefix?: string;
  name: string;
  teamId: string;
  scopes: string;
  rateLimit: number;
  quotaDaily: number;
  enabled: number;
  lastUsedAt?: string;
  createdAt: string;
  revokedAt?: string;
}

export function generateApiKey(teamId: string, options?: {
  name?: string;
  scopes?: string[];
  rateLimit?: number;
  quotaDaily?: number;
}): ApiKey;

export function validateApiKey(rawKey: string): ApiKey | null;

// ── Enterprise Teams ─────────────────────────────────────────────

export interface Team {
  id: string;
  name: string;
  slug: string;
  plan: string;
  createdAt: string;
}

export interface TeamMember {
  teamId: string;
  userId: string;
  role: 'admin' | 'member' | 'viewer';
}

export function createTeam(options: { name: string; plan?: string; creatorId?: string }): Team;
export function getTeam(id: string): Team | null;
export function listTeamMembers(teamId: string): TeamMember[];

// ── Enterprise Scheduled Reports ─────────────────────────────────

export interface ScheduledReport {
  id: string;
  teamId: string;
  name: string;
  reportType: string;
  schedule: string;
  nextRunAt?: string;
  enabled: number;
}

export function createScheduledReport(options: {
  teamId: string;
  reportType: string;
  schedule?: string;
  name?: string;
}): ScheduledReport;
export function runScheduledReport(id: string): { success: boolean; report?: any };

// ── Phase 3: SSO ──────────────────────────────────────────────────

export interface SsoToken {
  token: string;
  sessionId: string;
  expiresAt: string;
  userId: string;
  email?: string | null;
  name?: string | null;
  teamId: string;
}

export interface SsoSession {
  id: string;
  teamId: string;
  userId: string;
  email?: string;
  name?: string;
  tokenType: string;
  issuedAt: string;
  expiresAt?: string;
  revokedAt?: string;
}

export function issueToken(teamId: string, options?: {
  subject?: string;
  userId?: string;
  email?: string;
  name?: string;
  scopes?: string[];
  ttlSeconds?: number;
  audience?: string;
}): SsoToken;
export function validateToken(token: string): Record<string, unknown> | null;
export function validateSession(token: string): { session: SsoSession; payload: Record<string, unknown> } | null;

// ── Phase 3: SCIM ─────────────────────────────────────────────────

export interface ScimUser {
  id: string;
  userName?: string;
  displayName?: string;
  email?: string;
  active: boolean;
}

export interface ScimGroup {
  id: string;
  displayName?: string;
  members: Array<{ value: string }>;
}

export function createScimUser(teamId: string | null, body: Record<string, unknown>): ScimUser;
export function listScimUsers(teamId: string | null): { totalResults: number; Resources: ScimUser[] };
export function createScimGroup(teamId: string | null, body: Record<string, unknown>): ScimGroup;

// ── Phase 3: Policy Engine ────────────────────────────────────────

export interface Policy {
  id: string;
  teamId?: string;
  name: string;
  enabled: number;
  priority: number;
  action: 'allow' | 'deny' | 'redact' | 'quarantine';
  scope: string;
  conditions: Record<string, unknown>;
}

export interface PolicyDecision {
  allowed: boolean;
  action: string;
  matched: boolean;
  policy: { id: string; name: string; priority: number; action: string } | null;
}

export function createPolicy(options: {
  name: string;
  teamId?: string;
  action?: string;
  scope?: string;
  conditions?: Record<string, unknown>;
  priority?: number;
}): Policy;
export function evaluate(context: {
  teamId?: string;
  userId?: string;
  scope?: string;
  channel?: string;
  text?: string;
  piiTypes?: string[];
  riskScore?: number;
}): PolicyDecision;

// ── Phase 3: Alerts ───────────────────────────────────────────────

export interface AlertRule {
  id: string;
  name: string;
  eventType: string;
  severity: string;
  enabled: number;
  channels: string[];
}

export interface Alert {
  id: string;
  ruleId?: string;
  severity: string;
  title: string;
  message: string;
  status: string;
}

export function createAlertRule(options: {
  name: string;
  teamId?: string;
  eventType?: string;
  severity?: string;
  channels?: string[];
  condition?: Record<string, unknown>;
}): AlertRule;
export function fireAlertEvent(event: {
  eventType: string;
  teamId?: string;
  severity?: string;
  title?: string;
  message?: string;
  payload?: Record<string, unknown>;
}): { count: number; alerts: string[] };
export function listAlerts(teamId: string | null): Alert[];

// ── Phase 3: Shadow Mode ──────────────────────────────────────────

export interface ShadowObservation {
  id: number;
  aiService: string;
  shadowRecorded: boolean;
  actionTaken: 'observed';
}

export function observeShadow(options: {
  teamId?: string;
  userId?: string;
  source?: string;
  eventType?: string;
  aiService?: string;
  url?: string;
  prompt?: string;
  response?: string;
  piiTypes?: string[];
  riskScore?: number;
}): ShadowObservation | null;

// ── Phase 3: Network Agent ────────────────────────────────────────

export interface NetworkAnalysis {
  piiTypes: string[];
  riskScore: number;
}

export function analyzePayload(payload: string): NetworkAnalysis;
export function recordNetworkConnection(options: {
  teamId?: string;
  sourceIp?: string;
  destIp?: string;
  destPort?: number;
  domain?: string;
  aiService?: string;
  protocol?: string;
  payload?: string;
  riskScore?: number;
}): { id: number; aiService: string | null; recorded: boolean };

// ── Phase 4: RBAC ──────────────────────────────────────────────────

export type PermissionAction = 'read' | 'write' | 'delete' | 'manage';

export interface PermissionGrant {
  teamId: string;
  userId: string;
  permission: string;
  granted: boolean;
}

export function hasPermission(teamId: string, userId: string, permission: string): boolean;
export function getPermissions(teamId: string, userId: string): { role?: string; permissions: string[] };
export function setMemberPermission(teamId: string, userId: string, permission: string, granted: boolean): PermissionGrant;
export function ensureSeedPermissions(): void;

// ── Phase 4: Multi-tenancy (Organizations) ─────────────────────────

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: string;
  status: string;
  createdAt: string;
}

export function createOrganization(options: {
  name: string;
  plan?: string;
  slug?: string;
  creatorId?: string;
}): Organization;
export function getOrganization(id: string): Organization | null;
export function listOrganizations(options?: { plan?: string }): Organization[];
export function addTeamToOrg(orgId: string, teamId: string): { linked: boolean };
export function listOrgTeams(orgId: string): Array<{ id: string; name: string }>;

// ── Phase 4: Advanced Reporting ────────────────────────────────────

export interface TrendPoint {
  day: string;
  events: number;
  pii_events: number;
  high_risk: number;
}

export function detectionTrend(teamId: string | null, period?: string): TrendPoint[];
export function piiTypeDistribution(teamId: string | null, period?: string): Array<{ piiType: string; count: number }>;
export function dashboard(teamId: string | null, period?: string): Record<string, unknown>;
export function runReport(teamId: string | null, options?: { period?: string; type?: string }): {
  id: string;
  markdown: string;
  data: Record<string, unknown>;
};

// ── Phase 4: Rule & Policy Marketplace ─────────────────────────────

export interface RulePack {
  id: string;
  slug: string;
  name: string;
  category?: string;
  version?: string;
  rules_count: number;
  installed: number;
}

export interface PolicyTemplate {
  id: string;
  slug: string;
  name: string;
  category?: string;
  action: string;
  conditions: Record<string, unknown>;
}

export function listRulePacks(options?: { category?: string }): RulePack[];
export function installPack(idOrSlug: string): { installed: boolean; packId: string; rulesInstalled: number };
export function listPolicyTemplates(category?: string): PolicyTemplate[];
export function applyTemplate(idOrSlug: string, options?: { teamId?: string; name?: string }): {
  applied: boolean;
  policy: Record<string, unknown>;
};

// ── Plugin System ──────────────────────────────────────────────

export interface PluginModule {
  rules?: CustomRuleConfig[];
  fakers?: Record<string, () => string>;
  formatters?: Record<string, (text: string) => string>;
}

export function loadPlugins(pluginPaths: string[]): PluginModule;

// ── Constants ──────────────────────────────────────────────────

export const BUILTIN_RULES: PIIRule[];
export const FAKERS: Record<string, () => string>;
export const COMPLIANCE_PROFILES: Record<string, { desc: string; match: (id: string) => boolean }>;

// ── Config file structure ──────────────────────────────────────

export const DEFAULT_CONFIG: AiFirewallConfig;

// ── Server Types ───────────────────────────────────────────────

export interface ServerOptions {
  config?: string | null;
  profile?: ComplianceProfile;
  mode?: 'placeholder' | 'realistic';
}

// ── Server Functions (from server.js) ──────────────────────────

export function createApp(configOpts?: ServerOptions): unknown;

export function startServer(port: number, configOpts?: ServerOptions, callback?: (server: unknown) => void): unknown;
