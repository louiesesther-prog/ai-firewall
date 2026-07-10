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

export function encryptValue(text: string, key: Buffer): string;

export function decryptValue(encoded: string, key: Buffer): string | null;

export function deriveKey(passphrase: string): Buffer;

// ── Diff Report ────────────────────────────────────────────────

export function generateDiffReport(results: Record<string, ScanFinding[]>, origContents: Record<string, string>, scrubbedContents: Record<string, string>): string;

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
