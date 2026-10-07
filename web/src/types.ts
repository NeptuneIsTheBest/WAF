export type Role = "admin" | "operator" | "viewer";
export interface User {
  id: string;
  username: string;
  role: Role;
  disabled: boolean;
  created: string;
}
export interface Session {
  user: User;
  csrf_token: string;
  development: boolean;
}
export interface Upstream {
  url: string;
  weight: number;
  health_path: string;
}
export interface Scope {
  mode: "all" | "sites";
  site_ids: string[];
}
export const allSites = (): Scope => ({ mode: "all", site_ids: [] });
export interface Exclusion {
  scope: Scope;
  rule_id: number;
  path_prefix: string;
  target: string;
}
export type RuleAction =
  | "block"
  | "skip"
  | "log"
  | "managed_challenge"
  | "non_interactive_challenge"
  | "interactive_challenge";
export interface ChallengeOptions {
  work_factor: number;
  clearance_seconds: number;
}
export const defaultChallenge = (): ChallengeOptions => ({
  work_factor: 5000,
  clearance_seconds: 1800,
});
export const isChallengeAction = (action: string) =>
  [
    "managed_challenge",
    "non_interactive_challenge",
    "interactive_challenge",
  ].includes(action);
export interface CustomRule {
  scope: Scope;
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  expression: string;
  action: RuleAction;
  challenge?: ChallengeOptions;
  skip: string[];
}
export interface RateLimit {
  scope: Scope;
  id: string;
  name: string;
  enabled: boolean;
  expression: string;
  key: "ip" | "site" | "ip_path";
  requests_per_second: number;
  burst: number;
  ban_seconds: number;
}
export interface RoutePolicy {
  path_prefix: string;
  methods: string[];
  body_mode: "inspect" | "stream";
  max_body_bytes: number;
  idle_timeout_seconds: number;
  max_duration_seconds: number;
  max_concurrent: number;
}
export interface Site {
  id: string;
  name: string;
  enabled: boolean;
  domains: string[];
  https: boolean;
  redirect_http: boolean;
  dns_credential: string;
  upstreams: Upstream[];
  routes: RoutePolicy[];
  max_connections_per_ip: number;
  websocket_origins: string[];
}
export interface ManagedPolicy {
  mode: "off" | "observe" | "block";
  paranoia: number;
  threshold: number;
  exclusions: Exclusion[];
}
export interface ManagedOverride {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  scope: Scope;
  expression: string;
  policy: ManagedPolicy;
}
export interface Security {
  custom_rules: CustomRule[];
  rate_limits: RateLimit[];
  managed: { default: ManagedPolicy; overrides: ManagedOverride[] };
}
export interface Bundle {
  sites: Site[];
  security: Security;
}
export const defaultManaged = (): ManagedPolicy => ({
  mode: "observe",
  paranoia: 1,
  threshold: 5,
  exclusions: [],
});
export const defaultSecurity = (): Security => ({
  custom_rules: [],
  rate_limits: [],
  managed: { default: defaultManaged(), overrides: [] },
});
export const defaultBundle = (): Bundle => ({
  sites: [],
  security: defaultSecurity(),
});
export const scopeMatches = (scope: Scope, id: string) =>
  scope.mode === "all" || scope.site_ids.includes(id);
export function normalizeBundle(b: Bundle): Bundle {
  const security = b.security || defaultSecurity();
  const managed = (m: ManagedPolicy): ManagedPolicy => ({
    ...m,
    exclusions: (m.exclusions || []).map((x) => ({
      ...x,
      scope: { ...allSites(), ...x.scope, site_ids: x.scope?.site_ids || [] },
    })),
  });
  const scoped = <T extends { scope: Scope }>(r: T): T => ({
    ...r,
    scope: { ...allSites(), ...r.scope, site_ids: r.scope?.site_ids || [] },
  });
  return {
    ...b,
    sites: (b.sites || []).map(normalizeSite),
    security: {
      ...security,
      custom_rules: (security.custom_rules || []).map((r) => ({
        ...scoped(r),
        skip: r.skip || [],
      })),
      rate_limits: (security.rate_limits || []).map(scoped),
      managed: {
        default: managed(security.managed.default),
        overrides: (security.managed.overrides || []).map((o) => ({
          ...scoped(o),
          policy: managed(o.policy),
        })),
      },
    },
  };
}
export interface Draft {
  base_revision: number;
  version: number;
  bundle: Bundle;
}
export interface Revision {
  id: number;
  created: string;
  actor: string;
  crs_version: string;
  bundle: Bundle;
}
export interface ManagedRule {
  tunable: boolean;
  id: number;
  group: string;
  message: string;
  tags: string[];
  paranoia: number;
}
export interface Certificate {
  domain: string;
  credential: string;
  state: string;
  expires?: string;
  last_error?: string;
  last_event?: string;
  staging: boolean;
}
export interface SecurityEvent {
  id: number;
  time: string;
  site_id: string;
  request_id: string;
  client_ip: string;
  method: string;
  path: string;
  status: number;
  action: string;
  rule_id?: string;
  managed_policy_id?: string;
  matched_rule_ids?: number[];
  challenge_mode?: "non_interactive" | "interactive";
  message?: string;
  duration_ms: number;
  bytes: number;
  inspection: string;
  revision: number;
}
export interface Audit {
  id: number;
  time: string;
  actor: string;
  action: string;
  detail: string;
}
export interface Overview {
  stats: Record<string, number>;
  revision: number;
  crs_version: string;
  upstreams: {
    site_id: string;
    url: string;
    healthy: boolean;
    health_path: string;
  }[];
  certificates: Certificate[];
  development: boolean;
}
export const defaultRoute = (): RoutePolicy => ({
  path_prefix: "/",
  methods: [],
  body_mode: "inspect",
  max_body_bytes: 8 * 1024 * 1024,
  idle_timeout_seconds: 300,
  max_duration_seconds: 0,
  max_concurrent: 256,
});
export const defaultSite = (): Site => ({
  id: "",
  name: "",
  enabled: true,
  domains: [],
  https: true,
  redirect_http: true,
  dns_credential: "cloudflare",
  upstreams: [{ url: "", weight: 1, health_path: "/health" }],
  routes: [defaultRoute()],
  max_connections_per_ip: 32,
  websocket_origins: [],
});
export function normalizeSite(s: Site): Site {
  return {
    ...s,
    routes: s.routes || [],
    websocket_origins: s.websocket_origins || [],
  };
}
