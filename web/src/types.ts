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
export interface Exclusion {
  rule_id: number;
  path_prefix: string;
  target: string;
}
export interface CustomRule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  expression: string;
  action: "block" | "log" | "challenge" | "skip";
  skip: string[];
}
export interface RateLimit {
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
  allow_challenge: boolean;
}
export interface BotPolicy {
  enabled: boolean;
  user_agent_patterns: string[];
  requests_per_minute: number;
  action: "block" | "challenge";
  difficulty: number;
  clearance_seconds: number;
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
  managed: {
    mode: "off" | "observe" | "block";
    paranoia: number;
    threshold: number;
    exclusions: Exclusion[];
  };
  rules: CustomRule[];
  rate_limits: RateLimit[];
  routes: RoutePolicy[];
  bot: BotPolicy;
  max_connections_per_ip: number;
  websocket_origins: string[];
}
export interface Bundle {
  sites: Site[];
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
  allow_challenge: false,
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
  managed: { mode: "observe", paranoia: 1, threshold: 5, exclusions: [] },
  rules: [],
  rate_limits: [],
  routes: [defaultRoute()],
  bot: {
    enabled: false,
    user_agent_patterns: [],
    requests_per_minute: 120,
    action: "challenge",
    difficulty: 16,
    clearance_seconds: 1800,
  },
  max_connections_per_ip: 32,
  websocket_origins: [],
});
export function normalizeSite(s: Site): Site {
  return {
    ...s,
    rules: s.rules || [],
    rate_limits: s.rate_limits || [],
    routes: s.routes || [],
    websocket_origins: s.websocket_origins || [],
    managed: { ...s.managed, exclusions: s.managed.exclusions || [] },
    bot: { ...s.bot, user_agent_patterns: s.bot.user_agent_patterns || [] },
  };
}
