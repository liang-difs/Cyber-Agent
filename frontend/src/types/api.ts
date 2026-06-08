// Auth
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  role: string;
  tenant_id: string;
}

export interface JwtPayload {
  sub: string;
  user_id?: string;
  role: string;
  tenant_id: string;
  exp: number;
}

// CVE
export interface CveItem {
  id: string;
  cve_id: string;
  description: string;
  cvss_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  published: string;
}

export interface CveListResponse {
  items: CveItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface CveStatsResponse {
  total: number;
  by_severity: Record<string, number>;
  recent: Array<{
    id: string;
    severity: string;
    cvss_score: number;
    published: string;
  }>;
}

// WebSocket events
export type WSEvent =
  | { type: 'llm_backend'; provider: string; model: string }
  | { type: 'tool_call'; tool: string; status: 'running'; tool_call_id?: string }
  | { type: 'tool_result'; tool: string; success: boolean; tool_call_id?: string; evidence?: EvidenceItem[]; evidence_source?: string[]; execution_time_ms?: number; error?: string }
  | { type: 'token'; content: string }
  | { type: 'thinking'; content: string }
  | { type: 'usage'; total_tokens: number }
  | { type: 'done'; session_id: string; total_tokens: number }
  | { type: 'error'; code: string; message: string };

// Chat
export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  thinking?: string;        // 推理摘要（完整内容折叠）
  streaming?: boolean;
  toolCalls?: Array<Record<string, any>>;
  toolCallId?: string;
  metadata?: Record<string, any>;
}

// Tool Execution State Machine
export type ToolStatus = 'queued' | 'running' | 'retrying' | 'success' | 'timeout' | 'failed' | 'cancelled';

export interface ToolExecution {
  id: string;              // tool_call_id
  tool: string;
  label?: string;
  status: ToolStatus;
  startTime: number;
  endTime?: number;
  messageId?: string;
  error?: string;
  retryCount?: number;
  input?: Record<string, any>;
  evidence?: EvidenceItem[];
  ragSummary?: {
    query: string;
    found: boolean;
    resultCount: number;
    sources: string[];
  };
}

export interface EvidenceItem {
  source: string;          // "VirusTotal" | "NVD" | "AbuseIPDB" | "OTX"
  label?: string;          // "72/100" | "3 pulses"
  url?: string;
  confidence?: number;     // 0-1
}

// Usage Metrics (session-level)
export interface UsageMetrics {
  promptTokens: number;
  completionTokens: number;
  reasoningTokens: number;
  toolTokens: number;
  totalTokens: number;
  turnCount: number;
}

// Streaming state
export type StreamingState = 'idle' | 'thinking' | 'tool_calling' | 'answering';

export interface Session {
  id: string;
  title: string;
  lastMessage: string;
  updatedAt: number;
  messageCount?: number;
  summary?: string;
  modelName?: string;
  userId?: string;
  tenantId?: string;
}

// Task
export interface TaskStatus {
  task_id: string;
  status: string;
  result: any;
  traceback?: string;
  warning?: string;
}

export interface PcapUploadResponse {
  task_id: string;
  status: string;
  queue: string;
  filename: string;
  size_bytes: number;
  sync?: boolean;
  result?: PcapResult;
}

export interface AlertTriageResult {
  task_id: string;
  status: string;
  queue: string;
  result?: Record<string, any>;
  warning?: string;
}

export interface AlertTriageOutcome {
  alert_id: string;
  verdict: string;
  confidence: number;
  ttps: Array<{ tactic: string; name: string; technique: string }>;
  tactic?: string;
  ttp_ids?: string[];
  reasoning?: string;
  tenant_id?: string;
  assessment?: AlertAssessment;
  enrichment?: {
    ip_reputation?: number | null;
    geo?: Record<string, any> | null;
  };
}

export interface AlertAssessment {
  confidence: number;
  confidence_label: 'low' | 'medium' | 'high';
  facts: string[];
  inferences: string[];
  boundary: string[];
  evidence: string[];
}

// Pcap Analysis
export interface PcapAnomaly {
  type: string;
  severity: string;
  src_ip?: string;
  dst_ip?: string;
  detail?: string;
  first_seen?: number;
  last_seen?: number;
  unique_ports?: number;
  sample_ports?: string[];
  total_bytes?: number;
  connection_count?: number;
  dst_port?: number | string;
  mean_interval_s?: number;
  cv?: number;
  tls_version?: string;
  server_name?: string;
  sample_domains?: string[];
}

export interface PcapSummary {
  total_packets: number;
  total_flows: number;
  duration_s: number;
  total_bytes: number;
  start_time: string;
  end_time: string;
  anomaly_count: number;
  top_protocols: Array<{ protocol: string; count: number }>;
}

export interface PcapFlow {
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  app_protocol: string;
  packets: number;
  bytes: number;
  start_time: number;
  end_time: number;
  duration_s: number;
  direction: string;
  tcp_flags: { SYN: number; ACK: number; RST: number; FIN: number };
}

export interface DnsQuery {
  name: string;
  type: string;
  response: string;
  timestamp: number;
  src_ip: string;
}

export interface DnsStats {
  total_queries: number;
  unique_domains: number;
  query_types: Record<string, number>;
  top_domains: Array<{ domain: string; count: number }>;
  long_subdomains: string[];
  txt_queries: string[];
  high_frequency: Array<{ domain: string; count: number; window_s: number }>;
}

export interface ProtocolInsights {
  http_hosts: Array<{ host: string; count: number; methods: string[] }>;
  tls_sni: Array<{ server_name: string; count: number; tls_versions: string[] }>;
  tls_versions: Record<string, number>;
  ssh_versions: string[];
}

export interface TimelineEvent {
  timestamp: number;
  event_type: string;
  src_ip: string;
  dst_ip?: string;
  detail: string;
}

export interface PcapResult {
  success: boolean;
  summary?: PcapSummary;
  pcap_identity?: {
    display_filename?: string;
    original_filename?: string;
    source_path?: string;
    sha256?: string | null;
  };
  flows?: PcapFlow[];
  anomalies?: PcapAnomaly[];
  protocols?: Record<string, number>;
  ips?: {
    source_ips: string[];
    destination_ips: string[];
    internal_ips: string[];
    external_ips: string[];
  };
  dns?: { queries: DnsQuery[]; stats: DnsStats };
  protocol_insights?: ProtocolInsights;
  timeline?: TimelineEvent[];
  external_ips_for_lookup?: string[];
  domains_for_lookup?: string[];
  llm_context?: Record<string, any>;
  warning?: string;
  error?: string;
  tenant_id?: string;
  sanitized_for_llm?: boolean;
  redaction_count?: number;
}

// Alerts
export interface AlertAsset {
  name?: string;
  asset_type?: string;
  criticality?: string;
  owner?: string;
  department?: string;
}

export interface Alert {
  id: string;
  rule_id: string;
  src_ip?: string;
  dst_ip?: string;
  severity: string;
  status: string;
  verdict?: string;
  confidence: number;
  description?: string;
  ttp_ids?: string[];
  assessment?: AlertAssessment;
  asset?: AlertAsset;
  tenant_id: string;
  created_at: string;
  updated_at: string;
}

// Attack Chain
export interface ChainNode {
  alert_id: string;
  rule_id: string;
  src_ip?: string;
  dst_ip?: string;
  tactic: string;
  severity: string;
  timestamp: string;
  description?: string;
}

export interface AttackChain {
  chain_id: string;
  length: number;
  src_ips: string[];
  dst_ips: string[];
  tactics_covered: string[];
  progression_score: number;
  severity: string;
  nodes: ChainNode[];
}

export interface AttackChainResponse {
  chains: AttackChain[];
  total_alerts: number;
  warning?: string;
}

// Correlation
export interface CorrelationPattern {
  pattern_type: string;
  description: string;
  confidence: number;
  related_alerts: string[];
  metadata?: Record<string, any>;
}

export interface CorrelationResponse {
  total_alerts: number;
  patterns: CorrelationPattern[];
  top_src_ips: Array<{ ip: string; count: number }>;
  top_rules: Array<{ rule_id: string; count: number }>;
  severity_distribution: Record<string, number>;
  time_range?: { earliest: string; latest: string };
  warning?: string;
}

// Audit
export interface AuditLog {
  id: string;
  user_id?: string;
  action: string;
  resource: string;
  detail?: Record<string, any>;
  ip_address?: string;
  tenant_id: string;
  created_at: string;
}

export interface AuditLogResponse {
  logs: AuditLog[];
  total: number;
  limit?: number;
  offset?: number;
  warning?: string;
  error?: string;
}

// Health
export interface HealthCheck {
  status: string;
  cluster_status?: string;
  detail?: string;
  workers?: number;
  default_model?: string;
  fallback_models?: string[];
  circuits?: Record<string, { failures: number; open: boolean; reset_in_seconds: number }>;
  usage_event_count?: number;
  total_cost_usd?: number;
  recent_usage?: Array<Record<string, any>>;
}

export interface HealthResponse {
  status: string;
  timestamp: string;
  version: string;
  checks?: Record<string, HealthCheck>;
}

// Dashboard
export interface DashboardAlertSummary {
  rule_id: string;
  severity: string;
  src_ip?: string;
  dst_ip?: string;
  status: string;
  created_at?: string;
}

export interface DashboardData {
  alerts: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    recent: DashboardAlertSummary[];
    trend: Array<{ date: string; critical: number; high: number; medium: number; low: number }>;
  };
  cve: {
    total: number;
    by_severity: Record<string, number>;
    recent: Array<{ id: string; severity: string; cvss_score?: number; published?: string }>;
  };
  health: {
    status: string;
    services: Record<string, string>;
    llm_model?: string;
  };
  session_count: number;
  timestamp: string;
}

// Assets (CMDB)
export interface Asset {
  id: string;
  name: string;
  asset_type: string;
  ip_address?: string;
  hostname?: string;
  os?: string;
  owner?: string;
  department?: string;
  criticality: string;
  status: string;
  tags?: string[];
  notes?: string;
  created_at?: string;
  updated_at?: string;
}

// Users
export interface User {
  id: string;
  username: string;
  email?: string;
  role: string;
  tenant_id: string;
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}
