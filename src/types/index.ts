/**
 * Shared TypeScript types — mirror the backend Pydantic models exactly.
 * These are the contracts for API responses; never add fields here that
 * the backend doesn't send.
 */

export type ScanStatus =
  | "queued"
  | "initializing"
  | "launching_browser"
  | "collecting_requests"
  | "exploring_pages"
  | "analyzing_javascript"
  | "inspecting_headers"
  | "checking_cookies"
  | "finding_secrets"
  | "generating_report"
  | "completed"
  | "failed"
  | "cancelled";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "secret"
  | "header"
  | "cookie"
  | "storage"
  | "network"
  | "javascript"
  | "tls"
  | "cors"
  | "csp"
  | "mixed_content";

export interface NetworkRequest {
  method: string;
  url: string;
  status: number;
  content_type: string | null;
  duration_ms: number | null;
  flagged: boolean;
  flag_reason: string | null;
}

export interface CookieItem {
  name: string;
  domain: string;
  path: string;
  secure: boolean;
  http_only: boolean;
  same_site: string | null;
  session: boolean;
  issues: string[];
}

export interface StorageItem {
  key: string;
  value_preview: string;
  storage_type: string;
  flagged: boolean;
  flag_reason: string | null;
}

export interface SecurityHeader {
  name: string;
  present: boolean;
  value: string | null;
  grade: string;
  recommendation: string | null;
}

export interface SecretFinding {
  pattern_name: string;
  location: string;
  value_preview: string;
  confidence: number;
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  location: string | null;
  evidence: string | null;
  recommendation: string;
  references: string[];
  fixed: boolean;
}

export interface PageInfo {
  url: string;
  title: string | null;
  status: number | null;
  visited: boolean;
}

export interface SecurityReport {
  scan_id: string;
  target_url: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  score: number;
  grade: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  pages: PageInfo[];
  network_requests: NetworkRequest[];
  cookies: CookieItem[];
  storage_items: StorageItem[];
  security_headers: SecurityHeader[];
  secrets: SecretFinding[];
  findings: Finding[];
  ai_summary: string | null;
  ai_recommendations: string[];
  tech_stack: string[];
}

export interface ScanLogEntry {
  ts: string;
  level: "info" | "warn" | "error" | "ok";
  message: string;
}

export interface ScanCreateResponse {
  scan_id: string;
  status: ScanStatus;
  message: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  progress: number;
  current_step: string;
  logs: ScanLogEntry[];
  report: SecurityReport | null;
  error: string | null;
}

export interface ScanSummary {
  scan_id: string;
  url: string;
  status: ScanStatus;
  progress: number;
  score: number | null;
  grade: string | null;
  critical_count: number;
  high_count: number;
  completed_at: string | null;
  duration_seconds: number | null;
}

export const TERMINAL_STATUSES: ScanStatus[] = ["completed", "failed", "cancelled"];
export const ACTIVE_STATUSES: ScanStatus[] = [
  "queued",
  "initializing",
  "launching_browser",
  "collecting_requests",
  "exploring_pages",
  "analyzing_javascript",
  "inspecting_headers",
  "checking_cookies",
  "finding_secrets",
  "generating_report",
];
