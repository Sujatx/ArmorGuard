// ---------- Backend response types (CamelModel serialisation) ----------

export type ScanMode = "default" | "deep" | "custom";
export type BackendScanStatus = "running" | "completed" | "failed";
export type Severity = "Critical" | "High" | "Medium" | "Low";

export interface ConsentRecord {
  consentId: string;
  targetUrl: string;
  operatorIp: string;
  timestamp: string;
  acknowledged: boolean;
}

export interface ScanResponse {
  scanId: string;
  status: string;
}

export interface Finding {
  findingId: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  evidence?: string | null;
  createdAt: string;
}

export interface ScanStatusResponse {
  scanId: string;
  targetUrl: string;
  scanMode: ScanMode;
  status: BackendScanStatus;
  progress: number;
  findings: Finding[];
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SessionItem {
  scanId: string;
  targetUrl: string;
  date: string;
  severitySummary: SeveritySummary;
}

export interface SessionsResponse {
  sessions: SessionItem[];
}

export interface ReportSummary {
  riskScore: number;
  totalFindings: number;
  bySeverity: SeveritySummary;
}

export interface ReportResponse {
  scanId: string;
  targetUrl: string;
  scanMode: ScanMode;
  summary: ReportSummary;
  findings: Finding[];
  fixPrompt?: string | null;
}

// ---------- Frontend adapter types (what pages expect) ----------

export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface Scan {
  id: string;
  target: string;
  scanType: string;
  status: ScanStatus;
  riskScore?: number | null;
  progress?: number | null;
  vulnerabilitiesCount?: number | null;
  assetsCount?: number | null;
  description?: string | null;
  startedAt?: string | null;
  completedAt?: string | null;
  createdAt: string;
}

export interface ScanLog {
  id: string;
  scanId: string;
  message: string;
  level: string;
  timestamp: string;
}

export interface NetworkMap {
  nodes: Array<{
    id: string;
    label: string;
    type: string;
    riskLevel: string | null;
    metadata?: Record<string, unknown> | null;
  }>;
  edges: Array<{ source: string; target: string; label: string | null }>;
}

export interface Vulnerability {
  id: string;
  scanId: string;
  title: string;
  description?: string | null;
  severity: string;
  status: string;
  target?: string | null;
  cve?: string | null;
  affectedAsset?: string | null;
  discoveredAt: string;
}

export interface Asset {
  id: string;
  scanId: string;
  type: string;
  value: string;
  metadata?: Record<string, unknown> | null;
  riskLevel?: string | null;
  discoveredAt: string;
}

export interface DashboardSummary {
  totalScans: number;
  activeScans: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  totalAssets: number;
  averageRiskScore: number;
  resolvedThisWeek: number;
}

export interface RiskTrendPoint {
  date: string;
  riskScore: number;
  vulnerabilities: number;
}

export interface SeverityCount {
  severity: string;
  count: number;
}

export interface ActivityEvent {
  id: number;
  type: string;
  message: string;
  target: string;
  severity?: string | null;
  timestamp: string;
}

export interface Notification {
  id: number;
  type: string;
  title: string;
  message: string;
  read: boolean;
  severity?: string | null;
  createdAt: string;
}

export interface HealthStatus {
  status: string;
}

export interface SuccessResponse {
  success: boolean;
}

export interface ScanInput {
  target: string;
  scanType?: string;
  selectedTools?: string[];
  consentId?: string | null;
  description?: string | null;
}

export type ListVulnerabilitiesParams = {
  scanId?: string;
  severity?: string;
};

export type ListAssetsParams = {
  scanId?: string;
};
