import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { UseQueryResult, QueryKey } from "@tanstack/react-query";
import { apiFetch, BACKEND_URL } from "../custom-fetch";
import type {
  Scan,
  ScanLog,
  NetworkMap,
  Vulnerability,
  Asset,
  DashboardSummary,
  RiskTrendPoint,
  SeverityCount,
  ActivityEvent,
  Notification,
  HealthStatus,
  SuccessResponse,
  ScanInput,
  ListVulnerabilitiesParams,
  ListAssetsParams,
  SessionsResponse,
  SessionItem,
  ScanStatus,
  ScanStatusResponse,
  Finding,
  ConsentRecord,
  ScanResponse,
  ReportResponse,
} from "./api.schemas";

// ---------- Target classification ----------

// Mirrors backend is_local_target (main.py) — local/private targets skip the
// consent gate, public targets require an acknowledged ConsentRecord.
export function isLocalTarget(target: string): boolean {
  if (!target) return true;
  let host = target.trim();
  // Strip scheme + path + port to isolate the hostname.
  host = host.replace(/^[a-z]+:\/\//i, "");
  host = host.split("/")[0].split("?")[0];
  host = host.replace(/:\d+$/, "");
  host = host.toLowerCase();

  if (["localhost", "127.0.0.1", "demo-target", "host.docker.internal"].includes(host)) {
    return true;
  }
  if (host.startsWith("10.") || host.startsWith("192.168.")) return true;
  // 172.16.0.0 – 172.31.255.255
  const m = host.match(/^172\.(\d{1,3})\./);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

// ---------- Adapter helpers ----------

function severityTotal(s: SessionItem["severitySummary"]): number {
  return s.critical + s.high + s.medium + s.low;
}

function sessionToScan(s: SessionItem): Scan {
  const raw =
    s.severitySummary.critical * 40 +
    s.severitySummary.high * 25 +
    s.severitySummary.medium * 10 +
    s.severitySummary.low * 2;
  return {
    id: s.scanId,
    target: s.targetUrl,
    scanType: "default",
    status: (s.status ?? "running") as ScanStatus,
    riskScore: Math.min(raw, 100),
    vulnerabilitiesCount: severityTotal(s.severitySummary),
    assetsCount: 0,
    createdAt: s.date,
    startedAt: s.date,
  };
}

function statusRespToScan(r: ScanStatusResponse): Scan {
  return {
    id: r.scanId,
    target: r.targetUrl,
    scanType: r.scanMode,
    status: r.status,
    progress: r.progress,
    vulnerabilitiesCount: r.findings.length,
    assetsCount: 0,
    createdAt: new Date().toISOString(),
    startedAt: new Date().toISOString(),
  };
}

function findingToVuln(f: Finding, scanId: string): Vulnerability {
  return {
    id: f.findingId,
    scanId,
    title: f.title,
    description: f.description,
    severity: f.severity.toLowerCase(),
    status: "open",
    affectedAsset: f.evidence ?? null,
    discoveredAt: f.createdAt,
  };
}

// ---------- Query key helpers (used by pages for cache invalidation) ----------

export const getListScansQueryKey = () => ["sessions"] as const;
export const getGetScanQueryKey = (id: string) => ["scan", id] as const;
export const getListVulnerabilitiesQueryKey = (params?: ListVulnerabilitiesParams) =>
  ["vulns", params?.scanId] as const;
export const getListNotificationsQueryKey = () => ["notifications"] as const;

// ---------- Scan hooks ----------

export function useListScans(): UseQueryResult<Scan[]> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: getListScansQueryKey(),
    queryFn: async () => {
      const r = await apiFetch<SessionsResponse>("/sessions");
      return r.sessions.map(sessionToScan);
    },
  });
  return { ...q, queryKey: getListScansQueryKey() };
}

// Records operator consent for a public target. Hitting this endpoint IS the
// acknowledgment (backend stores acknowledged: true), so only call it once the
// operator has actually acknowledged the disclaimer.
export function useCreateConsent() {
  return useMutation({
    mutationKey: ["createConsent"],
    mutationFn: async ({ targetUrl }: { targetUrl: string }): Promise<ConsentRecord> =>
      apiFetch<ConsentRecord>("/consent", {
        method: "POST",
        body: JSON.stringify({ targetUrl }),
      }),
  });
}

export function useCreateScan() {
  return useMutation({
    mutationKey: ["createScan"],
    mutationFn: async ({ data }: { data: ScanInput }): Promise<ScanResponse> => {
      const scanMode =
        data.scanType === "deep" || data.scanType === "custom"
          ? data.scanType
          : "default";
      return apiFetch<ScanResponse>("/scan", {
        method: "POST",
        body: JSON.stringify({
          targetUrl: data.target,
          scanMode,
          ...(scanMode === "custom" && { selectedTools: data.selectedTools ?? [] }),
          consentId: data.consentId ?? null,
        }),
      });
    },
  });
}

export function useGetScan(id: string): UseQueryResult<Scan> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: getGetScanQueryKey(id),
    queryFn: async () => {
      const r = await apiFetch<ScanStatusResponse>(`/scan/${id}`);
      return statusRespToScan(r);
    },
    enabled: !!id,
    refetchInterval: (query) => {
      const status = (query.state.data as Scan | undefined)?.status;
      return status === "running" ? 3000 : false;
    },
  });
  return { ...q, queryKey: getGetScanQueryKey(id) };
}

export function useDeleteScan() {
  return useMutation({
    mutationKey: ["deleteScan"],
    mutationFn: async (_vars: { id: string }): Promise<void> => {
      // Backend has no delete endpoint — silently no-op
    },
  });
}

// ---------- Logs via WebSocket ----------

export function useGetScanLogs(id: string): {
  data: ScanLog[] | undefined;
  isLoading: boolean;
  queryKey: QueryKey;
} {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const idRef = useRef(id);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!id) return;
    idRef.current = id;
    setLogs([]);

    // Findings and the report are served over REST (/report/{id}); refetch them as the
    // live stream reports progress so the Findings/Report tabs fill without a manual reload.
    const refreshScanData = () => {
      queryClient.invalidateQueries({ queryKey: getGetScanQueryKey(id) });
      queryClient.invalidateQueries({ queryKey: getListVulnerabilitiesQueryKey({ scanId: id }) });
      queryClient.invalidateQueries({ queryKey: ["report", id] });
    };

    const wsUrl = BACKEND_URL.replace(/^http/, "ws") + `/ws/scan/${id}`;
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data as string) as {
          event: string;
          data: Record<string, unknown>;
        };

        const push = (message: string, level: string) =>
          setLogs((prev) => [
            ...prev,
            {
              id: crypto.randomUUID(),
              scanId: id,
              message,
              level,
              timestamp: new Date().toISOString(),
            },
          ]);

        if (msg.event === "tool_status") {
          const tool = String(msg.data.tool ?? "");
          const status = String(msg.data.status ?? "");
          const text = String(msg.data.message ?? status);
          push(tool ? `[${tool}] ${text}` : text, status === "running" ? "info" : "ok");
          // Refetch scan status so the progress bar advances live as each tool finishes.
          queryClient.invalidateQueries({ queryKey: getGetScanQueryKey(id) });
        } else if (msg.event === "agent_reasoning") {
          const text = String(msg.data.text ?? "").trim();
          if (text) push(`[agent] ${text}`, "info");
        } else if (msg.event === "finding_discovered") {
          const title = String(msg.data.title ?? "Finding");
          const sev = String(msg.data.severity ?? "");
          push(`[FINDING][${sev}] ${title}`, "warn");
          refreshScanData();
        } else if (msg.event === "intent_drift_detected") {
          const classification = String(msg.data.driftClassification ?? "");
          const action = String(msg.data.attemptedAction ?? "");
          const reason = String(msg.data.blockReason ?? "");
          push(
            `[POLICY BLOCK] ${classification}${action ? ` — attempted: ${action}` : ""}${reason ? ` — ${reason}` : ""}`,
            "error",
          );
        } else if (msg.event === "scan_completed") {
          push("Scan completed successfully.", "ok");
          refreshScanData();
        } else if (msg.event === "scan_failed") {
          push(`Scan failed: ${String(msg.data.reason ?? "unknown")}`, "error");
          refreshScanData();
        }
      } catch {
        // ignore parse errors
      }
    };

    return () => ws.close();
  }, [id]);

  return {
    data: logs.length > 0 ? logs : undefined,
    isLoading: false,
    queryKey: [`/api/scans/${id}/logs`],
  };
}

// ---------- Map (stubbed — no backend equivalent) ----------

export function useGetScanMap(id: string): UseQueryResult<NetworkMap> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: [`scan-map-${id}`],
    queryFn: async (): Promise<NetworkMap> => ({ nodes: [], edges: [] }),
    enabled: !!id,
  });
  return { ...q, queryKey: [`scan-map-${id}`] };
}

// ---------- Vulnerabilities (fetched from /report/{scanId}) ----------

export function useListVulnerabilities(
  params?: ListVulnerabilitiesParams,
): UseQueryResult<Vulnerability[]> & { queryKey: QueryKey } {
  const scanId = params?.scanId;
  const q = useQuery({
    queryKey: getListVulnerabilitiesQueryKey(params),
    queryFn: async () => {
      if (!scanId) return [] as Vulnerability[];
      const r = await apiFetch<ReportResponse>(`/report/${scanId}`);
      return r.findings.map((f) => findingToVuln(f, scanId));
    },
    enabled: !params || !!params.scanId,
  });
  return { ...q, queryKey: getListVulnerabilitiesQueryKey(params) };
}

// ---------- Assets (stubbed — no backend equivalent) ----------

export function useListAssets(
  _params?: ListAssetsParams,
): UseQueryResult<Asset[]> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: ["assets"],
    queryFn: async (): Promise<Asset[]> => [],
  });
  return { ...q, queryKey: ["assets"] };
}

// ---------- Dashboard (derived from /sessions) ----------

export function useGetDashboardSummary(): UseQueryResult<DashboardSummary> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: async () => {
      const r = await apiFetch<SessionsResponse>("/sessions");
      const totals = r.sessions.reduce(
        (acc, s) => ({
          critical: acc.critical + s.severitySummary.critical,
          high: acc.high + s.severitySummary.high,
          medium: acc.medium + s.severitySummary.medium,
          low: acc.low + s.severitySummary.low,
        }),
        { critical: 0, high: 0, medium: 0, low: 0 }
      );
      return {
        totalScans: r.sessions.length,
        activeScans: 0,
        totalVulnerabilities: totals.critical + totals.high + totals.medium + totals.low,
        criticalCount: totals.critical,
        highCount: totals.high,
        totalAssets: 0,
        averageRiskScore: 0,
        resolvedThisWeek: 0,
      } satisfies DashboardSummary;
    },
  });
  return { ...q, queryKey: ["dashboard-summary"] };
}

export function useGetRiskTrend(): UseQueryResult<RiskTrendPoint[]> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: ["risk-trend"],
    queryFn: async (): Promise<RiskTrendPoint[]> => [],
  });
  return { ...q, queryKey: ["risk-trend"] };
}

export function useGetSeverityBreakdown(): UseQueryResult<SeverityCount[]> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: ["severity-breakdown"],
    queryFn: async () => {
      const r = await apiFetch<SessionsResponse>("/sessions");
      const totals = r.sessions.reduce(
        (acc, s) => ({
          critical: acc.critical + s.severitySummary.critical,
          high: acc.high + s.severitySummary.high,
          medium: acc.medium + s.severitySummary.medium,
          low: acc.low + s.severitySummary.low,
        }),
        { critical: 0, high: 0, medium: 0, low: 0 }
      );
      return (
        [
          { severity: "critical", count: totals.critical },
          { severity: "high", count: totals.high },
          { severity: "medium", count: totals.medium },
          { severity: "low", count: totals.low },
        ] as SeverityCount[]
      ).filter((x) => x.count > 0);
    },
  });
  return { ...q, queryKey: ["severity-breakdown"] };
}

function sessionActivityType(status: string): ActivityEvent["type"] {
  if (status === "failed") return "threat_detected";
  if (status === "running" || status === "queued") return "scan_started";
  return "scan_completed";
}

function sessionActivityMessage(status: string, targetUrl: string): string {
  if (status === "failed") return `Scan failed for ${targetUrl}`;
  if (status === "running" || status === "queued") return `Scan running for ${targetUrl}`;
  return `Scan completed for ${targetUrl}`;
}

export function useGetRecentActivity(): UseQueryResult<ActivityEvent[]> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: ["recent-activity"],
    queryFn: async () => {
      const r = await apiFetch<SessionsResponse>("/sessions");
      return r.sessions.slice(0, 10).map(
        (s, i): ActivityEvent => ({
          id: i,
          type: sessionActivityType(s.status ?? "completed"),
          message: sessionActivityMessage(s.status ?? "completed", s.targetUrl),
          target: s.targetUrl,
          severity:
            s.severitySummary.critical > 0
              ? "critical"
              : s.severitySummary.high > 0
              ? "high"
              : null,
          timestamp: s.date,
        })
      );
    },
  });
  return { ...q, queryKey: ["recent-activity"] };
}

// ---------- Notifications (stubbed) ----------

export function useListNotifications(): UseQueryResult<Notification[]> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: ["notifications"],
    queryFn: async (): Promise<Notification[]> => [],
  });
  return { ...q, queryKey: ["notifications"] };
}

export function useMarkAllNotificationsRead() {
  return useMutation({
    mutationKey: ["markAllNotificationsRead"],
    mutationFn: async (): Promise<SuccessResponse> => ({ success: true }),
  });
}

// ---------- Health ----------

export function useHealthCheck(): UseQueryResult<HealthStatus> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: ["health"],
    queryFn: () => apiFetch<HealthStatus>("/health"),
  });
  return { ...q, queryKey: ["health"] };
}

// ---------- Full report (used by reports page for PDF export) ----------

export function useGetReport(scanId: string | undefined): UseQueryResult<ReportResponse> & { queryKey: QueryKey } {
  const q = useQuery({
    queryKey: ["report", scanId],
    queryFn: () => apiFetch<ReportResponse>(`/report/${scanId}`),
    enabled: !!scanId,
  });
  return { ...q, queryKey: ["report", scanId] };
}
