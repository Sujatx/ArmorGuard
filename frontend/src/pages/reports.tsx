import { motion } from "framer-motion";
import { FileText, Download, BarChart3, Shield, Activity, TrendingUp, CheckCircle, Loader2 } from "lucide-react";
import Layout from "@/components/layout";
import { useGetDashboardSummary, useGetSeverityBreakdown, useListScans, useListVulnerabilities, useListAssets, BACKEND_URL } from "@workspace/api-client-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, Legend
} from "recharts";
import { useState } from "react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6366f1",
};

type DownloadState = "idle" | "loading" | "done";

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function Reports() {
  const { data: summary } = useGetDashboardSummary();
  const { data: severity } = useGetSeverityBreakdown();
  const { data: scans } = useListScans();
  const { data: vulns } = useListVulnerabilities({});
  const { data: assets } = useListAssets({});
  const [downloadStates, setDownloadStates] = useState<Record<number, DownloadState>>({});

  const severityData = severity?.filter(s => s.count > 0) ?? [];

  const scanStatusData = [
    { name: "Completed", value: scans?.filter(s => s.status === "completed").length ?? 0, color: "#22c55e" },
    { name: "Running", value: scans?.filter(s => s.status === "running").length ?? 0, color: "#3b82f6" },
    { name: "Queued", value: scans?.filter(s => s.status === "queued").length ?? 0, color: "#eab308" },
    { name: "Failed", value: scans?.filter(s => s.status === "failed").length ?? 0, color: "#ef4444" },
  ].filter(d => d.value > 0);

  function setDlState(i: number, state: DownloadState) {
    setDownloadStates(prev => ({ ...prev, [i]: state }));
  }

  async function handleDownload(index: number) {
    setDlState(index, "loading");
    await new Promise(r => setTimeout(r, 600));

    const now = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

    if (index === 0) {
      // Executive Summary — plain text
      const lines = [
        "ArmorGuard — Executive Security Summary",
        "=".repeat(50),
        `Generated: ${new Date().toLocaleString()}`,
        "",
        "OVERVIEW",
        `  Total Scans:         ${summary?.totalScans ?? 0}`,
        `  Vulnerabilities:     ${summary?.totalVulnerabilities ?? 0}`,
        `  Critical:            ${summary?.criticalCount ?? 0}`,
        `  High:                ${summary?.highCount ?? 0}`,
        `  Assets Mapped:       ${summary?.totalAssets ?? 0}`,
        `  Average Risk Score:  ${summary?.averageRiskScore ?? 0}/100`,
        `  Resolved This Week:  ${summary?.resolvedThisWeek ?? 0}`,
        "",
        "SEVERITY BREAKDOWN",
        ...(severity ?? []).map(s => `  ${s.severity.padEnd(12)} ${s.count}`),
        "",
        "RECENT SCANS",
        ...(scans?.slice(0, 10) ?? []).map(s =>
          `  [${s.status.toUpperCase().padEnd(9)}] ${s.target.padEnd(40)} Risk: ${s.riskScore ?? "N/A"}`
        ),
        "",
        "ArmorGuard — armorguard.io",
      ];
      const blob = new Blob([lines.join("\n")], { type: "text/plain" });
      downloadBlob(blob, `armorguard-executive-summary-${now}.txt`);
    }

    if (index === 1) {
      // Vulnerability Report — CSV
      const headers = ["id", "title", "severity", "status", "target", "description"];
      const rows = (vulns ?? []).map(v => [
        v.id,
        `"${(v.title ?? "").replace(/"/g, '""')}"`,
        v.severity,
        v.status,
        `"${(v.target ?? "").replace(/"/g, '""')}"`,
        `"${(v.description ?? "").replace(/"/g, '""')}"`,
      ].join(","));
      const csv = [headers.join(","), ...rows].join("\n");
      const blob = new Blob([csv], { type: "text/csv" });
      downloadBlob(blob, `armorguard-vulnerabilities-${now}.csv`);
    }

    if (index === 2) {
      // Asset Inventory — JSON
      const payload = {
        generated: new Date().toISOString(),
        totalAssets: assets?.length ?? 0,
        assets: (assets ?? []).map(a => ({
          id: a.id,
          type: a.type,
          value: a.value,
          status: a.status,
          riskScore: a.riskScore,
          target: a.target,
          discoveredAt: a.discoveredAt,
        })),
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      downloadBlob(blob, `armorguard-assets-${now}.json`);
    }

    if (index === 3) {
      // Risk Trend — CSV
      const headers = ["scan_id", "target", "scan_type", "status", "risk_score", "vulnerability_count", "asset_count", "created_at"];
      const rows = (scans ?? []).map(s => [
        s.id,
        `"${(s.target ?? "").replace(/"/g, '""')}"`,
        s.scanType,
        s.status,
        s.riskScore ?? "",
        s.vulnerabilityCount ?? 0,
        s.assetCount ?? 0,
        s.createdAt,
      ].join(","));
      const csv = [headers.join(","), ...rows].join("\n");
      const blob = new Blob([csv], { type: "text/csv" });
      downloadBlob(blob, `armorguard-risk-trend-${now}.csv`);
    }

    setDlState(index, "done");
    setTimeout(() => setDlState(index, "idle"), 2000);
  }

  const REPORT_TEMPLATES = [
    {
      icon: Shield,
      title: "Executive Summary",
      desc: "High-level overview of security posture for leadership",
      badge: "TXT",
      color: "text-blue-500",
      bg: "bg-blue-500/10 border-blue-500/20",
    },
    {
      icon: BarChart3,
      title: "Vulnerability Report",
      desc: "Detailed breakdown of all discovered vulnerabilities",
      badge: "CSV",
      color: "text-red-500",
      bg: "bg-red-500/10 border-red-500/20",
    },
    {
      icon: Activity,
      title: "Asset Inventory",
      desc: "Complete list of discovered network assets",
      badge: "JSON",
      color: "text-green-500",
      bg: "bg-green-500/10 border-green-500/20",
    },
    {
      icon: TrendingUp,
      title: "Risk Trend Analysis",
      desc: "Risk score data across all scans",
      badge: "CSV",
      color: "text-orange-500",
      bg: "bg-orange-500/10 border-orange-500/20",
    },
  ];

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div>
          <motion.h1 initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-xl font-bold">
            Reports
          </motion.h1>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.08 }} className="text-sm text-muted-foreground mt-0.5">
            Generate and export security reports
          </motion.p>
        </div>

        {/* Stats summary */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Total Scans", value: summary?.totalScans ?? 0, icon: Activity, color: "text-primary" },
            { label: "Vulnerabilities", value: summary?.totalVulnerabilities ?? 0, icon: Shield, color: "text-red-500" },
            { label: "Assets Mapped", value: summary?.totalAssets ?? 0, icon: BarChart3, color: "text-green-500" },
            { label: "Resolved", value: summary?.resolvedThisWeek ?? 0, icon: CheckCircle, color: "text-emerald-500" },
          ].map((item, i) => (
            <motion.div
              key={item.label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className="bg-card border border-card-border rounded-xl px-4 py-3 flex items-center gap-3"
            >
              <item.icon className={`w-5 h-5 ${item.color}`} />
              <div>
                <p className="text-lg font-bold tabular-nums">{item.value}</p>
                <p className="text-xs text-muted-foreground">{item.label}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Charts */}
        <div className="grid grid-cols-2 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25 }}
            className="bg-card border border-card-border rounded-xl p-5"
          >
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-4">Vulnerability Distribution</p>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={severityData} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
                  <XAxis dataKey="severity" tick={{ fontSize: 10, textTransform: "capitalize" }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{ background: "hsl(20, 10%, 10%)", border: "1px solid hsl(20, 8%, 20%)", borderRadius: "8px", fontSize: "12px" }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityData.map((entry) => (
                      <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] ?? "#6366f1"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-44 flex items-center justify-center text-muted-foreground text-sm">No data</div>
            )}
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-card border border-card-border rounded-xl p-5"
          >
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-4">Scan Status Distribution</p>
            {scanStatusData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={scanStatusData} dataKey="value" nameKey="name" innerRadius={40} outerRadius={65} paddingAngle={3}>
                    {scanStatusData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "hsl(20, 10%, 10%)", border: "1px solid hsl(20, 8%, 20%)", borderRadius: "8px", fontSize: "12px" }} />
                  <Legend formatter={(v) => <span style={{ fontSize: "11px" }}>{v}</span>} iconSize={8} iconType="circle" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-44 flex items-center justify-center text-muted-foreground text-sm">No data</div>
            )}
          </motion.div>
        </div>

        {/* PDF export — one per completed scan */}
        {scans && scans.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
              PDF Reports (per scan)
            </p>
            <div className="space-y-2">
              {scans.map((s) => (
                <div
                  key={s.id}
                  className="bg-card border border-card-border rounded-xl px-4 py-3 flex items-center justify-between"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-mono font-medium truncate">{s.target}</p>
                    <p className="text-xs text-muted-foreground capitalize">
                      {s.scanType} · {new Date(s.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <a
                    href={`${BACKEND_URL}/report/${s.id}/export`}
                    download={`armorguard-report-${s.id}.pdf`}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors flex-shrink-0 ml-4"
                  >
                    <Download className="w-3.5 h-3.5" />
                    PDF
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Report templates */}
        <div>
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Export Templates</p>
          <div className="grid grid-cols-2 gap-3">
            {REPORT_TEMPLATES.map((r, i) => {
              const dlState = downloadStates[i] ?? "idle";
              return (
                <motion.button
                  key={r.title}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4 + i * 0.06 }}
                  className="bg-card border border-card-border rounded-xl p-4 hover:border-primary/40 hover:shadow-sm transition-all group cursor-pointer text-left w-full disabled:opacity-60"
                  onClick={() => handleDownload(i)}
                  disabled={dlState === "loading"}
                  data-testid={`report-template-${i}`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <div className={`w-8 h-8 rounded-lg border flex items-center justify-center flex-shrink-0 ${r.bg}`}>
                        <r.icon className={`w-4 h-4 ${r.color}`} />
                      </div>
                      <div>
                        <p className="text-sm font-semibold">{r.title}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{r.desc}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-bold text-muted-foreground bg-muted px-1.5 py-0.5 rounded">{r.badge}</span>
                      {dlState === "loading" ? (
                        <Loader2 className="w-4 h-4 text-primary animate-spin" />
                      ) : dlState === "done" ? (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      ) : (
                        <Download className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                      )}
                    </div>
                  </div>
                </motion.button>
              );
            })}
          </div>
        </div>
      </div>
    </Layout>
  );
}
