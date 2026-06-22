import { useEffect, useRef, useState } from "react";
import { useParams, Link } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import {
  ArrowLeft, RefreshCw, Loader, CheckCircle, XCircle, Clock,
  ShieldAlert, Terminal, Scan, FileText, Download, Plus, Copy, Check,
} from "lucide-react";
import Layout from "@/components/layout";
import {
  useGetScan,
  useGetScanLogs,
  useListVulnerabilities,
  useGetReport,
  BACKEND_URL,
} from "@workspace/api-client-react";
import { useNewScan } from "@/hooks/use-new-scan";
import { cn } from "@/lib/utils";

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; icon: React.ElementType; className: string }> = {
    completed: { label: "Completed", icon: CheckCircle, className: "bg-green-500/10 text-green-400 border-green-500/20" },
    running: { label: "Running", icon: Loader, className: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
    queued: { label: "Queued", icon: Clock, className: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" },
    failed: { label: "Failed", icon: XCircle, className: "bg-red-500/10 text-red-400 border-red-500/20" },
  };
  const { label, icon: Icon, className } = map[status] ?? map.queued;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs font-medium border", className)}>
      <Icon className={cn("w-3 h-3", status === "running" && "animate-spin")} />
      {label}
    </span>
  );
}

function LogLevel({ level }: { level: string }) {
  const map: Record<string, string> = {
    ok: "text-green-400",
    info: "text-slate-400",
    warn: "text-amber-400",
    error: "text-red-400",
    debug: "text-purple-400",
  };
  return (
    <span className={cn("font-bold uppercase text-[10px] w-8 flex-shrink-0", map[level] ?? "text-slate-400")}>
      [{level.slice(0, 3).toUpperCase()}]
    </span>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6366f1",
};

type Tab = "terminal" | "vulns" | "report";

export default function ScanDetail() {
  const params = useParams<{ id: string }>();
  const id = params.id ?? "";
  const [tab, setTab] = useState<Tab>("terminal");
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const { openNewScan } = useNewScan();

  const { data: scan, isLoading: scanLoading } = useGetScan(id);
  const { data: logs } = useGetScanLogs(id);
  const { data: vulns } = useListVulnerabilities({ scanId: id });
  const { data: report } = useGetReport(id);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  if (scanLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-full">
          <Loader className="w-6 h-6 animate-spin text-primary" />
        </div>
      </Layout>
    );
  }

  if (!scan) {
    return (
      <Layout>
        <div className="flex flex-col items-center justify-center h-full gap-3">
          <Scan className="w-8 h-8 text-muted-foreground/40" />
          <p className="text-muted-foreground">Scan not found</p>
          <Link href="/">
            <button className="text-sm text-primary hover:underline">← Back to Dashboard</button>
          </Link>
        </div>
      </Layout>
    );
  }

  const riskScore = report?.summary.riskScore ?? null;
  const bySeverity = report?.summary.bySeverity;
  const criticalHigh = (bySeverity?.critical ?? 0) + (bySeverity?.high ?? 0);

  const tabs: Array<{ id: Tab; icon: React.ElementType; label: string; count?: number }> = [
    { id: "terminal", icon: Terminal, label: "Live Terminal", count: logs?.length },
    { id: "vulns", icon: ShieldAlert, label: "Findings", count: vulns?.length },
    { id: "report", icon: FileText, label: "Report" },
  ];

  function formatDate(ts: string | null | undefined) {
    if (!ts) return "—";
    return new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function riskColor(score: number) {
    return score >= 75 ? "text-red-400" : score >= 50 ? "text-orange-400" : score >= 25 ? "text-yellow-400" : "text-green-400";
  }

  function copyFixPrompt(text: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedPrompt(true);
      setTimeout(() => setCopiedPrompt(false), 2000);
    });
  }

  return (
    <Layout>
      <div className="p-6 space-y-5 h-full overflow-auto">
        {/* Back + header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <Link href="/">
              <motion.button
                whileHover={{ x: -2 }}
                className="w-8 h-8 rounded-lg border border-border flex items-center justify-center text-muted-foreground hover:text-foreground transition-colors"
                data-testid="button-back"
              >
                <ArrowLeft className="w-4 h-4" />
              </motion.button>
            </Link>
            <div>
              <motion.h1 initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-xl font-bold font-mono">
                {scan.target}
              </motion.h1>
              <div className="flex items-center gap-3 mt-1">
                <StatusBadge status={scan.status} />
                <span className="text-xs text-muted-foreground capitalize">{scan.scanType} scan</span>
                <span className="text-xs text-muted-foreground">Started {formatDate(scan.startedAt)}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {riskScore != null && (
              <div className="text-right">
                <p className="text-xs text-muted-foreground">Risk Score</p>
                <p className={cn("text-xl font-bold tabular-nums", riskColor(riskScore))}>{riskScore}</p>
              </div>
            )}
            <div className="text-right">
              <p className="text-xs text-muted-foreground">Progress</p>
              <p className="text-xl font-bold tabular-nums text-primary">{scan.progress ?? 0}%</p>
            </div>
            <button
              onClick={openNewScan}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-border text-foreground hover:border-primary/40 hover:text-primary transition-colors"
              data-testid="button-new-scan-detail"
            >
              <Plus className="w-3.5 h-3.5" />
              New Scan
            </button>
            {report && (
              <a
                href={`${BACKEND_URL}/report/${id}/export`}
                download={`armorguard-report-${id}.pdf`}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                data-testid="button-export-pdf"
              >
                <Download className="w-3.5 h-3.5" />
                PDF
              </a>
            )}
          </div>
        </div>

        {/* Progress bar */}
        {scan.status === "running" && (
          <div className="h-1.5 bg-muted rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-primary rounded-full"
              initial={{ width: 0 }}
              animate={{ width: `${scan.progress ?? 0}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
            />
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Findings", value: vulns?.length ?? scan.vulnerabilitiesCount ?? 0, color: "text-red-400" },
            { label: "Critical + High", value: criticalHigh, color: "text-orange-400" },
            { label: "Risk Score", value: riskScore ?? 0, color: "text-yellow-400" },
            { label: "Log Entries", value: logs?.length ?? 0, color: "text-primary" },
          ].map((item, i) => (
            <motion.div
              key={item.label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className="bg-card border border-card-border rounded-xl px-4 py-3"
            >
              <p className="text-xs text-muted-foreground">{item.label}</p>
              <p className={cn("text-2xl font-bold tabular-nums mt-0.5", item.color)}>{item.value}</p>
            </motion.div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors",
                tab === t.id
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
              data-testid={`tab-${t.id}`}
            >
              <t.icon className="w-3.5 h-3.5" />
              {t.label}
              {t.count != null && t.count > 0 && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full bg-muted text-xs tabular-nums">{t.count}</span>
              )}
            </button>
          ))}
        </div>

        {/* Tab panels */}
        <AnimatePresence mode="wait">
          {tab === "terminal" && (
            <motion.div
              key="terminal"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="bg-[hsl(224,71%,3%)] border border-border rounded-xl overflow-hidden"
              style={{ height: "420px" }}
            >
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-card/50">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-red-500/60" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
                  <div className="w-3 h-3 rounded-full bg-green-500/60" />
                </div>
                <span className="text-xs font-mono text-muted-foreground">recon-agent — {scan.target}</span>
                {scan.status === "running" && <RefreshCw className="w-3 h-3 text-muted-foreground ml-auto animate-spin" />}
              </div>
              <div
                ref={logContainerRef}
                className="p-4 font-mono text-[11px] leading-relaxed overflow-auto terminal-scroll"
                style={{ height: "calc(100% - 42px)" }}
                data-testid="terminal-output"
              >
                {!logs?.length && (
                  <p className="text-slate-500">Waiting for agent output...</p>
                )}
                {logs?.map((log, i) => (
                  <motion.div
                    key={log.id}
                    initial={{ opacity: 0, x: -4 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: Math.min(i * 0.02, 0.5) }}
                    className="flex items-start gap-2 mb-1"
                    data-testid={`log-entry-${log.id}`}
                  >
                    <span className="text-slate-600 flex-shrink-0 tabular-nums">
                      {new Date(log.timestamp).toLocaleTimeString("en-US", { hour12: false })}
                    </span>
                    <LogLevel level={log.level} />
                    <span className={cn(
                      "flex-1",
                      log.level === "error" ? "text-red-300" :
                      log.level === "warn" ? "text-amber-300" :
                      log.level === "ok" ? "text-green-300" :
                      log.level === "debug" ? "text-purple-300" :
                      "text-slate-300"
                    )}>
                      {log.message}
                    </span>
                  </motion.div>
                ))}
                <div className="flex items-center gap-1 mt-2">
                  <span className="text-primary">❯</span>
                  <span className="text-slate-600 animate-pulse">_</span>
                </div>
              </div>
            </motion.div>
          )}

          {tab === "vulns" && (
            <motion.div
              key="vulns"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-2"
            >
              {!vulns?.length && (
                <div className="py-12 text-center text-muted-foreground text-sm bg-card border border-card-border rounded-xl">
                  {scan.status === "running" ? "Scanning… findings will appear here as they're discovered." : "No findings for this scan."}
                </div>
              )}
              {vulns?.map((v, i) => (
                <motion.div
                  key={v.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="bg-card border border-card-border rounded-xl px-4 py-3 flex items-start gap-3"
                  data-testid={`vuln-item-${v.id}`}
                >
                  <div
                    className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0"
                    style={{ backgroundColor: SEVERITY_COLORS[v.severity] ?? "#6366f1" }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium">{v.title}</p>
                      <span
                        className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase"
                        style={{
                          backgroundColor: `${SEVERITY_COLORS[v.severity] ?? "#6366f1"}20`,
                          color: SEVERITY_COLORS[v.severity] ?? "#6366f1",
                        }}
                      >
                        {v.severity}
                      </span>
                      {v.cve && <span className="text-xs font-mono text-muted-foreground">{v.cve}</span>}
                    </div>
                    {v.description && <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{v.description}</p>}
                    {v.affectedAsset && <p className="text-xs font-mono text-primary/70 mt-1">↳ {v.affectedAsset}</p>}
                  </div>
                  <div className="text-right flex-shrink-0">
                    <p className="text-xs text-muted-foreground capitalize">{v.status}</p>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          )}

          {tab === "report" && (
            <motion.div
              key="report"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-4"
            >
              {!report ? (
                <div className="py-12 text-center text-muted-foreground text-sm bg-card border border-card-border rounded-xl">
                  Report will be available once the scan has findings.
                </div>
              ) : (
                <>
                  {/* Summary cards */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-card border border-card-border rounded-xl p-5 flex items-center gap-4">
                      <div className="text-center">
                        <p className={cn("text-4xl font-bold tabular-nums", riskColor(report.summary.riskScore))}>
                          {report.summary.riskScore}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">Risk Score / 100</p>
                      </div>
                      <div className="h-12 w-px bg-border" />
                      <div>
                        <p className="text-2xl font-bold tabular-nums">{report.summary.totalFindings}</p>
                        <p className="text-xs text-muted-foreground">Total Findings</p>
                      </div>
                    </div>

                    {/* Severity breakdown */}
                    <div className="bg-card border border-card-border rounded-xl p-5">
                      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">By Severity</p>
                      <div className="grid grid-cols-4 gap-2">
                        {([
                          ["critical", "Critical"],
                          ["high", "High"],
                          ["medium", "Medium"],
                          ["low", "Low"],
                        ] as const).map(([key, label]) => (
                          <div key={key} className="text-center">
                            <p className="text-xl font-bold tabular-nums" style={{ color: SEVERITY_COLORS[key] }}>
                              {report.summary.bySeverity[key]}
                            </p>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* PDF export CTA */}
                  <div className="bg-card border border-card-border rounded-xl px-5 py-4 flex items-center justify-between">
                    <div>
                      <p className="text-sm font-semibold">Forensic PDF Report</p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        Full findings, evidence, and remediation for {scan.target}.
                      </p>
                    </div>
                    <a
                      href={`${BACKEND_URL}/report/${id}/export`}
                      download={`armorguard-report-${id}.pdf`}
                      className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors flex-shrink-0"
                      data-testid="button-export-pdf-report"
                    >
                      <Download className="w-4 h-4" />
                      Download PDF
                    </a>
                  </div>

                  {report.fixPrompt && (
                    <div className="bg-card border border-card-border rounded-xl p-5">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Suggested Fix Prompt</p>
                        <button
                          onClick={() => copyFixPrompt(report.fixPrompt!)}
                          className="flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium border border-border text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
                          data-testid="button-copy-fix-prompt"
                          title="Copy fix prompt"
                        >
                          {copiedPrompt ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                          {copiedPrompt ? "Copied" : "Copy"}
                        </button>
                      </div>
                      <pre className="text-xs font-mono whitespace-pre-wrap text-muted-foreground leading-relaxed">{report.fixPrompt}</pre>
                    </div>
                  )}
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Layout>
  );
}
