import { useEffect, useRef, useState } from "react";
import { useParams, Link, useLocation } from "wouter";
import { motion } from "framer-motion";
import {
  ArrowLeft, RefreshCw, Loader, CheckCircle, XCircle, Clock,
  ShieldAlert, Terminal, Download, Plus, Copy, Check, FileText, ChevronDown, Square,
} from "lucide-react";
import Layout from "@/components/layout";
import {
  useGetScan,
  useGetScanLogs,
  useListVulnerabilities,
  useGetReport,
  useCreateScan,
  useStopScan,
  BACKEND_URL,
} from "@workspace/api-client-react";
import { useNewScan } from "@/hooks/use-new-scan";
import { cn } from "@/lib/utils";

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; icon: React.ElementType; className: string }> = {
    completed: { label: "Completed", icon: CheckCircle, className: "bg-green-500/10 text-green-500 border-green-500/20" },
    running:   { label: "Running",   icon: Loader,       className: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
    queued:    { label: "Queued",    icon: Clock,        className: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" },
    failed:    { label: "Failed",    icon: XCircle,      className: "bg-red-500/10 text-red-400 border-red-500/20" },
    halted:    { label: "Halted",    icon: ShieldAlert,  className: "bg-red-500/10 text-red-400 border-red-500/20" },
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
  const colors: Record<string, string> = {
    ok:    "text-green-400",
    info:  "text-slate-400",
    warn:  "text-[#C9923A]",
    error: "text-red-400",
    debug: "text-purple-400",
  };
  return (
    <span className={cn("font-bold uppercase text-[10px] w-8 flex-shrink-0", colors[level] ?? "text-slate-400")}>
      [{level.slice(0, 3).toUpperCase()}]
    </span>
  );
}

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  info:     "#6366f1",
};

function SevPill({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border"
      style={{ borderColor: `${color}40`, color, backgroundColor: `${color}12` }}
    >
      {count} {label}
    </span>
  );
}

export default function ScanDetail() {
  const params = useParams<{ id: string }>();
  const id = params.id ?? "";
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [copiedAll, setCopiedAll] = useState(false);
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set());
  const [leftPct, setLeftPct] = useState(55);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const splitContainerRef = useRef<HTMLDivElement>(null);
  const { openNewScan } = useNewScan();
  const [, navigate] = useLocation();
  const retryScan = useCreateScan();
  const stopScan = useStopScan();

  function startDrag(e: React.MouseEvent) {
    e.preventDefault();
    const startX = e.clientX;
    const startPct = leftPct;
    function onMove(ev: MouseEvent) {
      if (!splitContainerRef.current) return;
      const w = splitContainerRef.current.offsetWidth;
      const delta = ((ev.clientX - startX) / w) * 100;
      setLeftPct(Math.max(30, Math.min(70, startPct + delta)));
    }
    function onUp() {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    }
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }

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
          <ShieldAlert className="w-8 h-8 text-muted-foreground/40" />
          <p className="text-muted-foreground">Scan not found</p>
          <Link href="/"><button className="text-sm text-primary hover:underline">← Back to Dashboard</button></Link>
        </div>
      </Layout>
    );
  }

  const bySev = report?.summary.bySeverity;

  function formatDate(ts: string | null | undefined) {
    if (!ts) return "—";
    return new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function riskColor(score: number) {
    return score >= 75 ? "text-red-400" : score >= 50 ? "text-orange-400" : score >= 25 ? "text-yellow-400" : "text-green-400";
  }

  function toggleVuln(id: string) {
    setExpandedVulns(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function copyAllFindings() {
    if (!vulns?.length) return;
    const text = vulns.map((v, i) =>
      [
        `[${i + 1}] ${v.title}`,
        `Severity: ${v.severity}`,
        v.cve ? `CVE: ${v.cve}` : null,
        v.description,
        v.affectedAsset ? `Affected: ${v.affectedAsset}` : null,
      ].filter(Boolean).join("\n")
    ).join("\n\n---\n\n");
    navigator.clipboard.writeText(text).then(() => {
      setCopiedAll(true);
      setTimeout(() => setCopiedAll(false), 2000);
    });
  }

  function copyFixPrompt(text: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedPrompt(true);
      setTimeout(() => setCopiedPrompt(false), 2000);
    });
  }

  return (
    <Layout>
      {/* Full-height flex column */}
      <div className="flex flex-col h-full overflow-hidden bg-black/[0.04] dark:bg-black/20">

        {/* ── Header ── */}
        <div className="flex-shrink-0 px-5 pt-5 pb-3 border-b border-border space-y-2 bg-background">
          <div className="flex items-center justify-between">
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
                <h1 className="text-base font-bold font-mono leading-tight">{scan.target}</h1>
                <div className="flex items-center gap-2 mt-0.5">
                  <StatusBadge status={scan.status} />
                  <span className="text-xs text-muted-foreground capitalize">{scan.scanType} scan</span>
                  <span className="text-xs text-muted-foreground">{formatDate(scan.startedAt)}</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {scan.status === "running" && (
                <>
                  <span className="text-sm font-bold tabular-nums text-primary">{scan.progress ?? 0}%</span>
                  <button
                    onClick={() => stopScan.mutate({ scanId: id! })}
                    disabled={stopScan.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-red-500/40 text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    data-testid="button-stop-scan"
                  >
                    <Square className="w-3.5 h-3.5 fill-current" />
                    {stopScan.isPending ? "Stopping…" : "Stop"}
                  </button>
                </>
              )}
              {scan.status === "failed" && (
                <button
                  onClick={() => retryScan.mutate(
                    { data: { target: scan.target, scanType: scan.scanType as "default" | "deep" | "custom", consentId: null } },
                    { onSuccess: (r: { scanId: string }) => navigate(`/scans/${r.scanId}`) }
                  )}
                  disabled={retryScan.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-red-500/40 text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  data-testid="button-retry-scan"
                >
                  <RefreshCw className={cn("w-3.5 h-3.5", retryScan.isPending && "animate-spin")} />
                  {retryScan.isPending ? "Retrying…" : "Retry"}
                </button>
              )}
              {scan.status === "completed" && (
                <button
                  onClick={() => openNewScan({ target: scan.target, scanType: scan.scanType })}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-border text-muted-foreground hover:border-primary/40 hover:text-foreground transition-colors"
                  data-testid="button-rescan"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Re-scan
                </button>
              )}
              <button
                onClick={() => openNewScan()}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-border text-foreground hover:border-primary/40 hover:text-primary transition-colors cursor-pointer"
                data-testid="button-new-scan-detail"
              >
                <Plus className="w-3.5 h-3.5" />
                New Scan
              </button>
              {(scan.status === "completed" || scan.status === "failed") && report && (
                <a
                  href={`${BACKEND_URL}/report/${id}/export`}
                  download={`armorguard-${scan.target.replace(/^https?:\/\//, "").split("/")[0].replace(/:\d+$/, "")}.pdf`}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
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
            <div className="h-1 bg-muted rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-primary rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${scan.progress ?? 0}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              />
            </div>
          )}
        </div>

        {/* ── 2-column body ── */}
        <div ref={splitContainerRef} className="flex flex-1 min-h-0 gap-3 p-3">

          {/* Left — Terminal */}
          <div
            className="flex flex-col rounded-xl overflow-hidden border border-border min-h-0 flex-shrink-0"
            style={{ width: `${leftPct}%` }}
          >
            {/* Terminal titlebar */}
            <div className="flex items-center gap-2 px-4 py-2 border-b border-white/10 bg-[hsl(224,71%,7%)] flex-shrink-0 rounded-t-xl">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
                <div className="w-2.5 h-2.5 rounded-full bg-[#C9923A]" />
                <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
              </div>
              <Terminal className="w-3 h-3 text-slate-400" />
              <span className="text-xs font-mono text-slate-300 flex-1 truncate">recon-agent — {scan.target}</span>
              {scan.status === "running" && <RefreshCw className="w-3 h-3 text-slate-400 animate-spin flex-shrink-0" />}
            </div>
            {/* Terminal body */}
            <div
              ref={logContainerRef}
              className="flex-1 min-h-0 overflow-auto p-4 font-mono text-[11px] leading-relaxed terminal-scroll bg-[hsl(224,71%,3%)]"
              data-testid="terminal-output"
            >
              {!logs?.length && <p className="text-slate-500">Waiting for agent output…</p>}
              {logs?.map((log, i) => (
                <motion.div
                  key={log.id}
                  initial={{ opacity: 0, x: -4 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: Math.min(i * 0.015, 0.4) }}
                  className="flex items-start gap-2 mb-0.5"
                  data-testid={`log-entry-${log.id}`}
                >
                  <span className="text-slate-600 flex-shrink-0 tabular-nums">
                    {new Date(log.timestamp).toLocaleTimeString("en-US", { hour12: false })}
                  </span>
                  <LogLevel level={log.level} />
                  <span className={cn(
                    "flex-1",
                    log.level === "error" ? "text-red-300" :
                    log.level === "warn"  ? "text-[#D4AA6A]" :
                    log.level === "ok"    ? "text-green-300" :
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
          </div>

          {/* Drag handle */}
          <div
            className="flex-shrink-0 w-2 flex items-center justify-center cursor-col-resize group select-none"
            onMouseDown={startDrag}
          >
            <div className="w-0.5 h-10 rounded-full bg-border group-hover:bg-primary transition-colors duration-150" />
          </div>

          {/* Right — Findings + Report */}
          <div className="flex flex-col flex-1 min-h-0 rounded-xl border border-border overflow-hidden bg-card">

            {/* Findings header */}
            <div className="flex-shrink-0 px-4 py-3 border-b border-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                <span className="text-sm font-semibold">Findings</span>
                {(vulns?.length ?? 0) > 0 && (
                  <span className="px-1.5 py-0.5 rounded-full bg-muted text-xs font-medium tabular-nums">
                    {vulns?.length}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {bySev && (
                  <div className="flex items-center gap-1">
                    {bySev.critical > 0 && <SevPill label="C" count={bySev.critical} color={SEV_COLOR.critical} />}
                    {bySev.high     > 0 && <SevPill label="H" count={bySev.high}     color={SEV_COLOR.high} />}
                    {bySev.medium   > 0 && <SevPill label="M" count={bySev.medium}   color={SEV_COLOR.medium} />}
                    {bySev.low      > 0 && <SevPill label="L" count={bySev.low}      color={SEV_COLOR.low} />}
                  </div>
                )}
                {report && (
                  <>
                    <div className="h-4 w-px bg-border flex-shrink-0" />
                    <span className={cn("text-sm font-bold tabular-nums", riskColor(report.summary.riskScore))}>
                      {report.summary.riskScore}
                      <span className="text-xs text-muted-foreground font-normal">/100</span>
                    </span>
                    <span className="text-xs text-muted-foreground">risk</span>
                  </>
                )}
                {(vulns?.length ?? 0) > 0 && (
                  <>
                    <div className="h-4 w-px bg-border flex-shrink-0" />
                    <button
                      onClick={copyAllFindings}
                      className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                    >
                      {copiedAll ? <><Check className="w-3 h-3 text-green-500" /> Copied</> : <><Copy className="w-3 h-3" /> Copy all</>}
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Single scrollable area: findings + fix prompt */}
            <div className="flex-1 min-h-0 overflow-auto px-3 py-2 space-y-1">
              {!vulns?.length && (
                <p className="py-10 text-center text-xs text-muted-foreground">
                  {scan.status === "running"
                    ? "Scanning… findings will appear here."
                    : "No findings for this scan."}
                </p>
              )}
              {vulns?.map((v, i) => {
                const isOpen = expandedVulns.has(v.id);

                return (
                  <motion.div
                    key={v.id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.04 }}
                    className="rounded-lg overflow-hidden border border-border/60"
                    data-testid={`vuln-item-${v.id}`}
                  >
                    {/* Collapsed row — always visible */}
                    <button
                      onClick={() => toggleVuln(v.id)}
                      className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-accent/40 transition-colors"
                    >
                      <span
                        className="text-[11px] font-bold px-2 py-0.5 rounded uppercase flex-shrink-0"
                        style={{
                          backgroundColor: `${SEV_COLOR[v.severity] ?? SEV_COLOR.info}18`,
                          color: SEV_COLOR[v.severity] ?? SEV_COLOR.info,
                        }}
                      >
                        {v.severity}
                      </span>
                      <p className="text-sm font-medium flex-1 text-left truncate">{v.title}</p>
                      {v.cve && <span className="text-xs font-mono text-muted-foreground/50 flex-shrink-0">{v.cve}</span>}
                      <ChevronDown
                        className={cn("w-4 h-4 text-muted-foreground/40 flex-shrink-0 transition-transform duration-200", isOpen && "rotate-180")}
                      />
                    </button>

                    {/* Expanded body */}
                    {isOpen && (
                      <div className="px-4 pb-4 border-t border-border/40 bg-accent/20">
                        {v.description && (
                          <p className="text-sm text-muted-foreground leading-relaxed pt-3">{v.description}</p>
                        )}
                        {v.affectedAsset && (
                          <p className="text-xs font-mono text-primary/60 mt-2.5 truncate">↳ {v.affectedAsset}</p>
                        )}
                      </div>
                    )}
                  </motion.div>
                );
              })}

              {/* Fix prompt */}
              {report?.fixPrompt && (
                <div className="mt-3">
                  <div className="rounded-xl overflow-hidden border border-border">
                    {/* Header bar */}
                    <div className="flex items-center justify-between px-4 py-2 bg-accent border-b border-border">
                      <div className="flex items-center gap-2">
                        <FileText className="w-3.5 h-3.5 text-foreground/60" />
                        <span className="text-xs font-semibold text-foreground">One-Prompt Fix</span>
                      </div>
                      <button
                        onClick={() => copyFixPrompt(report.fixPrompt!)}
                        className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium text-foreground/60 hover:text-foreground hover:bg-border transition-colors"
                        data-testid="button-copy-fix-prompt"
                      >
                        {copiedPrompt ? <Check className="w-3 h-3 text-green-500" /> : <Copy className="w-3 h-3" />}
                        {copiedPrompt ? "Copied" : "Copy"}
                      </button>
                    </div>
                    {/* Body */}
                    <pre className="text-xs font-mono whitespace-pre-wrap text-foreground leading-relaxed bg-muted px-4 py-3">
                      {report.fixPrompt}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
