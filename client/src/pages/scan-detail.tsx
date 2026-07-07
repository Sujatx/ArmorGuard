import { useEffect, useRef, useState } from "react";
import { useParams, Link, useLocation } from "wouter";
import { motion } from "framer-motion";
import {
  ArrowLeft, RefreshCw, Loader, CheckCircle, XCircle, Clock,
  ShieldAlert, Terminal, Download, Plus, Copy, Check, FileText, ChevronDown, Square,
  Fingerprint, Brain, Swords, ShieldCheck, ShieldQuestion, Target, Wrench, TerminalSquare,
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
import type { ScanLog } from "@workspace/api-client-react";
import { useNewScan } from "@/hooks/use-new-scan";
import { cn } from "@/lib/utils";
import { Hint } from "@/components/ui/hint";

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

// ── Elapsed scan timer ─────────────────────────────────────────────────────
// Counts up live while the scan runs (like a "thinking" timer); freezes at the
// true wall-clock duration once the backend stamps completed_at.
function formatDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m > 0) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${s}s`;
}

function ScanTimer({ startedAt, completedAt, running }: {
  startedAt?: string | null; completedAt?: string | null; running: boolean;
}) {
  const startMs = startedAt ? new Date(startedAt).getTime() : null;
  const [now, setNow] = useState(() => Date.now());
  // Track whether we watched this scan run in the current session. If so, freezing on the
  // last tick is an accurate end estimate even when the backend didn't persist completed_at.
  const observedRunning = useRef(running);
  useEffect(() => {
    if (running) observedRunning.current = true;
    if (!running) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [running]);
  if (!startMs || Number.isNaN(startMs)) return null;

  const completedMs = completedAt ? new Date(completedAt).getTime() : NaN;
  let endMs: number;
  if (running) {
    endMs = now;
  } else if (!Number.isNaN(completedMs)) {
    endMs = completedMs;                 // persisted true end — always accurate
  } else if (observedRunning.current) {
    endMs = now;                         // finished while we watched — freeze on last tick
  } else {
    return null;                         // historical scan with no stored end — don't guess
  }
  return (
    <>
      <span className="text-muted-foreground/40">·</span>
      <span className={cn(
        "inline-flex items-center gap-1 text-xs tabular-nums font-medium",
        running ? "text-primary" : "text-muted-foreground",
      )}>
        <Clock className={cn("w-3 h-3", running && "animate-pulse")} />
        {formatDuration(endMs - startMs)}
      </span>
    </>
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

// ── Autonomous phased terminal ─────────────────────────────────────────────
// The intent pipeline narrates itself with [fingerprint]/[select]/[attack]/
// [confirm]/[report] tags. We group the flat WS log stream into those phases and
// render them as labelled, colour-coded sections — a legible pentester's console
// instead of one gray wall of text. Deterministic modes keep the classic flat view.
type PhaseKey = "fingerprint" | "select" | "attack" | "confirm" | "report";
const PHASE_META: Record<PhaseKey, { label: string; icon: React.ElementType; color: string }> = {
  fingerprint: { label: "Fingerprint", icon: Fingerprint, color: "#a78bfa" },
  select:      { label: "Select",      icon: Brain,       color: "#60a5fa" },
  attack:      { label: "Attack",      icon: Swords,      color: "#fb923c" },
  confirm:     { label: "Confirm",     icon: ShieldCheck, color: "#4ade80" },
  report:      { label: "Report",      icon: FileText,    color: "#fbbf24" },
};
const PHASE_RE = /\[(fingerprint|select|attack|confirm|report)\]/i;

function detectPhase(message: string): PhaseKey | null {
  const m = message.match(PHASE_RE);
  return m ? (m[1].toLowerCase() as PhaseKey) : null;
}

function cleanMessage(message: string, hasPhase: boolean): string {
  let m = message.replace(/^\[agent\]\s*/i, "").replace(/^\[tool\]\s*/i, "");
  if (hasPhase) m = m.replace(PHASE_RE, "");
  return m.replace(/^\s*[—–-]\s*/, "").trim();
}

// Wrap MITRE technique IDs (T1190, T1550.001) in a small chip.
function renderWithChips(text: string) {
  const parts = text.split(/(T\d{4}(?:\.\d{3})?)/g);
  return parts.map((p, i) =>
    /^T\d{4}(?:\.\d{3})?$/.test(p) ? (
      <span
        key={i}
        className="inline-flex items-center px-1.5 py-px mx-0.5 rounded bg-primary/15 text-primary text-[10px] font-semibold align-middle"
      >
        {p}
      </span>
    ) : (
      <span key={i}>{p}</span>
    ),
  );
}

function lineTone(message: string, level: string): string {
  if (level === "error") return "text-red-300";
  if (/✔|proven/i.test(message)) return "text-green-300";
  if (/demoted|unconfirmed/i.test(message)) return "text-[#D4AA6A]";
  if (level === "warn") return "text-[#D4AA6A]";
  if (level === "ok") return "text-green-300";
  return "text-slate-300";
}

type PhaseGroup = { phase: PhaseKey | "init"; lines: ScanLog[] };

function groupByPhase(logs: ScanLog[]): PhaseGroup[] {
  const groups: PhaseGroup[] = [];
  let current: PhaseKey | "init" = "init";
  for (const log of logs) {
    const p = detectPhase(log.message);
    if (p) current = p;
    let g = groups[groups.length - 1];
    if (!g || g.phase !== current) {
      g = { phase: current, lines: [] };
      groups.push(g);
    }
    g.lines.push(log);
  }
  return groups;
}

function PhasedTerminal({ logs }: { logs: ScanLog[] }) {
  const groups = groupByPhase(logs);
  return (
    <>
      {groups.map((g, gi) => {
        const meta = g.phase === "init" ? null : PHASE_META[g.phase];
        return (
          <div key={gi} className={cn("mb-3", meta && "pl-3 border-l-2")} style={meta ? { borderColor: `${meta.color}55` } : undefined}>
            {meta && (
              <div className="flex items-center gap-1.5 mb-1 -ml-3 pl-2.5">
                <meta.icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: meta.color }} />
                <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: meta.color }}>
                  {meta.label}
                </span>
              </div>
            )}
            {g.lines.map((log) => {
              const msg = cleanMessage(log.message, g.phase !== "init");
              if (!msg) return null;
              return (
                <motion.div
                  key={log.id}
                  initial={{ opacity: 0, x: -4 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-start gap-2 mb-0.5"
                  data-testid={`log-entry-${log.id}`}
                >
                  <span className="text-slate-600 flex-shrink-0 tabular-nums text-[10px] pt-px">
                    {new Date(log.timestamp).toLocaleTimeString("en-US", { hour12: false })}
                  </span>
                  <span className={cn("flex-1 leading-relaxed", lineTone(log.message, log.level))}>
                    {renderWithChips(msg)}
                  </span>
                </motion.div>
              );
            })}
          </div>
        );
      })}
    </>
  );
}

function FlatTerminal({ logs }: { logs: ScanLog[] }) {
  return (
    <>
      {logs.map((log, i) => (
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
          <span className={cn("flex-1", lineTone(log.message, log.level))}>
            {log.message}
          </span>
        </motion.div>
      ))}
    </>
  );
}

// Per-mode badge — a bordered tint pill, one distinct color per scan mode.
const MODE_META: Record<string, { label: string; color: string }> = {
  autonomous: { label: "Auto", color: "#a78bfa" }, // violet — echoes the pipeline phases
  deep:       { label: "Deep",       color: "#60a5fa" }, // blue
  custom:     { label: "Custom",     color: "#94a3b8" }, // slate
  default:    { label: "Default",    color: "#34d399" }, // emerald
};

function ScanModeBadge({ mode }: { mode: string }) {
  const meta = MODE_META[mode] ?? { label: mode, color: "#94a3b8" };
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
      style={{ color: meta.color, borderColor: `${meta.color}55`, backgroundColor: `${meta.color}14` }}
    >
      {meta.label}
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
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold uppercase border"
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
  const [isMobile, setIsMobile] = useState(() => typeof window !== "undefined" && window.innerWidth < 640);
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

  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth < 640);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const { data: scan, isLoading: scanLoading } = useGetScan(id);
  const { data: logs } = useGetScanLogs(id);
  const { data: vulns } = useListVulnerabilities({ scanId: id });
  const { data: report } = useGetReport(id, { isRunning: scan?.status === "running" });

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
  const isAutonomous = scan.scanType === "autonomous";

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
      {/* Full-height flex column — locked so the panels fill the viewport on mobile and desktop */}
      <div className="flex flex-col h-full overflow-hidden bg-black/[0.04] dark:bg-black/20">

        {/* ── Header ── */}
        <div className="flex-shrink-0 px-3 sm:px-5 pt-3 sm:pt-5 pb-3 border-b border-border bg-background/80 backdrop-blur-xl supports-[backdrop-filter]:bg-background/60">

          {/* Row 1: back · target · actions */}
          <div className="flex items-center gap-2 sm:gap-3">
            <Link href="/">
              <motion.button
                whileHover={{ x: -2 }}
                whileTap={{ scale: 0.92 }}
                className="w-9 h-9 sm:w-8 sm:h-8 flex-shrink-0 rounded-xl border border-border flex items-center justify-center text-muted-foreground hover:text-foreground transition-colors"
                data-testid="button-back"
              >
                <ArrowLeft className="w-5 h-5 sm:w-4 sm:h-4" />
              </motion.button>
            </Link>

            {/* Target — stretches to fill, truncates on overflow */}
            <h1 className="flex-1 min-w-0 text-base font-bold font-mono leading-tight truncate">{scan.target}</h1>

            {/* Action buttons — icon-only on mobile, labelled on sm+ */}
            <div className="flex items-center gap-1 flex-shrink-0">
              {scan.status === "running" && (
                <Hint label="Stop scan" side="bottom">
                  <button
                    onClick={() => stopScan.mutate({ scanId: id! })}
                    disabled={stopScan.isPending}
                    className="w-9 h-9 sm:w-auto sm:h-auto sm:px-3 sm:py-1.5 sm:gap-1.5 rounded-xl text-xs font-semibold border border-red-500/40 text-red-400 hover:bg-red-500/10 transition-all active:scale-95 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                    data-testid="button-stop-scan"
                  >
                    <Square className="w-5 h-5 sm:w-3.5 sm:h-3.5 fill-current flex-shrink-0" />
                    <span className="hidden sm:inline">{stopScan.isPending ? "Stopping…" : "Stop"}</span>
                  </button>
                </Hint>
              )}
              {scan.status === "failed" && (
                <Hint label="Retry scan" side="bottom">
                  <button
                    onClick={() => retryScan.mutate(
                      { data: { target: scan.target, scanType: scan.scanType as "default" | "deep" | "custom" | "autonomous", consentId: null } },
                      { onSuccess: (r: { scanId: string }) => navigate(`/scans/${r.scanId}`) }
                    )}
                    disabled={retryScan.isPending}
                    className="w-9 h-9 sm:w-auto sm:h-auto sm:px-3 sm:py-1.5 sm:gap-1.5 rounded-xl text-xs font-semibold border border-red-500/40 text-red-400 hover:bg-red-500/10 transition-all active:scale-95 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                    data-testid="button-retry-scan"
                  >
                    <RefreshCw className={cn("w-5 h-5 sm:w-3.5 sm:h-3.5 flex-shrink-0", retryScan.isPending && "animate-spin")} />
                    <span className="hidden sm:inline">{retryScan.isPending ? "Retrying…" : "Retry"}</span>
                  </button>
                </Hint>
              )}
              {scan.status === "completed" && (
                <Hint label="Re-scan this target" side="bottom">
                  <button
                    onClick={() => openNewScan({ target: scan.target, scanType: scan.scanType })}
                    className="w-9 h-9 sm:w-auto sm:h-auto sm:px-3 sm:py-1.5 sm:gap-1.5 rounded-xl text-xs font-semibold border border-border text-muted-foreground hover:border-foreground/20 hover:bg-accent hover:text-foreground transition-all active:scale-95 cursor-pointer flex items-center justify-center"
                    data-testid="button-rescan"
                  >
                    <RefreshCw className="w-5 h-5 sm:w-3.5 sm:h-3.5 flex-shrink-0" />
                    <span className="hidden sm:inline">Re-scan</span>
                  </button>
                </Hint>
              )}
              <Hint label="New scan" side="bottom">
                <button
                  onClick={() => openNewScan()}
                  className="w-9 h-9 sm:w-auto sm:h-auto sm:px-3 sm:py-1.5 sm:gap-1.5 rounded-xl text-xs font-semibold border border-border text-foreground hover:border-foreground/20 hover:bg-accent hover:text-foreground transition-all active:scale-95 cursor-pointer flex items-center justify-center"
                  data-testid="button-new-scan-detail"
                >
                  <Plus className="w-5 h-5 sm:w-3.5 sm:h-3.5 flex-shrink-0" />
                  <span className="hidden sm:inline">New Scan</span>
                </button>
              </Hint>
              {(scan.status === "completed" || scan.status === "failed") && report && (
                <Hint label="Export PDF report" side="bottom-end">
                  <a
                    href={`${BACKEND_URL}/report/${id}/export`}
                    download={`armorguard-${scan.target.replace(/^https?:\/\//, "").split("/")[0].replace(/:\d+$/, "")}.pdf`}
                    className="w-9 h-9 sm:w-auto sm:h-auto sm:px-3 sm:py-1.5 sm:gap-1.5 rounded-xl text-xs font-semibold border border-border text-muted-foreground hover:border-foreground/20 hover:bg-accent hover:text-foreground transition-all active:scale-95 flex items-center justify-center"
                    data-testid="button-export-pdf"
                  >
                    <Download className="w-5 h-5 sm:w-3.5 sm:h-3.5 flex-shrink-0" />
                    <span className="hidden sm:inline">Export</span>
                  </a>
                </Hint>
              )}
            </div>
          </div>

          {/* Row 2: status · scan type · elapsed timer · progress % */}
          <div className="flex items-center gap-2 mt-2 pl-10 sm:pl-11 flex-wrap">
            <StatusBadge status={scan.status} />
            <ScanModeBadge mode={scan.scanType} />
            <ScanTimer startedAt={scan.startedAt} completedAt={scan.completedAt} running={scan.status === "running"} />
            {scan.status === "running" && (
              <span className="text-xs font-bold tabular-nums text-primary ml-auto sm:ml-0">{scan.progress ?? 0}%</span>
            )}
          </div>

          {/* Progress bar with running shimmer */}
          {scan.status === "running" && (
            <div className="h-1 bg-muted rounded-full overflow-hidden mt-2.5 relative">
              <motion.div
                className="h-full bg-primary rounded-full relative overflow-hidden"
                initial={{ width: 0 }}
                animate={{ width: `${scan.progress ?? 0}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              >
                <motion.div
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-white/40 to-transparent"
                  animate={{ x: ["-100%", "200%"] }}
                  transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
                />
              </motion.div>
            </div>
          )}
        </div>

        {/* ── 2-column body ── */}
        <div ref={splitContainerRef} className="flex flex-col sm:flex-row flex-1 min-h-0 gap-3 p-2 sm:p-3">

          {/* Left — Terminal */}
          <div
            className="flex flex-col rounded-2xl overflow-hidden border border-border flex-1 min-h-0 sm:flex-none shadow-sm"
            style={isMobile ? undefined : { width: `${leftPct}%` }}
          >
            {/* Terminal titlebar */}
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/10 bg-[hsl(224,71%,7%)] flex-shrink-0 rounded-t-2xl">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <div className="w-3 h-3 rounded-full bg-[#C9923A]" />
                <div className="w-3 h-3 rounded-full bg-green-500" />
              </div>
              <Terminal className="w-4 h-4 text-slate-400 flex-shrink-0" />
              <span className="text-xs sm:text-[13px] font-mono text-slate-300 flex-1 truncate">
                {isAutonomous ? "armoriq-agent" : "recon-agent"} — {scan.target}
              </span>
              {scan.status === "running" && <RefreshCw className="w-4 h-4 text-slate-400 animate-spin flex-shrink-0" />}
            </div>
            {/* Terminal body */}
            <div
              ref={logContainerRef}
              className="flex-1 min-h-0 overflow-auto p-4 font-mono text-[11px] leading-relaxed terminal-scroll bg-[hsl(224,71%,3%)]"
              data-testid="terminal-output"
            >
              {!logs?.length && <p className="text-slate-500">Waiting for agent output…</p>}
              {logs && (isAutonomous ? <PhasedTerminal logs={logs} /> : <FlatTerminal logs={logs} />)}
              <div className="flex items-center gap-1 mt-2">
                <span className="text-primary">❯</span>
                <span className="text-slate-600 animate-pulse">_</span>
              </div>
            </div>
          </div>

          {/* Drag handle — desktop only */}
          <div
            className="hidden sm:flex flex-shrink-0 w-2 items-center justify-center cursor-col-resize group select-none"
            onMouseDown={startDrag}
          >
            <div className="w-0.5 h-10 rounded-full bg-border group-hover:bg-primary transition-colors duration-150" />
          </div>

          {/* Right — Findings + Report */}
          <div className="flex flex-col flex-1 min-h-0 rounded-2xl border border-border overflow-hidden bg-card shadow-sm">

            {/* Findings header */}
            <div className="flex-shrink-0 px-4 py-2.5 border-b border-border space-y-1.5">
              {/* Row 1: title + risk score + copy */}
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <ShieldAlert className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                  <span className="text-sm font-semibold">Findings</span>
                  {(vulns?.length ?? 0) > 0 && (
                    <span className="px-1.5 py-0.5 rounded-full bg-muted text-xs font-medium tabular-nums">
                      {vulns?.length}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  {report && (
                    <>
                      <span className={cn("text-sm font-bold tabular-nums", riskColor(report.summary.riskScore))}>
                        {report.summary.riskScore}
                        <span className="text-xs text-muted-foreground font-normal">/100</span>
                      </span>
                      <span className="text-xs text-muted-foreground">risk</span>
                    </>
                  )}
                  {(vulns?.length ?? 0) > 0 && (
                    <>
                      {report && <div className="h-4 w-px bg-border flex-shrink-0" />}
                      <button
                        onClick={copyAllFindings}
                        className="flex items-center gap-1 px-2 py-0.5 rounded-lg text-xs font-medium text-muted-foreground hover:text-foreground hover:bg-accent transition-colors active:scale-95"
                      >
                        {copiedAll ? <><Check className="w-3 h-3 text-green-500" /> Copied</> : <><Copy className="w-3 h-3" /> Copy all</>}
                      </button>
                    </>
                  )}
                </div>
              </div>
              {/* Row 2: severity pills — only when present */}
              {bySev && (bySev.critical > 0 || bySev.high > 0 || bySev.medium > 0 || bySev.low > 0) && (
                <div className="flex items-center gap-1 flex-wrap">
                  {bySev.critical > 0 && <SevPill label="C" count={bySev.critical} color={SEV_COLOR.critical} />}
                  {bySev.high     > 0 && <SevPill label="H" count={bySev.high}     color={SEV_COLOR.high} />}
                  {bySev.medium   > 0 && <SevPill label="M" count={bySev.medium}   color={SEV_COLOR.medium} />}
                  {bySev.low      > 0 && <SevPill label="L" count={bySev.low}      color={SEV_COLOR.low} />}
                </div>
              )}
            </div>

            {/* Single scrollable area: findings + fix prompt */}
            <div className="flex-1 min-h-0 overflow-auto px-3 py-2 space-y-1 pb-4">
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
                    className="rounded-xl overflow-hidden border border-border/60"
                    data-testid={`vuln-item-${v.id}`}
                  >
                    {/* Collapsed row — always visible */}
                    <button
                      onClick={() => toggleVuln(v.id)}
                      className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-accent/40 transition-colors"
                    >
                      <span
                        className="text-xs font-bold px-2 py-0.5 rounded uppercase flex-shrink-0"
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
                      <div className="px-4 pb-4 border-t border-border/40 bg-accent/20 space-y-3 pt-3">
                        {/* Confidence badge + metadata strip (CVSS / CWE / OWASP / MITRE) */}
                        {(v.confidence || v.cvssScore || v.cweId || v.owaspCategory || v.attackTechniqueId) && (
                          <div className="flex flex-wrap items-center gap-1.5">
                            {v.confidence && (
                              <span
                                className={cn(
                                  "flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider border",
                                  v.confidence.toLowerCase().includes("confirmed")
                                    ? "bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/30"
                                    : "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30",
                                )}
                              >
                                {v.confidence.toLowerCase().includes("confirmed")
                                  ? <ShieldCheck className="w-3 h-3" />
                                  : <ShieldQuestion className="w-3 h-3" />}
                                {v.confidence}
                              </span>
                            )}
                            {v.cvssScore != null && (
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-border bg-muted text-foreground/70">
                                CVSS {v.cvssScore.toFixed(1)}
                              </span>
                            )}
                            {v.cweId && (
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-border bg-muted text-foreground/70">
                                {v.cweId}
                              </span>
                            )}
                            {v.owaspCategory && (
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-border bg-muted text-foreground/70">
                                {v.owaspCategory}
                              </span>
                            )}
                            {v.attackTechniqueId && (
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-border bg-muted text-foreground/70">
                                {v.attackTechniqueId}
                              </span>
                            )}
                          </div>
                        )}

                        {v.description && (
                          <p className="text-sm text-muted-foreground leading-relaxed">{v.description}</p>
                        )}

                        {v.businessImpact && (
                          <div>
                            <p className="flex items-center gap-1.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                              <Target className="w-3 h-3" /> Business Impact
                            </p>
                            <p className="text-sm text-foreground/80 leading-relaxed">{v.businessImpact}</p>
                          </div>
                        )}

                        {v.affectedAsset && (
                          <div>
                            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Affected Asset</p>
                            <p className="text-xs font-mono text-primary/70 break-all">{v.affectedAsset}</p>
                          </div>
                        )}

                        {v.reproduction && (
                          <div>
                            <p className="flex items-center gap-1.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                              <Wrench className="w-3 h-3" /> Reproduction
                            </p>
                            <p className="text-xs font-mono text-foreground/70 leading-relaxed bg-muted rounded-lg px-2.5 py-2 whitespace-pre-wrap">
                              {v.reproduction}
                            </p>
                          </div>
                        )}

                        {/* Proof of exploitation — the [PROOF] blast-radius block, never truncated */}
                        {v.evidence && (
                          <div>
                            <p className="flex items-center gap-1.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                              <TerminalSquare className="w-3 h-3" /> Evidence
                            </p>
                            <pre className="text-xs font-mono leading-relaxed bg-neutral-950 text-green-400 rounded-lg px-3 py-2.5 whitespace-pre-wrap break-all max-h-64 overflow-y-auto terminal-scroll border border-border/60">
                              {v.evidence}
                            </pre>
                          </div>
                        )}

                        {v.compliance && v.compliance.length > 0 && (
                          <div>
                            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Compliance Mapping</p>
                            <div className="flex flex-wrap gap-1.5">
                              {v.compliance.map((tag) => (
                                <span
                                  key={tag}
                                  className="text-[10px] font-semibold px-1.5 py-0.5 rounded border border-primary/30 bg-primary/10 text-primary"
                                >
                                  {tag}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </motion.div>
                );
              })}

              {/* Fix prompt */}
              {report?.fixPrompt && (
                <div className="mt-3">
                  <div className="rounded-2xl overflow-hidden border border-border">
                    {/* Header bar */}
                    <div className="flex items-center justify-between px-4 py-2 bg-accent border-b border-border">
                      <div className="flex items-center gap-2">
                        <FileText className="w-3.5 h-3.5 text-foreground/60" />
                        <span className="text-xs font-semibold text-foreground">One-Prompt Fix</span>
                      </div>
                      <button
                        onClick={() => copyFixPrompt(report.fixPrompt!)}
                        className="flex items-center gap-1 px-2 py-0.5 rounded-lg text-xs font-medium text-foreground/60 hover:text-foreground hover:bg-border transition-colors active:scale-95"
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
