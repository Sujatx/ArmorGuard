import { useState, useEffect, useRef, useMemo } from "react";
import { motion, useReducedMotion, type Variants } from "framer-motion";
import {
  Scan, ShieldAlert, AlertTriangle, Flame, Activity, ArrowRight,
  ShieldCheck, Crosshair, Target, Terminal,
} from "lucide-react";
import Layout from "@/components/layout";
import {
  useGetDashboardSummary,
  useGetSeverityBreakdown,
  useGetRecentActivity,
  useListScans,
  useGetReport,
} from "@workspace/api-client-react";
import { useNewScan } from "@/hooks/use-new-scan";
import { cn } from "@/lib/utils";

function useCountUp(target: number, duration = 1200) {
  const [val, setVal] = useState(0);
  const start = useRef(0);
  const frame = useRef<number>(0);
  useEffect(() => {
    const t0 = performance.now();
    const from = start.current;
    function tick(now: number) {
      const p = Math.min((now - t0) / duration, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(from + (target - from) * ease));
      if (p < 1) frame.current = requestAnimationFrame(tick);
      else start.current = target;
    }
    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
  }, [target, duration]);
  return val;
}

function AnimatedNumber({ value, suffix = "" }: { value: number; suffix?: string }) {
  const animated = useCountUp(value);
  return <span>{animated}{suffix}</span>;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6366f1",
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

// ---------- Spotlight sourcing ----------
// The backend enriches confirmed findings with fields beyond the generated
// `Finding` type (confidence, attackTechniqueId, cvssScore, ...). We only read
// them defensively, so a local structural extension keeps this type-safe without
// touching the shared API client.
type ProvenFinding = {
  findingId: string;
  severity: string;
  title: string;
  description: string;
  evidence?: string | null;
  confidence?: string | null;
  attackTechniqueId?: string | null;
};

function extractProof(evidence?: string | null): string | null {
  if (!evidence) return null;
  const i = evidence.indexOf("[PROOF]");
  if (i < 0) return null;
  const proof = evidence.slice(i + "[PROOF]".length).trim();
  return proof.length ? proof : null;
}

function isConfirmed(f: ProvenFinding): boolean {
  return f.confidence === "Confirmed (Exploited)" || !!extractProof(f.evidence);
}

function RiskGauge({ score }: { score: number }) {
  const angle = -135 + (score / 100) * 270;
  const color = score >= 75 ? "#ef4444" : score >= 50 ? "#f97316" : score >= 25 ? "#eab308" : "#22c55e";
  return (
    <div className="flex flex-col items-center justify-center gap-1">
      <svg viewBox="0 0 120 80" className="w-28 h-20">
        <path d="M 15 75 A 50 50 0 0 1 105 75" fill="none" stroke="currentColor" strokeWidth="8" strokeLinecap="round" className="text-muted/30" />
        <motion.path
          d="M 15 75 A 50 50 0 0 1 105 75"
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray="157"
          initial={{ strokeDashoffset: 157 }}
          animate={{ strokeDashoffset: 157 - (score / 100) * 157 }}
          transition={{ duration: 1.5, ease: "easeOut" }}
        />
        <motion.g
          initial={{ rotate: -135, originX: 60, originY: 75 }}
          animate={{ rotate: angle, originX: 60, originY: 75 }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          style={{ transformOrigin: "60px 75px" }}
        >
          <line x1="60" y1="75" x2="60" y2="35" stroke={color} strokeWidth="2.5" strokeLinecap="round" />
          <circle cx="60" cy="75" r="4" fill={color} />
        </motion.g>
      </svg>
      <p className="text-2xl font-bold tabular-nums" style={{ color }}>
        <AnimatedNumber value={score} />
      </p>
      <p className="text-xs text-muted-foreground">Aggregate Risk</p>
    </div>
  );
}

function MetricCard({
  label, value, icon: Icon, accent = false, delay = 0,
}: {
  label: string;
  value: number;
  icon: React.ElementType;
  accent?: boolean;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
      className="bg-card border border-card-border rounded-xl p-4 hover:border-primary/30 transition-colors group"
      data-testid={`metric-card-${label.toLowerCase().replace(/\s+/g, "-")}`}
    >
      <div className="flex items-center gap-2 mb-3">
        <Icon className={cn("w-4 h-4 transition-transform group-hover:scale-110", accent ? "text-primary" : "text-muted-foreground")} />
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{label}</p>
      </div>
      <p className="text-3xl font-bold tabular-nums leading-none">
        <AnimatedNumber value={value} />
      </p>
    </motion.div>
  );
}

function ActivityType({ type }: { type: string }) {
  const map: Record<string, { label: string; color: string }> = {
    scan_started: { label: "SCAN", color: "bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/30" },
    scan_completed: { label: "SCAN", color: "bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/30" },
    vulnerability_found: { label: "VULN", color: "bg-red-500/15 text-red-500 border-red-500/30" },
    threat_detected: { label: "THREAT", color: "bg-red-500/15 text-red-500 border-red-500/30" },
  };
  const { label, color } = map[type] ?? { label: type.toUpperCase(), color: "bg-muted text-muted-foreground" };
  return (
    <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider border", color)}>
      {label}
    </span>
  );
}

function SeverityChip({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  const color = SEVERITY_COLORS[s] ?? SEVERITY_COLORS.info;
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border"
      style={{ color, borderColor: `${color}55`, backgroundColor: `${color}18` }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {s}
    </span>
  );
}

export default function Dashboard() {
  const reduceMotion = useReducedMotion();
  const { data: summary } = useGetDashboardSummary();
  const { data: severity } = useGetSeverityBreakdown();
  const { data: activity } = useGetRecentActivity();
  const { data: scans } = useListScans();
  const { openNewScan } = useNewScan();

  const sevCount = (name: string) => severity?.find(s => s.severity === name)?.count ?? 0;

  const totalScans = summary?.totalScans ?? 0;
  const totalVulns = summary?.totalVulnerabilities ?? 0;
  const hasScans = totalScans > 0 || (scans?.length ?? 0) > 0;
  const scanRunning = scans?.some(s => s.status === "running" || s.status === "queued") ?? false;

  // Weights chosen so a handful of criticals reads meaningfully below 100;
  // only truly severe scan sets should approach the cap.
  const aggregateRisk = Math.min(
    100,
    Math.round(sevCount("critical") * 15 + sevCount("high") * 8 + sevCount("medium") * 3 + sevCount("low") * 0.5)
  );

  // --- Spotlight: the most recent completed scan that actually found something ---
  const spotlightScanId = useMemo(() => {
    if (!scans?.length) return undefined;
    const candidate = scans.find(
      s => s.status === "completed" && (s.vulnerabilitiesCount ?? 0) > 0
    );
    return candidate?.id;
  }, [scans]);

  const spotlightTarget = useMemo(
    () => scans?.find(s => s.id === spotlightScanId)?.target,
    [scans, spotlightScanId],
  );

  const { data: report } = useGetReport(spotlightScanId);

  const provenFinding = useMemo<ProvenFinding | null>(() => {
    const findings = (report?.findings as ProvenFinding[] | undefined) ?? [];
    const confirmed = findings.filter(isConfirmed);
    if (!confirmed.length) return null;
    return [...confirmed].sort(
      (a, b) => (SEVERITY_RANK[b.severity.toLowerCase()] ?? 0) - (SEVERITY_RANK[a.severity.toLowerCase()] ?? 0)
    )[0];
  }, [report]);

  const proofLines = useMemo(() => {
    const proof = extractProof(provenFinding?.evidence);
    if (!proof) return [];
    return proof.split("\n").map(l => l.trim()).filter(Boolean).slice(0, 6);
  }, [provenFinding]);

  function formatTime(ts: string) {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  const heroContainer: Variants = {
    hidden: {},
    show: { transition: { staggerChildren: reduceMotion ? 0 : 0.08, delayChildren: 0.05 } },
  };
  const heroItem: Variants = {
    hidden: { opacity: 0, y: reduceMotion ? 0 : 18 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 120, damping: 18 } },
  };

  return (
    <Layout>
      <div className="p-3 sm:p-6 space-y-5 sm:space-y-8">

        {/* ============ 1. HERO — the Halo ============ */}
        <motion.section
          variants={heroContainer}
          initial="hidden"
          animate="show"
          className="relative overflow-hidden rounded-2xl border border-card-border bg-card"
        >
          {/* Low-opacity atmospheric backdrop */}
          <div className="pointer-events-none absolute inset-0" aria-hidden="true">
            <div
              className="absolute inset-0 opacity-[0.05] dark:opacity-[0.07]"
              style={{
                backgroundImage:
                  "linear-gradient(hsl(var(--foreground)) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--foreground)) 1px, transparent 1px)",
                backgroundSize: "34px 34px",
                maskImage: "radial-gradient(ellipse 80% 90% at 70% 0%, black, transparent 75%)",
                WebkitMaskImage: "radial-gradient(ellipse 80% 90% at 70% 0%, black, transparent 75%)",
              }}
            />
            <div className="absolute -top-32 -right-24 w-[28rem] h-[28rem] rounded-full bg-primary/10 blur-3xl" />
            {!reduceMotion && (
              <motion.div
                className="absolute inset-x-0 h-24 bg-gradient-to-b from-transparent via-primary/10 to-transparent"
                initial={{ top: "-10%" }}
                animate={{ top: ["-10%", "110%"] }}
                transition={{ duration: 6, repeat: Infinity, ease: "linear" }}
              />
            )}
          </div>

          <div className="relative px-5 py-10 sm:px-10 sm:py-16 min-h-[420px] sm:min-h-[520px] flex flex-col justify-center max-w-3xl">
            {/* Eyebrow + live status */}
            <motion.div variants={heroItem} className="flex items-center gap-2.5 mb-5">
              <span className="inline-flex items-center gap-2 rounded-full border border-card-border bg-background/60 backdrop-blur px-3 py-1 text-xs font-medium text-muted-foreground">
                <ShieldCheck className="w-3.5 h-3.5 text-primary" />
                Autonomous offensive security
              </span>
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                <span className="relative flex h-2 w-2">
                  {!reduceMotion && scanRunning && (
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
                  )}
                  <span className={cn("relative inline-flex h-2 w-2 rounded-full", scanRunning ? "bg-primary" : "bg-green-500")} />
                </span>
                {scanRunning ? "Scan in progress" : "Systems ready"}
              </span>
            </motion.div>

            {/* Headline */}
            <motion.h1
              variants={heroItem}
              className="text-4xl sm:text-6xl font-bold tracking-tight leading-[1.05]"
            >
              Prove what's actually
              <br className="hidden sm:block" />{" "}
              <span className="text-primary">exploitable.</span>
            </motion.h1>

            {/* Subhead */}
            <motion.p
              variants={heroItem}
              className="mt-5 text-base sm:text-lg text-muted-foreground max-w-xl leading-relaxed"
            >
              ArmorGuard doesn't scan — it <span className="text-foreground font-medium">proves</span>.
              It exploits every vulnerability it finds and extracts real, safely-masked
              evidence. Confirmed, not guessed.
            </motion.p>

            {/* Personalized live line */}
            <motion.p
              variants={heroItem}
              className="mt-4 text-sm text-muted-foreground/90"
            >
              {hasScans ? (
                <>
                  <span className="font-semibold text-foreground tabular-nums">
                    <AnimatedNumber value={totalVulns} />
                  </span>{" "}
                  {totalVulns === 1 ? "vulnerability" : "vulnerabilities"} confirmed across{" "}
                  <span className="font-semibold text-foreground tabular-nums">
                    <AnimatedNumber value={totalScans} />
                  </span>{" "}
                  {totalScans === 1 ? "scan" : "scans"}.
                </>
              ) : (
                <>No scans yet — run your first and watch ArmorGuard prove what's exploitable.</>
              )}
            </motion.p>

            {/* Primary CTA */}
            <motion.div variants={heroItem} className="mt-8 flex flex-wrap items-center gap-4">
              <div className="relative group">
                <div className="absolute -inset-1 rounded-xl bg-primary/40 blur-lg opacity-0 group-hover:opacity-70 transition-opacity duration-300" aria-hidden="true" />
                <motion.button
                  whileHover={{ scale: 1.03 }}
                  whileTap={{ scale: 0.97 }}
                  onClick={() => openNewScan()}
                  className="relative flex items-center gap-2 px-6 py-3 rounded-xl bg-primary text-primary-foreground text-sm font-semibold shadow-lg shadow-primary/20 hover:bg-primary/90 transition-colors"
                  data-testid="button-new-scan-hero"
                >
                  <Crosshair className="w-4 h-4" />
                  {hasScans ? "New Scan" : "Run your first scan"}
                  <ArrowRight className="w-4 h-4" />
                </motion.button>
              </div>
              <span className="text-xs text-muted-foreground">
                Autonomous · Fingerprint → Exploit → Confirm
              </span>
            </motion.div>
          </div>
        </motion.section>

        {/* ============ 2. THE PEAK — Latest Proven Finding ============ */}
        <motion.section
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15, duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        >
          <div className="flex items-center gap-2 mb-3">
            <ShieldCheck className="w-4 h-4 text-primary" />
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Latest Proven Finding</h2>
          </div>

          {provenFinding ? (
            <div className="relative overflow-hidden rounded-2xl border border-primary/25 bg-gradient-to-br from-primary/[0.07] via-card to-card">
              <div className="absolute -top-24 -left-16 w-72 h-72 rounded-full bg-primary/10 blur-3xl pointer-events-none" aria-hidden="true" />
              <div className="relative grid grid-cols-1 lg:grid-cols-2 gap-5 p-5 sm:p-7">
                {/* Left — the claim */}
                <div className="flex flex-col">
                  <div className="flex flex-wrap items-center gap-2 mb-4">
                    <SeverityChip severity={provenFinding.severity} />
                    <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border border-green-500/40 bg-green-500/15 text-green-600 dark:text-green-400">
                      <ShieldCheck className="w-3 h-3" /> Confirmed · Exploited
                    </span>
                    {provenFinding.attackTechniqueId && (
                      <span className="text-[11px] font-mono text-muted-foreground border border-card-border rounded px-1.5 py-0.5">
                        {provenFinding.attackTechniqueId}
                      </span>
                    )}
                  </div>
                  <h3 className="text-2xl sm:text-3xl font-bold leading-tight">{provenFinding.title}</h3>
                  {spotlightTarget && (
                    <p className="mt-2 flex items-center gap-1.5 text-sm text-muted-foreground">
                      <Target className="w-3.5 h-3.5" />
                      <span className="font-mono truncate">{spotlightTarget}</span>
                    </p>
                  )}
                  <p className="mt-3 text-sm text-muted-foreground leading-relaxed line-clamp-3">
                    {provenFinding.description}
                  </p>
                  <div className="mt-auto pt-5">
                    <motion.button
                      whileHover={{ x: 3 }}
                      onClick={() => openNewScan()}
                      className="inline-flex items-center gap-1.5 text-sm font-semibold text-primary hover:underline"
                    >
                      Prove it on your target <ArrowRight className="w-4 h-4" />
                    </motion.button>
                  </div>
                </div>

                {/* Right — the proof (the thesis made visible) */}
                <div className="rounded-xl border border-card-border bg-background/70 backdrop-blur overflow-hidden">
                  <div className="flex items-center gap-2 px-3.5 py-2 border-b border-card-border bg-muted/40">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
                    <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
                    <span className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
                    <span className="ml-1.5 flex items-center gap-1.5 text-[11px] font-mono text-muted-foreground">
                      <Terminal className="w-3 h-3" /> proof-of-exploitation
                    </span>
                  </div>
                  <div className="p-3.5 font-mono text-xs leading-relaxed space-y-1.5">
                    {proofLines.map((line, i) => {
                      const evidence = /•|masked|exposed|sensitive/i.test(line);
                      return (
                        <p
                          key={i}
                          className={cn("break-words", evidence ? "text-foreground" : "text-muted-foreground")}
                        >
                          <span className="select-none text-primary/70">$ </span>
                          {line}
                        </p>
                      );
                    })}
                    <p className="pt-1 text-[11px] text-muted-foreground/70 not-italic">
                      Values masked — evidence never leaves the extractor unredacted.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-2xl border border-dashed border-card-border bg-card p-8 text-center">
              <div className="mx-auto w-11 h-11 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center mb-3">
                <ShieldCheck className="w-5 h-5 text-primary" />
              </div>
              <p className="text-sm font-semibold">No proven findings yet</p>
              <p className="text-sm text-muted-foreground mt-1 max-w-md mx-auto">
                Run an autonomous scan. When ArmorGuard exploits a vulnerability, the masked
                proof lands right here.
              </p>
              <button
                onClick={() => openNewScan()}
                className="mt-4 inline-flex items-center gap-1.5 text-sm font-semibold text-primary hover:underline"
              >
                Start a scan <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </motion.section>

        {/* ============ 3. Metrics + Risk — Fluency (demoted) ============ */}
        <section className="space-y-3">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Overview</h2>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 grid grid-cols-2 gap-3 sm:gap-4">
              <MetricCard label="Total Scans" value={summary?.totalScans ?? 0} icon={Scan} accent delay={0.05} />
              <MetricCard label="Vulnerabilities" value={summary?.totalVulnerabilities ?? 0} icon={ShieldAlert} delay={0.1} />
              <MetricCard label="Critical" value={summary?.criticalCount ?? 0} icon={Flame} delay={0.15} />
              <MetricCard label="High" value={summary?.highCount ?? 0} icon={AlertTriangle} delay={0.2} />
            </div>

            {/* Risk profile — supporting visual */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.25, duration: 0.45 }}
              className="bg-card border border-card-border rounded-xl p-4 sm:p-5 flex flex-col gap-4"
            >
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Risk Profile</p>
              <div className="flex items-center justify-center">
                <RiskGauge score={aggregateRisk} />
              </div>
              <div className="space-y-2">
                {[
                  { label: "Critical", count: sevCount("critical"), color: SEVERITY_COLORS.critical },
                  { label: "High", count: sevCount("high"), color: SEVERITY_COLORS.high },
                  { label: "Medium", count: sevCount("medium"), color: SEVERITY_COLORS.medium },
                  { label: "Low", count: sevCount("low"), color: SEVERITY_COLORS.low },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                      <span className="text-muted-foreground">{item.label}</span>
                    </div>
                    <span className="font-semibold tabular-nums">{item.count}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          </div>
        </section>

        {/* ============ 4. Recent activity — supporting rail ============ */}
        <motion.section
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 0.45 }}
          className="bg-card border border-card-border rounded-xl p-4 sm:p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Recent Activity</p>
            <Activity className="w-3.5 h-3.5 text-muted-foreground" />
          </div>
          <div className="space-y-3">
            {activity?.slice(0, 7).map((event, i) => (
              <motion.div
                key={event.id}
                initial={{ opacity: 0, x: 10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.35 + i * 0.06 }}
                className="flex items-start gap-3 group"
                data-testid={`activity-item-${event.id}`}
              >
                <ActivityType type={event.type} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-foreground leading-snug truncate">{event.message}</p>
                  <p className="text-xs text-muted-foreground/70 mt-0.5">{event.target} · {formatTime(event.timestamp)}</p>
                </div>
                {event.severity && (
                  <span className="text-xs text-muted-foreground/60 flex-shrink-0 capitalize">{event.severity}</span>
                )}
              </motion.div>
            ))}
            {!activity?.length && (
              <div className="py-6 text-center text-muted-foreground text-sm">No recent activity</div>
            )}
          </div>
        </motion.section>

        {/* ============ 5. The close — Peak-end ============ */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
          className="relative overflow-hidden rounded-2xl border border-primary/25 bg-gradient-to-r from-primary/[0.08] to-primary/[0.02] px-6 py-8 sm:px-10 sm:py-10"
        >
          <div className="absolute -bottom-20 -right-10 w-72 h-72 rounded-full bg-primary/10 blur-3xl pointer-events-none" aria-hidden="true" />
          <div className="relative flex flex-col sm:flex-row items-start sm:items-center justify-between gap-5">
            <div>
              <h3 className="text-2xl sm:text-3xl font-bold tracking-tight">Stop guessing. Start proving.</h3>
              <p className="mt-2 text-sm sm:text-base text-muted-foreground max-w-lg">
                Point ArmorGuard at a target and get exploited-and-confirmed findings — with the
                evidence to back every one.
              </p>
            </div>
            <div className="relative group shrink-0">
              <div className="absolute -inset-1 rounded-xl bg-primary/40 blur-lg opacity-0 group-hover:opacity-70 transition-opacity duration-300" aria-hidden="true" />
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                onClick={() => openNewScan()}
                className="relative flex items-center gap-2 px-6 py-3 rounded-xl bg-primary text-primary-foreground text-sm font-semibold shadow-lg shadow-primary/20 hover:bg-primary/90 transition-colors"
                data-testid="button-new-scan-close"
              >
                <Crosshair className="w-4 h-4" />
                New Scan
                <ArrowRight className="w-4 h-4" />
              </motion.button>
            </div>
          </div>
        </motion.section>
      </div>
    </Layout>
  );
}
