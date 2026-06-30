import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import {
  Scan, ShieldAlert, AlertTriangle, Flame, Activity, ArrowRight, Zap,
} from "lucide-react";
import Layout from "@/components/layout";
import {
  useGetDashboardSummary,
  useGetSeverityBreakdown,
  useGetRecentActivity,
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
  label, value, sub, icon: Icon, color, delay = 0,
}: {
  label: string;
  value: number;
  sub?: string;
  icon: React.ElementType;
  color: string;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4, ease: "easeOut" }}
      className="relative bg-card border border-card-border rounded-xl p-4 hover:border-primary/30 transition-colors group"
      data-testid={`metric-card-${label.toLowerCase().replace(/\s+/g, "-")}`}
    >
      <div className={cn("absolute top-3 right-3 w-8 h-8 rounded-lg flex items-center justify-center transition-transform group-hover:scale-110", color)}>
        <Icon className="w-4 h-4" />
      </div>
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3 pr-10">{label}</p>
      <p className="text-2xl font-bold tabular-nums">
        <AnimatedNumber value={value} />
      </p>
      {sub && <p className="text-xs text-muted-foreground mt-1">{sub}</p>}
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

export default function Dashboard() {
  const { data: summary } = useGetDashboardSummary();
  const { data: severity } = useGetSeverityBreakdown();
  const { data: activity } = useGetRecentActivity();
  const { openNewScan } = useNewScan();

  const sevCount = (name: string) => severity?.find(s => s.severity === name)?.count ?? 0;

  // Weights chosen so a handful of criticals reads meaningfully below 100;
  // only truly severe scan sets should approach the cap.
  const aggregateRisk = Math.min(
    100,
    Math.round(sevCount("critical") * 15 + sevCount("high") * 8 + sevCount("medium") * 3 + sevCount("low") * 0.5)
  );

  function formatTime(ts: string) {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  return (
    <Layout>
      <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <motion.h1
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xl font-bold"
            >
              Attack Surface Command
            </motion.h1>
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.1 }}
              className="text-sm text-muted-foreground mt-0.5"
            >
              Know your vulnerabilities before your adversaries do.
            </motion.p>
          </div>
        </div>

        {/* Metric cards grid — all real, derived from /sessions */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          <MetricCard
            label="Total Scans"
            value={summary?.totalScans ?? 0}
            sub="All time"
            icon={Scan}
            color="bg-primary/10 text-primary"
            delay={0.05}
          />
          <MetricCard
            label="Vulnerabilities"
            value={summary?.totalVulnerabilities ?? 0}
            sub="Across all sessions"
            icon={ShieldAlert}
            color="bg-red-500/10 text-red-500"
            delay={0.1}
          />
          <MetricCard
            label="Critical"
            value={summary?.criticalCount ?? 0}
            sub="Highest priority"
            icon={Flame}
            color="bg-red-500/10 text-red-500"
            delay={0.15}
          />
          <MetricCard
            label="High"
            value={summary?.highCount ?? 0}
            sub="Needs attention"
            icon={AlertTriangle}
            color="bg-orange-500/10 text-orange-500"
            delay={0.2}
          />
        </div>

        {/* Risk profile + Recent activity */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25 }}
            className="col-span-1 bg-card border border-card-border rounded-xl p-4 sm:p-5 flex flex-col gap-4"
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

          {/* Recent activity */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="col-span-1 lg:col-span-2 bg-card border border-card-border rounded-xl p-4 sm:p-5"
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
          </motion.div>
        </div>

        {/* Quick action */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-gradient-to-r from-primary/10 to-primary/5 border border-primary/20 rounded-xl p-5"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center">
                <Zap className="w-4 h-4 text-primary" />
              </div>
              <div>
                <p className="text-sm font-semibold">Start a New Scan</p>
                <p className="text-xs text-muted-foreground">Discover vulnerabilities and map your attack surface</p>
              </div>
            </div>
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => openNewScan()}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-colors"
              data-testid="button-go-to-scans"
            >
              New Scan
              <ArrowRight className="w-4 h-4" />
            </motion.button>
          </div>
        </motion.div>
      </div>
    </Layout>
  );
}
