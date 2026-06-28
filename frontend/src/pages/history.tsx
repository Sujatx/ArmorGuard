import { motion } from "framer-motion";
import { History, ChevronRight, CheckCircle, Loader2, Clock, XCircle, ShieldAlert, Database, Calendar } from "lucide-react";
import { Link } from "wouter";
import Layout from "@/components/layout";
import { useListScans } from "@workspace/api-client-react";
import { cn } from "@/lib/utils";

const STATUS_CONFIG: Record<string, { label: string; icon: React.ElementType; color: string; bg: string }> = {
  completed: { label: "Completed", icon: CheckCircle, color: "text-green-500", bg: "bg-green-500/10" },
  running: { label: "Running", icon: Loader2, color: "text-blue-500", bg: "bg-blue-500/10" },
  queued: { label: "Queued", icon: Clock, color: "text-yellow-500", bg: "bg-yellow-500/10" },
  failed: { label: "Failed", icon: XCircle, color: "text-red-500", bg: "bg-red-500/10" },
};

function RiskBadge({ score }: { score: number | null | undefined }) {
  if (score == null) return null;
  const color = score >= 75 ? "bg-red-500/10 text-red-500 border-red-500/30"
    : score >= 50 ? "bg-orange-500/10 text-orange-500 border-orange-500/30"
    : score >= 25 ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/30"
    : "bg-green-500/10 text-green-500 border-green-500/30";
  return (
    <span className={cn("text-xs font-bold px-2 py-0.5 rounded-md border tabular-nums", color)}>
      {score}
    </span>
  );
}

function formatDate(ts: string) {
  const d = new Date(ts);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function formatTime(ts: string) {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
}

export default function HistoryPage() {
  const { data: scans, isLoading } = useListScans();

  const sorted = (scans ?? []).slice().sort((a, b) => {
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
  });

  const completedCount = sorted.filter(s => s.status === "completed").length;
  const totalVulns = sorted.reduce((acc, s) => acc + (s.vulnerabilitiesCount ?? 0), 0);
  const avgRisk = sorted.length > 0
    ? Math.round(sorted.filter(s => s.riskScore != null).reduce((acc, s) => acc + (s.riskScore ?? 0), 0) / sorted.filter(s => s.riskScore != null).length)
    : 0;

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div>
          <motion.h1 initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-xl font-bold flex items-center gap-2">
            <History className="w-5 h-5 text-primary" />
            Scan History
          </motion.h1>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.08 }} className="text-sm text-muted-foreground mt-0.5">
            All past scans — click any to view details and vulnerabilities
          </motion.p>
        </div>

        {/* Summary stats */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: "Total Scans", value: sorted.length, icon: History, color: "text-primary bg-primary/10" },
            { label: "Completed", value: completedCount, icon: CheckCircle, color: "text-green-500 bg-green-500/10" },
            { label: "Vulnerabilities Found", value: totalVulns, icon: ShieldAlert, color: "text-red-500 bg-red-500/10" },
          ].map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className="bg-card border border-card-border rounded-xl px-4 py-3 flex items-center gap-3"
            >
              <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center", stat.color.split(" ")[1])}>
                <stat.icon className={cn("w-4 h-4", stat.color.split(" ")[0])} />
              </div>
              <div>
                <p className="text-xl font-bold tabular-nums">{stat.value}</p>
                <p className="text-xs text-muted-foreground">{stat.label}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Scan list */}
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">All Scans</p>
          {isLoading && (
            <div className="py-10 text-center text-muted-foreground text-sm flex items-center justify-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading history...
            </div>
          )}
          <div className="space-y-2">
            {sorted.map((scan, i) => {
              const status = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG["queued"];
              const StatusIcon = status.icon;
              return (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 + i * 0.04 }}
                  data-testid={`history-scan-${scan.id}`}
                >
                  <Link href={`/scans/${scan.id}`}>
                    <div className="bg-card border border-card-border rounded-xl px-5 py-4 hover:border-primary/40 hover:shadow-sm transition-all cursor-pointer group">
                      <div className="flex items-center gap-4">
                        {/* Status icon */}
                        <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0", status.bg)}>
                          <StatusIcon className={cn("w-4 h-4", status.color, scan.status === "running" && "animate-spin")} />
                        </div>

                        {/* Target + type */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-sm font-semibold truncate">{scan.target}</p>
                            <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-muted text-muted-foreground capitalize">
                              {scan.scanType}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 mt-0.5">
                            <span className={cn("text-xs font-medium", status.color)}>{status.label}</span>
                            <span className="text-xs text-muted-foreground flex items-center gap-1">
                              <Calendar className="w-3 h-3" />
                              {formatDate(scan.createdAt)} at {formatTime(scan.createdAt)}
                            </span>
                          </div>
                        </div>

                        {/* Stats */}
                        <div className="flex items-center gap-4 flex-shrink-0">
                          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                            <ShieldAlert className="w-3.5 h-3.5" />
                            <span className="tabular-nums font-medium">{scan.vulnerabilitiesCount ?? 0}</span>
                            <span>vulns</span>
                          </div>
                          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                            <Database className="w-3.5 h-3.5" />
                            <span className="tabular-nums font-medium">{scan.assetsCount ?? 0}</span>
                            <span>assets</span>
                          </div>
                          <RiskBadge score={scan.riskScore} />
                          <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                        </div>
                      </div>
                    </div>
                  </Link>
                </motion.div>
              );
            })}
            {!isLoading && sorted.length === 0 && (
              <div className="py-12 text-center text-muted-foreground text-sm">No scan history yet</div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
