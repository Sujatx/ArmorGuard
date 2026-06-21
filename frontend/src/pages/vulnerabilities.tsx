import { useState } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, Search, Filter, Loader } from "lucide-react";
import Layout from "@/components/layout";
import { useListVulnerabilities } from "@workspace/api-client-react";
import { cn } from "@/lib/utils";
import { Link } from "wouter";

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  critical: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/20", dot: "#ef4444" },
  high: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/20", dot: "#f97316" },
  medium: { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/20", dot: "#eab308" },
  low: { bg: "bg-green-500/10", text: "text-green-400", border: "border-green-500/20", dot: "#22c55e" },
  info: { bg: "bg-indigo-500/10", text: "text-indigo-400", border: "border-indigo-500/20", dot: "#6366f1" },
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default function Vulnerabilities() {
  const [search, setSearch] = useState("");
  const [filterSev, setFilterSev] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");

  const { data: vulns, isLoading } = useListVulnerabilities();

  const filtered = vulns?.filter(v => {
    const matchSearch = v.title.toLowerCase().includes(search.toLowerCase()) ||
      v.affectedAsset?.toLowerCase().includes(search.toLowerCase()) ||
      v.cve?.toLowerCase().includes(search.toLowerCase());
    const matchSev = filterSev === "all" || v.severity === filterSev;
    const matchStatus = filterStatus === "all" || v.status === filterStatus;
    return matchSearch && matchSev && matchStatus;
  }) ?? [];

  const counts = SEVERITIES.reduce((acc, s) => {
    acc[s] = vulns?.filter(v => v.severity === s).length ?? 0;
    return acc;
  }, {} as Record<string, number>);

  return (
    <Layout>
      <div className="p-6 space-y-5">
        {/* Header */}
        <div>
          <motion.h1 initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-xl font-bold">
            Vulnerabilities
          </motion.h1>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.08 }} className="text-sm text-muted-foreground mt-0.5">
            {vulns?.length ?? 0} total · {counts.critical} critical
          </motion.p>
        </div>

        {/* Severity summary cards */}
        <div className="grid grid-cols-5 gap-3">
          {SEVERITIES.map((sev, i) => {
            const c = SEVERITY_COLORS[sev];
            return (
              <motion.button
                key={sev}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.06 }}
                onClick={() => setFilterSev(filterSev === sev ? "all" : sev)}
                className={cn(
                  "flex flex-col items-center gap-1 py-3 rounded-xl border transition-all text-center",
                  c.bg, c.border,
                  filterSev === sev && "ring-1 ring-offset-1 ring-offset-background",
                  filterSev === sev ? `ring-[${c.dot}]` : ""
                )}
                data-testid={`filter-severity-${sev}`}
              >
                <p className={cn("text-xl font-bold tabular-nums", c.text)}>{counts[sev]}</p>
                <p className={cn("text-[10px] font-semibold uppercase tracking-wider", c.text)}>{sev}</p>
              </motion.button>
            );
          })}
        </div>

        {/* Search + filter */}
        <div className="flex gap-3">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <input
              type="search"
              placeholder="Search vulnerabilities..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full h-9 pl-8 pr-3 text-sm bg-muted/50 border border-border rounded-lg outline-none focus:border-primary/50 transition-colors"
              data-testid="input-search-vulns"
            />
          </div>
          <div className="flex items-center gap-1.5 border border-border rounded-lg px-2 text-xs text-muted-foreground">
            <Filter className="w-3.5 h-3.5" />
            {["all", "open", "resolved", "ignored"].map(s => (
              <button
                key={s}
                onClick={() => setFilterStatus(s)}
                className={cn(
                  "px-2 py-1 rounded capitalize transition-colors",
                  filterStatus === s ? "text-foreground bg-accent" : "hover:text-foreground"
                )}
                data-testid={`filter-status-${s}`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* List */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-2"
        >
          {isLoading && (
            <div className="py-12 text-center text-muted-foreground text-sm">
              <Loader className="w-5 h-5 animate-spin mx-auto mb-2" />
              Loading vulnerabilities...
            </div>
          )}
          {!isLoading && !filtered.length && (
            <div className="py-12 text-center bg-card border border-card-border rounded-xl">
              <ShieldAlert className="w-8 h-8 text-muted-foreground/40 mx-auto mb-2" />
              <p className="text-muted-foreground text-sm">No vulnerabilities match your filter</p>
            </div>
          )}
          {filtered.map((v, i) => {
            const c = SEVERITY_COLORS[v.severity] ?? SEVERITY_COLORS.info;
            return (
              <motion.div
                key={v.id}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.25 + i * 0.04 }}
                className={cn(
                  "bg-card border rounded-xl px-4 py-4 hover:border-border transition-colors",
                  v.severity === "critical" || v.severity === "high"
                    ? "border-l-2"
                    : "border-card-border",
                )}
                style={v.severity === "critical" || v.severity === "high"
                  ? { borderLeftColor: c.dot }
                  : {}}
                data-testid={`vuln-row-${v.id}`}
              >
                <div className="flex items-start gap-4">
                  <div className="w-2 h-2 rounded-full mt-2 flex-shrink-0" style={{ backgroundColor: c.dot }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start gap-2 flex-wrap">
                      <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded uppercase border", c.bg, c.text, c.border)}>
                        {v.severity}
                      </span>
                      <p className="text-sm font-semibold leading-tight">{v.title}</p>
                    </div>
                    {v.description && (
                      <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed">{v.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-2">
                      {v.affectedAsset && (
                        <span className="text-xs font-mono text-primary/70">↳ {v.affectedAsset}</span>
                      )}
                      {v.cve && (
                        <span className="text-xs font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">{v.cve}</span>
                      )}
                      {v.scanId && (
                        <Link href={`/scans/${v.scanId}`}>
                          <span className="text-xs text-muted-foreground hover:text-primary transition-colors">
                            Scan #{v.scanId}
                          </span>
                        </Link>
                      )}
                    </div>
                  </div>
                  <div className="flex-shrink-0 text-right">
                    <span className={cn(
                      "text-xs px-2 py-1 rounded-lg border capitalize",
                      v.status === "resolved" ? "bg-green-500/10 text-green-400 border-green-500/20" :
                      v.status === "ignored" ? "bg-slate-500/10 text-slate-400 border-slate-500/20" :
                      "bg-red-500/10 text-red-400 border-red-500/20"
                    )}>{v.status}</span>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </motion.div>
      </div>
    </Layout>
  );
}
