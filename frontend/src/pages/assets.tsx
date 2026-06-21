import { useState } from "react";
import { motion } from "framer-motion";
import { Database, Search, Globe, Network, Server, Lock, Cpu, Loader } from "lucide-react";
import Layout from "@/components/layout";
import { useListAssets } from "@workspace/api-client-react";
import { cn } from "@/lib/utils";
import { Link } from "wouter";

const ASSET_TYPES = ["all", "domain", "subdomain", "ip", "port", "service", "certificate"] as const;

const TYPE_ICONS: Record<string, React.ElementType> = {
  domain: Globe,
  subdomain: Network,
  ip: Server,
  port: Lock,
  service: Cpu,
  certificate: Lock,
};

const RISK_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/20" },
  high: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/20" },
  medium: { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/20" },
  low: { bg: "bg-green-500/10", text: "text-green-400", border: "border-green-500/20" },
  info: { bg: "bg-indigo-500/10", text: "text-indigo-400", border: "border-indigo-500/20" },
};

export default function Assets() {
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState<string>("all");
  const { data: assets, isLoading } = useListAssets();

  const filtered = assets?.filter(a => {
    const matchSearch = a.value.toLowerCase().includes(search.toLowerCase()) ||
      a.type.toLowerCase().includes(search.toLowerCase());
    const matchType = filterType === "all" || a.type === filterType;
    return matchSearch && matchType;
  }) ?? [];

  const counts = ASSET_TYPES.reduce((acc, t) => {
    acc[t] = t === "all" ? (assets?.length ?? 0) : (assets?.filter(a => a.type === t).length ?? 0);
    return acc;
  }, {} as Record<string, number>);

  function formatDate(ts: string) {
    return new Date(ts).toLocaleDateString("en-US", { month: "short", day: "numeric" });
  }

  return (
    <Layout>
      <div className="p-6 space-y-5">
        {/* Header */}
        <div>
          <motion.h1 initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-xl font-bold">
            Assets
          </motion.h1>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.08 }} className="text-sm text-muted-foreground mt-0.5">
            {assets?.length ?? 0} discovered assets across all scans
          </motion.p>
        </div>

        {/* Type filter tabs */}
        <div className="flex gap-1 flex-wrap">
          {ASSET_TYPES.map((t, i) => (
            <motion.button
              key={t}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04 }}
              onClick={() => setFilterType(t)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border capitalize transition-colors",
                filterType === t
                  ? "bg-primary text-primary-foreground border-primary"
                  : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground"
              )}
              data-testid={`filter-type-${t}`}
            >
              {t} <span className="opacity-60 tabular-nums">({counts[t]})</span>
            </motion.button>
          ))}
        </div>

        {/* Search */}
        <div className="relative max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input
            type="search"
            placeholder="Search assets..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full h-9 pl-8 pr-3 text-sm bg-muted/50 border border-border rounded-lg outline-none focus:border-primary/50 transition-colors"
            data-testid="input-search-assets"
          />
        </div>

        {/* Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {isLoading && (
            <div className="col-span-3 py-12 text-center text-muted-foreground text-sm">
              <Loader className="w-5 h-5 animate-spin mx-auto mb-2" />
              Loading assets...
            </div>
          )}
          {!isLoading && !filtered.length && (
            <div className="col-span-3 py-12 text-center bg-card border border-card-border rounded-xl">
              <Database className="w-8 h-8 text-muted-foreground/40 mx-auto mb-2" />
              <p className="text-muted-foreground text-sm">No assets match your filter</p>
            </div>
          )}
          {filtered.map((asset, i) => {
            const Icon = TYPE_ICONS[asset.type] ?? Database;
            const risk = asset.riskLevel ? RISK_COLORS[asset.riskLevel] : null;
            return (
              <motion.div
                key={asset.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                className="bg-card border border-card-border rounded-xl p-4 hover:border-primary/30 transition-colors"
                data-testid={`asset-card-${asset.id}`}
              >
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-4 h-4 text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-sm font-mono font-medium truncate">{asset.value}</p>
                      {risk && (
                        <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded uppercase border flex-shrink-0", risk.bg, risk.text, risk.border)}>
                          {asset.riskLevel}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 mt-1.5">
                      <span className="text-xs text-muted-foreground capitalize bg-muted px-1.5 py-0.5 rounded">{asset.type}</span>
                      <span className="text-xs text-muted-foreground">{formatDate(asset.discoveredAt)}</span>
                    </div>
                    {asset.scanId && (
                      <Link href={`/scans/${asset.scanId}`}>
                        <p className="text-xs text-primary/60 hover:text-primary transition-colors mt-1.5">
                          Scan #{asset.scanId} →
                        </p>
                      </Link>
                    )}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </Layout>
  );
}
