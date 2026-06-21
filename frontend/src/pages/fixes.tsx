import { useState } from "react";
import { motion } from "framer-motion";
import { Wrench, ChevronDown, ChevronRight, CheckCircle, AlertTriangle, ShieldAlert, Info, ExternalLink } from "lucide-react";
import Layout from "@/components/layout";
import { useListVulnerabilities } from "@workspace/api-client-react";
import { cn } from "@/lib/utils";

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string; icon: React.ElementType }> = {
  critical: { color: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/30", icon: ShieldAlert },
  high: { color: "text-orange-500", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: AlertTriangle },
  medium: { color: "text-yellow-500", bg: "bg-yellow-500/10", border: "border-yellow-500/30", icon: AlertTriangle },
  low: { color: "text-green-500", bg: "bg-green-500/10", border: "border-green-500/30", icon: Info },
  info: { color: "text-blue-500", bg: "bg-blue-500/10", border: "border-blue-500/30", icon: Info },
};

const FIX_ADVICE: Record<string, { steps: string[]; ref?: string }> = {
  "SQL Injection": {
    steps: [
      "Use parameterized queries or prepared statements instead of string concatenation.",
      "Implement an ORM (like Drizzle, Prisma, or Sequelize) with bound parameters.",
      "Apply input validation and whitelist acceptable characters.",
      "Least-privilege DB accounts — no DROP/ALTER from app credentials.",
      "Enable WAF rules targeting SQL injection patterns.",
    ],
    ref: "https://owasp.org/www-community/attacks/SQL_Injection",
  },
  "XSS": {
    steps: [
      "Encode all user-supplied output (HTML-encode <, >, \", ', &).",
      "Use Content Security Policy (CSP) headers to restrict inline scripts.",
      "Sanitize rich-text inputs with a library like DOMPurify.",
      "Set HttpOnly and Secure flags on session cookies.",
    ],
    ref: "https://owasp.org/www-community/attacks/xss/",
  },
  "Open Port": {
    steps: [
      "Close or firewall ports that are not required for the service.",
      "Use a host-based firewall (iptables, nftables) to restrict access by IP.",
      "Disable unused services in the OS systemd or init configuration.",
      "Document all intentionally open ports in a network runbook.",
    ],
  },
  "Outdated Software": {
    steps: [
      "Apply the latest security patches from the vendor.",
      "Subscribe to the vendor's security advisory mailing list.",
      "Use automated dependency scanners (Dependabot, Renovate) to track CVEs.",
      "Establish a patch SLA: critical in 24 h, high in 7 days, medium in 30 days.",
    ],
  },
  "Weak Authentication": {
    steps: [
      "Enforce minimum password length (≥ 12 characters) and complexity.",
      "Require multi-factor authentication (MFA) for all accounts.",
      "Implement account lockout after N failed attempts.",
      "Use secure password hashing (Argon2id or bcrypt cost ≥ 12).",
      "Disable default or shared credentials immediately after provisioning.",
    ],
    ref: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
  },
  "Missing Headers": {
    steps: [
      "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.",
      "Set `X-Content-Type-Options: nosniff`.",
      "Configure `X-Frame-Options: DENY` or use CSP `frame-ancestors`.",
      "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
      "Review and tighten `Content-Security-Policy` to remove `unsafe-inline`.",
    ],
    ref: "https://securityheaders.com/",
  },
  "Default": {
    steps: [
      "Conduct a targeted code review of the affected component.",
      "Apply vendor or community patches as soon as available.",
      "Isolate the vulnerable component behind an additional authentication layer.",
      "Log and monitor exploitation attempts through your SIEM.",
      "Schedule a follow-up scan after remediation to verify the fix.",
    ],
  },
};

function getAdvice(title: string) {
  for (const [key, val] of Object.entries(FIX_ADVICE)) {
    if (key !== "Default" && title.toLowerCase().includes(key.toLowerCase())) return val;
  }
  return FIX_ADVICE["Default"];
}

function FixCard({ vuln, index }: { vuln: { id: number; title: string; severity: string; status: string; target: string; description?: string | null }; index: number }) {
  const [open, setOpen] = useState(false);
  const cfg = SEVERITY_CONFIG[vuln.severity] ?? SEVERITY_CONFIG["info"];
  const Icon = cfg.icon;
  const advice = getAdvice(vuln.title);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      className={cn("bg-card border rounded-xl overflow-hidden", cfg.border, open && "shadow-md")}
      data-testid={`fix-card-${vuln.id}`}
    >
      <button
        className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-accent/30 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0", cfg.bg)}>
          <Icon className={cn("w-4 h-4", cfg.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-semibold truncate">{vuln.title}</p>
            <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider border", cfg.bg, cfg.border, cfg.color)}>
              {vuln.severity}
            </span>
            {vuln.status === "resolved" && (
              <span className="flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider bg-green-500/10 border border-green-500/30 text-green-600 dark:text-green-400">
                <CheckCircle className="w-3 h-3" /> Resolved
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5 truncate">{vuln.target}</p>
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-muted-foreground flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />}
      </button>

      <AnimateOpen open={open}>
        <div className="border-t border-border/60 px-5 py-4 space-y-4">
          {vuln.description && (
            <p className="text-sm text-muted-foreground">{vuln.description}</p>
          )}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Remediation Steps</p>
            <ol className="space-y-2">
              {advice.steps.map((step, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-primary/15 text-primary text-[10px] font-bold flex items-center justify-center mt-0.5">
                    {i + 1}
                  </span>
                  <span className="text-foreground/80">{step}</span>
                </li>
              ))}
            </ol>
          </div>
          {advice.ref && (
            <a
              href={advice.ref}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline"
            >
              <ExternalLink className="w-3 h-3" />
              OWASP Reference
            </a>
          )}
        </div>
      </AnimateOpen>
    </motion.div>
  );
}

function AnimateOpen({ open, children }: { open: boolean; children: React.ReactNode }) {
  return (
    <motion.div
      initial={false}
      animate={{ height: open ? "auto" : 0, opacity: open ? 1 : 0 }}
      transition={{ duration: 0.22, ease: "easeInOut" }}
      style={{ overflow: "hidden" }}
    >
      {children}
    </motion.div>
  );
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export default function Fixes() {
  const { data: vulns } = useListVulnerabilities({});
  const [filter, setFilter] = useState<string>("all");

  const sorted = (vulns ?? []).slice().sort((a, b) => {
    return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  });

  const filtered = filter === "all" ? sorted : sorted.filter(v => v.severity === filter);

  const counts = SEVERITY_ORDER.reduce((acc, s) => {
    acc[s] = (vulns ?? []).filter(v => v.severity === s).length;
    return acc;
  }, {} as Record<string, number>);

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div>
          <motion.h1 initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-xl font-bold flex items-center gap-2">
            <Wrench className="w-5 h-5 text-primary" />
            Fixes
          </motion.h1>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.08 }} className="text-sm text-muted-foreground mt-0.5">
            Step-by-step remediation guidance for discovered vulnerabilities
          </motion.p>
        </div>

        {/* Severity filter */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setFilter("all")}
            className={cn("px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors", filter === "all" ? "bg-primary text-primary-foreground border-primary" : "border-border text-muted-foreground hover:text-foreground hover:bg-accent")}
          >
            All ({vulns?.length ?? 0})
          </button>
          {SEVERITY_ORDER.map((s) => {
            const cfg = SEVERITY_CONFIG[s];
            if (!counts[s]) return null;
            return (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={cn("px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors capitalize", filter === s ? `${cfg.bg} ${cfg.color} ${cfg.border}` : "border-border text-muted-foreground hover:text-foreground hover:bg-accent")}
              >
                {s} ({counts[s]})
              </button>
            );
          })}
        </div>

        {/* Fix cards */}
        <div className="space-y-3">
          {filtered.length === 0 && (
            <div className="py-12 text-center text-muted-foreground text-sm">No vulnerabilities found</div>
          )}
          {filtered.map((vuln, i) => (
            <FixCard key={vuln.id} vuln={vuln} index={i} />
          ))}
        </div>
      </div>
    </Layout>
  );
}
