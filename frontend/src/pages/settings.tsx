import { useState } from "react";
import { motion } from "framer-motion";
import { Settings as SettingsIcon, Bell, Shield, Database, Key, User, Moon, Sun, Monitor } from "lucide-react";
import Layout from "@/components/layout";
import { useTheme } from "@/components/ui/theme-provider";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

function Section({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-card border border-card-border rounded-xl overflow-hidden"
    >
      <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-border">
        <Icon className="w-4 h-4 text-primary" />
        <h2 className="text-sm font-semibold">{title}</h2>
      </div>
      <div className="p-5 space-y-4">{children}</div>
    </motion.div>
  );
}

function Toggle({ label, desc, checked, onChange }: { label: string; desc?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium">{label}</p>
        {desc && <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>}
      </div>
      <button
        onClick={() => onChange(!checked)}
        className={cn(
          "relative w-10 h-5.5 rounded-full transition-colors",
          checked ? "bg-primary" : "bg-muted"
        )}
        style={{ minWidth: "40px", height: "22px" }}
        data-testid={`toggle-${label.toLowerCase().replace(/\s+/g, "-")}`}
      >
        <span
          className={cn(
            "absolute top-0.5 left-0.5 w-4.5 h-4.5 rounded-full bg-white transition-transform",
          )}
          style={{
            width: "18px",
            height: "18px",
            transform: checked ? "translateX(18px)" : "translateX(0)",
          }}
        />
      </button>
    </div>
  );
}

export default function Settings() {
  const { theme, setTheme } = useTheme();
  const [notifScans, setNotifScans] = useState(true);
  const [notifThreats, setNotifThreats] = useState(true);
  const [notifReports, setNotifReports] = useState(false);
  const [autoScan, setAutoScan] = useState(false);
  const [deepScan, setDeepScan] = useState(false);
  const [rateLimit, setRateLimit] = useState("100");
  const [timeout, setTimeout] = useState("30");
  const [orgName, setOrgName] = useState("InsightMapper Workspace");

  return (
    <Layout>
      <div className="p-6 space-y-5 max-w-2xl">
        {/* Header */}
        <div>
          <motion.h1 initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-xl font-bold">
            Settings
          </motion.h1>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.08 }} className="text-sm text-muted-foreground mt-0.5">
            Configure your workspace and preferences
          </motion.p>
        </div>

        {/* Appearance */}
        <Section title="Appearance" icon={Monitor}>
          <div>
            <p className="text-sm font-medium mb-3">Theme</p>
            <div className="grid grid-cols-3 gap-2">
              {[
                { id: "light" as const, label: "Light", icon: Sun },
                { id: "dark" as const, label: "Dark", icon: Moon },
                { id: "system" as const, label: "System", icon: Monitor },
              ].map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setTheme(id)}
                  className={cn(
                    "flex flex-col items-center gap-2 py-3 rounded-xl border text-xs font-medium transition-colors",
                    theme === id
                      ? "bg-primary text-primary-foreground border-primary"
                      : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground"
                  )}
                  data-testid={`theme-${id}`}
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </button>
              ))}
            </div>
          </div>
        </Section>

        {/* Notifications */}
        <Section title="Notifications" icon={Bell}>
          <Toggle label="Scan Alerts" desc="Notify when scans complete or fail" checked={notifScans} onChange={setNotifScans} />
          <Toggle label="Threat Detections" desc="Alert on new critical/high vulnerabilities" checked={notifThreats} onChange={setNotifThreats} />
          <Toggle label="Report Ready" desc="Notify when scheduled reports are available" checked={notifReports} onChange={setNotifReports} />
        </Section>

        {/* Scan defaults */}
        <Section title="Scan Configuration" icon={Shield}>
          <Toggle label="Auto-scan on target add" desc="Automatically start a quick scan when a target is added" checked={autoScan} onChange={setAutoScan} />
          <Toggle label="Deep packet inspection" desc="Enable full port range and service fingerprinting" checked={deepScan} onChange={setDeepScan} />
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Rate limit (req/s)</label>
              <Input value={rateLimit} onChange={e => setRateLimit(e.target.value)} className="mt-1.5" type="number" />
            </div>
            <div>
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Timeout (sec)</label>
              <Input value={timeout} onChange={e => setTimeout(e.target.value)} className="mt-1.5" type="number" />
            </div>
          </div>
        </Section>

        {/* Workspace */}
        <Section title="Workspace" icon={User}>
          <div>
            <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Organization Name</label>
            <Input value={orgName} onChange={e => setOrgName(e.target.value)} className="mt-1.5" />
          </div>
          <div className="flex items-center justify-between pt-2">
            <div>
              <p className="text-sm font-medium">Data Retention</p>
              <p className="text-xs text-muted-foreground mt-0.5">Scan data is kept for 90 days</p>
            </div>
            <Button variant="outline" size="sm" data-testid="button-manage-retention">Manage</Button>
          </div>
        </Section>

        {/* API */}
        <Section title="API Access" icon={Key}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">API Key</p>
              <p className="text-xs font-mono text-muted-foreground mt-0.5">im_••••••••••••••••••••••••</p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" data-testid="button-copy-api-key">Copy</Button>
              <Button variant="outline" size="sm" data-testid="button-regenerate-api-key">Rotate</Button>
            </div>
          </div>
          <div className="flex items-center justify-between pt-2 border-t border-border">
            <div>
              <p className="text-sm font-medium text-red-400">Danger Zone</p>
              <p className="text-xs text-muted-foreground mt-0.5">Permanently delete all workspace data</p>
            </div>
            <Button variant="destructive" size="sm" data-testid="button-delete-workspace">Delete Workspace</Button>
          </div>
        </Section>

        <div className="flex justify-end">
          <Button data-testid="button-save-settings">Save Changes</Button>
        </div>
      </div>
    </Layout>
  );
}
