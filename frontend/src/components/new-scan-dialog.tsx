import { useState } from "react";
import { motion } from "framer-motion";
import { useLocation } from "wouter";
import { Loader, X, ShieldAlert, Globe } from "lucide-react";
import {
  useCreateScan,
  useCreateConsent,
  getListScansQueryKey,
  isLocalTarget,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useNewScan } from "@/hooks/use-new-scan";
import { cn } from "@/lib/utils";

const SCAN_TYPES = ["default", "deep", "custom"] as const;
const ALL_TOOLS = ["nmap", "katana", "ffuf", "arjun", "httpx", "nuclei", "nikto", "sqlmap", "hydra"] as const;

export default function NewScanDialog() {
  const { open, close } = useNewScan();

  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState<string>("default");
  const [selectedTools, setSelectedTools] = useState<string[]>([...ALL_TOOLS]);
  const [description, setDescription] = useState("");
  const [showConsent, setShowConsent] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);

  const [, navigate] = useLocation();
  const createScan = useCreateScan();
  const createConsent = useCreateConsent();
  const queryClient = useQueryClient();

  const targetIsPublic = target.trim() !== "" && !isLocalTarget(target.trim());
  const launching = createScan.isPending || createConsent.isPending;

  function resetAndClose() {
    setShowConsent(false);
    setAcknowledged(false);
    setTarget("");
    setDescription("");
    setScanType("default");
    setSelectedTools([...ALL_TOOLS]);
    close();
  }

  // Fires POST /scan with an optional consentId, then navigates to the detail page.
  function launchScan(consentId: string | null) {
    createScan.mutate(
      {
        data: {
          target: target.trim(),
          scanType,
          selectedTools,
          consentId,
          description: description || null,
        },
      },
      {
        onSuccess: (data) => {
          queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
          resetAndClose();
          navigate(`/scans/${data.scanId}`);
        },
      }
    );
  }

  function handleCreate() {
    if (!target.trim()) return;
    if (scanType === "custom" && selectedTools.length === 0) return;
    // Local/private targets skip consent; public targets must acknowledge first.
    if (targetIsPublic) {
      setShowConsent(true);
      return;
    }
    launchScan(null);
  }

  // Public-target path: record acknowledged consent, then launch with its id.
  function handleConfirmConsent() {
    if (!acknowledged) return;
    createConsent.mutate(
      { targetUrl: target.trim() },
      { onSuccess: (consent) => launchScan(consent.consentId) }
    );
  }

  if (!open) return null;

  return (
    <>
      {/* New Scan Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4" data-testid="dialog-new-scan">
        <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={resetAndClose} />
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 8 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          className="relative z-10 w-full max-w-md bg-card border border-card-border rounded-2xl shadow-2xl p-6"
        >
          <div className="flex items-start justify-between mb-5">
            <div>
              <h2 className="text-base font-bold">New Scan</h2>
              <p className="text-xs text-muted-foreground mt-0.5">Configure and launch a security reconnaissance scan.</p>
            </div>
            <button onClick={resetAndClose} className="text-muted-foreground hover:text-foreground transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Target</label>
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                placeholder="example.com or 10.0.0.0/24"
                className="w-full mt-1.5 h-9 px-3 text-sm bg-muted/50 border border-border rounded-lg outline-none focus:border-primary/50 transition-colors"
                data-testid="input-scan-target"
                onKeyDown={e => e.key === "Enter" && handleCreate()}
                autoFocus
              />
              {targetIsPublic && (
                <p className="flex items-center gap-1.5 text-[11px] text-amber-400 mt-1.5">
                  <Globe className="w-3 h-3 flex-shrink-0" />
                  Public target — consent required before scanning.
                </p>
              )}
            </div>
            <div>
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Scan Type</label>
              <div className="grid grid-cols-3 gap-2 mt-1.5">
                {SCAN_TYPES.map(t => (
                  <button
                    key={t}
                    onClick={() => setScanType(t)}
                    className={cn(
                      "px-3 py-2 rounded-lg text-xs font-medium border capitalize transition-colors",
                      scanType === t
                        ? "bg-primary text-primary-foreground border-primary"
                        : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground"
                    )}
                    data-testid={`button-scan-type-${t}`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
            {scanType === "custom" && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Tools</label>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => setSelectedTools([...ALL_TOOLS])}
                      className="text-[10px] text-primary hover:underline"
                    >all</button>
                    <span className="text-[10px] text-muted-foreground">/</span>
                    <button
                      type="button"
                      onClick={() => setSelectedTools([])}
                      className="text-[10px] text-muted-foreground hover:underline"
                    >none</button>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-1.5">
                  {ALL_TOOLS.map(tool => {
                    const checked = selectedTools.includes(tool);
                    return (
                      <button
                        key={tool}
                        type="button"
                        onClick={() =>
                          setSelectedTools(prev =>
                            checked ? prev.filter(t => t !== tool) : [...prev, tool]
                          )
                        }
                        className={cn(
                          "px-2 py-1.5 rounded-lg text-xs font-mono font-medium border transition-colors text-left",
                          checked
                            ? "bg-primary/10 border-primary/40 text-primary"
                            : "border-border text-muted-foreground hover:border-primary/20"
                        )}
                      >
                        {checked ? "✓ " : ""}{tool}
                      </button>
                    );
                  })}
                </div>
                {selectedTools.length === 0 && (
                  <p className="text-[10px] text-red-400 mt-1">Select at least one tool</p>
                )}
              </div>
            )}

            <div>
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Description (optional)</label>
              <input
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="Brief description..."
                className="w-full mt-1.5 h-9 px-3 text-sm bg-muted/50 border border-border rounded-lg outline-none focus:border-primary/50 transition-colors"
                data-testid="input-scan-description"
              />
            </div>
            <div className="flex gap-2 pt-1">
              <button
                onClick={resetAndClose}
                className="flex-1 h-9 rounded-lg border border-border text-sm font-medium text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
                data-testid="button-cancel-scan"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={!target.trim() || launching || (scanType === "custom" && selectedTools.length === 0)}
                className="flex-1 h-9 rounded-lg bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                data-testid="button-create-scan"
              >
                {launching ? <Loader className="w-4 h-4 animate-spin" /> : targetIsPublic ? "Continue →" : "Launch Scan"}
              </button>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Consent disclaimer — public targets only */}
      {showConsent && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" data-testid="dialog-consent">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => !launching && setShowConsent(false)} />
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            className="relative z-10 w-full max-w-md bg-card border border-card-border rounded-2xl shadow-2xl p-6"
          >
            <div className="flex items-start gap-3 mb-4">
              <div className="w-9 h-9 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center flex-shrink-0">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <h2 className="text-base font-bold">Authorization Required</h2>
                <p className="text-xs text-muted-foreground mt-0.5 font-mono break-all">{target.trim()}</p>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-muted/30 p-3.5 text-xs leading-relaxed text-muted-foreground">
              I confirm I am authorized to test this target. I understand this scan may include
              active exploitation attempts (including SQL injection via sqlmap in Deep mode) and
              that my IP address and acknowledgment will be logged for audit purposes.
            </div>

            <label className="flex items-start gap-2.5 mt-4 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={e => setAcknowledged(e.target.checked)}
                className="mt-0.5 w-4 h-4 accent-primary cursor-pointer"
                data-testid="checkbox-consent"
              />
              <span className="text-sm font-medium">I acknowledge and accept responsibility for this scan.</span>
            </label>

            <div className="flex gap-2 pt-5">
              <button
                onClick={() => setShowConsent(false)}
                disabled={launching}
                className="flex-1 h-9 rounded-lg border border-border text-sm font-medium text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors disabled:opacity-50"
                data-testid="button-cancel-consent"
              >
                Back
              </button>
              <button
                onClick={handleConfirmConsent}
                disabled={!acknowledged || launching}
                className="flex-1 h-9 rounded-lg bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                data-testid="button-confirm-consent"
              >
                {launching ? <Loader className="w-4 h-4 animate-spin" /> : "Acknowledge & Scan"}
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </>
  );
}
