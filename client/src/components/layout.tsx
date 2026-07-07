import { useState, useRef, useEffect, useCallback } from "react";
import { useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard,
  Plus,
  Bell,
  Sun,
  Moon,
  X,
  Check,
  PanelLeft,
  History,
  Menu,
} from "lucide-react";
import { useTheme } from "@/components/ui/theme-provider";
import {
  useListNotifications,
  useMarkAllNotificationsRead,
  getListNotificationsQueryKey,
  getListScansQueryKey,
  useListScans,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useNewScan } from "@/hooks/use-new-scan";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { Hint } from "@/components/ui/hint";

const navItems = [
  { path: "/", icon: LayoutDashboard, label: "Dashboard" },
];

const STATUS_DOT: Record<string, string> = {
  running: "bg-blue-400 animate-pulse",
  completed: "bg-green-400",
  failed: "bg-red-400",
  queued: "bg-yellow-400",
};

// Wrapper that handles stopPropagation + tooltip for strip buttons
function StripBtn({
  icon: Icon,
  label,
  onClick,
  active = false,
  circle = false,
  testId,
}: {
  icon: React.ElementType;
  label: string;
  onClick: (e: React.MouseEvent<HTMLButtonElement>) => void;
  active?: boolean;
  circle?: boolean;
  testId?: string;
}) {
  return (
    <Hint label={label} side="right" className="w-full justify-center">
      <button
        onClick={onClick}
        data-testid={testId}
        className={cn(
          "w-8 h-8 flex items-center justify-center transition-colors rounded-lg cursor-pointer",
          circle
            ? "text-foreground/75 hover:text-foreground"
            : active
              ? "text-foreground hover:bg-foreground/10"
              : "text-foreground/70 hover:text-foreground hover:bg-foreground/10",
        )}
      >
        {circle ? (
          /* smaller inner circle so the bg ring feels compact, not full-button-sized */
          <div className="w-[22px] h-[22px] rounded-full bg-foreground/12 flex items-center justify-center">
            <Icon className="w-3.5 h-3.5" />
          </div>
        ) : (
          <Icon className="w-4 h-4" />
        )}
      </button>
    </Hint>
  );
}

function NotificationTag({ type }: { type: string }) {
  const base = "text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider border";
  if (type === "scan")
    return <span className={cn(base, "bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/30")}>SCAN</span>;
  if (type === "threat")
    return <span className={cn(base, "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30")}>THREAT</span>;
  if (type === "report")
    return <span className={cn(base, "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30")}>REPORT</span>;
  return <span className={cn(base, "bg-muted text-muted-foreground")}>INFO</span>;
}

function NotificationsPanel({ onClose }: { onClose: () => void }) {
  const { data: notifications } = useListNotifications();
  const markRead = useMarkAllNotificationsRead();
  const queryClient = useQueryClient();

  function handleMarkAllRead() {
    markRead.mutate(undefined, {
      onSuccess: () => queryClient.invalidateQueries({ queryKey: getListNotificationsQueryKey() }),
    });
  }

  function formatTime(ts: string) {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: -8, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -8, scale: 0.97 }}
      transition={{ duration: 0.18 }}
      className="absolute right-0 top-10 z-50 w-[320px] sm:w-[380px] rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <span className="text-sm font-semibold">Notifications</span>
        <div className="flex items-center gap-3">
          <button
            onClick={handleMarkAllRead}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            data-testid="button-mark-all-read"
          >
            <Check className="w-3 h-3" />
            Mark all read
          </button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
      <div className="max-h-[420px] overflow-y-auto">
        {!notifications?.length && (
          <div className="py-10 text-center text-muted-foreground text-sm">No notifications</div>
        )}
        {notifications?.map((n, i) => (
          <motion.div
            key={n.id}
            initial={{ opacity: 0, x: 10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.04 }}
            className={cn(
              "flex gap-3 px-4 py-3.5 border-b border-border/50 relative",
              !n.read && "bg-primary/5",
              !n.read && n.type === "threat" && "border-l-2 border-l-red-500",
              !n.read && n.type === "scan" && "border-l-2 border-l-green-500",
              !n.read && n.type === "report" && "border-l-2 border-l-blue-500",
            )}
            data-testid={`notification-item-${n.id}`}
          >
            <div className="pt-0.5 flex-shrink-0">
              <NotificationTag type={n.type} />
            </div>
            <div className="flex-1 min-w-0">
              <p className={cn("text-sm font-medium leading-snug", n.read && "text-muted-foreground")}>{n.title}</p>
              <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{n.message}</p>
              <p className="text-xs text-muted-foreground/60 mt-1">{formatTime(n.createdAt)}</p>
            </div>
            {!n.read && (
              <div className="w-2 h-2 rounded-full bg-primary mt-1.5 flex-shrink-0 animate-pulse" />
            )}
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}

export default function Layout({ children }: { children: React.ReactNode }) {
  const [location, navigate] = useLocation();
  const { theme, setTheme } = useTheme();
  const { openNewScan } = useNewScan();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: scans, isLoading: scansLoading } = useListScans();
  const [showNotifications, setShowNotifications] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const sidebarCloseTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cancelSidebarClose = useCallback(() => {
    if (sidebarCloseTimer.current) {
      clearTimeout(sidebarCloseTimer.current);
      sidebarCloseTimer.current = null;
    }
  }, []);

  const handleSidebarEnter = useCallback(() => {
    cancelSidebarClose();
    setSidebarOpen(true);
  }, [cancelSidebarClose]);

  const handleSidebarLeave = useCallback(() => {
    sidebarCloseTimer.current = setTimeout(() => setSidebarOpen(false), 120);
  }, []);
  const { data: notifications } = useListNotifications();
  const unreadCount = notifications?.filter(n => !n.read).length ?? 0;

  const hasRunning = scans?.some(s => s.status === "running" || s.status === "queued") ?? false;
  useEffect(() => {
    if (!hasRunning) return;
    // Immediate refresh so the running indicator appears without waiting for first tick
    queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
    const id = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
    }, 2000);
    return () => clearInterval(id);
  }, [hasRunning, queryClient]);

  const prevStatusRef = useRef<Record<string, string>>({});
  useEffect(() => {
    if (!scans) return;
    const prev = prevStatusRef.current;
    scans.forEach(s => {
      const wasActive = prev[s.id] === "running" || prev[s.id] === "queued";
      const nowDone = s.status === "completed" || s.status === "failed";
      const onThisScan = location === `/scans/${s.id}`;
      if (wasActive && nowDone && !onThisScan) {
        toast({
          title: s.status === "completed" ? "Scan completed" : "Scan failed",
          description: s.target,
        });
      }
      prev[s.id] = s.status;
    });
  }, [scans, location, toast]);

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground relative">

      {/* ── Icon strip — desktop only ── */}
      <div className="hidden sm:flex w-[52px] flex-shrink-0 flex-col items-center pt-4 pb-3 gap-1 bg-sidebar border-r border-border/60 z-50">
        <div className="flex flex-col items-center w-full gap-1">
          {/* Toggle */}
          <StripBtn
            icon={PanelLeft}
            label="Toggle sidebar"
            onClick={e => { e.stopPropagation(); setSidebarOpen(v => !v); }}
            testId="button-toggle-sidebar"
          />

          {/* Push the action icons a bit lower */}
          <div className="h-3" />

          {/* New Scan — circle background */}
          <StripBtn
            icon={Plus}
            label="New Scan"
            onClick={e => { e.stopPropagation(); openNewScan(); }}
            circle
            testId="button-new-scan"
          />

          {/* Nav icons */}
          {navItems.map(item => {
            const isActive = item.path === "/" ? location === "/" : location.startsWith(item.path);
            return (
              <StripBtn
                key={item.path}
                icon={item.icon}
                label={item.label}
                onClick={e => { e.stopPropagation(); navigate(item.path); }}
                active={isActive}
                testId={`nav-item-${item.label.toLowerCase()}`}
              />
            );
          })}

          {/* History — hover popover, click opens panel */}
          <div className="group relative w-full flex justify-center">
          <button
            onClick={e => { e.stopPropagation(); setSidebarOpen(true); }}
            data-testid="button-history"
            className="w-8 h-8 flex items-center justify-center rounded-lg text-foreground/70 hover:text-foreground hover:bg-foreground/10 transition-colors cursor-pointer"
          >
            <History className="w-4 h-4" />
          </button>

          {/* Popover: no gap — uses pl-3 bridge so mouse can cross without losing hover */}
          <div className="absolute left-full top-0 z-[70] w-[224px] hidden group-hover:block">
            {/* transparent left padding bridges the gap between button edge and card */}
            <div className="pl-3">
              <div className="bg-card border border-border rounded-xl shadow-2xl overflow-hidden">
                <div className="px-3 py-2 border-b border-border/60">
                  <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest">Recent Scans</p>
                </div>
                <div className="max-h-[300px] overflow-y-auto sidebar-scroll">
                  {!scans?.length && (
                    <p className="px-3 py-3 text-xs text-muted-foreground">No scans yet</p>
                  )}
                  {scans?.slice(0, 10).map(s => (
                    <div
                      key={s.id}
                      onClick={() => navigate(`/scans/${s.id}`)}
                      className="flex items-center gap-2 px-3 py-2.5 text-xs hover:bg-accent transition-colors cursor-pointer border-b border-border/30 last:border-0"
                    >
                      <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", STATUS_DOT[s.status] ?? "bg-muted-foreground/40")} />
                      <span className="truncate text-foreground/80">{s.target}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
        </div>{/* end top-icons no-hover wrapper */}

        {/* Hover zone — only the LEFT part of this empty space triggers the panel. The
            right ~16px is an inert buffer (pointer-events-none) so the panel doesn't open
            when the cursor merely grazes the strip's right edge coming in from the content. */}
        <div className="flex-1 w-full flex">
          <div className="h-full flex-1" onMouseEnter={handleSidebarEnter} onMouseLeave={handleSidebarLeave} />
          <div className="h-full w-4 pointer-events-none" aria-hidden />
        </div>

        {/* Avatar */}
        <div
          className="w-7 h-7 rounded-full bg-muted border border-border flex items-center justify-center text-[9px] font-bold text-foreground select-none"
          onMouseEnter={handleSidebarEnter}
          onMouseLeave={handleSidebarLeave}
        >
          AG
        </div>
      </div>

      {/* ── Overlay panel — slides from left-0, covers the strip ── */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            {/* Tap-to-close backdrop on mobile */}
            <div
              className="fixed inset-0 z-[55] bg-black/50 sm:hidden"
              onClick={() => setSidebarOpen(false)}
            />
            <motion.div
              initial={{ x: -252 }}
              animate={{ x: 0 }}
              exit={{ x: -252 }}
              transition={{ duration: 0.2, ease: "easeInOut" }}
              className="absolute left-0 top-0 bottom-0 w-[252px] z-[60] bg-sidebar border-r border-border/60 flex flex-col overflow-hidden shadow-2xl"
              onMouseEnter={handleSidebarEnter}
              onMouseLeave={handleSidebarLeave}
            >
              {/* Header: logo left, toggle right — mirrors strip layout */}
              <div className="h-12 flex items-center justify-between px-4 flex-shrink-0">
                <div className="flex items-center gap-2">
                  <img src="/favicon.svg" className="w-4 h-4 flex-shrink-0" alt="" />
                  <span className="text-sm font-semibold text-foreground tracking-tight">ArmorGuard</span>
                </div>
                <button
                  onClick={() => setSidebarOpen(false)}
                  className="w-8 h-8 flex items-center justify-center rounded-lg text-foreground/60 hover:text-foreground hover:bg-accent transition-colors"
                  data-testid="button-close-sidebar"
                >
                  <PanelLeft className="w-4 h-4" />
                </button>
              </div>

              {/* Actions */}
              <div className="px-2 flex flex-col gap-0.5">
                <button
                  onClick={() => { openNewScan(); setSidebarOpen(false); }}
                  className="flex items-center gap-2.5 px-2 py-2 rounded-md text-sm text-foreground/60 hover:text-foreground hover:bg-accent transition-colors text-left"
                  data-testid="button-new-scan-panel"
                >
                  <Plus className="w-4 h-4 flex-shrink-0" />
                  <span className="font-medium">New Scan</span>
                </button>

                {navItems.map(item => {
                  const isActive = item.path === "/" ? location === "/" : location.startsWith(item.path);
                  return (
                    <button
                      key={item.path}
                      onClick={() => { navigate(item.path); setSidebarOpen(false); }}
                      className={cn(
                        "flex items-center gap-2.5 px-2 py-2 rounded-md text-sm w-full text-left transition-colors",
                        isActive
                          ? "text-foreground bg-accent"
                          : "text-foreground/60 hover:text-foreground hover:bg-accent"
                      )}
                      data-testid={`nav-panel-${item.label.toLowerCase()}`}
                    >
                      <item.icon className="w-4 h-4 flex-shrink-0" />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </div>

              {/* Recents */}
              <div className="px-4 pt-4 pb-1 flex-shrink-0">
                <span className="text-[10px] font-medium text-foreground/30 uppercase tracking-widest">Recents</span>
              </div>
              <div className="flex-1 min-h-0 overflow-y-auto px-2 space-y-0.5 pb-2 sidebar-scroll" data-testid="sidebar-history">
                {scansLoading && <p className="px-2 py-2 text-xs text-foreground/30">Loading…</p>}
                {!scansLoading && !scans?.length && <p className="px-2 py-2 text-xs text-foreground/30">No scans yet</p>}
                {scans?.map(s => {
                  const active = location === `/scans/${s.id}`;
                  return (
                    <div
                      key={s.id}
                      onClick={() => { navigate(`/scans/${s.id}`); setSidebarOpen(false); }}
                      className={cn(
                        "flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer transition-colors",
                        active ? "bg-accent text-foreground" : "text-foreground/50 hover:text-foreground hover:bg-accent/60"
                      )}
                      data-testid={`session-item-${s.id}`}
                    >
                      <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", STATUS_DOT[s.status] ?? "bg-muted-foreground/40")} />
                      <p className="text-xs truncate flex-1">{s.target}</p>
                    </div>
                  );
                })}
              </div>
            </motion.div>

          </>
        )}
      </AnimatePresence>

      {/* ── Main content ── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-10 flex-shrink-0 border-b border-border/50 flex items-center px-4 bg-transparent">
          {/* Hamburger — mobile only */}
          <button
            onClick={() => setSidebarOpen(v => !v)}
            className="sm:hidden w-7 h-7 rounded-md flex items-center justify-center text-foreground/60 hover:text-foreground hover:bg-accent transition-colors cursor-pointer"
            data-testid="button-hamburger"
          >
            <Menu className="w-4 h-4" />
          </button>

          <div className="ml-auto flex items-center gap-1">
            <button
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className="w-7 h-7 rounded-md flex items-center justify-center text-foreground/40 hover:text-foreground hover:bg-accent transition-colors cursor-pointer"
              data-testid="button-toggle-theme"
            >
              {theme === "dark" ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
            </button>

            <div className="relative">
              <button
                onClick={() => setShowNotifications(v => !v)}
                className="relative w-7 h-7 rounded-md flex items-center justify-center text-foreground/40 hover:text-foreground hover:bg-accent transition-colors cursor-pointer"
                data-testid="button-notifications"
              >
                <Bell className="w-3.5 h-3.5" />
                {unreadCount > 0 && (
                  <span className="absolute -top-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-primary text-primary-foreground text-[8px] font-bold flex items-center justify-center">
                    {unreadCount > 9 ? "9+" : unreadCount}
                  </span>
                )}
              </button>
              <AnimatePresence>
                {showNotifications && (
                  <NotificationsPanel onClose={() => setShowNotifications(false)} />
                )}
              </AnimatePresence>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-auto" data-testid="main-content">
          <AnimatePresence mode="wait">
            <motion.div
              key={location}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
              className="h-full"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      {showNotifications && (
        <div className="fixed inset-0 z-40" onClick={() => setShowNotifications(false)} />
      )}
    </div>
  );
}
