import { useState } from "react";
import { Link, useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard,
  Plus,
  Bell,
  Sun,
  Moon,
  ChevronRight,
  X,
  Check,
  User,
  LogOut,
  KeyRound,
  Shield,
} from "lucide-react";
import { useTheme } from "@/components/ui/theme-provider";
import { useListNotifications, useMarkAllNotificationsRead, getListNotificationsQueryKey, useListScans } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useNewScan } from "@/hooks/use-new-scan";
import { cn } from "@/lib/utils";

const navItems = [
  { path: "/", icon: LayoutDashboard, label: "Dashboard" },
];

function relTime(ts: string) {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const STATUS_DOT: Record<string, string> = {
  running: "bg-blue-400 animate-pulse",
  completed: "bg-green-400",
  failed: "bg-red-400",
  queued: "bg-yellow-400",
};

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
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListNotificationsQueryKey() });
      },
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
      className="absolute right-0 top-10 z-50 w-[380px] rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
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

function ProfilePanel({ onClose }: { onClose: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -8, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -8, scale: 0.97 }}
      transition={{ duration: 0.18 }}
      className="absolute right-0 top-10 z-50 w-[260px] rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
    >
      <div className="px-4 py-4 border-b border-border flex items-center gap-3">
        <div className="w-10 h-10 rounded-full bg-primary/20 border-2 border-primary/30 flex items-center justify-center text-sm font-bold text-primary flex-shrink-0">
          AG
        </div>
        <div className="min-w-0">
          <p className="text-sm font-semibold truncate">Admin User</p>
          <p className="text-xs text-muted-foreground truncate">admin@armorguard.io</p>
        </div>
      </div>
      <div className="py-1">
        {[
          { icon: User, label: "Profile Settings" },
          { icon: KeyRound, label: "API Keys" },
          { icon: Shield, label: "Security" },
        ].map((item) => (
          <button
            key={item.label}
            className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-foreground hover:bg-accent transition-colors text-left"
          >
            <item.icon className="w-4 h-4 text-muted-foreground" />
            {item.label}
          </button>
        ))}
      </div>
      <div className="border-t border-border py-1">
        <button
          onClick={onClose}
          className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-red-500 hover:bg-red-500/10 transition-colors text-left"
        >
          <LogOut className="w-4 h-4" />
          Sign out
        </button>
      </div>
    </motion.div>
  );
}

export default function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { theme, setTheme } = useTheme();
  const { openNewScan } = useNewScan();
  const { data: scans, isLoading: scansLoading } = useListScans();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const { data: notifications } = useListNotifications();
  const unreadCount = notifications?.filter(n => !n.read).length ?? 0;

  const currentNav = navItems.find(n => n.path === location || (n.path !== "/" && location.startsWith(n.path)));

  function NavItem({ item }: { item: typeof navItems[0] }) {
    const isActive = item.path === "/" ? location === "/" : location.startsWith(item.path);
    return (
      <Link href={item.path}>
        <motion.div
          className={cn(
            "relative flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer text-sm font-medium transition-colors",
            isActive
              ? "text-foreground bg-accent"
              : "text-muted-foreground hover:text-foreground hover:bg-accent/60"
          )}
          whileHover={{ x: 2 }}
          transition={{ type: "spring", stiffness: 400, damping: 30 }}
          data-testid={`nav-item-${item.label.toLowerCase()}`}
        >
          {isActive && (
            <motion.div
              layoutId="nav-indicator"
              className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-primary rounded-r-full"
              transition={{ type: "spring", stiffness: 350, damping: 30 }}
            />
          )}
          <item.icon className={cn("w-4 h-4 flex-shrink-0", isActive && "text-primary")} />
          <span>{item.label}</span>
        </motion.div>
      </Link>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      {/* Sidebar */}
      <aside className="w-[240px] flex-shrink-0 border-r border-border flex flex-col py-4 bg-sidebar">
        {/* Logo */}
        <div className="px-5 mb-5">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center shadow-sm">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="font-bold text-sm tracking-wide text-foreground">ArmorGuard</span>
          </div>
        </div>

        {/* New Scan — global trigger */}
        <div className="px-3 mb-3">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={openNewScan}
            className="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg bg-primary text-primary-foreground text-sm font-semibold hover:bg-primary/90 transition-colors shadow-sm"
            data-testid="button-new-scan"
          >
            <Plus className="w-4 h-4" />
            New Scan
          </motion.button>
        </div>

        {/* Main nav */}
        <nav className="px-2 space-y-0.5" data-testid="sidebar-nav">
          {navItems.map((item) => (
            <NavItem key={item.path} item={item} />
          ))}
        </nav>

        {/* Session history */}
        <div className="px-4 mt-4 mb-1.5">
          <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">History</span>
        </div>
        <div className="flex-1 min-h-0 overflow-y-auto px-2 space-y-0.5" data-testid="sidebar-history">
          {scansLoading && (
            <p className="px-2.5 py-2 text-xs text-muted-foreground">Loading…</p>
          )}
          {!scansLoading && !scans?.length && (
            <p className="px-2.5 py-2 text-xs text-muted-foreground">No scans yet</p>
          )}
          {scans?.map((s) => {
            const active = location === `/scans/${s.id}`;
            return (
              <Link key={s.id} href={`/scans/${s.id}`}>
                <div
                  className={cn(
                    "group flex items-center gap-2.5 px-2.5 py-2 rounded-lg cursor-pointer transition-colors",
                    active ? "bg-accent" : "hover:bg-accent/60"
                  )}
                  data-testid={`session-item-${s.id}`}
                >
                  <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", STATUS_DOT[s.status] ?? "bg-muted-foreground")} />
                  <div className="min-w-0 flex-1">
                    <p className={cn(
                      "text-xs font-medium truncate",
                      active ? "text-foreground" : "text-muted-foreground group-hover:text-foreground"
                    )}>
                      {s.target}
                    </p>
                    <p className="text-[10px] text-muted-foreground/60">{relTime(s.createdAt)}</p>
                  </div>
                </div>
              </Link>
            );
          })}
        </div>

        {/* Bottom user */}
        <div className="px-4 pt-3 border-t border-border">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-xs font-bold text-primary">
              AG
            </div>
            <div>
              <p className="text-xs font-medium">Admin</p>
              <p className="text-[10px] text-muted-foreground">Security Analyst</p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main content area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="h-12 flex-shrink-0 border-b border-border flex items-center justify-between px-5 bg-card/80 backdrop-blur-sm">
          {/* Breadcrumb */}
          <div className="flex items-center gap-1.5 text-sm">
            <span className="text-muted-foreground">ArmorGuard</span>
            <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/50" />
            <span className="font-semibold">{currentNav?.label ?? "Production"}</span>
          </div>

          {/* Right actions */}
          <div className="flex items-center gap-2">
            {/* Theme toggle */}
            <button
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className="w-8 h-8 rounded-lg flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
              data-testid="button-toggle-theme"
            >
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            {/* Notifications */}
            <div className="relative">
              <button
                onClick={() => { setShowNotifications(v => !v); setShowProfile(false); }}
                className="relative w-8 h-8 rounded-lg flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                data-testid="button-notifications"
              >
                <Bell className="w-4 h-4" />
                {unreadCount > 0 && (
                  <motion.span
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-primary text-primary-foreground text-[9px] font-bold flex items-center justify-center"
                  >
                    {unreadCount > 9 ? "9+" : unreadCount}
                  </motion.span>
                )}
              </button>
              <AnimatePresence>
                {showNotifications && (
                  <NotificationsPanel onClose={() => setShowNotifications(false)} />
                )}
              </AnimatePresence>
            </div>

            {/* Profile avatar */}
            <div className="relative">
              <button
                onClick={() => { setShowProfile(v => !v); setShowNotifications(false); }}
                className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-xs font-bold text-primary hover:bg-primary/30 transition-colors cursor-pointer"
                data-testid="button-profile"
              >
                AG
              </button>
              <AnimatePresence>
                {showProfile && (
                  <ProfilePanel onClose={() => setShowProfile(false)} />
                )}
              </AnimatePresence>
            </div>
          </div>
        </header>

        {/* Page content */}
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

      {/* Click-away overlay */}
      {(showNotifications || showProfile) && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => { setShowNotifications(false); setShowProfile(false); }}
        />
      )}
    </div>
  );
}
