import { Bell, Check, CheckCheck, X, AlertTriangle, Info, ShieldAlert } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { formatRelativeTime, cn } from "@/lib/utils";
import { useNotificationStore, type Notification } from "@/stores/notificationStore";
import { useUIStore } from "@/stores/uiStore";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";

// ─── Notification item ────────────────────────────────────────────────────────

const TYPE_ICONS: Record<string, React.ReactNode> = {
  alert:         <AlertTriangle className="w-4 h-4" />,
  investigation: <ShieldAlert className="w-4 h-4" />,
  system:        <Info className="w-4 h-4" />,
  info:          <Info className="w-4 h-4" />,
};

function NotificationItem({
  n,
  onRead,
  onRemove,
}: {
  n: Notification;
  onRead: () => void;
  onRemove: () => void;
}) {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 16 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 16 }}
      className={cn(
        "px-4 py-3 border-b border-border last:border-0 hover:bg-bg-elevated/50 transition-colors",
        !n.read && "bg-accent/5"
      )}
    >
      <div className="flex items-start gap-3">
        <span
          className={cn(
            "mt-0.5 flex-shrink-0",
            n.severity === "critical" && "text-severity-critical",
            n.severity === "high" && "text-severity-high",
            n.severity === "medium" && "text-severity-medium",
            n.severity === "low" && "text-severity-low",
            !n.severity && "text-text-muted"
          )}
        >
          {TYPE_ICONS[n.type] ?? <Info className="w-4 h-4" />}
        </span>

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <p className={cn("text-sm font-medium", n.read ? "text-text-secondary" : "text-text-primary")}>
              {n.title}
            </p>
            {!n.read && (
              <span className="w-1.5 h-1.5 bg-accent rounded-full flex-shrink-0 mt-1.5" />
            )}
          </div>
          <p className="text-xs text-text-muted mt-0.5 line-clamp-2">{n.message}</p>
          {n.actionLabel && n.actionHref && (
            <a href={n.actionHref} className="text-xs text-accent hover:underline mt-1 inline-block">
              {n.actionLabel}
            </a>
          )}
          <p className="text-2xs text-text-muted mt-1.5">{formatRelativeTime(n.timestamp)}</p>
        </div>

        <div className="flex flex-col gap-1 flex-shrink-0">
          {!n.read && (
            <button
              onClick={onRead}
              className="text-text-muted hover:text-accent transition-colors"
              aria-label="Mark as read"
            >
              <Check className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            onClick={onRemove}
            className="text-text-muted hover:text-severity-critical transition-colors"
            aria-label="Dismiss"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </motion.div>
  );
}

// ─── NotificationCenter ───────────────────────────────────────────────────────

export function NotificationCenter() {
  const open = useUIStore((s) => s.notificationCenterOpen);
  const close = useUIStore((s) => s.closeNotificationCenter);
  const { notifications, unreadCount, markRead, markAllRead, removeNotification, clearAll } =
    useNotificationStore();

  return (
    <AnimatePresence>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={close} />
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.97 }}
            transition={{ duration: 0.15 }}
            className="absolute right-0 top-full mt-2 z-50 w-[380px] bg-bg-elevated border border-border rounded-xl shadow-panel overflow-hidden"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-text-primary">Notifications</h3>
                {unreadCount > 0 && (
                  <Badge variant="primary" className="text-xs">
                    {unreadCount}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-1">
                {unreadCount > 0 && (
                  <Button variant="ghost" size="xs" onClick={markAllRead}>
                    <CheckCheck className="w-3.5 h-3.5" />
                    Mark all read
                  </Button>
                )}
                {notifications.length > 0 && (
                  <Button variant="ghost" size="xs" onClick={clearAll} className="text-text-muted hover:text-severity-critical">
                    Clear all
                  </Button>
                )}
              </div>
            </div>

            {/* List */}
            <div className="max-h-[480px] overflow-y-auto">
              {notifications.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <Bell className="w-8 h-8 text-text-muted mb-2" />
                  <p className="text-sm text-text-muted">No notifications</p>
                </div>
              ) : (
                <AnimatePresence>
                  {notifications.map((n) => (
                    <NotificationItem
                      key={n.id}
                      n={n}
                      onRead={() => markRead(n.id)}
                      onRemove={() => removeNotification(n.id)}
                    />
                  ))}
                </AnimatePresence>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

// ─── NotificationBell (trigger button) ────────────────────────────────────────

export function NotificationBell() {
  const unreadCount = useNotificationStore((s) => s.unreadCount);
  const toggle = useUIStore((s) => s.toggleNotificationCenter);

  return (
    <div className="relative">
      <button
        onClick={toggle}
        className="relative p-1.5 rounded text-text-muted hover:text-text-primary hover:bg-bg-subtle transition-colors focus-ring"
        aria-label="Notifications"
      >
        <Bell className="w-4 h-4" />
        {unreadCount > 0 && (
          <span className="absolute top-0.5 right-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full bg-severity-critical text-white text-2xs font-bold">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>
      <NotificationCenter />
    </div>
  );
}
