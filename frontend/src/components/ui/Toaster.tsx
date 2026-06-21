import * as Toast from "@radix-ui/react-toast";
import { X, AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { useNotificationStore } from "@/stores/notificationStore";
import type { Notification } from "@/stores/notificationStore";

// ─── Toast viewport ───────────────────────────────────────────────────────────

export function Toaster() {
  const { notifications, markRead } = useNotificationStore();
  const recentUnread = notifications.filter((n) => !n.read).slice(0, 5);

  return (
    <Toast.Provider swipeDirection="right" duration={5000}>
      <AnimatePresence>
        {recentUnread.map((n) => (
          <ToastItem key={n.id} notification={n} onDismiss={() => markRead(n.id)} />
        ))}
      </AnimatePresence>
      <Toast.Viewport className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 w-[360px] max-w-[100vw-2rem]" />
    </Toast.Provider>
  );
}

// ─── Individual toast item ────────────────────────────────────────────────────

const ICONS: Record<string, React.ReactNode> = {
  alert:         <AlertTriangle className="w-4 h-4" />,
  investigation: <Info className="w-4 h-4" />,
  system:        <Info className="w-4 h-4" />,
  info:          <Info className="w-4 h-4" />,
  error:         <XCircle className="w-4 h-4" />,
  success:       <CheckCircle2 className="w-4 h-4" />,
};

const TYPE_ICON_COLOR: Record<string, string> = {
  error:   "text-red-400",
  success: "text-emerald-400",
  alert:   "text-amber-400",
};

const TYPE_BORDER: Record<string, string> = {
  error:   "border-red-500/30",
  success: "border-emerald-500/25",
  alert:   "border-amber-500/25",
};

const SEVERITY_CLASSES: Record<string, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-amber-400",
  low:      "text-blue-400",
};

function ToastItem({
  notification,
  onDismiss,
}: {
  notification: Notification;
  onDismiss: () => void;
}) {
  const iconColor = notification.severity
    ? SEVERITY_CLASSES[notification.severity]
    : TYPE_ICON_COLOR[notification.type] ?? "text-text-muted";

  return (
    <Toast.Root
      open
      onOpenChange={(open) => { if (!open) onDismiss(); }}
      asChild
    >
      <motion.div
        initial={{ opacity: 0, x: 40 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: 40 }}
        transition={{ duration: 0.2, ease: "easeOut" }}
        className={cn(
          "bg-bg-elevated border border-border rounded-lg shadow-elevated",
          "p-3.5 flex items-start gap-3",
          TYPE_BORDER[notification.type],
          notification.severity === "critical" && "border-red-500/30"
        )}
      >
        <span className={cn("mt-0.5 flex-shrink-0", iconColor)}>
          {ICONS[notification.type] ?? <Info className="w-4 h-4" />}
        </span>
        <div className="flex-1 min-w-0">
          <Toast.Title className="text-sm font-medium text-text-primary">{notification.title}</Toast.Title>
          <Toast.Description className="text-xs text-text-secondary mt-0.5 line-clamp-2">
            {notification.message}
          </Toast.Description>
          {notification.actionLabel && notification.actionHref && (
            <a
              href={notification.actionHref}
              className="text-xs text-accent hover:underline mt-1 inline-block"
            >
              {notification.actionLabel}
            </a>
          )}
        </div>
        <Toast.Close onClick={onDismiss} className="text-text-muted hover:text-text-primary transition-colors mt-0.5">
          <X className="w-3.5 h-3.5" />
        </Toast.Close>
      </motion.div>
    </Toast.Root>
  );
}
