import { AnimatePresence, motion } from "framer-motion";
import { ArrowUp } from "lucide-react";
import { formatDistanceToNowStrict } from "date-fns";

interface NewAlertsIndicatorProps {
  count: number;
  since: Date | null;
  onDismiss: () => void;
}

export function NewAlertsIndicator({ count, since, onDismiss }: NewAlertsIndicatorProps) {
  return (
    <AnimatePresence>
      {count > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ type: "spring", stiffness: 400, damping: 30 }}
          className="flex items-center gap-2 px-3 py-1.5 bg-accent/10 border border-accent/20 rounded-lg"
        >
          <ArrowUp className="w-3.5 h-3.5 text-accent" />
          <span className="text-xs text-accent font-medium">
            {count} new alert{count !== 1 ? "s" : ""}
            {since && (
              <span className="font-normal text-accent/70">
                {" "}since {formatDistanceToNowStrict(since, { addSuffix: true })}
              </span>
            )}
          </span>
          <button
            onClick={onDismiss}
            className="ml-1 text-xs text-accent/70 hover:text-accent underline transition-colors"
          >
            Dismiss
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
