import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  CheckCircle,
  Copy,
  Check,
  AlertTriangle,
  X,
  Clock,
  Terminal,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { InstallerTokenGenerateResponse } from "@/types/installer";

interface Props {
  open: boolean;
  token: InstallerTokenGenerateResponse | null;
  onClose: () => void;
}

function useCountdown(expiresAt: string | undefined) {
  const [display, setDisplay] = useState("");
  const [isUrgent, setIsUrgent] = useState(false);

  useEffect(() => {
    if (!expiresAt) return;

    function tick() {
      const diff = new Date(expiresAt!).getTime() - Date.now();
      if (diff <= 0) {
        setDisplay("Expired");
        setIsUrgent(true);
        return;
      }
      setIsUrgent(diff < 5 * 60 * 1000);
      const h = Math.floor(diff / 3_600_000);
      const m = Math.floor((diff % 3_600_000) / 60_000);
      const s = Math.floor((diff % 60_000) / 1_000);
      setDisplay(
        `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`,
      );
    }

    tick();
    const id = setInterval(tick, 1_000);
    return () => clearInterval(id);
  }, [expiresAt]);

  return { display, isUrgent };
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2_000);
    } catch {
      /* clipboard not available in some browser contexts */
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className={cn(
        "flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium transition-all duration-150",
        copied
          ? "bg-severity-low/15 text-severity-low border border-severity-low/30"
          : "bg-bg-subtle text-text-secondary hover:text-text-primary border border-border hover:border-border-strong",
      )}
      aria-label={`Copy ${label ?? "to clipboard"}`}
    >
      {copied ? (
        <>
          <Check className="w-3 h-3" />
          Copied
        </>
      ) : (
        <>
          <Copy className="w-3 h-3" />
          Copy
        </>
      )}
    </button>
  );
}

const INSTALL_STEPS = [
  {
    step: 1,
    text: "Download bootstrap.ps1 from the SOC Platform distribution package",
  },
  {
    step: 2,
    text: "Open PowerShell as Administrator on the target machine",
  },
  {
    step: 3,
    text: "Run the command above — the agent installs and self-registers automatically",
  },
  {
    step: 4,
    text: 'Verify the agent appears as "Online" in the Agents section within 60 seconds',
  },
];

export function TokenSuccessModal({ open, token, onClose }: Props) {
  const { display: countdown, isUrgent } = useCountdown(token?.expires_at);

  const installCommand = token
    ? `powershell -ExecutionPolicy Bypass -File bootstrap.ps1 -Token ${token.raw_token}`
    : "";

  const handleClose = useCallback(() => {
    onClose();
  }, [onClose]);

  return (
    <AnimatePresence>
      {open && token && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm"
          />

          {/* Panel */}
          <motion.div
            key="panel"
            initial={{ opacity: 0, scale: 0.96, y: 12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 12 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto"
            role="dialog"
            aria-modal="true"
            aria-labelledby="success-modal-title"
          >
            <div className="card w-full max-w-xl shadow-elevated my-auto">
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-4 border-b border-border">
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded-full bg-severity-low/15 border border-severity-low/25 flex items-center justify-center">
                    <CheckCircle className="w-4 h-4 text-severity-low" />
                  </div>
                  <div>
                    <h2
                      id="success-modal-title"
                      className="text-sm font-semibold text-text-primary"
                    >
                      Token Generated
                    </h2>
                    <p className="text-xs text-text-muted">
                      {token.machine_name} · {token.organization}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleClose}
                  className="btn-ghost p-1.5 rounded"
                  aria-label="Close"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-5 space-y-4">
                {/* One-time warning */}
                <div className="flex items-start gap-2.5 p-3 rounded bg-severity-high/8 border border-severity-high/25">
                  <AlertTriangle className="w-4 h-4 text-severity-high mt-0.5 flex-shrink-0" />
                  <p className="text-xs text-severity-high leading-relaxed">
                    <span className="font-semibold">
                      This token will not be displayed again.
                    </span>{" "}
                    Copy it now before closing this window.
                  </p>
                </div>

                {/* Countdown */}
                <div className="flex items-center gap-2 px-3 py-2 rounded bg-bg-elevated border border-border">
                  <Clock
                    className={cn(
                      "w-3.5 h-3.5 flex-shrink-0",
                      isUrgent ? "text-severity-critical" : "text-text-muted",
                    )}
                  />
                  <span className="text-xs text-text-secondary">
                    Expires in:
                  </span>
                  <span
                    className={cn(
                      "font-mono text-xs font-semibold tabular-nums",
                      isUrgent ? "text-severity-critical" : "text-severity-low",
                    )}
                  >
                    {countdown}
                  </span>
                </div>

                {/* Raw token */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-medium text-text-secondary">
                      Installer Token
                    </label>
                    <CopyButton text={token.raw_token} label="token" />
                  </div>
                  <div className="px-3 py-2.5 rounded bg-bg-base border border-border font-mono text-xs text-text-primary break-all leading-relaxed select-all">
                    {token.raw_token}
                  </div>
                </div>

                {/* Install command */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-text-muted" />
                      <label className="text-xs font-medium text-text-secondary">
                        Install Command
                      </label>
                    </div>
                    <CopyButton text={installCommand} label="command" />
                  </div>
                  <div className="px-3 py-2.5 rounded bg-bg-base border border-border font-mono text-xs text-text-primary break-all leading-relaxed select-all whitespace-pre-wrap">
                    {installCommand}
                  </div>
                  <p className="text-xs text-text-muted mt-1.5">
                    Run as Administrator on the target machine
                  </p>
                </div>

                {/* Installation steps */}
                <div>
                  <p className="text-xs font-medium text-text-secondary mb-2">
                    Installation Steps
                  </p>
                  <ol className="space-y-2">
                    {INSTALL_STEPS.map(({ step, text }) => (
                      <li key={step} className="flex items-start gap-2.5">
                        <span className="flex-shrink-0 w-5 h-5 rounded-full bg-bg-elevated border border-border flex items-center justify-center">
                          <span className="text-2xs font-semibold text-text-muted">
                            {step}
                          </span>
                        </span>
                        <span className="text-xs text-text-secondary leading-relaxed pt-0.5">
                          {text}
                        </span>
                      </li>
                    ))}
                  </ol>
                </div>

                {/* Close */}
                <div className="flex items-center justify-end pt-1 border-t border-border">
                  <button
                    type="button"
                    onClick={handleClose}
                    className="btn-secondary text-sm flex items-center gap-1.5"
                  >
                    Done
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
