import { useState, FormEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Terminal, AlertCircle, Info } from "lucide-react";
import { cn, extractApiError } from "@/lib/utils";
import { useGenerateToken } from "./useInstallerTokens";
import type { InstallerTokenGenerateResponse } from "@/types/installer";

const LOG_LEVELS = ["INFO", "DEBUG", "WARNING", "ERROR"] as const;
type LogLevel = (typeof LOG_LEVELS)[number];

interface Props {
  open: boolean;
  onClose: () => void;
  onSuccess: (token: InstallerTokenGenerateResponse) => void;
}

export function GenerateTokenModal({ open, onClose, onSuccess }: Props) {
  const [machineName, setMachineName] = useState("");
  const [organization, setOrganization] = useState("");
  const [logLevel, setLogLevel] = useState<LogLevel>("INFO");
  const [tags, setTags] = useState("");
  const [error, setError] = useState<string | null>(null);

  const generateMutation = useGenerateToken();

  function resetForm() {
    setMachineName("");
    setOrganization("");
    setLogLevel("INFO");
    setTags("");
    setError(null);
  }

  function handleClose() {
    if (generateMutation.isPending) return;
    resetForm();
    onClose();
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    const metadata: Record<string, unknown> = { log_level: logLevel };
    if (tags.trim()) {
      metadata.tags = tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
    }

    try {
      const result = await generateMutation.mutateAsync({
        organization: organization.trim(),
        machine_name: machineName.trim(),
        metadata,
      });
      resetForm();
      onSuccess(result);
    } catch (err) {
      setError(extractApiError(err));
    }
  }

  const isLoading = generateMutation.isPending;

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            onClick={handleClose}
          />

          {/* Panel */}
          <motion.div
            key="panel"
            initial={{ opacity: 0, scale: 0.97, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: 8 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="gen-modal-title"
          >
            <div className="card w-full max-w-md shadow-elevated">
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-4 border-b border-border">
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded-md bg-accent/10 border border-accent/20 flex items-center justify-center">
                    <Terminal className="w-3.5 h-3.5 text-accent" />
                  </div>
                  <div>
                    <h2
                      id="gen-modal-title"
                      className="text-sm font-semibold text-text-primary"
                    >
                      Generate Installer Token
                    </h2>
                    <p className="text-xs text-text-muted">
                      Single-use · expires in 1 hour
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleClose}
                  disabled={isLoading}
                  className="btn-ghost p-1.5 rounded"
                  aria-label="Close"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Body */}
              <form onSubmit={handleSubmit} className="p-5 space-y-4">
                {/* Error */}
                <AnimatePresence>
                  {error && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="flex items-start gap-2.5 p-3 rounded bg-severity-critical/10 border border-severity-critical/20"
                    >
                      <AlertCircle className="w-4 h-4 text-severity-critical mt-0.5 flex-shrink-0" />
                      <p className="text-xs text-severity-critical">{error}</p>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* Machine Name */}
                <div>
                  <label
                    htmlFor="machine-name"
                    className="block text-xs font-medium text-text-secondary mb-1.5"
                  >
                    Machine Name <span className="text-severity-critical">*</span>
                  </label>
                  <input
                    id="machine-name"
                    type="text"
                    value={machineName}
                    onChange={(e) => setMachineName(e.target.value)}
                    className="input-base font-mono text-xs"
                    placeholder="WIN-SRV-PROD-01"
                    required
                    disabled={isLoading}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <p className="text-xs text-text-muted mt-1">
                    Hostname of the machine to be enrolled
                  </p>
                </div>

                {/* Organization */}
                <div>
                  <label
                    htmlFor="organization"
                    className="block text-xs font-medium text-text-secondary mb-1.5"
                  >
                    Organization <span className="text-severity-critical">*</span>
                  </label>
                  <input
                    id="organization"
                    type="text"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    className="input-base"
                    placeholder="Acme Corp — IT Security"
                    required
                    disabled={isLoading}
                  />
                </div>

                {/* Log Level */}
                <div>
                  <label
                    htmlFor="log-level"
                    className="block text-xs font-medium text-text-secondary mb-1.5"
                  >
                    Agent Log Level
                  </label>
                  <select
                    id="log-level"
                    value={logLevel}
                    onChange={(e) => setLogLevel(e.target.value as LogLevel)}
                    className="input-base appearance-none cursor-pointer"
                    disabled={isLoading}
                  >
                    {LOG_LEVELS.map((l) => (
                      <option key={l} value={l}>
                        {l}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Tags */}
                <div>
                  <label
                    htmlFor="tags"
                    className="block text-xs font-medium text-text-secondary mb-1.5"
                  >
                    Tags{" "}
                    <span className="text-text-muted font-normal">(optional)</span>
                  </label>
                  <input
                    id="tags"
                    type="text"
                    value={tags}
                    onChange={(e) => setTags(e.target.value)}
                    className="input-base"
                    placeholder="prod, us-east, finance"
                    disabled={isLoading}
                  />
                  <p className="text-xs text-text-muted mt-1">
                    Comma-separated labels for this agent
                  </p>
                </div>

                {/* Info notice */}
                <div className="flex items-start gap-2 p-3 rounded bg-accent/5 border border-accent/15">
                  <Info className="w-3.5 h-3.5 text-accent mt-0.5 flex-shrink-0" />
                  <p className="text-xs text-text-secondary leading-relaxed">
                    The raw token is shown{" "}
                    <span className="text-text-primary font-medium">once</span>{" "}
                    after generation and cannot be retrieved again. Copy it
                    immediately.
                  </p>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-end gap-3 pt-1">
                  <button
                    type="button"
                    onClick={handleClose}
                    className="btn-secondary text-sm"
                    disabled={isLoading}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className={cn(
                      "btn-primary text-sm flex items-center gap-2",
                      isLoading && "opacity-70 cursor-not-allowed",
                    )}
                    disabled={isLoading || !machineName.trim() || !organization.trim()}
                  >
                    {isLoading ? (
                      <>
                        <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        Generating…
                      </>
                    ) : (
                      "Generate Token"
                    )}
                  </button>
                </div>
              </form>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
