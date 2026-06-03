import { ShieldCheck, GitMerge } from "lucide-react";
import { useNavigate } from "react-router-dom";

export function InvestigationsPage() {
  const navigate = useNavigate();
  return (
    <div className="space-y-6">
      <div>
        <h1 className="page-title">Investigations</h1>
        <p className="text-sm text-text-muted mt-1">Correlated threat investigations and case management</p>
      </div>

      <div
        className="rounded-2xl p-12 flex flex-col items-center justify-center text-center border"
        style={{
          background: "rgba(0,0,0,0.6)",
          borderColor: "rgba(59,130,246,0.15)",
          borderStyle: "dashed",
        }}
      >
        <div
          className="w-14 h-14 rounded-2xl flex items-center justify-center mb-4"
          style={{ background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.2)" }}
        >
          <ShieldCheck className="w-6 h-6 text-primary-400" />
        </div>
        <h2 className="font-display text-lg font-semibold text-text-primary mb-2">
          No Investigations Yet
        </h2>
        <p className="text-sm text-text-muted max-w-md leading-relaxed mb-6">
          Investigations are created automatically when NEURASHIELD correlates multiple related
          alerts into a unified case. Triage alerts to get started.
        </p>
        <div className="flex items-center gap-4">
          <button
            className="btn-primary text-sm"
            onClick={() => navigate("/alerts")}
          >
            <ShieldCheck className="w-4 h-4" />
            Go to Alerts
          </button>
          <div className="flex items-center gap-2 text-xs text-cyber-400">
            <GitMerge className="w-3.5 h-3.5" />
            <span>Auto-correlated by AI</span>
          </div>
        </div>
      </div>
    </div>
  );
}
