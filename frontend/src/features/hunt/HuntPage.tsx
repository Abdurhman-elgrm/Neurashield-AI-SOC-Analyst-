import { Crosshair, Sparkles } from "lucide-react";

export function HuntPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="page-title">Threat Hunt</h1>
        <p className="text-sm text-text-muted mt-1">Proactively hunt for adversaries in your environment</p>
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
          <Crosshair className="w-6 h-6 text-primary-400" />
        </div>
        <h2 className="font-display text-lg font-semibold text-text-primary mb-2">
          Hunt Sessions Coming Soon
        </h2>
        <p className="text-sm text-text-muted max-w-md leading-relaxed mb-6">
          Build and execute hunting queries against your event data. Search for indicators
          of compromise, anomalous behaviors, and threat patterns.
        </p>
        <div className="flex items-center gap-2 text-xs text-primary-400">
          <Sparkles className="w-3.5 h-3.5" />
          <span>AI-assisted hunting queries powered by NEURASHIELD</span>
        </div>
      </div>
    </div>
  );
}
