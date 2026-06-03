import { Database, Search, Filter, Sparkles } from "lucide-react";

export function EventsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="page-title">Events</h1>
        <p className="text-sm text-text-muted mt-1">Search and analyze raw security telemetry</p>
      </div>

      <div
        className="rounded-2xl p-12 flex flex-col items-center justify-center text-center border"
        style={{
          background: "rgba(0,0,0,0.6)",
          borderColor: "rgba(6,182,212,0.15)",
          borderStyle: "dashed",
        }}
      >
        <div
          className="w-14 h-14 rounded-2xl flex items-center justify-center mb-4"
          style={{ background: "rgba(6,182,212,0.08)", border: "1px solid rgba(56,189,248,0.2)" }}
        >
          <Database className="w-6 h-6 text-cyber-400" />
        </div>
        <h2 className="font-display text-lg font-semibold text-text-primary mb-2">
          Event Explorer
        </h2>
        <p className="text-sm text-text-muted max-w-md leading-relaxed mb-6">
          Full-text search, KQL-style queries, and faceted filters across billions of security
          events ingested from your endpoints and network.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-3">
          {[
            { icon: Search, label: "Full-text search" },
            { icon: Filter, label: "KQL filters" },
            { icon: Sparkles, label: "AI field extraction" },
          ].map(({ icon: Icon, label }) => (
            <div
              key={label}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-cyber-400"
              style={{ background: "rgba(6,182,212,0.06)", border: "1px solid rgba(6,182,212,0.15)" }}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
