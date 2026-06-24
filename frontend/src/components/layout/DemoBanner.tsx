import { useState } from "react";
import { Zap, X } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";

export function DemoBanner() {
  const user = useAuthStore((s) => s.user);
  const [dismissed, setDismissed] = useState(false);

  if (dismissed || user?.email !== "demo@neurashield.io") return null;

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 8,
      padding: "6px 16px",
      background: "rgba(6,182,212,0.08)",
      borderBottom: "1px solid rgba(6,182,212,0.2)",
      flexShrink: 0,
    }}>
      <Zap size={11} style={{ color: "#22D3EE", flexShrink: 0 }} />
      <span style={{ fontSize: 11, color: "#67E8F9", fontWeight: 600 }}>
        DEMO MODE
      </span>
      <span style={{ fontSize: 11, color: "#5C6373", marginLeft: 2 }}>
        · You&apos;re viewing a pre-seeded demo environment. All data is synthetic and resets every 24 h.
        No real infrastructure is monitored.
      </span>
      <button
        onClick={() => setDismissed(true)}
        style={{
          marginLeft: "auto", background: "none", border: "none",
          cursor: "pointer", color: "#5C6373", display: "flex", alignItems: "center",
          padding: 2, flexShrink: 0,
        }}
        aria-label="Dismiss demo banner"
      >
        <X size={12} />
      </button>
    </div>
  );
}
