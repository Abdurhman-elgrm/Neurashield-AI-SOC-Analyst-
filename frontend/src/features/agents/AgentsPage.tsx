import { Server, Plus } from "lucide-react";
import { useNavigate } from "react-router-dom";

export function AgentsPage() {
  const navigate = useNavigate();
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Agents</h1>
          <p className="text-sm text-text-muted mt-1">Deployed collection agents and their health status</p>
        </div>
        <button
          className="btn-primary text-sm"
          onClick={() => navigate("/installer")}
        >
          <Plus className="w-4 h-4" />
          Deploy Agent
        </button>
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
          style={{ background: "rgba(52,211,153,0.08)", border: "1px solid rgba(52,211,153,0.2)" }}
        >
          <Server className="w-6 h-6 text-status-online" />
        </div>
        <h2 className="font-display text-lg font-semibold text-text-primary mb-2">
          No Agents Deployed
        </h2>
        <p className="text-sm text-text-muted max-w-md leading-relaxed mb-6">
          Deploy NEURASHIELD agents to your endpoints and servers to start collecting
          security telemetry. Each agent checks in every 30 seconds.
        </p>
        <button
          className="btn-primary text-sm"
          onClick={() => navigate("/installer")}
        >
          <Plus className="w-4 h-4" />
          Generate Installer Token
        </button>
      </div>
    </div>
  );
}
