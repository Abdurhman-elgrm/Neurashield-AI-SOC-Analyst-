import { Server } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";

export function AgentsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Agents</h1>
        <p className="text-sm text-text-muted mt-1">Deployed collection agents and their health status</p>
      </div>

      <EmptyState
        icon={<Server className="w-8 h-8" />}
        title="No agents deployed"
        description="Deploy agents to start collecting security telemetry."
      />
    </div>
  );
}
