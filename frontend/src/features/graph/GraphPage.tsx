import { Network } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";

export function GraphPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Graph Analysis</h1>
        <p className="text-sm text-text-muted mt-1">Visualize attack paths and entity relationships</p>
      </div>

      <EmptyState
        icon={<Network className="w-8 h-8" />}
        title="No graph data"
        description="Select an investigation or alert to visualize its attack graph."
      />
    </div>
  );
}
