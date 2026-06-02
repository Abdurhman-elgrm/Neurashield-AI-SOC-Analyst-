import { Search } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";

export function HuntPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Threat Hunt</h1>
        <p className="text-sm text-text-muted mt-1">Proactively hunt for threats in your environment</p>
      </div>

      <EmptyState
        icon={<Search className="w-8 h-8" />}
        title="No hunt sessions"
        description="Start a new hunt to search for indicators of compromise."
      />
    </div>
  );
}
