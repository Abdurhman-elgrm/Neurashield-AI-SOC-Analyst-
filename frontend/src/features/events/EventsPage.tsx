import { FileSearch } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";

export function EventsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Log Explorer</h1>
        <p className="text-sm text-text-muted mt-1">Search and analyze raw security events</p>
      </div>

      <EmptyState
        icon={<FileSearch className="w-8 h-8" />}
        title="No events loaded"
        description="Use the search bar above to query your event data."
      />
    </div>
  );
}
