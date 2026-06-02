import { ShieldCheck } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";

export function InvestigationsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Investigations</h1>
        <p className="text-sm text-text-muted mt-1">Open investigations and case management</p>
      </div>

      <EmptyState
        icon={<ShieldCheck className="w-8 h-8" />}
        title="No investigations"
        description="Investigations are created automatically from correlated alerts."
      />
    </div>
  );
}
