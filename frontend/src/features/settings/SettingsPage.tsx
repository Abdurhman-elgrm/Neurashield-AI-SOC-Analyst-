import { Settings } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";

export function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">Settings</h1>
        <p className="text-sm text-text-muted mt-1">Platform and tenant configuration</p>
      </div>

      <EmptyState
        icon={<Settings className="w-8 h-8" />}
        title="Settings"
        description="Platform settings will be available here."
      />
    </div>
  );
}
