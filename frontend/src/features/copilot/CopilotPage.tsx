import { Brain } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";

export function CopilotPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-text-primary">AI Copilot</h1>
        <p className="text-sm text-text-muted mt-1">AI-powered investigation assistant</p>
      </div>

      <EmptyState
        icon={<Brain className="w-8 h-8" />}
        title="Start a conversation"
        description="Ask the AI copilot to help analyze alerts, investigate threats, or explain findings."
      />
    </div>
  );
}
