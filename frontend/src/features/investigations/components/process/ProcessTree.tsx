import { useState, memo } from "react";
import { ChevronRight, ChevronDown, AlertTriangle, Activity } from "lucide-react";
import { cn } from "@/lib/utils";
import { EmptyState } from "@/components/ui/EmptyState";

// ─── Process tree types ───────────────────────────────────────────────────────

export interface ProcessNode {
  guid: string;
  pid: number;
  name: string;
  commandLine?: string;
  imageHash?: string;
  signer?: string;
  suspicious: boolean;
  children: ProcessNode[];
  startTime?: string;
}

// ─── Process row ──────────────────────────────────────────────────────────────

const ProcessRow = memo(function ProcessRow({
  node,
  depth,
}: {
  node: ProcessNode;
  depth: number;
}) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children.length > 0;

  return (
    <div>
      <div
        className={cn(
          "flex items-center gap-1.5 py-1.5 px-2 rounded-md hover:bg-bg-elevated transition-colors group",
          node.suspicious && "border-l-2 border-l-severity-high"
        )}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
      >
        {/* Expand toggle */}
        {hasChildren ? (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="flex-shrink-0 text-text-muted hover:text-text-secondary"
          >
            {expanded ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" />
            )}
          </button>
        ) : (
          <span className="w-3.5 flex-shrink-0" />
        )}

        {/* Suspicious indicator */}
        {node.suspicious ? (
          <AlertTriangle className="w-3.5 h-3.5 text-severity-high flex-shrink-0" />
        ) : (
          <Activity className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
        )}

        {/* Process name */}
        <span
          className={cn(
            "text-xs font-medium",
            node.suspicious ? "text-severity-high" : "text-text-primary"
          )}
        >
          {node.name}
        </span>

        <span className="text-2xs text-text-muted ml-1">PID: {node.pid}</span>

        {/* Expand command line on hover */}
        {node.commandLine && (
          <span className="text-2xs text-text-muted truncate max-w-[200px] hidden group-hover:block">
            {node.commandLine}
          </span>
        )}

        {/* Hash + signer */}
        <div className="ml-auto flex items-center gap-2 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
          {node.signer && (
            <span className="text-2xs text-status-online">{node.signer}</span>
          )}
          {node.imageHash && (
            <span className="text-2xs font-mono text-text-muted">
              {node.imageHash.slice(0, 8)}…
            </span>
          )}
        </div>
      </div>

      {/* Command line (always visible when suspicious) */}
      {node.suspicious && node.commandLine && (
        <div
          className="text-2xs font-mono text-text-muted bg-bg-elevated rounded px-2 py-1 mx-2 mb-1 overflow-x-auto"
          style={{ marginLeft: `${depth * 16 + 28}px` }}
        >
          {node.commandLine}
        </div>
      )}

      {/* Children */}
      {expanded && hasChildren && (
        <div>
          {node.children.map((child) => (
            <ProcessRow key={child.guid} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
});

// ─── ProcessTree ──────────────────────────────────────────────────────────────

interface ProcessTreeProps {
  roots: ProcessNode[];
  isLoading?: boolean;
}

export function ProcessTree({ roots, isLoading }: ProcessTreeProps) {
  if (isLoading) {
    return (
      <div className="space-y-2 p-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-7 bg-bg-elevated rounded animate-pulse" />
        ))}
      </div>
    );
  }

  if (!roots.length) {
    return (
      <EmptyState
        icon={<Activity className="w-5 h-5" />}
        title="No process tree"
        description="Process relationships will appear as events are ingested."
        className="py-8"
      />
    );
  }

  return (
    <div className="overflow-x-auto">
      {roots.map((root) => (
        <ProcessRow key={root.guid} node={root} depth={0} />
      ))}
    </div>
  );
}
