import { memo } from "react";
import { cn } from "@/lib/utils";

export interface OnlineAnalyst {
  id: string;
  name: string;
  avatarColor: string;
  activeSection: string;
  lastSeen: string;
}

function AnalystAvatar({ analyst }: { analyst: OnlineAnalyst }) {
  const initials = analyst.name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);

  return (
    <div className="relative group">
      <div
        className="w-6 h-6 rounded-full flex items-center justify-center text-2xs font-semibold text-white ring-2 ring-bg-surface"
        style={{ backgroundColor: analyst.avatarColor }}
      >
        {initials}
      </div>
      {/* Online dot */}
      <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 bg-status-online rounded-full ring-1 ring-bg-surface" />
      {/* Tooltip */}
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 hidden group-hover:block z-20">
        <div className="bg-bg-elevated border border-border rounded px-2 py-1 whitespace-nowrap shadow-lg">
          <p className="text-2xs text-text-primary font-medium">{analyst.name}</p>
          <p className="text-2xs text-text-muted capitalize">{analyst.activeSection}</p>
        </div>
      </div>
    </div>
  );
}

interface AnalystPresenceProps {
  analysts: OnlineAnalyst[];
  className?: string;
}

export const AnalystPresence = memo(function AnalystPresence({
  analysts,
  className,
}: AnalystPresenceProps) {
  if (!analysts.length) return null;

  return (
    <div className={cn("flex items-center gap-1.5", className)}>
      <span className="text-2xs text-text-muted">Viewing:</span>
      <div className="flex items-center -space-x-1.5">
        {analysts.slice(0, 5).map((a) => (
          <AnalystAvatar key={a.id} analyst={a} />
        ))}
        {analysts.length > 5 && (
          <div className="w-6 h-6 rounded-full bg-bg-elevated border border-border flex items-center justify-center text-2xs text-text-muted">
            +{analysts.length - 5}
          </div>
        )}
      </div>
    </div>
  );
});
