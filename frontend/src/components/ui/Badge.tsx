import { type HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
import type { AlertSeverity } from "@/types/alerts";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium",
  {
    variants: {
      variant: {
        default:   "bg-bg-elevated text-text-secondary border border-border",
        primary:   "bg-primary-500/15 text-primary-300 border border-primary-500/30",
        critical:  "bg-severity-critical/10 text-severity-critical border border-severity-critical/20",
        high:      "bg-severity-high/10 text-severity-high border border-severity-high/20",
        medium:    "bg-severity-medium/10 text-severity-medium border border-severity-medium/20",
        low:       "bg-severity-low/10 text-severity-low border border-severity-low/20",
        info:      "bg-bg-subtle text-text-muted border border-border",
        success:   "bg-status-online/10 text-status-online border border-status-online/20",
        warning:   "bg-severity-medium/10 text-severity-medium border border-severity-medium/20",
        error:     "bg-severity-critical/10 text-severity-critical border border-severity-critical/20",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {
  dot?: boolean;
}

export function Badge({ className, variant, dot, children, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props}>
      {dot && (
        <span
          className={cn(
            "w-1.5 h-1.5 rounded-full flex-shrink-0",
            variant === "critical" && "bg-severity-critical",
            variant === "high" && "bg-severity-high",
            variant === "medium" && "bg-severity-medium",
            variant === "low" && "bg-severity-low",
            variant === "success" && "bg-status-online",
            (!variant || variant === "default" || variant === "info") && "bg-text-muted",
          )}
        />
      )}
      {children}
    </span>
  );
}

// Convenience: severity → badge variant
const SEVERITY_VARIANT: Record<AlertSeverity, VariantProps<typeof badgeVariants>["variant"]> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

export function SeverityBadge({
  severity,
  ...props
}: { severity: AlertSeverity } & Omit<BadgeProps, "variant">) {
  return (
    <Badge variant={SEVERITY_VARIANT[severity]} dot {...props}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </Badge>
  );
}
