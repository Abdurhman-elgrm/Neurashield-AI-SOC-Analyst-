import * as RadixTooltip from "@radix-ui/react-tooltip";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export const TooltipProvider = RadixTooltip.Provider;
export const TooltipRoot = RadixTooltip.Root;
export const TooltipTrigger = RadixTooltip.Trigger;

export function TooltipContent({ className, sideOffset = 6, ...props }: RadixTooltip.TooltipContentProps) {
  return (
    <RadixTooltip.Portal>
      <RadixTooltip.Content
        sideOffset={sideOffset}
        className={cn(
          "z-50 overflow-hidden rounded px-2.5 py-1.5 text-xs",
          "bg-bg-elevated border border-border text-text-primary shadow-elevated",
          "animate-fade-in",
          className
        )}
        {...props}
      />
    </RadixTooltip.Portal>
  );
}

// Convenience wrapper
export interface TooltipProps {
  content: ReactNode;
  children: ReactNode;
  side?: RadixTooltip.TooltipContentProps["side"];
  delayDuration?: number;
  className?: string;
}

export function Tooltip({ content, children, side = "top", delayDuration = 400, className }: TooltipProps) {
  return (
    <TooltipProvider delayDuration={delayDuration}>
      <TooltipRoot>
        <TooltipTrigger asChild>{children}</TooltipTrigger>
        <TooltipContent side={side} className={className}>
          {content}
        </TooltipContent>
      </TooltipRoot>
    </TooltipProvider>
  );
}
