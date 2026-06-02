import * as RadixTabs from "@radix-ui/react-tabs";
import { cn } from "@/lib/utils";

export const Tabs = RadixTabs.Root;

export function TabsList({ className, ...props }: RadixTabs.TabsListProps) {
  return (
    <RadixTabs.List
      className={cn(
        "flex items-center gap-0.5 border-b border-border",
        className
      )}
      {...props}
    />
  );
}

export function TabsTrigger({ className, ...props }: RadixTabs.TabsTriggerProps) {
  return (
    <RadixTabs.Trigger
      className={cn(
        "px-3 py-2 text-sm font-medium text-text-muted transition-colors duration-150",
        "border-b-2 border-transparent -mb-px",
        "hover:text-text-secondary",
        "data-[state=active]:text-text-primary data-[state=active]:border-accent",
        "focus-ring rounded-t",
        "disabled:opacity-50 disabled:cursor-not-allowed",
        className
      )}
      {...props}
    />
  );
}

export function TabsContent({ className, ...props }: RadixTabs.TabsContentProps) {
  return (
    <RadixTabs.Content
      className={cn("focus-ring outline-none pt-4", className)}
      {...props}
    />
  );
}
