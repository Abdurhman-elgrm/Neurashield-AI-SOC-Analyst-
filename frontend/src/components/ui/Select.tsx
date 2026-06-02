import * as RadixSelect from "@radix-ui/react-select";
import { Check, ChevronDown, ChevronUp } from "lucide-react";
import { cn } from "@/lib/utils";


export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

// Styled primitives
export const SelectRoot = RadixSelect.Root;

export function SelectTrigger({ className, children, ...props }: RadixSelect.SelectTriggerProps) {
  return (
    <RadixSelect.Trigger
      className={cn(
        "flex h-8 w-full items-center justify-between gap-2 rounded border border-border bg-bg-elevated px-3",
        "text-sm text-text-primary placeholder:text-text-muted",
        "focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30",
        "disabled:cursor-not-allowed disabled:opacity-50",
        "transition-colors duration-150",
        className
      )}
      {...props}
    >
      {children}
      <RadixSelect.Icon asChild>
        <ChevronDown className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
      </RadixSelect.Icon>
    </RadixSelect.Trigger>
  );
}

export function SelectContent({ className, children, position = "popper", ...props }: RadixSelect.SelectContentProps) {
  return (
    <RadixSelect.Portal>
      <RadixSelect.Content
        position={position}
        className={cn(
          "relative z-50 max-h-64 min-w-[8rem] overflow-hidden rounded-lg border border-border bg-bg-elevated shadow-elevated",
          "data-[state=open]:animate-fade-in",
          position === "popper" && "translate-y-1",
          className
        )}
        {...props}
      >
        <RadixSelect.ScrollUpButton className="flex items-center justify-center py-1">
          <ChevronUp className="w-3.5 h-3.5 text-text-muted" />
        </RadixSelect.ScrollUpButton>
        <RadixSelect.Viewport className="p-1">{children}</RadixSelect.Viewport>
        <RadixSelect.ScrollDownButton className="flex items-center justify-center py-1">
          <ChevronDown className="w-3.5 h-3.5 text-text-muted" />
        </RadixSelect.ScrollDownButton>
      </RadixSelect.Content>
    </RadixSelect.Portal>
  );
}

export function SelectItem({ className, children, ...props }: RadixSelect.SelectItemProps) {
  return (
    <RadixSelect.Item
      className={cn(
        "relative flex cursor-pointer select-none items-center gap-2 rounded pl-8 pr-3 py-1.5 text-sm",
        "text-text-secondary outline-none transition-colors duration-100",
        "focus:bg-bg-subtle focus:text-text-primary",
        "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
        className
      )}
      {...props}
    >
      <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
        <RadixSelect.ItemIndicator>
          <Check className="w-3 h-3 text-accent" />
        </RadixSelect.ItemIndicator>
      </span>
      <RadixSelect.ItemText>{children}</RadixSelect.ItemText>
    </RadixSelect.Item>
  );
}

export function SelectLabel({ className, ...props }: RadixSelect.SelectLabelProps) {
  return (
    <RadixSelect.Label
      className={cn("px-2 py-1 text-2xs font-semibold uppercase tracking-wider text-text-muted", className)}
      {...props}
    />
  );
}

export function SelectSeparator({ className, ...props }: RadixSelect.SelectSeparatorProps) {
  return <RadixSelect.Separator className={cn("-mx-1 my-1 h-px bg-border", className)} {...props} />;
}

// Convenience component
export interface SelectProps {
  value?: string;
  onValueChange?: (v: string) => void;
  placeholder?: string;
  options: SelectOption[];
  disabled?: boolean;
  className?: string;
  label?: string;
}

export function Select({ value, onValueChange, placeholder, options, disabled, className, label }: SelectProps) {
  return (
    <div className="flex flex-col gap-1">
      {label && <label className="text-xs font-medium text-text-secondary">{label}</label>}
      <SelectRoot value={value} onValueChange={onValueChange} disabled={disabled}>
        <SelectTrigger className={className}>
          <RadixSelect.Value placeholder={placeholder ?? "Select…"} />
        </SelectTrigger>
        <SelectContent>
          {options.map((opt) => (
            <SelectItem key={opt.value} value={opt.value} disabled={opt.disabled}>
              {opt.label}
            </SelectItem>
          ))}
        </SelectContent>
      </SelectRoot>
    </div>
  );
}
