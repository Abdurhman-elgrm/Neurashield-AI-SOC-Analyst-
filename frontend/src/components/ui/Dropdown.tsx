import * as RadixDropdown from "@radix-ui/react-dropdown-menu";
import { Check, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

export const DropdownMenu = RadixDropdown.Root;
export const DropdownMenuTrigger = RadixDropdown.Trigger;
export const DropdownMenuGroup = RadixDropdown.Group;
export const DropdownMenuSub = RadixDropdown.Sub;
export const DropdownMenuRadioGroup = RadixDropdown.RadioGroup;

export function DropdownMenuContent({
  className,
  sideOffset = 6,
  align = "start",
  ...props
}: RadixDropdown.DropdownMenuContentProps) {
  return (
    <RadixDropdown.Portal>
      <RadixDropdown.Content
        sideOffset={sideOffset}
        align={align}
        className={cn(
          "z-50 min-w-[10rem] overflow-hidden rounded-lg border border-border bg-bg-elevated shadow-elevated",
          "data-[state=open]:animate-fade-in data-[state=closed]:animate-fade-in",
          "p-1",
          className
        )}
        {...props}
      />
    </RadixDropdown.Portal>
  );
}

export function DropdownMenuItem({
  className,
  inset,
  ...props
}: RadixDropdown.DropdownMenuItemProps & { inset?: boolean }) {
  return (
    <RadixDropdown.Item
      className={cn(
        "relative flex cursor-pointer select-none items-center gap-2 rounded px-2 py-1.5 text-sm",
        "text-text-secondary outline-none transition-colors duration-100",
        "focus:bg-bg-subtle focus:text-text-primary",
        "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
        inset && "pl-8",
        className
      )}
      {...props}
    />
  );
}

export function DropdownMenuCheckboxItem({
  className,
  children,
  checked,
  ...props
}: RadixDropdown.DropdownMenuCheckboxItemProps) {
  return (
    <RadixDropdown.CheckboxItem
      className={cn(
        "relative flex cursor-pointer select-none items-center gap-2 rounded pl-8 pr-2 py-1.5 text-sm",
        "text-text-secondary outline-none transition-colors duration-100",
        "focus:bg-bg-subtle focus:text-text-primary",
        className
      )}
      checked={checked}
      {...props}
    >
      <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
        <RadixDropdown.ItemIndicator>
          <Check className="w-3 h-3" />
        </RadixDropdown.ItemIndicator>
      </span>
      {children}
    </RadixDropdown.CheckboxItem>
  );
}

export function DropdownMenuLabel({ className, inset, ...props }: RadixDropdown.DropdownMenuLabelProps & { inset?: boolean }) {
  return (
    <RadixDropdown.Label
      className={cn(
        "px-2 py-1 text-2xs font-semibold uppercase tracking-wider text-text-muted",
        inset && "pl-8",
        className
      )}
      {...props}
    />
  );
}

export function DropdownMenuSeparator({ className, ...props }: RadixDropdown.DropdownMenuSeparatorProps) {
  return (
    <RadixDropdown.Separator
      className={cn("-mx-1 my-1 h-px bg-border", className)}
      {...props}
    />
  );
}

export function DropdownMenuSubTrigger({ className, inset, children, ...props }: RadixDropdown.DropdownMenuSubTriggerProps & { inset?: boolean }) {
  return (
    <RadixDropdown.SubTrigger
      className={cn(
        "flex cursor-default select-none items-center gap-2 rounded px-2 py-1.5 text-sm",
        "text-text-secondary outline-none transition-colors duration-100",
        "focus:bg-bg-subtle data-[state=open]:bg-bg-subtle",
        inset && "pl-8",
        className
      )}
      {...props}
    >
      {children}
      <ChevronRight className="ml-auto w-4 h-4" />
    </RadixDropdown.SubTrigger>
  );
}

export function DropdownMenuSubContent({ className, ...props }: RadixDropdown.DropdownMenuSubContentProps) {
  return (
    <RadixDropdown.SubContent
      className={cn(
        "z-50 min-w-[8rem] overflow-hidden rounded-lg border border-border bg-bg-elevated shadow-elevated p-1",
        "data-[state=open]:animate-fade-in",
        className
      )}
      {...props}
    />
  );
}
