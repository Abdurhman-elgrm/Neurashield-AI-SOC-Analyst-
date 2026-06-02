import { forwardRef } from "react";
import * as RadixCheckbox from "@radix-ui/react-checkbox";
import { Check, Minus } from "lucide-react";
import { cn } from "@/lib/utils";

export interface CheckboxProps extends RadixCheckbox.CheckboxProps {
  label?: string;
  description?: string;
  indeterminate?: boolean;
}

export const Checkbox = forwardRef<HTMLButtonElement, CheckboxProps>(
  ({ className, label, description, indeterminate, id, ...props }, ref) => {
    const checkboxId = id ?? (label ? label.toLowerCase().replace(/\s+/g, "-") : undefined);
    return (
      <div className="flex items-start gap-2.5">
        <RadixCheckbox.Root
          ref={ref}
          id={checkboxId}
          className={cn(
            "peer h-4 w-4 shrink-0 rounded border border-border bg-bg-elevated",
            "focus-ring transition-colors duration-150",
            "data-[state=checked]:bg-accent data-[state=checked]:border-accent",
            "data-[state=indeterminate]:bg-accent data-[state=indeterminate]:border-accent",
            "disabled:cursor-not-allowed disabled:opacity-50",
            className
          )}
          checked={indeterminate ? "indeterminate" : props.checked}
          {...props}
        >
          <RadixCheckbox.Indicator className="flex items-center justify-center text-white">
            {indeterminate ? (
              <Minus className="w-2.5 h-2.5" strokeWidth={3} />
            ) : (
              <Check className="w-2.5 h-2.5" strokeWidth={3} />
            )}
          </RadixCheckbox.Indicator>
        </RadixCheckbox.Root>

        {(label || description) && (
          <div className="flex flex-col">
            {label && (
              <label
                htmlFor={checkboxId}
                className="text-sm font-medium text-text-primary cursor-pointer peer-disabled:cursor-not-allowed peer-disabled:opacity-50"
              >
                {label}
              </label>
            )}
            {description && (
              <p className="text-xs text-text-muted">{description}</p>
            )}
          </div>
        )}
      </div>
    );
  }
);
Checkbox.displayName = "Checkbox";
