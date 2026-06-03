import { forwardRef, type InputHTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/utils";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
  wrapperClassName?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, label, error, hint, leftIcon, rightIcon, wrapperClassName, id, ...props }, ref) => {
    const inputId = id ?? (label ? label.toLowerCase().replace(/\s+/g, "-") : undefined);

    return (
      <div className={cn("flex flex-col gap-1", wrapperClassName)}>
        {label && (
          <label htmlFor={inputId} className="text-xs font-medium text-text-secondary">
            {label}
          </label>
        )}
        <div className="relative">
          {leftIcon && (
            <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted">
              {leftIcon}
            </span>
          )}
          <input
            id={inputId}
            ref={ref}
            className={cn(
              "w-full bg-bg-elevated border border-border rounded px-3 py-2",
              "text-sm text-text-primary placeholder:text-text-muted",
              "focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/20",
              "disabled:opacity-50 disabled:cursor-not-allowed",
              "transition-colors duration-150",
              leftIcon && "pl-8",
              rightIcon && "pr-8",
              error && "border-severity-critical focus:border-severity-critical focus:ring-severity-critical/20",
              className
            )}
            {...props}
          />
          {rightIcon && (
            <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted">
              {rightIcon}
            </span>
          )}
        </div>
        {error && <p className="text-xs text-severity-critical">{error}</p>}
        {hint && !error && <p className="text-xs text-text-muted">{hint}</p>}
      </div>
    );
  }
);
Input.displayName = "Input";

// Search input variant
export function SearchInput({
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className="relative">
      <svg
        className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={2}
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
      <input
        className={cn(
          "w-full bg-bg-elevated border border-border rounded px-3 py-1.5 pl-8",
          "text-sm text-text-primary placeholder:text-text-muted",
          "focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/20",
          "transition-colors duration-150",
          className
        )}
        {...props}
      />
    </div>
  );
}
