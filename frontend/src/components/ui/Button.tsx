import { forwardRef, type ButtonHTMLAttributes } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded font-medium transition-colors duration-150 focus-ring disabled:opacity-50 disabled:cursor-not-allowed select-none",
  {
    variants: {
      variant: {
        primary:   "bg-accent hover:bg-accent-hover text-white",
        secondary: "bg-bg-elevated hover:bg-bg-subtle text-text-primary border border-border",
        ghost:     "hover:bg-bg-subtle text-text-secondary hover:text-text-primary",
        danger:    "bg-severity-critical hover:opacity-90 text-white",
        outline:   "border border-border text-text-secondary hover:border-border-strong hover:text-text-primary",
        link:      "text-accent hover:text-accent-hover underline-offset-4 hover:underline p-0 h-auto",
      },
      size: {
        xs: "h-6 px-2 text-xs",
        sm: "h-7 px-3 text-sm",
        md: "h-8 px-4 text-sm",
        lg: "h-10 px-5 text-base",
        icon: "h-8 w-8 p-0",
        "icon-sm": "h-7 w-7 p-0",
      },
    },
    defaultVariants: {
      variant: "primary",
      size: "md",
    },
  }
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, loading, children, disabled, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size }), className)}
        ref={ref}
        disabled={disabled || loading}
        {...props}
      >
        {loading ? (
          <>
            <span className="w-3.5 h-3.5 border-2 border-current/30 border-t-current rounded-full animate-spin" />
            {children}
          </>
        ) : (
          children
        )}
      </Comp>
    );
  }
);
Button.displayName = "Button";

export { buttonVariants };
