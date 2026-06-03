import { forwardRef, type ButtonHTMLAttributes } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  [
    "inline-flex items-center justify-center gap-1.5",
    "whitespace-nowrap font-medium",
    "transition-all duration-[120ms] ease-out",
    "focus:outline-none focus:ring-1 focus:ring-blue-500/40 focus:ring-offset-0",
    "disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none",
    "select-none active:scale-[0.98]",
  ].join(" "),
  {
    variants: {
      variant: {
        primary: [
          "bg-blue-600 text-white",
          "border border-blue-500/20",
          "hover:bg-blue-500",
          "hover:shadow-[0_0_18px_rgba(59,130,246,0.22)]",
        ].join(" "),

        secondary: [
          "bg-[#111111] text-[#B8C0CC]",
          "border border-white/[0.08]",
          "hover:bg-[#161616] hover:text-[#F5F7FA]",
          "hover:border-white/[0.13]",
        ].join(" "),

        ghost: [
          "bg-transparent text-[#8B95A7]",
          "border border-transparent",
          "hover:bg-white/[0.04] hover:text-[#F5F7FA]",
        ].join(" "),

        danger: [
          "bg-red-500/10 text-red-300",
          "border border-red-500/20",
          "hover:bg-red-500/[0.16] hover:border-red-500/30",
        ].join(" "),

        outline: [
          "bg-transparent text-[#B8C0CC]",
          "border border-white/[0.09]",
          "hover:text-[#F5F7FA] hover:border-white/[0.17]",
          "hover:bg-white/[0.03]",
        ].join(" "),

        link: [
          "bg-transparent border-0 p-0 h-auto",
          "text-blue-400 hover:text-blue-300",
          "underline-offset-4 hover:underline",
        ].join(" "),
      },

      size: {
        xs:       "h-[26px] px-2.5 text-[10px] tracking-[0.02em] rounded-[4px]",
        sm:       "h-[30px] px-3   text-[11px] tracking-[0.01em] rounded-[5px]",
        md:       "h-[34px] px-4   text-[12px] tracking-[0.01em] rounded-[5px]",
        lg:       "h-[38px] px-5   text-[13px]                   rounded-[6px]",
        icon:     "h-[32px] w-[32px] p-0 rounded-[5px]",
        "icon-sm":"h-[28px] w-[28px] p-0 rounded-[4px]",
      },
    },
    defaultVariants: {
      variant: "secondary",
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
            <span className="w-3 h-3 border border-current/30 border-t-current rounded-full animate-spin" />
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
