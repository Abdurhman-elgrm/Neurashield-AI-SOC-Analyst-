import { type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

export type DrawerSide = "left" | "right" | "top" | "bottom";

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  description?: string;
  children: ReactNode;
  side?: DrawerSide;
  width?: string;
  showClose?: boolean;
  className?: string;
}

type SlideTarget = { x?: string | number; y?: string | number };
const SLIDE_VARIANTS: Record<DrawerSide, { hidden: SlideTarget; visible: SlideTarget }> = {
  right:  { hidden: { x: "100%" }, visible: { x: 0 } },
  left:   { hidden: { x: "-100%" }, visible: { x: 0 } },
  top:    { hidden: { y: "-100%" }, visible: { y: 0 } },
  bottom: { hidden: { y: "100%" }, visible: { y: 0 } },
};

const POSITION_CLASSES: Record<DrawerSide, string> = {
  right:  "right-0 top-0 h-full",
  left:   "left-0 top-0 h-full",
  top:    "top-0 left-0 w-full",
  bottom: "bottom-0 left-0 w-full",
};

export function Drawer({
  open,
  onClose,
  title,
  description,
  children,
  side = "right",
  width = "w-[480px]",
  showClose = true,
  className,
}: DrawerProps) {
  const variants = SLIDE_VARIANTS[side];

  return (
    <Dialog.Root open={open} onOpenChange={(v) => !v && onClose()}>
      <AnimatePresence>
        {open && (
          <Dialog.Portal forceMount>
            <Dialog.Overlay asChild>
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
              />
            </Dialog.Overlay>

            <Dialog.Content asChild>
              <motion.div
                initial={variants.hidden}
                animate={variants.visible}
                exit={variants.hidden}
                transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                className={cn(
                  "fixed z-50 bg-bg-surface border-border flex flex-col overflow-hidden shadow-panel",
                  POSITION_CLASSES[side],
                  (side === "left" || side === "right") && [width, "border-l"],
                  (side === "top" || side === "bottom") && "border-b h-auto max-h-[80vh]",
                  side === "left" && "border-r border-l-0",
                  className
                )}
              >
                {(title || showClose) && (
                  <div className="flex items-center justify-between px-5 py-4 border-b border-border flex-shrink-0">
                    <div>
                      {title && (
                        <Dialog.Title className="text-sm font-semibold text-text-primary">
                          {title}
                        </Dialog.Title>
                      )}
                      {description && (
                        <Dialog.Description className="text-xs text-text-secondary mt-0.5">
                          {description}
                        </Dialog.Description>
                      )}
                    </div>
                    {showClose && (
                      <Dialog.Close className="text-text-muted hover:text-text-primary transition-colors rounded focus-ring">
                        <X className="w-4 h-4" />
                      </Dialog.Close>
                    )}
                  </div>
                )}
                <div className="flex-1 overflow-y-auto">{children}</div>
              </motion.div>
            </Dialog.Content>
          </Dialog.Portal>
        )}
      </AnimatePresence>
    </Dialog.Root>
  );
}

export function DrawerBody({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-5 py-4", className)} {...props} />;
}

export function DrawerFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "flex items-center justify-end gap-2 px-5 py-4 border-t border-border flex-shrink-0",
        className
      )}
      {...props}
    />
  );
}
