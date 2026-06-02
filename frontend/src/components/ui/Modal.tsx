import { type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  description?: string;
  children: ReactNode;
  size?: "sm" | "md" | "lg" | "xl" | "full";
  showClose?: boolean;
  className?: string;
}

const SIZE_CLASSES: Record<NonNullable<ModalProps["size"]>, string> = {
  sm:   "max-w-sm",
  md:   "max-w-md",
  lg:   "max-w-lg",
  xl:   "max-w-2xl",
  full: "max-w-[95vw] h-[90vh]",
};

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  size = "md",
  showClose = true,
  className,
}: ModalProps) {
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
                transition={{ duration: 0.15 }}
                className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
              />
            </Dialog.Overlay>

            <Dialog.Content asChild>
              <motion.div
                initial={{ opacity: 0, scale: 0.96, y: 8 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.96, y: 8 }}
                transition={{ duration: 0.15, ease: "easeOut" }}
                className={cn(
                  "fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2",
                  "w-full bg-bg-surface border border-border rounded-xl shadow-panel",
                  "flex flex-col max-h-[90vh] overflow-hidden",
                  SIZE_CLASSES[size],
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

export function ModalBody({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-5 py-4", className)} {...props} />;
}

export function ModalFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
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
