import { useEffect } from "react";
import { useUIStore } from "@/stores/uiStore";

/**
 * Registers global keyboard shortcuts. Rendered once inside AppShell.
 * Returns null — this is a side-effect-only component.
 */
export function KeyboardShortcuts(): null {
  const toggleCommandPalette = useUIStore((s) => s.toggleCommandPalette);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Cmd+K / Ctrl+K → command palette
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        toggleCommandPalette();
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [toggleCommandPalette]);

  return null;
}

/**
 * Registers a single keyboard shortcut with an arbitrary callback.
 */
export function useKeyboard(
  key: string,
  handler: (e: KeyboardEvent) => void,
  options: { meta?: boolean; ctrl?: boolean; shift?: boolean; alt?: boolean } = {}
) {
  useEffect(() => {
    const listener = (e: KeyboardEvent) => {
      if (options.meta !== undefined && e.metaKey !== options.meta) return;
      if (options.ctrl !== undefined && e.ctrlKey !== options.ctrl) return;
      if (options.shift !== undefined && e.shiftKey !== options.shift) return;
      if (options.alt !== undefined && e.altKey !== options.alt) return;
      if (e.key === key) handler(e);
    };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, [key, handler, options.meta, options.ctrl, options.shift, options.alt]);
}
