import { useEffect } from "react";
import { useWSManager } from "@/websocket/WSProvider";
import type { RealtimeEventType } from "@/types/realtime";

type EventHandler<P> = (payload: P, event: { tenant_id: string; timestamp: string }) => void;

/**
 * Subscribe to a typed realtime event for the lifetime of the component.
 * Returns a cleanup function automatically via useEffect.
 */
export function useRealtime<P = unknown>(
  eventType: RealtimeEventType | "welcome",
  handler: EventHandler<P>,
  deps: unknown[] = []
): void {
  const ws = useWSManager();

  useEffect(() => {
    const off = ws.on<P>(eventType, (event) => {
      handler(
        (event as { payload: P; tenant_id: string; timestamp: string }).payload,
        {
          tenant_id: (event as { tenant_id: string }).tenant_id,
          timestamp: (event as { timestamp: string }).timestamp,
        }
      );
    });
    return off;
     
  }, [ws, eventType, ...deps]);
}
