import { createContext, useContext, useEffect, useRef, type ReactNode } from "react";
import { wsManager, WSManager } from "./WSManager";
import { useAuthStore } from "@/stores/authStore";
import { useRealtimeStore } from "@/stores/realtimeStore";
import type { RealtimeEvent, WelcomePayload, AnalystJoinedPayload } from "@/types/realtime";
import { ALL_CHANNELS } from "@/types/realtime";

const WSContext = createContext<WSManager>(wsManager);

export function useWSManager(): WSManager {
  return useContext(WSContext);
}

// ─── WSProvider ───────────────────────────────────────────────────────────────

interface WSProviderProps {
  children: ReactNode;
}

export function WSProvider({ children }: WSProviderProps) {
  const accessToken = useAuthStore((s) => s.accessToken);
  const activeTenantId = useAuthStore((s) => s.activeTenantId);
  const { setConnectionState, setOnlineCount, addOnlineAnalyst, removeOnlineAnalyst } =
    useRealtimeStore();

  const connectedRef = useRef(false);

  // Connect / disconnect on auth state change
  useEffect(() => {
    if (!accessToken || !activeTenantId) {
      if (connectedRef.current) {
        wsManager.disconnect();
        connectedRef.current = false;
        setConnectionState("disconnected");
      }
      return;
    }

    wsManager.connect(accessToken, activeTenantId);
    connectedRef.current = true;

    // Subscribe to all channels
    for (const ch of ALL_CHANNELS) {
      wsManager.subscribe(ch);
    }

    // Track connection state
    const offState = wsManager.onStateChange(setConnectionState);

    // Handle welcome
    const offWelcome = wsManager.on<WelcomePayload>("welcome", (event) => {
      setOnlineCount(event.payload.online_analysts);
    });

    // Handle analyst presence
    const offJoined = wsManager.on<AnalystJoinedPayload>("analyst.joined", (event) => {
      addOnlineAnalyst({
        analyst_id: event.payload.analyst_id,
        tenant_id: event.tenant_id,
        display_name: event.payload.display_name,
        workspace: event.payload.workspace,
        investigation_id: null,
        idle: false,
        last_seen: event.timestamp,
      });
    });

    const offLeft = wsManager.on("analyst.left", (event) => {
      removeOnlineAnalyst((event as RealtimeEvent<{ analyst_id: string }>).payload.analyst_id);
    });

    return () => {
      offState();
      offWelcome();
      offJoined();
      offLeft();
    };
  }, [accessToken, activeTenantId]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      wsManager.disconnect();
    };
  }, []);

  return <WSContext.Provider value={wsManager}>{children}</WSContext.Provider>;
}
