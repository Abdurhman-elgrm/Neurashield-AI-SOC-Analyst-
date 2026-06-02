import type {
  ClientMessage,
  RealtimeChannel,
  RealtimeEvent,
  RealtimeEventHandler,
  RealtimeEventType,
  WSConnectionState,
} from "@/types/realtime";

const PING_INTERVAL_MS = 20_000;   // 20s — under server's 25s threshold
const PONG_TIMEOUT_MS  = 10_000;   // 10s grace to receive pong back
const BASE_BACKOFF_MS  = 1_000;
const MAX_BACKOFF_MS   = 30_000;
const MAX_RECONNECT    = 12;

type AnyHandler = RealtimeEventHandler<Record<string, unknown>>;

// ─── WSManager ────────────────────────────────────────────────────────────────

export class WSManager {
  private ws: WebSocket | null = null;
  private state: WSConnectionState = "disconnected";

  private token: string = "";
  private tenantId: string = "";

  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private pongTimer: ReturnType<typeof setTimeout> | null = null;

  private subscriptions: Set<RealtimeChannel> = new Set();
  // eventType → Set<handler>
  private handlers: Map<string, Set<AnyHandler>> = new Map();
  // state change listener
  private stateListeners: Set<(s: WSConnectionState) => void> = new Set();

  private stopped = false;

  // ── Public API ─────────────────────────────────────────────────────────────

  connect(token: string, tenantId: string): void {
    this.stopped = false;
    this.token = token;
    this.tenantId = tenantId;
    this._open();
  }

  disconnect(): void {
    this.stopped = true;
    this._cleanup();
    this._setState("disconnected");
  }

  subscribe(channel: RealtimeChannel): void {
    this.subscriptions.add(channel);
    if (this.state === "connected") {
      this._send({ type: "subscribe", channel });
    }
  }

  unsubscribe(channel: RealtimeChannel): void {
    this.subscriptions.delete(channel);
    if (this.state === "connected") {
      this._send({ type: "unsubscribe", channel });
    }
  }

  on<P = Record<string, unknown>>(
    eventType: RealtimeEventType | "state_change",
    handler: RealtimeEventHandler<P>
  ): () => void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, new Set());
    }
    this.handlers.get(eventType)!.add(handler as AnyHandler);
    return () => this.off(eventType, handler as AnyHandler);
  }

  off(eventType: string, handler: AnyHandler): void {
    this.handlers.get(eventType)?.delete(handler);
  }

  onStateChange(listener: (s: WSConnectionState) => void): () => void {
    this.stateListeners.add(listener);
    listener(this.state); // immediate sync
    return () => this.stateListeners.delete(listener);
  }

  getState(): WSConnectionState {
    return this.state;
  }

  setInvestigation(investigationId: string | null): void {
    if (this.state !== "connected") return;
    this._send({ type: "set_investigation", investigation_id: investigationId ?? undefined });
  }

  sendTyping(investigationId: string): void {
    if (this.state !== "connected") return;
    this._send({ type: "typing", investigation_id: investigationId });
  }

  sendHeartbeat(workspace?: string): void {
    if (this.state !== "connected") return;
    this._send({ type: "heartbeat", workspace });
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  private _open(): void {
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.close();
      this.ws = null;
    }

    this._setState("connecting");

    const base = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000";
    const url = `${base}/ws/realtime?token=${encodeURIComponent(this.token)}&tenant_id=${encodeURIComponent(this.tenantId)}`;

    try {
      this.ws = new WebSocket(url);
    } catch {
      this._scheduleReconnect();
      return;
    }

    this.ws.onopen = () => this._onOpen();
    this.ws.onmessage = (e) => this._onMessage(e);
    this.ws.onclose = (e) => this._onClose(e);
    this.ws.onerror = () => this._onError();
  }

  private _onOpen(): void {
    this.reconnectAttempts = 0;
    this._setState("connected");
    // Re-subscribe to all channels after reconnect
    for (const ch of this.subscriptions) {
      this._send({ type: "subscribe", channel: ch });
    }
    this._startPing();
  }

  private _onMessage(e: MessageEvent): void {
    let event: RealtimeEvent;
    try {
      event = JSON.parse(e.data as string) as RealtimeEvent;
    } catch {
      return;
    }

    // Handle ping from server → reply pong
    if (event.event_type === "ping") {
      this._send({ type: "pong" });
      return;
    }

    // Clear pong timeout if we get any message (server is alive)
    if (this.pongTimer) {
      clearTimeout(this.pongTimer);
      this.pongTimer = null;
    }

    this._emit(event.event_type, event);
    // Also emit to wildcard listeners
    this._emit("*", event);
  }

  private _onClose(e: CloseEvent): void {
    this._stopPing();
    // 4001 = unauthorized, 4003 = forbidden — don't reconnect
    if (e.code === 4001 || e.code === 4003) {
      this._setState("error");
      return;
    }
    if (!this.stopped) {
      this._scheduleReconnect();
    }
  }

  private _onError(): void {
    // onclose will follow immediately — let it handle reconnect
  }

  private _scheduleReconnect(): void {
    if (this.reconnectAttempts >= MAX_RECONNECT) {
      this._setState("error");
      return;
    }
    this._setState("reconnecting");
    const delay = Math.min(
      BASE_BACKOFF_MS * 2 ** this.reconnectAttempts,
      MAX_BACKOFF_MS
    );
    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      if (!this.stopped) this._open();
    }, delay);
  }

  private _startPing(): void {
    this._stopPing();
    this.pingTimer = setInterval(() => {
      if (this.state !== "connected") return;
      // We track liveness via the server's own ping; this is a client-side heartbeat
      this._send({ type: "heartbeat" });
      // Set a pong deadline — if no message within PONG_TIMEOUT_MS, reconnect
      this.pongTimer = setTimeout(() => {
        this.ws?.close();
      }, PONG_TIMEOUT_MS);
    }, PING_INTERVAL_MS);
  }

  private _stopPing(): void {
    if (this.pingTimer) { clearInterval(this.pingTimer); this.pingTimer = null; }
    if (this.pongTimer) { clearTimeout(this.pongTimer); this.pongTimer = null; }
  }

  private _cleanup(): void {
    this._stopPing();
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      try { this.ws.close(); } catch { /* ignore */ }
      this.ws = null;
    }
  }

  private _send(msg: ClientMessage): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  private _emit(eventType: string, event: RealtimeEvent): void {
    const set = this.handlers.get(eventType);
    if (!set) return;
    for (const h of set) {
      try { h(event); } catch { /* isolate handler errors */ }
    }
  }

  private _setState(state: WSConnectionState): void {
    this.state = state;
    for (const listener of this.stateListeners) {
      try { listener(state); } catch { /* ignore */ }
    }
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────
export const wsManager = new WSManager();
