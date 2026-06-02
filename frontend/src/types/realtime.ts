// ─── WebSocket connection states ──────────────────────────────────────────────

export type WSConnectionState =
  | "connecting"
  | "connected"
  | "reconnecting"
  | "disconnected"
  | "error";

// ─── Realtime event envelope (v=2 from Phase 3.5 backend) ────────────────────

export interface RealtimeEvent<P = Record<string, unknown>> {
  v: 2;
  event_id: string;
  event_type: RealtimeEventType;
  tenant_id: string;
  actor_id: string;
  channel: RealtimeChannel;
  timestamp: string;
  payload: P;
}

// ─── Event types ──────────────────────────────────────────────────────────────

export type RealtimeEventType =
  | "alert.created"
  | "alert.updated"
  | "investigation.created"
  | "investigation.updated"
  | "investigation.assigned"
  | "investigation.verdict_changed"
  | "investigation.status_updated"
  | "investigation.note_added"
  | "note.created"
  | "note.updated"
  | "evidence.added"
  | "case.merged"
  | "case.closed"
  | "analyst.joined"
  | "analyst.left"
  | "analyst.typing"
  | "hunt.completed"
  | "ping"
  | "pong"
  | "error"
  | "subscribed"
  | "unsubscribed"
  | "welcome"
  | "lock.acquired"
  | "lock.denied"
  | "lock.released"
  | "lock.not_owned";

// ─── Channels ─────────────────────────────────────────────────────────────────

export type RealtimeChannel =
  | "alerts"
  | "investigations"
  | "cases"
  | "activity"
  | "hunts"
  | "presence";

export const ALL_CHANNELS: RealtimeChannel[] = [
  "alerts",
  "investigations",
  "cases",
  "activity",
  "hunts",
  "presence",
];

// ─── Client → server messages ─────────────────────────────────────────────────

export type ClientMessageType =
  | "subscribe"
  | "unsubscribe"
  | "heartbeat"
  | "typing"
  | "set_investigation"
  | "acquire_lock"
  | "release_lock"
  | "pong";

export interface ClientMessage {
  type: ClientMessageType;
  channel?: RealtimeChannel;
  investigation_id?: string;
  workspace?: string;
  lock_id?: string;
}

// ─── Welcome payload ──────────────────────────────────────────────────────────

export interface WelcomePayload {
  analyst_id: string;
  tenant_id: string;
  available_channels: RealtimeChannel[];
  online_analysts: number;
  server_time: string;
}

// ─── Presence state ───────────────────────────────────────────────────────────

export interface PresenceState {
  analyst_id: string;
  tenant_id: string;
  display_name: string;
  workspace: string;
  investigation_id: string | null;
  idle: boolean;
  last_seen: string;
}

// ─── Event payload types ──────────────────────────────────────────────────────

export interface AlertCreatedPayload {
  alert_id: string;
  severity: string;
  title: string;
  source_host: string | null;
  status: string;
  created_at: string | null;
}

export interface InvestigationCreatedPayload {
  investigation_id: string;
  threat_score: number;
  confidence: string;
  status: string;
}

export interface AnalystJoinedPayload {
  analyst_id: string;
  display_name: string;
  workspace: string;
}

export interface AnalystTypingPayload {
  analyst_id: string;
  investigation_id: string;
}

export interface LockPayload {
  investigation_id: string;
  owner_id?: string;
  locked_at?: string;
  expires_at?: string;
  error?: string;
  released?: boolean;
}

// ─── Typed event handler ──────────────────────────────────────────────────────

export type RealtimeEventHandler<P = Record<string, unknown>> = (
  event: RealtimeEvent<P>
) => void;
