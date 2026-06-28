import { apiClient } from "@/api/client";
import type { APIResponse } from "@/types/api";
import type {
  Alert,
  AlertContext,
  AlertRiskContext,
  AlertSeverity,
  AlertStatus,
  AlertListParams,
  AlertListResponse,
  AlertTimelineEvent,
  BulkActionPayload,
  BulkActionResult,
  MitreAttack,
} from "@/features/alerts/types";

// ─── MITRE tactic name → ATT&CK ID ───────────────────────────────────────────

const TACTIC_IDS: Record<string, string> = {
  "Initial Access":        "TA0001",
  "Execution":             "TA0002",
  "Persistence":           "TA0003",
  "Privilege Escalation":  "TA0004",
  "Defense Evasion":       "TA0005",
  "Credential Access":     "TA0006",
  "Discovery":             "TA0007",
  "Lateral Movement":      "TA0008",
  "Collection":            "TA0009",
  "Exfiltration":          "TA0010",
  "Command and Control":   "TA0011",
  "Impact":                "TA0040",
};

// ─── Backend → Frontend adapter ───────────────────────────────────────────────

 
function _adaptMitre(raw: Record<string, any>): MitreAttack | undefined {
  const techniques: string[] = Array.isArray(raw.mitre_techniques) ? raw.mitre_techniques : [];
  const tactics: string[]    = Array.isArray(raw.mitre_tactics)    ? raw.mitre_tactics    : [];
  if (!techniques.length && !tactics.length) return undefined;
  const tacticName = tactics[0] ?? "";
  return {
    techniqueId:   techniques[0] ?? "",
    techniqueName: techniques.slice(1).join(", ") || techniques[0] || "",
    tacticId:      TACTIC_IDS[tacticName] ?? "",
    tacticName,
  };
}


function _severityToVerdict(s: string | undefined): "true_positive" | "benign" | "pending" {
  if (s === "malicious" || s === "suspicious") return "true_positive";
  if (s === "benign") return "benign";
  return "pending";
}

function _adaptAiVerdict(ai: Record<string, any> | null | undefined) {
  if (!ai) return undefined;
  // New format has `verdict`; old stored records only have `severity_assessment`
  const verdict = (ai.verdict ?? _severityToVerdict(ai.severity_assessment)) as
    "true_positive" | "false_positive" | "benign" | "pending";
  // New format stores confidence as 0-100; old format stored 0-1
  const rawConf = Number(ai.confidence ?? ai.confidence_score ?? 0);
  const confidence = rawConf <= 1 ? Math.round(rawConf * 100) : rawConf;
  return {
    verdict,
    confidence,
    reasoning:  ai.reasoning ?? ai.explanation ?? ai.summary ?? undefined,
    analyzedAt: ai.analyzed_at ?? ai.analyzedAt ?? undefined,
  };
}

 
function _adaptRiskContext(evidence: Record<string, any> | undefined | null): AlertRiskContext | undefined {
  const rc = evidence?.risk_context;
  if (!rc) return undefined;
  return {
    ruleSeverity:      String(rc.rule_base_severity ?? ""),
    finalSeverity:     String(rc.final_severity ?? ""),
    severityEscalated: Boolean(rc.severity_escalated),
    escalationReasons: Array.isArray(rc.escalation_reasons) ? rc.escalation_reasons : [],
    uebaScore:         Number(rc.ueba_score ?? 0),
    uebaFlags:         Array.isArray(rc.ueba_flags) ? rc.ueba_flags : [],
    isThreatIp:        Boolean(rc.is_threat_ip),
    abuseConfidence:   Number(rc.abuse_confidence ?? 0),
    threatIntelFlags:  Array.isArray(rc.threat_intel_flags) ? rc.threat_intel_flags : [],
  };
}

 
function adaptAlert(raw: Record<string, any>): Alert {
  const ev = (raw.evidence ?? {}) as Record<string, unknown>;
  const evUser    = (ev.user    ?? {}) as Record<string, string>;
  const evNetwork = (ev.network ?? {}) as Record<string, string>;

  // Rule name: prefer backend-sent field, then evidence.rule_name, then extract from title
  const rawTitle: string = String(raw.title ?? "");
  const ruleNameFallback = rawTitle.includes(" — ")
    ? rawTitle.split(" — ")[0]
    : rawTitle;

  return {
    id:               String(raw.id ?? ""),
    tenantId:         String(raw.tenant_id ?? ""),
    ruleId:           String(raw.rule_id ?? ""),
    ruleName:         String(raw.rule_name ?? (ev.rule_name as string) ?? ruleNameFallback),
    title:            rawTitle,
    description:      String(raw.description ?? ""),
    severity:         (raw.severity as AlertSeverity) ?? "low",
    status:           (raw.status as AlertStatus) ?? "open",
    hostname:         String(raw.source_host ?? raw.hostname ?? (ev.hostname as string) ?? ""),
    sourceIp:         (evNetwork.src_ip || raw.source_ip) ? String(evNetwork.src_ip || raw.source_ip) : undefined,
    username:         (evUser.name || evUser.username || raw.username)
                        ? String(evUser.name || evUser.username || raw.username)
                        : undefined,
    processName:      raw.process_name
                        ? String(raw.process_name)
                        : (ev.process as Record<string, string> | undefined)?.name ?? undefined,
    mitre:            _adaptMitre(raw),
    correlationId:    raw.correlation_id ? String(raw.correlation_id) : undefined,
    correlationScore: raw.correlation_score != null ? Number(raw.correlation_score) : undefined,
    assignedTo:       raw.assignee_id   ? String(raw.assignee_id)   : undefined,
    assignedToName:   raw.assignee_name ? String(raw.assignee_name) : undefined,
    aiVerdict:        _adaptAiVerdict(raw.ai_analysis),
    tags:             Array.isArray(raw.tags) ? (raw.tags as string[]) : [],
    rawEventCount:    Number(raw.raw_event_count ?? (ev.threshold_count as number) ?? 1),
    firstSeenAt:      String(raw.first_seen_at ?? (ev.event_timestamp as string) ?? raw.created_at ?? ""),
    lastSeenAt:       String(raw.last_seen_at ?? raw.updated_at ?? ""),
    createdAt:        String(raw.created_at ?? ""),
    updatedAt:        String(raw.updated_at ?? ""),
    acknowledgedAt:   raw.acknowledged_at ? String(raw.acknowledged_at) : undefined,
    closedAt:         raw.closed_at ? String(raw.closed_at) : undefined,
    notes:            raw.notes ? String(raw.notes) : undefined,
    riskContext:      _adaptRiskContext(raw.evidence),
  };
}

// ─── List alerts (paginated, filterable) ──────────────────────────────────────

export async function getAlerts(params: AlertListParams): Promise<AlertListResponse> {
  const { data } = await apiClient.get<any>("/alerts", {
    params: {
      limit: params.pageSize ?? 50,
      ...(params.status?.length   && { status:    params.status.join(",") }),
      ...(params.severity?.length && { severity:  params.severity.join(",") }),
      ...(params.hostname         && { source_host: params.hostname }),
      ...(params.search           && { search:    params.search }),
      ...(params.cursor           && { cursor:    params.cursor }),
      ...(params.fromTs           && { from_ts:   params.fromTs }),
      ...(params.toTs             && { to_ts:     params.toTs }),
    },
  });

  // Backend returns PaginatedResponse: { data: [...items], pagination: { next_cursor, has_more, limit }, meta: {...} }
  const items: Alert[] = (data.data ?? []).map(adaptAlert);
  const pagination = data.pagination ?? {};

  return {
    items,
    total:     items.length,
    page:      1,
    pageSize:  params.pageSize ?? 50,
    pageCount: pagination.has_more ? 2 : 1,
    nextCursor: pagination.next_cursor ?? undefined,
  } as AlertListResponse & { nextCursor?: string };
}

// ─── Single alert detail ──────────────────────────────────────────────────────

export async function getAlertDetail(alertId: string): Promise<Alert> {
   
  const { data } = await apiClient.get<APIResponse<any>>(`/alerts/${alertId}`);
  return adaptAlert(data.data!);
}

// ─── Update alert status / notes / assignee ───────────────────────────────────

export async function updateAlert(
  alertId: string,
  payload: { status?: string; notes?: string; assigneeId?: string }
): Promise<Alert> {
   
  const { data } = await apiClient.patch<APIResponse<any>>(`/alerts/${alertId}`, {
    ...(payload.status !== undefined && { status: payload.status }),
    ...(payload.notes !== undefined && { notes: payload.notes }),
    ...(payload.assigneeId !== undefined && { assignee_id: payload.assigneeId }),
  });
  return adaptAlert(data.data!);
}

// ─── Alert investigation context & timeline ───────────────────────────────────

export async function getAlertContext(alertId: string): Promise<AlertContext> {
  try {
     
    const { data } = await apiClient.get<APIResponse<any>>(`/alerts/${alertId}/context`);
    const d = data.data!;
    return {
      alertId,
      relatedAlerts:  (d.relatedAlerts ?? []).map(adaptAlert),
      investigation:  d.investigation ?? undefined,
    };
  } catch {
    return { alertId, relatedAlerts: [] };
  }
}

export async function getAlertTimeline(alertId: string): Promise<AlertTimelineEvent[]> {
  try {
     
    const { data } = await apiClient.get<APIResponse<any[]>>(`/alerts/${alertId}/timeline`);
     
    return (data.data ?? []).map((ev: any) => ({
      id:        String(ev.id ?? ""),
      alertId:   String(ev.alertId ?? alertId),
      eventType: ev.eventType as AlertTimelineEvent["eventType"],
      actorId:   ev.actorId   ? String(ev.actorId)   : undefined,
      actorName: ev.actorName ? String(ev.actorName) : undefined,
      details:   ev.details   ?? undefined,
      createdAt: String(ev.createdAt ?? ""),
    }));
  } catch {
    return [];
  }
}

// ─── Bulk operations ──────────────────────────────────────────────────────────

export async function bulkUpdateAlerts(
  payload: BulkActionPayload
): Promise<BulkActionResult> {
  const { data } = await apiClient.post<APIResponse<BulkActionResult>>(
    "/alerts/bulk",
    {
      alert_ids: payload.alertIds,
      action: payload.action,
      ...(payload.assignTo && { assign_to: payload.assignTo }),
      ...(payload.tag && { tag: payload.tag }),
      ...(payload.severity && { severity: payload.severity }),
    }
  );
  return data.data!;
}

// ─── Alert status summary (single call replaces 4 per-status count queries) ──

export interface AlertsSummary {
  open: number;
  acknowledged: number;
  closed: number;
  false_positive: number;
}

export async function getAlertsSummary(): Promise<AlertsSummary> {
  try {
     
    const { data } = await apiClient.get<any>("/alerts/summary");
    const d = data?.data ?? data;
    return {
      open:           Number(d?.open           ?? 0),
      acknowledged:   Number(d?.acknowledged   ?? 0),
      closed:         Number(d?.closed         ?? 0),
      false_positive: Number(d?.false_positive ?? 0),
    };
  } catch {
    // Backend endpoint not yet implemented — return zeros gracefully
    return { open: 0, acknowledged: 0, closed: 0, false_positive: 0 };
  }
}

// ─── Placeholder data ─────────────────────────────────────────────────────────

export const PLACEHOLDER_ALERT_LIST: AlertListResponse = {
  items: [],
  total: 0,
  page: 1,
  pageSize: 50,
  pageCount: 0,
};
