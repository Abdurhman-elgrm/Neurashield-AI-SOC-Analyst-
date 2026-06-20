import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNowStrict, format } from "date-fns";
import {
  Shield, Monitor, User, Globe, Brain, Link2, Clock, Tag,
  AlertTriangle, CheckCircle, XCircle, BarChart2, Send,
  ExternalLink, ChevronRight, FolderSearch, RotateCcw, Eye,
} from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { promoteAlert } from "@/features/investigations/api/investigationsApi";
import { updateAlert } from "@/services/alertsApi";
import { cn } from "@/lib/utils";
import { Drawer } from "@/components/ui/Drawer";
import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useAlertDetail, useAlertContext, useAlertTimeline } from "../hooks/useAlerts";
import { alertsKeys } from "../hooks/useAlerts";
import type { Alert, AlertRiskContext, AlertTimelineEvent, AIVerdictType, AlertStatus } from "../types";

// ─── Status display ───────────────────────────────────────────────────────────

const STATUS_VARIANT: Record<AlertStatus, "default" | "primary" | "success" | "info"> = {
  open:           "default",
  acknowledged:   "primary",
  closed:         "success",
  false_positive: "info",
};
const STATUS_LABEL: Record<AlertStatus, string> = {
  open: "Open", acknowledged: "Acknowledged", closed: "Closed", false_positive: "False Positive",
};

// ─── AI verdict display ───────────────────────────────────────────────────────

const VERDICT_ICON: Record<AIVerdictType, React.ReactNode> = {
  true_positive:  <AlertTriangle className="w-4 h-4 text-severity-critical" />,
  false_positive: <CheckCircle className="w-4 h-4 text-status-online" />,
  benign:         <CheckCircle className="w-4 h-4 text-text-muted" />,
  pending:        <Brain className="w-4 h-4 text-severity-medium" />,
};
const VERDICT_LABEL: Record<AIVerdictType, string> = {
  true_positive: "True Positive", false_positive: "False Positive",
  benign: "Benign", pending: "Pending Analysis",
};

// ─── Section: Overview ────────────────────────────────────────────────────────

function OverviewSection({ alert }: { alert: Alert }) {
  return (
    <div className="space-y-4">
      {/* Description */}
      <div className="bg-bg-subtle rounded-lg p-3">
        <p className="text-sm text-text-secondary leading-relaxed">{alert.description}</p>
      </div>

      {/* Key attributes grid */}
      <div className="grid grid-cols-2 gap-x-6 gap-y-3">
        <Attr icon={<Shield className="w-3.5 h-3.5" />} label="Severity">
          <SeverityBadge severity={alert.severity} />
        </Attr>
        <Attr icon={<Clock className="w-3.5 h-3.5" />} label="Status">
          <Badge variant={STATUS_VARIANT[alert.status]}>{STATUS_LABEL[alert.status]}</Badge>
        </Attr>
        <Attr icon={<Monitor className="w-3.5 h-3.5" />} label="Hostname">
          <span className="text-xs font-mono text-text-secondary">{alert.hostname || "—"}</span>
        </Attr>
        <Attr icon={<User className="w-3.5 h-3.5" />} label="Username">
          <span className="text-xs text-text-secondary">{alert.username || "—"}</span>
        </Attr>
        <Attr icon={<Globe className="w-3.5 h-3.5" />} label="Source IP">
          <span className="text-xs font-mono text-text-secondary">{alert.sourceIp || "—"}</span>
        </Attr>
        <Attr icon={<BarChart2 className="w-3.5 h-3.5" />} label="Raw Events">
          <span className="text-xs text-text-secondary tabular-nums">{alert.rawEventCount}</span>
        </Attr>
        <Attr icon={<Clock className="w-3.5 h-3.5" />} label="First Seen">
          <span className="text-xs text-text-muted">
            {formatDistanceToNowStrict(new Date(alert.firstSeenAt), { addSuffix: true })}
          </span>
        </Attr>
        <Attr icon={<Clock className="w-3.5 h-3.5" />} label="Last Seen">
          <span className="text-xs text-text-muted">
            {formatDistanceToNowStrict(new Date(alert.lastSeenAt), { addSuffix: true })}
          </span>
        </Attr>
      </div>

      {/* MITRE */}
      {alert.mitre && (
        <div className="border border-border rounded-lg p-3 space-y-1">
          <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">MITRE ATT&amp;CK</p>
          <div className="flex flex-wrap gap-2 mt-1.5">
            <span className="px-2 py-0.5 text-xs font-mono bg-accent/10 text-accent border border-accent/20 rounded">
              {alert.mitre.techniqueId}
            </span>
            <span className="text-sm text-text-secondary">{alert.mitre.techniqueName}</span>
          </div>
          <p className="text-xs text-text-muted">{alert.mitre.tacticName} ({alert.mitre.tacticId})</p>
        </div>
      )}

      {/* Tags */}
      {alert.tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {alert.tags.map((tag) => (
            <span
              key={tag}
              className="flex items-center gap-1 px-2 py-0.5 text-xs bg-bg-elevated text-text-muted border border-border rounded-full"
            >
              <Tag className="w-3 h-3" />
              {tag}
            </span>
          ))}
        </div>
      )}

      {/* Risk Context */}
      {alert.riskContext && <RiskContextCard rc={alert.riskContext} />}
    </div>
  );
}

// ─── Risk Context Card ────────────────────────────────────────────────────────

const ESCALATION_REASON_LABEL: Record<string, string> = {
  threat_ip_confirmed_malicious: "Confirmed malicious IP (AbuseIPDB ≥ 75)",
  threat_ip_suspicious:          "Suspicious IP (AbuseIPDB ≥ 25 or threat feed hit)",
  ueba_strong_anomaly:           "Strong behavioral anomaly (UEBA ≥ 0.80)",
  ueba_moderate_anomaly:         "Moderate behavioral anomaly (UEBA ≥ 0.60)",
  compound_threat_intel_and_ueba:"Compound: threat IP + behavioral anomaly",
  critical_attack_chain_detected:"Critical attack chain detected (floored to HIGH)",
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-severity-critical",
  high:     "text-severity-high",
  medium:   "text-severity-medium",
  low:      "text-severity-low",
  info:     "text-text-muted",
};

function RiskContextCard({ rc }: { rc: AlertRiskContext }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between px-3 py-2 bg-bg-elevated hover:bg-bg-subtle transition-colors text-left"
      >
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-accent" />
          <span className="text-xs font-medium text-text-primary">Risk Assessment</span>
          {rc.severityEscalated && (
            <span className="px-1.5 py-0.5 text-2xs font-semibold bg-severity-critical/15 text-severity-critical border border-severity-critical/25 rounded">
              ESCALATED
            </span>
          )}
        </div>
        <ChevronRight
          className={cn(
            "w-3.5 h-3.5 text-text-muted transition-transform duration-150",
            expanded && "rotate-90"
          )}
        />
      </button>

      {expanded && (
        <div className="px-3 py-3 space-y-3 border-t border-border bg-bg-subtle/50">
          {/* Severity delta */}
          <div className="flex items-center gap-3 text-xs">
            <div className="space-y-0.5">
              <p className="text-2xs text-text-muted uppercase tracking-wider">Rule Severity</p>
              <span className={cn("font-semibold capitalize", SEVERITY_COLOR[rc.ruleSeverity])}>
                {rc.ruleSeverity}
              </span>
            </div>
            {rc.severityEscalated && (
              <>
                <ChevronRight className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                <div className="space-y-0.5">
                  <p className="text-2xs text-text-muted uppercase tracking-wider">Final Severity</p>
                  <span className={cn("font-semibold capitalize", SEVERITY_COLOR[rc.finalSeverity])}>
                    {rc.finalSeverity}
                  </span>
                </div>
              </>
            )}
          </div>

          {/* Escalation reasons */}
          {rc.escalationReasons.length > 0 && (
            <div className="space-y-1">
              <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">
                Escalation Reasons
              </p>
              <ul className="space-y-1">
                {rc.escalationReasons.map((r) => (
                  <li key={r} className="flex items-start gap-1.5 text-xs text-text-secondary">
                    <span className="mt-0.5 w-1.5 h-1.5 rounded-full bg-severity-critical flex-shrink-0" />
                    {ESCALATION_REASON_LABEL[r] ?? r.replace(/_/g, " ")}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* UEBA */}
          {(rc.uebaScore > 0 || rc.uebaFlags.length > 0) && (
            <div className="space-y-1">
              <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">UEBA</p>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 bg-bg-elevated rounded-full overflow-hidden">
                  <div
                    className={cn(
                      "h-full rounded-full",
                      rc.uebaScore >= 0.8 ? "bg-severity-critical" :
                      rc.uebaScore >= 0.6 ? "bg-severity-high" :
                      rc.uebaScore >= 0.4 ? "bg-severity-medium" : "bg-severity-low"
                    )}
                    style={{ width: `${Math.round(rc.uebaScore * 100)}%` }}
                  />
                </div>
                <span className="text-xs font-mono text-text-secondary w-10 text-right">
                  {Math.round(rc.uebaScore * 100)}%
                </span>
              </div>
              {rc.uebaFlags.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {rc.uebaFlags.map((f) => (
                    <span key={f} className="px-1.5 py-0.5 text-2xs font-mono bg-severity-high/10 text-severity-high border border-severity-high/20 rounded">
                      {f}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Threat Intel */}
          {(rc.isThreatIp || rc.abuseConfidence > 0 || rc.threatIntelFlags.length > 0) && (
            <div className="space-y-1">
              <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">Threat Intel</p>
              <div className="flex items-center gap-3 text-xs text-text-secondary">
                {rc.isThreatIp && (
                  <span className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-severity-critical" />
                    Threat IP
                  </span>
                )}
                {rc.abuseConfidence > 0 && (
                  <span>AbuseIPDB: <span className="font-mono font-semibold">{rc.abuseConfidence}%</span></span>
                )}
              </div>
              {rc.threatIntelFlags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {rc.threatIntelFlags.map((f) => (
                    <span key={f} className="px-1.5 py-0.5 text-2xs font-mono bg-severity-critical/10 text-severity-critical border border-severity-critical/20 rounded">
                      {f}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Section: Investigation Context ──────────────────────────────────────────

function InvestigationSection({
  alertId,
  correlationId,
}: {
  alertId: string;
  correlationId?: string;
}) {
  const navigate  = useNavigate();
  const qc        = useQueryClient();
  const { data: ctx, isLoading } = useAlertContext(alertId);

  const promote = useMutation({
    mutationFn: () => promoteAlert(alertId),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["investigations"] });
      navigate(`/investigations/${res.investigation_id}`);
    },
  });

  if (isLoading) return <SkeletonText lines={6} />;

  return (
    <div className="space-y-4">
      {/* Linked investigation */}
      {ctx?.investigation ? (
        <div className="border border-border rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-text-primary flex items-center gap-1.5">
              <Link2 className="w-3.5 h-3.5 text-accent" />
              Linked Investigation
            </p>
            <button
              onClick={() => navigate(`/investigations/${ctx.investigation!.id}`)}
              className="flex items-center gap-1 text-xs text-accent hover:underline"
            >
              Open <ExternalLink className="w-3 h-3" />
            </button>
          </div>
          <p className="text-sm text-text-secondary">{ctx.investigation.title}</p>
          <div className="flex gap-3 text-xs text-text-muted">
            <span>{ctx.investigation.alertCount} alerts</span>
            <span>•</span>
            <span className="capitalize">{ctx.investigation.status}</span>
          </div>
        </div>
      ) : correlationId ? (
        <div className="text-xs text-text-muted bg-bg-subtle p-3 rounded-lg">
          Part of correlation group <span className="font-mono text-accent">{correlationId}</span>
        </div>
      ) : (
        <div>
          <EmptyState
            icon={<Link2 className="w-5 h-5" />}
            title="No investigation linked"
            description="This alert hasn't been correlated yet."
            className="py-4"
          />
          <div className="flex justify-center mt-2">
            <button
              onClick={() => promote.mutate()}
              disabled={promote.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition-colors"
              style={{
                background: "#0f2744",
                border: "1px solid rgba(59,130,246,0.35)",
                color: "#93C5FD",
                cursor: promote.isPending ? "not-allowed" : "pointer",
                opacity: promote.isPending ? 0.6 : 1,
              }}
            >
              <FolderSearch className="w-3.5 h-3.5" />
              {promote.isPending ? "Promoting…" : "Promote to Investigation"}
            </button>
          </div>
        </div>
      )}

      {/* Related alerts */}
      {(ctx?.relatedAlerts ?? []).length > 0 && (
        <div className="space-y-1">
          <p className="text-2xs text-text-muted uppercase tracking-wider font-medium mb-2">
            Related Alerts ({ctx!.relatedAlerts.length})
          </p>
          {ctx!.relatedAlerts.slice(0, 5).map((a: Alert) => (
            <div
              key={a.id}
              className="flex items-center gap-2 py-1.5 border-b border-border last:border-0"
            >
              <SeverityBadge severity={a.severity} />
              <span className="flex-1 text-xs text-text-secondary truncate">{a.title}</span>
              <span className="text-2xs text-text-muted flex-shrink-0">
                {formatDistanceToNowStrict(new Date(a.createdAt), { addSuffix: true })}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Section: Timeline ────────────────────────────────────────────────────────

const TIMELINE_ICONS: Record<string, React.ReactNode> = {
  alert_created:         <AlertTriangle className="w-3 h-3" />,
  status_changed:        <ChevronRight className="w-3 h-3" />,
  assigned:              <User className="w-3 h-3" />,
  note_added:            <Send className="w-3 h-3" />,
  ai_analyzed:           <Brain className="w-3 h-3" />,
  investigation_linked:  <Link2 className="w-3 h-3" />,
  tag_added:             <Tag className="w-3 h-3" />,
  tag_removed:           <Tag className="w-3 h-3" />,
  severity_changed:      <Shield className="w-3 h-3" />,
};

function TimelineEvent({ event }: { event: AlertTimelineEvent }) {
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center flex-shrink-0">
        <div className="w-6 h-6 rounded-full bg-bg-elevated border border-border flex items-center justify-center text-text-muted">
          {TIMELINE_ICONS[event.eventType] ?? <Clock className="w-3 h-3" />}
        </div>
        <div className="w-px flex-1 bg-border mt-1" />
      </div>
      <div className="flex-1 pb-4 min-w-0">
        <div className="flex items-start justify-between gap-2">
          <div>
            <p className="text-xs text-text-primary capitalize">
              {event.eventType.replace(/_/g, " ")}
            </p>
            {event.actorName && (
              <p className="text-2xs text-text-muted">by {event.actorName}</p>
            )}
            {typeof event.details.note === "string" && (
              <p className="mt-1 text-xs text-text-secondary bg-bg-subtle rounded p-2">
                {event.details.note}
              </p>
            )}
          </div>
          <span className="text-2xs text-text-muted flex-shrink-0">
            {format(new Date(event.createdAt), "MMM d, HH:mm")}
          </span>
        </div>
      </div>
    </div>
  );
}

function TimelineSection({ alertId }: { alertId: string }) {
  const { data: events, isLoading } = useAlertTimeline(alertId);

  if (isLoading) return <SkeletonText lines={8} />;
  if (!events?.length)
    return (
      <EmptyState
        icon={<Clock className="w-5 h-5" />}
        title="No timeline events"
        description="Events will appear here as the alert progresses."
        className="py-8"
      />
    );

  return (
    <div className="space-y-0">
      {events.map((e: AlertTimelineEvent) => (
        <TimelineEvent key={e.id} event={e} />
      ))}
    </div>
  );
}

// ─── Section: AI Analysis ─────────────────────────────────────────────────────

function AISection({ alert }: { alert: Alert }) {
  const verdict = alert.aiVerdict;

  if (!verdict || verdict.verdict === "pending") {
    return (
      <div className="space-y-3">
        <div className="flex items-center gap-2 p-3 bg-severity-medium/10 border border-severity-medium/20 rounded-lg">
          <Brain className="w-4 h-4 text-severity-medium flex-shrink-0" />
          <p className="text-sm text-severity-medium">
            {verdict ? "AI analysis in progress..." : "Not yet analyzed by AI"}
          </p>
        </div>
        <p className="text-xs text-text-muted">
          The AI investigator will automatically analyze this alert and provide a verdict.
        </p>
      </div>
    );
  }

  const isTP = verdict.verdict === "true_positive";

  return (
    <div className="space-y-4">
      {/* Verdict card */}
      <div
        className={cn(
          "p-4 rounded-lg border",
          isTP
            ? "bg-severity-critical/10 border-severity-critical/20"
            : verdict.verdict === "false_positive"
            ? "bg-status-online/10 border-status-online/20"
            : "bg-bg-subtle border-border"
        )}
      >
        <div className="flex items-center gap-2 mb-2">
          {VERDICT_ICON[verdict.verdict]}
          <span className="text-sm font-semibold text-text-primary">
            {VERDICT_LABEL[verdict.verdict]}
          </span>
          <span className="ml-auto text-xs text-text-muted">
            {verdict.confidence}% confidence
          </span>
        </div>
        <div className="h-1.5 bg-bg-elevated rounded-full overflow-hidden">
          <div
            className={cn(
              "h-full rounded-full",
              isTP ? "bg-severity-critical" : "bg-status-online"
            )}
            style={{ width: `${verdict.confidence}%` }}
          />
        </div>
        {verdict.analyzedAt && (
          <p className="text-2xs text-text-muted mt-2">
            Analyzed {formatDistanceToNowStrict(new Date(verdict.analyzedAt), { addSuffix: true })}
          </p>
        )}
      </div>

      {/* Reasoning */}
      {verdict.reasoning && (
        <div className="space-y-1.5">
          <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">AI Reasoning</p>
          <div className="bg-bg-subtle rounded-lg p-3 border border-border">
            <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap">
              {verdict.reasoning}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Section: Analyst ─────────────────────────────────────────────────────────

function AnalystSection({ alert }: { alert: Alert }) {
  const [note, setNote] = useState(alert.notes ?? "");
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: (payload: { status?: string; notes?: string }) =>
      updateAlert(alert.id, payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: alertsKeys.detail(alert.id) });
      void qc.invalidateQueries({ queryKey: alertsKeys.lists() });
      void qc.invalidateQueries({ queryKey: ["alerts", "count"] });
    },
  });

  const changeStatus = (status: string) => mutation.mutate({ status });
  const saveNote = () => {
    if (note.trim() !== (alert.notes ?? "")) {
      mutation.mutate({ notes: note.trim() });
    }
  };

  const isLoading = mutation.isPending;
  const status    = alert.status;

  return (
    <div className="space-y-4">
      {/* Status actions */}
      <div className="border border-border rounded-lg p-3 space-y-3">
        <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">
          Status Actions
        </p>

        <div className="flex items-center gap-2 mb-2">
          <Badge variant={STATUS_VARIANT[status]}>{STATUS_LABEL[status]}</Badge>
        </div>

        <div className="flex flex-wrap gap-2">
          {status === "open" && (
            <ActionBtn
              icon={<Eye className="w-3.5 h-3.5" />}
              label="Acknowledge"
              color="amber"
              disabled={isLoading}
              onClick={() => changeStatus("acknowledged")}
            />
          )}
          {(status === "open" || status === "acknowledged") && (
            <>
              <ActionBtn
                icon={<CheckCircle className="w-3.5 h-3.5" />}
                label="Close"
                color="green"
                disabled={isLoading}
                onClick={() => changeStatus("closed")}
              />
              <ActionBtn
                icon={<XCircle className="w-3.5 h-3.5" />}
                label="False Positive"
                color="blue"
                disabled={isLoading}
                onClick={() => changeStatus("false_positive")}
              />
            </>
          )}
          {(status === "closed" || status === "false_positive" || status === "acknowledged") && (
            <ActionBtn
              icon={<RotateCcw className="w-3.5 h-3.5" />}
              label="Reopen"
              color="red"
              disabled={isLoading}
              onClick={() => changeStatus("open")}
            />
          )}
        </div>

        {mutation.isError && (
          <p className="text-xs text-severity-critical">
            Failed to update. Please try again.
          </p>
        )}
        {mutation.isSuccess && (
          <p className="text-xs text-status-online">Saved.</p>
        )}
      </div>

      {/* Assignment */}
      <div className="border border-border rounded-lg p-3 space-y-2">
        <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">Assignment</p>
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-full bg-accent/20 flex items-center justify-center">
            <User className="w-3.5 h-3.5 text-accent" />
          </div>
          <span className="text-sm text-text-secondary">
            {alert.assignedToName ?? "Unassigned"}
          </span>
        </div>
      </div>

      {/* Notes */}
      <div className="border border-border rounded-lg p-3 space-y-2">
        <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">Analyst Notes</p>
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          onBlur={saveNote}
          placeholder="Add analyst notes..."
          rows={4}
          className="w-full px-3 py-2 text-sm bg-bg-elevated border border-border rounded-md text-text-primary placeholder:text-text-muted resize-none focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <button
          onClick={saveNote}
          disabled={isLoading || note.trim() === (alert.notes ?? "")}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-accent text-white rounded-md hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <Send className="w-3 h-3" />
          Save Note
        </button>
      </div>
    </div>
  );
}

// ─── Action button helper ─────────────────────────────────────────────────────

function ActionBtn({
  icon, label, color, disabled, onClick,
}: {
  icon: React.ReactNode;
  label: string;
  color: "amber" | "green" | "blue" | "red";
  disabled?: boolean;
  onClick: () => void;
}) {
  const colors = {
    amber: "border-amber-500/40 text-amber-400 hover:bg-amber-500/10",
    green: "border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10",
    blue:  "border-blue-500/40 text-blue-400 hover:bg-blue-500/10",
    red:   "border-red-500/40 text-red-400 hover:bg-red-500/10",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-md border transition-colors",
        "disabled:opacity-40 disabled:cursor-not-allowed",
        colors[color]
      )}
    >
      {icon}
      {label}
    </button>
  );
}

// ─── Attribute helper ─────────────────────────────────────────────────────────

function Attr({
  icon, label, children,
}: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-0.5">
      <div className="flex items-center gap-1 text-2xs text-text-muted">
        {icon}
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}

// ─── AlertDrawer ──────────────────────────────────────────────────────────────

interface AlertDrawerProps {
  alertId: string | null;
  onClose: () => void;
}

const TABS = [
  { id: "overview",        label: "Overview" },
  { id: "investigation",   label: "Context" },
  { id: "timeline",        label: "Timeline" },
  { id: "ai",              label: "AI Analysis" },
  { id: "analyst",         label: "Analyst" },
] as const;

export function AlertDrawer({ alertId, onClose }: AlertDrawerProps) {
  const [activeTab, setActiveTab] = useState<string>("overview");
  const prevAlertId = useRef<string | null>(null);

  // Reset to overview tab when opening a new alert
  if (alertId && alertId !== prevAlertId.current) {
    prevAlertId.current = alertId;
    if (activeTab !== "overview") setActiveTab("overview");
  }

  const { data: alert, isLoading } = useAlertDetail(alertId);

  return (
    <Drawer
      open={!!alertId}
      onClose={onClose}
      width="w-[580px]"
      title={isLoading ? "Loading..." : (alert?.title ?? "Alert Detail")}
      description={alert ? `Rule: ${alert.ruleName}` : undefined}
    >
      {isLoading || !alert ? (
        <div className="p-4 space-y-4">
          <SkeletonText lines={3} />
          <SkeletonText lines={6} />
        </div>
      ) : (
        <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col h-full">
          <TabsList className="px-4 flex-shrink-0">
            {TABS.map((tab) => (
              <TabsTrigger key={tab.id} value={tab.id}>
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>

          <div className="flex-1 overflow-y-auto px-4 py-4">
            <TabsContent value="overview">
              <OverviewSection alert={alert} />
            </TabsContent>
            <TabsContent value="investigation">
              <InvestigationSection
                alertId={alert.id}
                correlationId={alert.correlationId}
              />
            </TabsContent>
            <TabsContent value="timeline">
              <TimelineSection alertId={alert.id} />
            </TabsContent>
            <TabsContent value="ai">
              <AISection alert={alert} />
            </TabsContent>
            <TabsContent value="analyst">
              <AnalystSection alert={alert} />
            </TabsContent>
          </div>
        </Tabs>
      )}
    </Drawer>
  );
}
