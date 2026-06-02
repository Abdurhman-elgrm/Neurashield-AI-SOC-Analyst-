import { useState } from "react";
import ReactMarkdown from "react-markdown";
import { formatDistanceToNowStrict } from "date-fns";
import {
  Brain, ChevronDown, ChevronRight, AlertTriangle, CheckCircle,
  Target, Activity, Lightbulb, Server, TrendingUp,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import type { AIAnalysis, SuspiciousEntity, DetectedBehavior, InvestigationVerdict } from "../../types/investigation";

// ─── Confidence bar ───────────────────────────────────────────────────────────

function ConfidenceBar({ value, className }: { value: number; className?: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className={cn("flex-1 h-1.5 bg-bg-elevated rounded-full overflow-hidden", className)}>
        <div
          className={cn(
            "h-full rounded-full transition-all",
            value >= 80 ? "bg-severity-critical" :
            value >= 60 ? "bg-severity-high" :
            value >= 40 ? "bg-severity-medium" :
            "bg-text-muted"
          )}
          style={{ width: `${value}%` }}
        />
      </div>
      <span className="text-2xs text-text-muted tabular-nums w-8 text-right">{value}%</span>
    </div>
  );
}

// ─── Collapsible section ──────────────────────────────────────────────────────

function Section({
  icon, title, defaultOpen = true, children,
}: {
  icon: React.ReactNode;
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border-b border-border last:border-0">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-bg-subtle transition-colors"
      >
        <div className="flex items-center gap-2 text-xs font-medium text-text-secondary">
          <span className="text-accent">{icon}</span>
          {title}
        </div>
        {open ? <ChevronDown className="w-3.5 h-3.5 text-text-muted" /> : <ChevronRight className="w-3.5 h-3.5 text-text-muted" />}
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

// ─── Verdict display ──────────────────────────────────────────────────────────

const VERDICT_STYLES: Record<InvestigationVerdict, { bg: string; border: string; text: string }> = {
  true_positive:  { bg: "bg-severity-critical/10", border: "border-severity-critical/20", text: "text-severity-critical" },
  false_positive: { bg: "bg-status-online/10",     border: "border-status-online/20",     text: "text-status-online" },
  benign:         { bg: "bg-bg-subtle",             border: "border-border",               text: "text-text-muted" },
  inconclusive:   { bg: "bg-severity-medium/10",   border: "border-severity-medium/20",   text: "text-severity-medium" },
  pending:        { bg: "bg-bg-subtle",             border: "border-border",               text: "text-text-muted" },
};

// ─── Suspicious entity row ────────────────────────────────────────────────────

const ENTITY_ICON: Record<SuspiciousEntity["type"], React.ReactNode> = {
  host:    <Server className="w-3 h-3" />,
  user:    <Target className="w-3 h-3" />,
  ip:      <Activity className="w-3 h-3" />,
  process: <Activity className="w-3 h-3" />,
  file:    <Activity className="w-3 h-3" />,
  domain:  <Activity className="w-3 h-3" />,
};

function EntityRow({ entity }: { entity: SuspiciousEntity }) {
  return (
    <div className="flex items-center gap-2 py-1.5 border-b border-border last:border-0">
      <span className="text-text-muted flex-shrink-0">{ENTITY_ICON[entity.type]}</span>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-mono text-text-primary truncate">{entity.value}</p>
        <p className="text-2xs text-text-muted truncate">{entity.reason}</p>
      </div>
      <div className="flex-shrink-0 w-16">
        <ConfidenceBar value={entity.riskScore} />
      </div>
    </div>
  );
}

// ─── Behavior row ─────────────────────────────────────────────────────────────

function BehaviorRow({ b }: { b: DetectedBehavior }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-border rounded-md overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 px-2 py-2 hover:bg-bg-elevated transition-colors text-left"
      >
        <span className={cn(
          "w-2 h-2 rounded-full flex-shrink-0",
          b.severity === "critical" ? "bg-severity-critical" :
          b.severity === "high"     ? "bg-severity-high" :
          b.severity === "medium"   ? "bg-severity-medium" :
          "bg-severity-low"
        )} />
        <span className="flex-1 text-xs text-text-primary truncate">{b.name}</span>
        {b.techniqueId && (
          <span className="text-2xs font-mono text-accent">{b.techniqueId}</span>
        )}
        <span className="text-2xs text-text-muted">{b.confidence}%</span>
        {open ? <ChevronDown className="w-3 h-3 text-text-muted" /> : <ChevronRight className="w-3 h-3 text-text-muted" />}
      </button>
      {open && (
        <div className="px-2 pb-2 text-2xs text-text-muted border-t border-border pt-2">
          {b.description}
        </div>
      )}
    </div>
  );
}

// ─── AIInvestigationPanel ─────────────────────────────────────────────────────

interface AIInvestigationPanelProps {
  analysis?: AIAnalysis;
  isLoading?: boolean;
}

export function AIInvestigationPanel({ analysis, isLoading }: AIInvestigationPanelProps) {
  if (isLoading) {
    return (
      <div className="p-4 space-y-4">
        <SkeletonText lines={3} />
        <SkeletonText lines={5} />
        <SkeletonText lines={4} />
      </div>
    );
  }

  if (!analysis) {
    return (
      <EmptyState
        icon={<Brain className="w-6 h-6" />}
        title="Pending AI analysis"
        description="The AI investigator will analyze this investigation automatically."
        className="py-8"
      />
    );
  }

  const verdictStyle = VERDICT_STYLES[analysis.verdict];

  return (
    <div className="flex flex-col overflow-y-auto">
      {/* Verdict + risk score */}
      <div className={cn("mx-4 mt-4 mb-0 p-3 rounded-lg border", verdictStyle.bg, verdictStyle.border)}>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-1.5">
            {analysis.verdict === "true_positive" ? (
              <AlertTriangle className={cn("w-4 h-4", verdictStyle.text)} />
            ) : (
              <CheckCircle className={cn("w-4 h-4", verdictStyle.text)} />
            )}
            <span className={cn("text-sm font-semibold capitalize", verdictStyle.text)}>
              {analysis.verdict.replace(/_/g, " ")}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <TrendingUp className="w-3.5 h-3.5 text-text-muted" />
            <span className="text-xs text-text-muted">Risk: {analysis.riskScore}</span>
          </div>
        </div>
        <ConfidenceBar value={analysis.confidence} />
        <p className="text-2xs text-text-muted mt-1.5">
          Analyzed {formatDistanceToNowStrict(new Date(analysis.analyzedAt), { addSuffix: true })}
        </p>
      </div>

      {/* AI Reasoning */}
      {analysis.reasoning && (
        <Section icon={<Brain className="w-3.5 h-3.5" />} title="AI Reasoning">
          <div className="prose prose-invert prose-xs max-w-none text-text-secondary">
            <ReactMarkdown
              components={{
                p: ({ children }) => <p className="text-xs text-text-secondary mb-2 leading-relaxed">{children}</p>,
                ul: ({ children }) => <ul className="text-xs text-text-muted list-disc pl-4 space-y-0.5 mb-2">{children}</ul>,
                li: ({ children }) => <li>{children}</li>,
                strong: ({ children }) => <strong className="text-text-primary font-medium">{children}</strong>,
                code: ({ children }) => <code className="px-1 py-0.5 bg-bg-elevated rounded text-2xs font-mono text-accent">{children}</code>,
              }}
            >
              {analysis.reasoning}
            </ReactMarkdown>
          </div>
        </Section>
      )}

      {/* Attack chain */}
      {analysis.attackChain && (
        <Section icon={<Activity className="w-3.5 h-3.5" />} title="Attack Chain" defaultOpen={false}>
          <p className="text-xs text-text-secondary leading-relaxed">{analysis.attackChain}</p>
        </Section>
      )}

      {/* Suspicious entities */}
      {analysis.suspiciousEntities.length > 0 && (
        <Section icon={<Target className="w-3.5 h-3.5" />} title={`Suspicious Entities (${analysis.suspiciousEntities.length})`}>
          <div>
            {analysis.suspiciousEntities.map((e, i) => (
              <EntityRow key={i} entity={e} />
            ))}
          </div>
        </Section>
      )}

      {/* Detected behaviors */}
      {analysis.detectedBehaviors.length > 0 && (
        <Section icon={<AlertTriangle className="w-3.5 h-3.5" />} title={`Behaviors (${analysis.detectedBehaviors.length})`}>
          <div className="space-y-1">
            {analysis.detectedBehaviors.map((b) => (
              <BehaviorRow key={b.id} b={b} />
            ))}
          </div>
        </Section>
      )}

      {/* Recommended actions */}
      {analysis.recommendedActions.length > 0 && (
        <Section icon={<Lightbulb className="w-3.5 h-3.5" />} title="Recommended Actions" defaultOpen={false}>
          <ul className="space-y-1.5">
            {analysis.recommendedActions.map((action, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-text-secondary">
                <span className="text-accent font-medium mt-0.5 flex-shrink-0">{i + 1}.</span>
                {action}
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
