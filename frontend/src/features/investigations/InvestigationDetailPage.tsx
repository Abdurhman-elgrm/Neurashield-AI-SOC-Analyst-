import { useState, useRef, useCallback, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, Brain, PanelLeft, PanelRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { SkeletonText } from "@/components/ui/Skeleton";

import { InvestigationHeader } from "./components/InvestigationHeader";
import { InvestigationTimeline } from "./components/timeline/InvestigationTimeline";
import { AIInvestigationPanel } from "./components/ai/AIInvestigationPanel";
import { InvestigationGraphPreview } from "./components/graph/InvestigationGraphPreview";
import { EvidencePanel } from "./components/evidence/EvidencePanel";
import { ProcessTree } from "./components/process/ProcessTree";
import { MitreContext } from "./components/mitre/MitreContext";
import { RelatedAlerts } from "./components/RelatedAlerts";
import { ActivityFeed } from "./components/collaboration/ActivityFeed";
import { InvestigationNotes } from "./components/collaboration/InvestigationNotes";
import { AnalystPresence } from "./components/collaboration/AnalystPresence";

import { useInvestigation } from "./hooks/useInvestigation";
import { useRealtimeInvestigation } from "./hooks/useRealtimeInvestigation";

// ─── Panel size persistence ───────────────────────────────────────────────────

const STORAGE_KEY = "inv-panel-sizes";
const DEFAULT_SIZES = { left: 280, right: 360 };
const MIN_LEFT = 200;
const MAX_LEFT = 420;
const MIN_RIGHT = 280;
const MAX_RIGHT = 480;

function loadPanelSizes(): typeof DEFAULT_SIZES {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? (JSON.parse(stored) as typeof DEFAULT_SIZES) : DEFAULT_SIZES;
  } catch {
    return DEFAULT_SIZES;
  }
}

function savePanelSizes(sizes: typeof DEFAULT_SIZES) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(sizes));
  } catch {
    // ignore
  }
}

// ─── Drag handle ──────────────────────────────────────────────────────────────

function DragHandle({
  onDrag,
  className,
}: {
  onDrag: (delta: number) => void;
  className?: string;
}) {
  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      const startX = e.clientX;

      const onMove = (ev: MouseEvent) => onDrag(ev.clientX - startX);
      const onUp = () => {
        window.removeEventListener("mousemove", onMove);
        window.removeEventListener("mouseup", onUp);
      };

      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    },
    [onDrag]
  );

  return (
    <div
      onMouseDown={handleMouseDown}
      className={cn(
        "w-1 flex-shrink-0 cursor-col-resize group",
        "hover:bg-accent/30 active:bg-accent/50 transition-colors",
        className
      )}
    />
  );
}

// ─── InvestigationDetailPage ──────────────────────────────────────────────────

export function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const investigationId = id ?? "";

  const [panelSizes, setPanelSizes] = useState(loadPanelSizes);
  const [leftCollapsed, setLeftCollapsed] = useState(false);
  const [rightCollapsed, setRightCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");

  const leftBaseRef = useRef(panelSizes.left);
  const rightBaseRef = useRef(panelSizes.right);

  // Register realtime listeners
  useRealtimeInvestigation(investigationId);

  const { data: investigation, isLoading } = useInvestigation(investigationId);

  // Drag handlers
  const handleLeftDrag = useCallback((delta: number) => {
    const next = Math.max(MIN_LEFT, Math.min(MAX_LEFT, leftBaseRef.current + delta));
    setPanelSizes((prev) => {
      const updated = { ...prev, left: next };
      savePanelSizes(updated);
      return updated;
    });
  }, []);

  const handleRightDrag = useCallback((delta: number) => {
    const next = Math.max(MIN_RIGHT, Math.min(MAX_RIGHT, rightBaseRef.current - delta));
    setPanelSizes((prev) => {
      const updated = { ...prev, right: next };
      savePanelSizes(updated);
      return updated;
    });
  }, []);

  // Update base refs on mousedown so delta is always relative to drag start
  const updateLeftBase = useCallback(() => {
    leftBaseRef.current = panelSizes.left;
  }, [panelSizes.left]);

  const updateRightBase = useCallback(() => {
    rightBaseRef.current = panelSizes.right;
  }, [panelSizes.right]);

  // Sync base refs when sizes change externally
  useEffect(() => {
    leftBaseRef.current = panelSizes.left;
    rightBaseRef.current = panelSizes.right;
  }, [panelSizes]);

  if (!investigationId) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-text-muted">No investigation ID provided.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full -m-6 overflow-hidden">
      {/* Header */}
      <div className="flex-shrink-0">
        {/* Back nav */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-0">
          <button
            onClick={() => navigate("/investigations")}
            className="flex items-center gap-1 text-xs text-text-muted hover:text-text-secondary transition-colors"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            Investigations
          </button>
          {investigation?.id && (
            <>
              <span className="text-text-muted/40">/</span>
              <span className="text-xs text-text-muted font-mono">{investigation.id.slice(0, 8)}</span>
            </>
          )}
          <div className="ml-auto">
            {investigation && (
              <AnalystPresence analysts={[]} />
            )}
          </div>
        </div>

        {isLoading ? (
          <div className="px-6 py-4"><SkeletonText lines={2} /></div>
        ) : investigation && investigation.id ? (
          <InvestigationHeader investigation={investigation} />
        ) : null}
      </div>

      {/* 3-panel body */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* Left: Timeline */}
        <div
          className={cn(
            "flex flex-col border-r border-border bg-bg-surface transition-all duration-200 flex-shrink-0",
            leftCollapsed ? "w-0 overflow-hidden" : ""
          )}
          style={leftCollapsed ? undefined : { width: panelSizes.left }}
        >
          <InvestigationTimeline investigationId={investigationId} />
        </div>

        {/* Left drag handle */}
        <div className="relative flex-shrink-0">
          <DragHandle
            onDrag={handleLeftDrag}
            className="h-full border-r border-border bg-bg-surface"
          />
          <button
            onMouseDown={updateLeftBase}
            onClick={() => setLeftCollapsed((v) => !v)}
            className="absolute top-1/2 -translate-y-1/2 -right-3 z-10 w-6 h-6 rounded-full bg-bg-elevated border border-border flex items-center justify-center text-text-muted hover:text-text-primary hover:border-accent transition-colors shadow-sm"
          >
            {leftCollapsed ? (
              <PanelLeft className="w-3 h-3" />
            ) : (
              <ChevronLeft className="w-3 h-3" />
            )}
          </button>
        </div>

        {/* Center: Tabbed content */}
        <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
          <Tabs
            value={activeTab}
            onValueChange={setActiveTab}
            className="flex flex-col h-full"
          >
            <TabsList className="px-4 flex-shrink-0 bg-bg-surface">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
              <TabsTrigger value="process">Process Tree</TabsTrigger>
              <TabsTrigger value="notes">Notes</TabsTrigger>
            </TabsList>

            <div className="flex-1 overflow-y-auto">
              <TabsContent value="overview" className="p-4 space-y-4">
                {/* Graph preview */}
                <div style={{ height: 300 }}>
                  <InvestigationGraphPreview investigationId={investigationId} />
                </div>

                {/* MITRE context */}
                {investigation && (
                  <div className="card p-4">
                    <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
                      MITRE ATT&CK
                    </h3>
                    <MitreContext techniques={investigation.mitreTechniques} />
                  </div>
                )}

                {/* Affected hosts + users */}
                {investigation && (investigation.affectedHosts.length > 0 || investigation.affectedUsers.length > 0) && (
                  <div className="grid grid-cols-2 gap-4">
                    {investigation.affectedHosts.length > 0 && (
                      <div className="card p-4">
                        <p className="text-2xs text-text-muted uppercase tracking-wider font-medium mb-2">
                          Affected Hosts ({investigation.affectedHosts.length})
                        </p>
                        <div className="space-y-1">
                          {investigation.affectedHosts.map((h) => (
                            <p key={h} className="text-xs font-mono text-text-secondary">{h}</p>
                          ))}
                        </div>
                      </div>
                    )}
                    {investigation.affectedUsers.length > 0 && (
                      <div className="card p-4">
                        <p className="text-2xs text-text-muted uppercase tracking-wider font-medium mb-2">
                          Affected Users ({investigation.affectedUsers.length})
                        </p>
                        <div className="space-y-1">
                          {investigation.affectedUsers.map((u) => (
                            <p key={u} className="text-xs text-text-secondary">{u}</p>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </TabsContent>

              <TabsContent value="evidence" className="p-4">
                <EvidencePanel investigationId={investigationId} />
              </TabsContent>

              <TabsContent value="process" className="p-4">
                <div className="card p-4">
                  <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
                    Process Tree
                  </p>
                  <ProcessTree roots={[]} />
                </div>
              </TabsContent>

              <TabsContent value="notes" className="p-4">
                <div className="card p-4">
                  <InvestigationNotes
                    investigationId={investigationId}
                    notes={[]}
                  />
                </div>
              </TabsContent>
            </div>
          </Tabs>
        </div>

        {/* Right drag handle */}
        <div className="relative flex-shrink-0">
          <DragHandle
            onDrag={handleRightDrag}
            className="h-full border-l border-border bg-bg-surface"
          />
          <button
            onMouseDown={updateRightBase}
            onClick={() => setRightCollapsed((v) => !v)}
            className="absolute top-1/2 -translate-y-1/2 -left-3 z-10 w-6 h-6 rounded-full bg-bg-elevated border border-border flex items-center justify-center text-text-muted hover:text-text-primary hover:border-accent transition-colors shadow-sm"
          >
            {rightCollapsed ? (
              <PanelRight className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </button>
        </div>

        {/* Right: AI context sidebar */}
        <div
          className={cn(
            "flex flex-col border-l border-border bg-bg-surface overflow-y-auto transition-all duration-200 flex-shrink-0",
            rightCollapsed ? "w-0 overflow-hidden" : ""
          )}
          style={rightCollapsed ? undefined : { width: panelSizes.right }}
        >
          {/* AI Panel header */}
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border flex-shrink-0">
            <Brain className="w-3.5 h-3.5 text-accent" />
            <span className="text-xs font-semibold text-text-primary">AI Analysis</span>
          </div>

          <AIInvestigationPanel
            analysis={investigation?.aiAnalysis}
            isLoading={isLoading}
          />

          {/* Divider */}
          <div className="border-t border-border mx-4 my-0" />

          {/* Related alerts */}
          <div className="px-4 py-4 border-b border-border">
            <RelatedAlerts investigationId={investigationId} />
          </div>

          {/* Activity feed */}
          <div className="px-4 py-4 border-b border-border">
            <ActivityFeed investigationId={investigationId} />
          </div>
        </div>
      </div>
    </div>
  );
}
