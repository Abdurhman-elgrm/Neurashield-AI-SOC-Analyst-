import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useWSManager } from "@/websocket/WSProvider";
import { investigationKeys } from "./useInvestigation";
import type { Investigation } from "../types/investigation";
import type { TimelineEvent } from "../types/timeline";
import type { EvidenceItem } from "../types/evidence";

interface PresencePayload {
  analystId: string;
  analystName: string;
  avatarColor: string;
  activeSection: string;
  investigationId: string;
}

export function useRealtimeInvestigation(investigationId: string) {
  const ws = useWSManager();
  const qc = useQueryClient();
  const idRef = useRef(investigationId);
  idRef.current = investigationId;

  useEffect(() => {
    if (!investigationId) return;

    // investigation.updated — patch detail cache
    const offUpdated = ws.on<Investigation>("investigation.updated", (event) => {
      if (event.payload.id !== idRef.current) return;
      qc.setQueryData<Investigation>(
        investigationKeys.detail(idRef.current),
        (prev) => (prev ? { ...prev, ...event.payload } : prev)
      );
    });

    // investigation.assigned — patch assignee
    const offAssigned = ws.on<{ investigationId: string; assignedTo: string; assignedToName: string }>(
      "investigation.assigned",
      (event) => {
        if (event.payload.investigationId !== idRef.current) return;
        qc.setQueryData<Investigation>(
          investigationKeys.detail(idRef.current),
          (prev) =>
            prev
              ? {
                  ...prev,
                  assignedTo: event.payload.assignedTo,
                  assignedToName: event.payload.assignedToName,
                }
              : prev
        );
      }
    );

    // investigation.note_added — prepend to timeline
    const offNote = ws.on<TimelineEvent>("investigation.note_added", (event) => {
      if (event.payload.investigationId !== idRef.current) return;
      qc.setQueryData<TimelineEvent[]>(
        investigationKeys.timeline(idRef.current),
        (prev) => (prev ? [...prev, event.payload] : [event.payload])
      );
    });

    // investigation.verdict_updated — patch verdict
    const offVerdict = ws.on<{ investigationId: string; verdict: string }>(
      "investigation.verdict_changed",
      (event) => {
        if (event.payload.investigationId !== idRef.current) return;
        qc.setQueryData<Investigation>(
          investigationKeys.detail(idRef.current),
          (prev) =>
            prev
              ? { ...prev, verdict: event.payload.verdict as Investigation["verdict"] }
              : prev
        );
      }
    );

    // investigation.status_updated — patch status + timeline event
    const offStatus = ws.on<TimelineEvent>("investigation.status_updated", (event) => {
      if (event.payload.investigationId !== idRef.current) return;
      qc.setQueryData<TimelineEvent[]>(
        investigationKeys.timeline(idRef.current),
        (prev) => (prev ? [...prev, event.payload] : [event.payload])
      );
      void qc.invalidateQueries({ queryKey: investigationKeys.detail(idRef.current) });
    });

    // evidence.added — prepend to evidence cache
    const offEvidence = ws.on<EvidenceItem>("evidence.added", (event) => {
      if (event.payload.investigationId !== idRef.current) return;
      qc.setQueryData<EvidenceItem[]>(
        investigationKeys.evidence(idRef.current),
        (prev) => (prev ? [event.payload, ...prev] : [event.payload])
      );
    });

    // analyst.joined — ephemeral presence notification
    const offPresence = ws.on<PresencePayload>("analyst.joined", () => {
      // Presence is ephemeral — handled by a separate presence store if needed
    });

    return () => {
      offUpdated();
      offAssigned();
      offNote();
      offVerdict();
      offStatus();
      offEvidence();
      offPresence();
    };
  }, [ws, qc, investigationId]);
}
