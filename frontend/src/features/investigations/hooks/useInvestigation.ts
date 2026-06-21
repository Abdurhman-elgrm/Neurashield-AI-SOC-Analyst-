import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getInvestigation,
  addInvestigationNote,
  assignInvestigation,
  updateInvestigationStatus,
  updateInvestigationVerdict,
  getInvestigationActivity,
  PLACEHOLDER_ACTIVITY,
} from "../api/investigationsApi";
import { PLACEHOLDER_INVESTIGATION } from "../types/investigation";
import type { InvestigationStatus, InvestigationVerdict } from "../types/investigation";

// ─── Query key factory ────────────────────────────────────────────────────────

export const investigationKeys = {
  all: ["investigations"] as const,
  detail: (id: string) => [...investigationKeys.all, "detail", id] as const,
  timeline: (id: string) => [...investigationKeys.all, "timeline", id] as const,
  graph: (id: string) => [...investigationKeys.all, "graph", id] as const,
  evidence: (id: string) => [...investigationKeys.all, "evidence", id] as const,
  relatedAlerts: (id: string) => [...investigationKeys.all, "related-alerts", id] as const,
  activity: (id: string) => [...investigationKeys.all, "activity", id] as const,
};

// ─── Investigation detail ─────────────────────────────────────────────────────

export function useInvestigation(id: string) {
  return useQuery({
    queryKey: investigationKeys.detail(id),
    queryFn: () => getInvestigation(id),
    placeholderData: PLACEHOLDER_INVESTIGATION,
    staleTime: 15_000,
    refetchInterval: 30_000,
    enabled: !!id,
  });
}

// ─── Activity feed ────────────────────────────────────────────────────────────

export function useInvestigationActivity(id: string) {
  return useQuery({
    queryKey: investigationKeys.activity(id),
    queryFn: () => getInvestigationActivity(id),
    placeholderData: PLACEHOLDER_ACTIVITY,
    staleTime: 10_000,
    refetchInterval: 15_000,
    enabled: !!id,
  });
}

// ─── Add note mutation ────────────────────────────────────────────────────────

export function useAddNote(investigationId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (content: string) => addInvestigationNote(investigationId, content),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: investigationKeys.timeline(investigationId) });
      void qc.invalidateQueries({ queryKey: investigationKeys.activity(investigationId) });
    },
  });
}

// ─── Assign mutation ──────────────────────────────────────────────────────────

export function useAssignInvestigation(investigationId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId }: { userId: string; userName?: string }) =>
      assignInvestigation(investigationId, userId),
    onSuccess: (updated) => {
      qc.setQueryData(investigationKeys.detail(investigationId), updated);
    },
  });
}

// ─── Status mutation (optimistic) ────────────────────────────────────────────

export function useUpdateStatus(investigationId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (status: InvestigationStatus) =>
      updateInvestigationStatus(investigationId, status),
    onMutate: async (status) => {
      await qc.cancelQueries({ queryKey: investigationKeys.detail(investigationId) });
      const prev = qc.getQueryData(investigationKeys.detail(investigationId));
      qc.setQueryData(investigationKeys.detail(investigationId), (old: typeof prev) =>
        old ? { ...old, status } : old
      );
      return { prev };
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(investigationKeys.detail(investigationId), ctx.prev);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: investigationKeys.detail(investigationId) });
    },
  });
}

// ─── Verdict mutation (optimistic) ───────────────────────────────────────────

export function useUpdateVerdict(investigationId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ verdict, reasoning }: { verdict: InvestigationVerdict; reasoning?: string }) =>
      updateInvestigationVerdict(investigationId, verdict, reasoning),
    onMutate: async ({ verdict }) => {
      await qc.cancelQueries({ queryKey: investigationKeys.detail(investigationId) });
      const prev = qc.getQueryData(investigationKeys.detail(investigationId));
      qc.setQueryData(investigationKeys.detail(investigationId), (old: typeof prev) =>
        old ? { ...old, verdict } : old
      );
      return { prev };
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(investigationKeys.detail(investigationId), ctx.prev);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: investigationKeys.detail(investigationId) });
    },
  });
}
