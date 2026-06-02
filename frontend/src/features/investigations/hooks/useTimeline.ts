import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { getInvestigationTimeline, PLACEHOLDER_TIMELINE } from "../api/investigationsApi";
import { investigationKeys } from "./useInvestigation";
import type { TimelineFilterState, TimelineEvent } from "../types/timeline";

export function useTimeline(id: string, filters: TimelineFilterState) {
  const query = useQuery({
    queryKey: investigationKeys.timeline(id),
    queryFn: () => getInvestigationTimeline(id),
    placeholderData: PLACEHOLDER_TIMELINE,
    staleTime: 10_000,
    refetchInterval: 20_000,
    enabled: !!id,
  });

  // Filter client-side (timeline is typically < 500 events — no need for server filtering)
  const filtered = useMemo(() => {
    let events: TimelineEvent[] = query.data ?? [];

    if (filters.types.length > 0) {
      events = events.filter((e) => filters.types.includes(e.type));
    }
    if (filters.actorType !== "all") {
      events = events.filter((e) => e.actorType === filters.actorType);
    }
    if (filters.severity.length > 0) {
      events = events.filter((e) => e.severity && filters.severity.includes(e.severity));
    }
    if (filters.search.trim()) {
      const q = filters.search.toLowerCase();
      events = events.filter(
        (e) =>
          e.title.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          e.actorName?.toLowerCase().includes(q)
      );
    }

    // Sort chronological (newest last for feed display)
    return [...events].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
  }, [query.data, filters]);

  return { ...query, filtered };
}
