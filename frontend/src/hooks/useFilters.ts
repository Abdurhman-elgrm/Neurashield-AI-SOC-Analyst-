import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { FilterState, ActiveFilter, DateRange } from "@/components/filters/types";

// Minimal UUID — avoids adding uuid dependency
function randomId() {
  return Math.random().toString(36).slice(2, 10);
}

const DEFAULTS: FilterState = {
  search: "",
  filters: [],
  dateRange: null,
  savedViewId: null,
};

/**
 * Synchronizes FilterState with URL search params so filters survive page
 * refresh and are shareable via URL.
 */
export function useFilters(prefix = "") {
  const [params, setParams] = useSearchParams();

  const filterState = useMemo<FilterState>(() => {
    const search = params.get(`${prefix}q`) ?? "";
    const savedViewId = params.get(`${prefix}view`) ?? null;

    // Deserialize filters from URL
    const filtersRaw = params.get(`${prefix}filters`);
    let filters: ActiveFilter[] = [];
    if (filtersRaw) {
      try { filters = JSON.parse(atob(filtersRaw)); } catch { /* ignore */ }
    }

    // Deserialize date range
    const dateFrom = params.get(`${prefix}from`) ?? null;
    const dateTo   = params.get(`${prefix}to`)   ?? null;
    const preset   = params.get(`${prefix}preset`) as DateRange["preset"] ?? undefined;
    const dateRange: DateRange | null = (dateFrom || dateTo) ? { from: dateFrom, to: dateTo, preset } : null;

    return { search, filters, dateRange, savedViewId };
  }, [params, prefix]);

  const setFilterState = useCallback(
    (next: FilterState) => {
      setParams((prev) => {
        const p = new URLSearchParams(prev);

        // Search
        if (next.search) p.set(`${prefix}q`, next.search);
        else p.delete(`${prefix}q`);

        // Saved view
        if (next.savedViewId) p.set(`${prefix}view`, next.savedViewId);
        else p.delete(`${prefix}view`);

        // Filters
        if (next.filters.length > 0) p.set(`${prefix}filters`, btoa(JSON.stringify(next.filters)));
        else p.delete(`${prefix}filters`);

        // Date range
        if (next.dateRange?.from) p.set(`${prefix}from`, next.dateRange.from);
        else p.delete(`${prefix}from`);
        if (next.dateRange?.to) p.set(`${prefix}to`, next.dateRange.to);
        else p.delete(`${prefix}to`);
        if (next.dateRange?.preset) p.set(`${prefix}preset`, next.dateRange.preset);
        else p.delete(`${prefix}preset`);

        return p;
      }, { replace: true });
    },
    [setParams, prefix]
  );

  const addFilter = useCallback(
    (filter: Omit<ActiveFilter, "id">) => {
      setFilterState({
        ...filterState,
        filters: [...filterState.filters, { ...filter, id: randomId() }],
      });
    },
    [filterState, setFilterState]
  );

  const removeFilter = useCallback(
    (id: string) => {
      setFilterState({
        ...filterState,
        filters: filterState.filters.filter((f) => f.id !== id),
      });
    },
    [filterState, setFilterState]
  );

  const clearFilters = useCallback(() => {
    setFilterState(DEFAULTS);
  }, [setFilterState]);

  const setSearch = useCallback(
    (search: string) => setFilterState({ ...filterState, search }),
    [filterState, setFilterState]
  );

  const setDateRange = useCallback(
    (dateRange: DateRange | null) => setFilterState({ ...filterState, dateRange }),
    [filterState, setFilterState]
  );

  // Convert filter state to API query params
  const toQueryParams = useCallback((): Record<string, string | undefined> => {
    const { search, dateRange } = filterState;
    return {
      ...(search ? { search } : {}),
      ...(dateRange?.from ? { from: dateRange.from } : {}),
      ...(dateRange?.to ? { to: dateRange.to } : {}),
    };
  }, [filterState]);

  return {
    filterState,
    setFilterState,
    addFilter,
    removeFilter,
    clearFilters,
    setSearch,
    setDateRange,
    toQueryParams,
    hasActiveFilters:
      filterState.filters.length > 0 ||
      !!filterState.dateRange ||
      !!filterState.search,
  };
}
