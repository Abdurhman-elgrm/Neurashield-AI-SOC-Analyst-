import { apiGet, apiPost, apiDelete, apiClient } from "./client";

export type FeedType   = "stix_taxii" | "csv" | "opencti" | "misp" | "manual";
export type FeedStatus = "active" | "error" | "syncing";
export type IOCType    = "ip" | "domain" | "hash" | "url" | "email";

export interface ThreatFeed {
  id:                    string;
  name:                  string;
  type:                  FeedType;
  endpoint_url?:         string;
  last_updated:          string | null;
  ioc_count:             number;
  status:                FeedStatus;
  error_message?:        string;
  sync_interval_minutes: number;
}

export interface CreateFeedPayload {
  name:                  string;
  type:                  FeedType;
  endpoint_url?:         string;
  api_key?:              string;
  sync_interval_minutes?: number;
}

export interface ThreatIOC {
  id:               string;
  indicator:        string;
  type:             IOCType;
  confidence:       number;
  source_feed_id:   string;
  source_feed_name: string;
  first_seen:       string;
  last_seen:        string;
  hit_count:        number;
  tags:             string[];
}

export interface IOCMatch {
  ioc_id:      string;
  indicator:   string;
  type:        IOCType;
  alert_id?:   string;
  alert_title?: string;
  event_id?:   string;
  matched_at:  string;
}

export interface IOCListResponse {
  items: ThreatIOC[];
  total: number;
  page:  number;
}

export const threatIntelApi = {
  listFeeds: () =>
    apiGet<ThreatFeed[]>("/threat-intel/feeds"),

  createFeed: (payload: CreateFeedPayload) =>
    apiPost<ThreatFeed>("/threat-intel/feeds", payload),

  deleteFeed: (id: string) =>
    apiDelete<{ deleted: string }>(`/threat-intel/feeds/${id}`),

  syncFeed: (id: string) =>
    apiPost<ThreatFeed>(`/threat-intel/feeds/${id}/sync`),

  listIOCs: (params: { page?: number; search?: string; type?: IOCType; feedId?: string }) =>
    apiGet<IOCListResponse>("/threat-intel/iocs", {
      page:    params.page ?? 1,
      search:  params.search,
      type:    params.type,
      feed_id: params.feedId,
    } as Record<string, unknown>),

  importIOCs: (formData: FormData) =>
    apiClient
      .post<{ data: { imported: number } }>("/threat-intel/iocs/import", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      .then((r) => r.data.data!),

  listMatches: () =>
    apiGet<IOCMatch[]>("/threat-intel/matches"),
};
