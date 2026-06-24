import { apiGet } from "./client";

export interface RiskyUser {
  user_id:        string;
  username:       string;
  email?:         string;
  department?:    string;
  ueba_score:     number;
  top_flags:      string[];
  last_anomaly_at: string | null;
  alert_count:    number;
}

export interface UEBARiskPoint {
  date:  string;
  score: number;
}

export interface UEBAFlagCount {
  flag:  string;
  count: number;
}

export interface ImpossibleTravelEntry {
  username:           string;
  location_1:         string;
  location_2:         string;
  time_delta_minutes: number;
  detected_at:        string;
}

export const uebaApi = {
  getTopUsers: (limit = 20) =>
    apiGet<RiskyUser[]>("/ueba/top-users", { limit }),

  getUserTimeline: (userId: string, timeRange = "30d") =>
    apiGet<UEBARiskPoint[]>("/ueba/user-timeline", { user_id: userId, timeRange }),

  getFlagDistribution: () =>
    apiGet<UEBAFlagCount[]>("/ueba/flag-distribution"),

  getImpossibleTravel: () =>
    apiGet<ImpossibleTravelEntry[]>("/ueba/impossible-travel"),
};
