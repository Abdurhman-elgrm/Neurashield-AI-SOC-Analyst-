import { create } from "zustand";
import type { AlertSeverity } from "@/types/alerts";

export type NotificationType = "alert" | "investigation" | "system" | "info";

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  severity?: AlertSeverity;
  timestamp: string;
  read: boolean;
  actionLabel?: string;
  actionHref?: string;
  metadata?: Record<string, unknown>;
}

const MAX_NOTIFICATIONS = 100;

interface NotificationState {
  notifications: Notification[];
  unreadCount: number;

  addNotification: (n: Omit<Notification, "id" | "timestamp" | "read">) => void;
  markRead: (id: string) => void;
  markAllRead: () => void;
  removeNotification: (id: string) => void;
  clearAll: () => void;
}

let _nextId = 1;

export const useNotificationStore = create<NotificationState>()((set) => ({
  notifications: [],
  unreadCount: 0,

  addNotification: (partial) => {
    const n: Notification = {
      ...partial,
      id: String(_nextId++),
      timestamp: new Date().toISOString(),
      read: false,
    };
    set((s) => {
      const notifications = [n, ...s.notifications].slice(0, MAX_NOTIFICATIONS);
      return {
        notifications,
        unreadCount: notifications.filter((x) => !x.read).length,
      };
    });
  },

  markRead: (id) =>
    set((s) => {
      const notifications = s.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n
      );
      return { notifications, unreadCount: notifications.filter((x) => !x.read).length };
    }),

  markAllRead: () =>
    set((s) => ({
      notifications: s.notifications.map((n) => ({ ...n, read: true })),
      unreadCount: 0,
    })),

  removeNotification: (id) =>
    set((s) => {
      const notifications = s.notifications.filter((n) => n.id !== id);
      return { notifications, unreadCount: notifications.filter((x) => !x.read).length };
    }),

  clearAll: () => set({ notifications: [], unreadCount: 0 }),
}));
