import { useNotificationStore } from "@/stores/notificationStore";

export function toastError(message: string, title = "Error") {
  useNotificationStore.getState().addNotification({
    type: "error",
    title,
    message,
  });
}

export function toastSuccess(message: string, title = "Success") {
  useNotificationStore.getState().addNotification({
    type: "success",
    title,
    message,
  });
}

export function toastInfo(message: string, title = "Info") {
  useNotificationStore.getState().addNotification({
    type: "info",
    title,
    message,
  });
}

export function toastWarn(message: string, title = "Warning") {
  useNotificationStore.getState().addNotification({
    type: "system",
    title,
    message,
  });
}
