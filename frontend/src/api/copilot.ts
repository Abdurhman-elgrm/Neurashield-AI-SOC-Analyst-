import { apiClient } from './client'
import type { APIResponse } from '@/types/api'

export interface ChatRequest {
  message: string
  mode: 'deep_dive' | 'threat_actor' | 'false_positive'
  investigation_id?: string | null
}

export interface ChatResponse {
  response: string
  mode: string
  context_summary: Record<string, unknown>
}

export interface ChatMessageItem {
  id: string
  role: 'user' | 'assistant'
  content: string
  created_at: string
  investigation_id: string | null
}

export const copilotApi = {
  chat: (req: ChatRequest) =>
    apiClient.post<APIResponse<ChatResponse>>('/copilot/chat', req),

  history: () =>
    apiClient.get<APIResponse<ChatMessageItem[]>>('/copilot/history'),

  clearHistory: () =>
    apiClient.delete<APIResponse<{ deleted: number }>>('/copilot/history'),
}
