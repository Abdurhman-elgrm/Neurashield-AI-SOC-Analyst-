import { useState, useEffect, useRef, KeyboardEvent } from 'react'
import { Brain, Trash2, Send } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { copilotApi, type ChatMessageItem } from '@/api/copilot'

type Mode = 'deep_dive' | 'threat_actor' | 'false_positive'

interface Message {
  role: 'user' | 'assistant'
  content: string
  typing?: boolean
}

const MODES: { key: Mode; label: string; color: string }[] = [
  { key: 'deep_dive',     label: 'Deep Dive',     color: '#6366F1' },
  { key: 'threat_actor',  label: 'Threat Actor',  color: '#F59E0B' },
  { key: 'false_positive',label: 'False Positive', color: '#10B981' },
]

const WELCOME: Message = {
  role: 'assistant',
  content:
    "Welcome to NEURASHIELD Copilot. I have full context of your SOC environment — " +
    "open alerts, active investigations, and connected agents.\n\n" +
    "Ask me anything: *explain this alert*, *is this a false positive*, " +
    "*profile the threat actor*, or *what should I do next*.",
}

export function CopilotPage() {
  const [messages, setMessages] = useState<Message[]>([WELCOME])
  const [input, setInput] = useState('')
  const [mode, setMode] = useState<Mode>('deep_dive')
  const [isLoading, setIsLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const scrollToBottom = () => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  // Load history on mount
  useEffect(() => {
    copilotApi.history().then(res => {
      const items: ChatMessageItem[] = res.data?.data ?? []
      if (items.length > 0) {
        const loaded: Message[] = items.map(m => ({ role: m.role as 'user' | 'assistant', content: m.content }))
        setMessages([WELCOME, ...loaded])
      }
    }).catch(() => {
      // silently ignore — history is best-effort
    })
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleSend = async () => {
    const text = input.trim()
    if (!text || isLoading) return

    setInput('')
    setMessages(prev => [
      ...prev,
      { role: 'user', content: text },
      { role: 'assistant', content: '', typing: true },
    ])
    setIsLoading(true)

    try {
      const res = await copilotApi.chat({ message: text, mode })
      const reply = res.data?.data?.response ?? 'No response received.'
      setMessages(prev => [
        ...prev.slice(0, -1),
        { role: 'assistant', content: reply },
      ])
    } catch {
      setMessages(prev => [
        ...prev.slice(0, -1),
        {
          role: 'assistant',
          content: 'I encountered an error. Please check your API key configuration and try again.',
        },
      ])
    } finally {
      setIsLoading(false)
      textareaRef.current?.focus()
    }
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleClear = async () => {
    try {
      await copilotApi.clearHistory()
    } catch { /* ignore */ }
    setMessages([WELCOME])
    setInput('')
  }

  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      height: 'calc(100vh - 50px - 40px)',
      background: '#050505',
      overflow: 'hidden',
    }}>

      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '12px 20px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Brain size={18} style={{ color: '#6366F1' }} />
          <span style={{ fontSize: 14, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
            NEURASHIELD Copilot
          </span>
        </div>
        <button
          onClick={handleClear}
          style={{
            display: 'flex', alignItems: 'center', gap: 5,
            background: 'none', border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 6, padding: '4px 10px',
            fontSize: 11, color: '#5C6373', cursor: 'pointer',
          }}
        >
          <Trash2 size={11} /> Clear
        </button>
      </div>

      {/* Mode chips */}
      <div style={{
        display: 'flex', gap: 8, padding: '10px 20px',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        flexShrink: 0,
      }}>
        {MODES.map(m => (
          <button
            key={m.key}
            onClick={() => setMode(m.key)}
            style={{
              padding: '4px 12px', borderRadius: 20,
              fontSize: 11, fontWeight: 600, cursor: 'pointer',
              background: mode === m.key ? `${m.color}18` : 'transparent',
              border: `1px solid ${mode === m.key ? m.color : 'rgba(255,255,255,0.08)'}`,
              color: mode === m.key ? m.color : '#5C6373',
              transition: 'all 150ms',
            }}
          >
            {m.label}
          </button>
        ))}
      </div>

      {/* Messages */}
      <div style={{
        flex: 1, overflowY: 'auto', padding: '20px',
        display: 'flex', flexDirection: 'column', gap: 12,
        background: '#0A0A0A',
      }}>
        {messages.map((msg, i) => (
          <div
            key={i}
            style={{
              display: 'flex',
              justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
            }}
          >
            <div style={{
              maxWidth: '80%',
              padding: '10px 14px',
              borderRadius: msg.role === 'user' ? '12px 12px 4px 12px' : '12px 12px 12px 4px',
              background: msg.role === 'user'
                ? 'rgba(99, 102, 241, 0.15)'
                : 'rgba(255,255,255,0.02)',
              border: `1px solid ${msg.role === 'user' ? 'rgba(99, 102, 241, 0.3)' : 'rgba(255,255,255,0.05)'}`,
              fontSize: 13,
              color: '#F5F7FA',
              lineHeight: 1.6,
            }}>
              {msg.typing ? (
                <TypingDots />
              ) : msg.role === 'assistant' ? (
                <div className="markdown-content" style={{ fontSize: 13 }}>
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              ) : (
                <span style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</span>
              )}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={{
        padding: '12px 20px',
        borderTop: '1px solid rgba(255,255,255,0.06)',
        background: '#050505',
        flexShrink: 0,
      }}>
        <div style={{
          display: 'flex', alignItems: 'flex-end', gap: 10,
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 10, padding: '8px 12px',
        }}>
          <textarea
            ref={textareaRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about threats, alerts, or investigations... (Enter to send, Shift+Enter for newline)"
            disabled={isLoading}
            rows={1}
            style={{
              flex: 1, background: 'transparent', border: 'none', outline: 'none',
              resize: 'none', fontSize: 13, color: '#F5F7FA',
              fontFamily: "'Inter', sans-serif", lineHeight: 1.5,
              maxHeight: 120, overflowY: 'auto',
            }}
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: 32, height: 32, borderRadius: 8, flexShrink: 0,
              background: input.trim() && !isLoading ? '#6366F1' : 'rgba(255,255,255,0.06)',
              border: 'none', cursor: input.trim() && !isLoading ? 'pointer' : 'default',
              color: input.trim() && !isLoading ? '#fff' : '#3A4150',
              transition: 'all 150ms',
            }}
          >
            <Send size={14} />
          </button>
        </div>
      </div>
    </div>
  )
}

function TypingDots() {
  return (
    <div style={{ display: 'flex', gap: 4, alignItems: 'center', padding: '2px 0' }}>
      {[0, 1, 2].map(i => (
        <span
          key={i}
          style={{
            width: 6, height: 6, borderRadius: '50%',
            background: '#5C6373',
            animation: `typing-bounce 1.2s ease-in-out ${i * 0.2}s infinite`,
          }}
        />
      ))}
      <style>{`
        @keyframes typing-bounce {
          0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
          30% { transform: translateY(-6px); opacity: 1; }
        }
      `}</style>
    </div>
  )
}
