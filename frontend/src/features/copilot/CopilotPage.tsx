import { useState, useEffect, useRef, KeyboardEvent } from 'react'
import { Brain, Trash2, Send, Zap, MessageSquare, Shield, AlertTriangle, Search, ChevronRight } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { copilotApi, type ChatMessageItem } from '@/api/copilot'

type Mode = 'deep_dive' | 'threat_actor' | 'false_positive'

interface Message {
  role: 'user' | 'assistant'
  content: string
  typing?: boolean
}

const MODES: { key: Mode; label: string; description: string; color: string; icon: React.ElementType }[] = [
  { key: 'deep_dive',      label: 'Deep Dive',     description: 'Full investigation analysis', color: '#6366F1', icon: Search          },
  { key: 'threat_actor',   label: 'Threat Actor',  description: 'Profile & attribution',       color: '#F59E0B', icon: Shield          },
  { key: 'false_positive', label: 'FP Review',     description: 'Noise reduction analysis',    color: '#10B981', icon: AlertTriangle   },
]

const SUGGESTED_PROMPTS = [
  { label: "Summarize active critical alerts",          icon: AlertTriangle, color: "#EF4444" },
  { label: "What investigations need my attention?",    icon: MessageSquare, color: "#3B82F6" },
  { label: "Are there any signs of lateral movement?",  icon: Zap,           color: "#F59E0B" },
  { label: "Profile the top threat actors this week",   icon: Shield,        color: "#8B5CF6" },
  { label: "Which detections are firing most today?",   icon: Brain,         color: "#6366F1" },
  { label: "Identify potential false positives",        icon: Search,        color: "#10B981" },
]

const WELCOME: Message = {
  role: 'assistant',
  content:
    "Welcome to **NEURASHIELD Copilot** — your AI-powered SOC analyst.\n\n" +
    "I have full context of your environment: open alerts, active investigations, connected agents, and detection rules.\n\n" +
    "Select an analysis mode above and ask me anything — or pick a suggested prompt to get started.",
}

export function CopilotPage() {
  const [messages,    setMessages]    = useState<Message[]>([WELCOME])
  const [input,       setInput]       = useState('')
  const [mode,        setMode]        = useState<Mode>('deep_dive')
  const [isLoading,   setIsLoading]   = useState(false)
  const [showWelcome, setShowWelcome] = useState(true)
  const bottomRef   = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const scrollToBottom = () => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }

  useEffect(() => {
    copilotApi.history().then(res => {
      const items: ChatMessageItem[] = res.data?.data ?? []
      if (items.length > 0) {
        const loaded: Message[] = items.map(m => ({ role: m.role as 'user' | 'assistant', content: m.content }))
        setMessages([WELCOME, ...loaded])
        setShowWelcome(false)
      }
    }).catch(() => {})
  }, [])

  useEffect(() => { scrollToBottom() }, [messages])

  const handleSend = async (text?: string) => {
    const msg = (text ?? input).trim()
    if (!msg || isLoading) return
    setInput('')
    setShowWelcome(false)
    setMessages(prev => [
      ...prev,
      { role: 'user', content: msg },
      { role: 'assistant', content: '', typing: true },
    ])
    setIsLoading(true)
    try {
      const res = await copilotApi.chat({ message: msg, mode })
      const reply = res.data?.data?.response ?? 'No response received.'
      setMessages(prev => [...prev.slice(0, -1), { role: 'assistant', content: reply }])
    } catch {
      setMessages(prev => [...prev.slice(0, -1), {
        role: 'assistant',
        content: 'I encountered an error. Please check your API key configuration and try again.',
      }])
    } finally {
      setIsLoading(false)
      textareaRef.current?.focus()
    }
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() }
  }

  const handleClear = async () => {
    try { await copilotApi.clearHistory() } catch {}
    setMessages([WELCOME])
    setInput('')
    setShowWelcome(true)
  }

  const currentMode = MODES.find(m => m.key === mode)!

  return (
    <div style={{
      display: 'flex', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden', gap: 0,
    }}>

      {/* Left: Suggestions sidebar */}
      <div style={{
        width: 240, flexShrink: 0,
        borderRight: '1px solid rgba(255,255,255,0.06)',
        display: 'flex', flexDirection: 'column',
        background: '#050505',
        overflow: 'hidden',
      }}>
        {/* Mode selector */}
        <div style={{ padding: '16px 14px 10px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#3A4150', marginBottom: 8 }}>
            Analysis Mode
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {MODES.map(m => {
              const Icon = m.icon
              const active = mode === m.key
              return (
                <button
                  key={m.key}
                  onClick={() => setMode(m.key)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '7px 10px', borderRadius: 7, cursor: 'pointer',
                    background: active ? `${m.color}12` : 'transparent',
                    border: `1px solid ${active ? `${m.color}35` : 'transparent'}`,
                    transition: 'all 120ms', textAlign: 'left',
                  }}
                >
                  <Icon size={13} style={{ color: active ? m.color : '#3A4150', flexShrink: 0 }} />
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 600, color: active ? m.color : '#8B95A7' }}>{m.label}</div>
                    <div style={{ fontSize: 9, color: '#3A4150', marginTop: 1 }}>{m.description}</div>
                  </div>
                  {active && <ChevronRight size={11} style={{ color: m.color, marginLeft: 'auto', flexShrink: 0 }} />}
                </button>
              )
            })}
          </div>
        </div>

        {/* Suggested prompts */}
        <div style={{ flex: 1, padding: '12px 14px', overflowY: 'auto' }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#3A4150', marginBottom: 8 }}>
            Suggested Queries
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {SUGGESTED_PROMPTS.map(({ label, icon: Icon, color }) => (
              <button
                key={label}
                onClick={() => handleSend(label)}
                disabled={isLoading}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 7,
                  padding: '7px 10px', borderRadius: 6, cursor: 'pointer',
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  transition: 'all 120ms', textAlign: 'left',
                }}
                onMouseOver={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.05)')}
                onMouseOut={e  => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
              >
                <Icon size={11} style={{ color, flexShrink: 0, marginTop: 1 }} />
                <span style={{ fontSize: 11, color: '#8B95A7', lineHeight: 1.4 }}>{label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Context indicator */}
        <div style={{
          padding: '10px 14px',
          borderTop: '1px solid rgba(255,255,255,0.06)',
          background: 'rgba(16,185,129,0.04)',
        }}>
          <div style={{ fontSize: 9, fontWeight: 700, color: '#10B981', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 4 }}>
            Context Active
          </div>
          {[
            'Open alerts',
            'Active investigations',
            'Connected agents',
            'Detection rules',
          ].map(item => (
            <div key={item} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}>
              <span style={{ width: 4, height: 4, borderRadius: '50%', background: '#10B981', flexShrink: 0 }} />
              <span style={{ fontSize: 10, color: '#5C6373' }}>{item}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Right: Chat area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 20px',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          flexShrink: 0, background: '#050505',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8,
              background: `linear-gradient(135deg, ${currentMode.color}30, ${currentMode.color}10)`,
              border: `1px solid ${currentMode.color}30`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Brain size={16} style={{ color: currentMode.color }} />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
                NEURASHIELD Copilot
              </div>
              <div style={{ fontSize: 10, color: '#5C6373', marginTop: 1 }}>
                Mode: <span style={{ color: currentMode.color, fontWeight: 600 }}>{currentMode.label}</span>
                {' · '}{messages.filter(m => m.role === 'user').length} messages
              </div>
            </div>
          </div>
          <button
            onClick={handleClear}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              background: 'none', border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 6, padding: '4px 10px',
              fontSize: 11, color: '#5C6373', cursor: 'pointer',
              transition: 'all 120ms',
            }}
            onMouseOver={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'rgba(239,68,68,0.3)'; (e.currentTarget as HTMLButtonElement).style.color = '#EF4444'; }}
            onMouseOut={e  => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'rgba(255,255,255,0.08)'; (e.currentTarget as HTMLButtonElement).style.color = '#5C6373'; }}
          >
            <Trash2 size={11} /> Clear
          </button>
        </div>

        {/* Messages */}
        <div style={{
          flex: 1, overflowY: 'auto', padding: '20px',
          display: 'flex', flexDirection: 'column', gap: 14,
          background: '#0A0A0A',
        }}>

          {/* Welcome suggestions overlay (when no user messages) */}
          {showWelcome && messages.length === 1 && (
            <div style={{ textAlign: 'center', padding: '40px 0 20px' }}>
              <div style={{
                width: 56, height: 56, borderRadius: 14,
                background: `linear-gradient(135deg, ${currentMode.color}20, ${currentMode.color}08)`,
                border: `1px solid ${currentMode.color}30`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                margin: '0 auto 16px',
              }}>
                <Brain size={24} style={{ color: currentMode.color }} />
              </div>
              <div style={{ fontSize: 15, fontWeight: 700, color: '#F5F7FA', marginBottom: 6, fontFamily: "'Space Grotesk', sans-serif" }}>
                NEURASHIELD Copilot
              </div>
              <div style={{ fontSize: 12, color: '#5C6373', maxWidth: 360, margin: '0 auto', lineHeight: 1.6 }}>
                Your AI-powered SOC analyst with full context of your environment.
                Ask anything or pick a suggested query from the left panel.
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <div
              key={i}
              style={{
                display: 'flex',
                justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
                gap: 10,
                alignItems: 'flex-start',
              }}
            >
              {/* AI avatar */}
              {msg.role === 'assistant' && (
                <div style={{
                  width: 28, height: 28, borderRadius: 8, flexShrink: 0,
                  background: `${currentMode.color}12`,
                  border: `1px solid ${currentMode.color}25`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  marginTop: 2,
                }}>
                  <Brain size={13} style={{ color: currentMode.color }} />
                </div>
              )}

              <div style={{
                maxWidth: '78%',
                padding: '10px 14px',
                borderRadius: msg.role === 'user' ? '12px 12px 4px 12px' : '4px 12px 12px 12px',
                background: msg.role === 'user'
                  ? `rgba(99,102,241,0.12)`
                  : 'rgba(255,255,255,0.025)',
                border: `1px solid ${msg.role === 'user' ? 'rgba(99,102,241,0.25)' : 'rgba(255,255,255,0.06)'}`,
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

              {/* User avatar */}
              {msg.role === 'user' && (
                <div style={{
                  width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
                  background: 'linear-gradient(135deg, #2563EB 0%, #38BDF8 100%)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 10, fontWeight: 700, color: '#fff',
                  marginTop: 2,
                }}>
                  ME
                </div>
              )}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* Input area */}
        <div style={{
          padding: '12px 20px 16px',
          borderTop: '1px solid rgba(255,255,255,0.06)',
          background: '#050505',
          flexShrink: 0,
        }}>
          <div style={{
            display: 'flex', alignItems: 'flex-end', gap: 10,
            background: 'rgba(255,255,255,0.03)',
            border: `1px solid rgba(255,255,255,0.08)`,
            borderRadius: 10, padding: '10px 12px',
            transition: 'border-color 150ms',
          }}>
            <textarea
              ref={textareaRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={`${currentMode.label} mode — ask about threats, alerts, or investigations… (Enter to send)`}
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
              onClick={() => handleSend()}
              disabled={!input.trim() || isLoading}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                width: 34, height: 34, borderRadius: 8, flexShrink: 0,
                background: input.trim() && !isLoading ? currentMode.color : 'rgba(255,255,255,0.06)',
                border: 'none', cursor: input.trim() && !isLoading ? 'pointer' : 'default',
                color: input.trim() && !isLoading ? '#fff' : '#3A4150',
                transition: 'all 150ms',
                boxShadow: input.trim() && !isLoading ? `0 0 12px ${currentMode.color}40` : 'none',
              }}
            >
              <Send size={14} />
            </button>
          </div>
          <div style={{ fontSize: 10, color: '#3A4150', marginTop: 6, paddingLeft: 2 }}>
            Enter to send · Shift+Enter for newline · Mode: {currentMode.label}
          </div>
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
