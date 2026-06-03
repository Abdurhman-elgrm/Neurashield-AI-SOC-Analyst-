import { Brain, Sparkles, Zap, Shield } from "lucide-react";

const CAPABILITIES = [
  {
    icon: Zap,
    title: "Instant Analysis",
    desc: "Get AI explanations of alerts, logs, and threat indicators in seconds.",
  },
  {
    icon: Shield,
    title: "Investigation Assist",
    desc: "Let the AI correlate events, suggest pivots, and build attack timelines.",
  },
  {
    icon: Sparkles,
    title: "Natural Language Queries",
    desc: "Ask questions about your environment in plain English.",
  },
];

export function CopilotPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="page-title">AI Copilot</h1>
        <p className="text-sm text-text-muted mt-1">Your AI-powered investigation assistant</p>
      </div>

      <div
        className="rounded-2xl p-12 flex flex-col items-center justify-center text-center border"
        style={{
          background: "rgba(0,0,0,0.6)",
          borderColor: "rgba(59,130,246,0.15)",
          borderStyle: "dashed",
        }}
      >
        <div
          className="w-16 h-16 rounded-2xl flex items-center justify-center mb-5"
          style={{
            background: "linear-gradient(135deg, rgba(59,130,246,0.15), rgba(56,189,248,0.1))",
            border: "1px solid rgba(59,130,246,0.25)",
            boxShadow: "0 0 30px rgba(59,130,246,0.15)",
          }}
        >
          <Brain className="w-8 h-8 text-primary-400 animate-blue-pulse" />
        </div>
        <h2 className="font-display text-xl font-bold text-text-primary mb-2">
          NEURASHIELD AI Copilot
        </h2>
        <p className="text-sm text-text-muted max-w-lg leading-relaxed mb-8">
          Conversational threat analysis powered by large language models. Ask about any alert,
          event, or investigation — the AI has full context of your environment.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 w-full max-w-2xl">
          {CAPABILITIES.map((cap) => (
            <div
              key={cap.title}
              className="rounded-xl p-4 text-left"
              style={{
                background: "rgba(10,10,10,0.8)",
                border: "1px solid rgba(59,130,246,0.12)",
              }}
            >
              <cap.icon className="w-5 h-5 text-primary-400 mb-2" />
              <p className="text-xs font-semibold text-text-primary mb-1">{cap.title}</p>
              <p className="text-xs text-text-muted leading-relaxed">{cap.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
