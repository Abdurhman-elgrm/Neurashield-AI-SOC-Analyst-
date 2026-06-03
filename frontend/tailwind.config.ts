import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // ── Pure black backgrounds ──
        bg: {
          base:     "#000000",
          surface:  "#0A0A0A",
          elevated: "#111111",
          card:     "#0D0D0D",
          input:    "#080808",
          sidebar:  "#050505",
          subtle:   "#111111",
          overlay:  "rgba(13,13,13,0.8)",
          hover:    "rgba(255,255,255,0.025)",
          selected: "rgba(59,130,246,0.06)",
        },

        // ── Electric Blue primary ──
        blue: {
          300: "#93C5FD",
          400: "#60A5FA",
          500: "#3B82F6",
          600: "#2563EB",
          700: "#1D4ED8",
        },

        // ── Primary alias (backward compat) ──
        primary: {
          300: "#93C5FD",
          400: "#60A5FA",
          500: "#3B82F6",
          600: "#2563EB",
          700: "#1D4ED8",
        },

        // ── Borders ──
        border: {
          DEFAULT: "rgba(255,255,255,0.06)",
          card:    "rgba(255,255,255,0.07)",
          subtle:  "rgba(255,255,255,0.04)",
          strong:  "rgba(255,255,255,0.12)",
          active:  "rgba(59,130,246,0.5)",
          focus:   "rgba(59,130,246,0.6)",
          hover:   "rgba(255,255,255,0.12)",
          cyan:    "rgba(56,189,248,0.2)",
        },

        // ── New text scale ──
        tx: {
          1: "#F5F7FA",
          2: "#B8C0CC",
          3: "#8B95A7",
          4: "#5C6373",
          5: "#3A4150",
        },

        // ── Text (backward compat) ──
        text: {
          primary:   "#F5F7FA",
          secondary: "#B8C0CC",
          muted:     "#5C6373",
          disabled:  "#3A4150",
        },

        // ── New severity (pure colors) ──
        sev: {
          critical: "#EF4444",
          high:     "#F97316",
          medium:   "#F59E0B",
          low:      "#3B82F6",
          info:     "#6B7280",
        },

        // ── Severity (backward compat — text variants) ──
        severity: {
          critical: "#FCA5A5",
          high:     "#FDB07A",
          medium:   "#FCD34D",
          low:      "#6EE7B7",
          info:     "#93C5FD",
        },

        // ── Status ──
        status: {
          online:   "#10B981",
          offline:  "#4B5563",
          degraded: "#F59E0B",
          unknown:  "#4B5563",
        },

        // ── Legacy accent aliases ──
        accent:         "#3B82F6",
        "accent-hover": "#2563EB",

        // ── Ice blue (replaces cyan) ──
        cyber: {
          400: "#38BDF8",
          500: "#0EA5E9",
          900: "#082032",
        },

        // ── Pure blacks ──
        base: {
          950: "#000000",
          900: "#0A0A0A",
          800: "#111111",
          700: "#1A1A1A",
        },
      },

      fontFamily: {
        sans:    ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        display: ["Space Grotesk", "Inter", "sans-serif"],
        mono:    ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },

      fontSize: {
        "2xs": ["0.625rem",  { lineHeight: "0.875rem" }],
        xs:    ["0.75rem",   { lineHeight: "1rem" }],
        sm:    ["0.8125rem", { lineHeight: "1.25rem" }],
        base:  ["0.875rem",  { lineHeight: "1.375rem" }],
        lg:    ["1rem",      { lineHeight: "1.5rem" }],
        xl:    ["1.125rem",  { lineHeight: "1.625rem" }],
        "2xl": ["1.25rem",   { lineHeight: "1.75rem" }],
        "3xl": ["1.5rem",    { lineHeight: "2rem" }],
        "4xl": ["1.75rem",   { lineHeight: "2.25rem" }],
      },

      borderRadius: {
        sm:      "0.25rem",
        DEFAULT: "0.375rem",
        md:      "0.375rem",
        lg:      "0.5rem",
        xl:      "0.75rem",
        "2xl":   "1rem",
      },

      animation: {
        "fade-in":        "fadeIn 0.15s ease-out",
        "slide-in-right": "slideInRight 0.2s ease-out",
        "slide-out-right":"slideOutRight 0.2s ease-in",
        "pulse-subtle":   "pulseSubtle 2s ease-in-out infinite",
        "neural-pulse":   "neural-pulse 3s ease-in-out infinite",
        "float":          "float 4s ease-in-out infinite",
        "pulse-dot":      "pulse-dot 2s infinite",
        shimmer:          "shimmer 1.6s infinite",
      },

      keyframes: {
        fadeIn:        { from: { opacity: "0" }, to: { opacity: "1" } },
        slideInRight:  { from: { transform: "translateX(100%)", opacity: "0" }, to: { transform: "translateX(0)", opacity: "1" } },
        slideOutRight: { from: { transform: "translateX(0)", opacity: "1" }, to: { transform: "translateX(100%)", opacity: "0" } },
        pulseSubtle:   { "0%, 100%": { opacity: "1" }, "50%": { opacity: "0.6" } },
        "neural-pulse":{ "0%, 100%": { opacity: "0.6", transform: "scale(1)" }, "50%": { opacity: "1", transform: "scale(1.05)" } },
        float:         { "0%, 100%": { transform: "translateY(0px)" }, "50%": { transform: "translateY(-6px)" } },
        "pulse-dot":   { "0%, 100%": { opacity: "1" }, "50%": { opacity: "0.4" } },
        shimmer:       { "0%": { backgroundPosition: "200% 0" }, "100%": { backgroundPosition: "-200% 0" } },
      },

      boxShadow: {
        card:            "0 1px 3px rgba(0,0,0,0.6)",
        elevated:        "0 4px 12px rgba(0,0,0,0.6)",
        panel:           "0 8px 32px rgba(0,0,0,0.7)",
        glow:            "0 0 20px rgba(59,130,246,0.2)",
        "glow-sm":       "0 0 10px rgba(59,130,246,0.15)",
        "glow-blue":     "0 0 20px rgba(59,130,246,0.3)",
        "glow-cyan":     "0 0 20px rgba(56,189,248,0.3)",
        "glow-danger":   "0 0 20px rgba(239,68,68,0.3)",
        "glow-accent":   "0 0 12px rgba(59,130,246,0.2)",
        "glow-critical": "0 0 12px rgba(239,68,68,0.2)",
        "glow-purple":   "0 0 20px rgba(59,130,246,0.3)",
      },
    },
  },
  plugins: [],
};

export default config;
