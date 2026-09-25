/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0d14',
          card: '#0f172a',
          cardHover: '#1e293b',
          border: '#1e293b',
          borderLight: '#334155',
          cyan: '#06b6d4',
          blue: '#3b82f6',
          emerald: '#10b981',
          rose: '#f43f5e',
          amber: '#f59e0b',
          purple: '#8b5cf6',
          muted: '#94a3b8',
        }
      },
      boxShadow: {
        'cyber-cyan': '0 0 20px -5px rgba(6, 182, 212, 0.3)',
        'cyber-rose': '0 0 20px -5px rgba(244, 63, 94, 0.3)',
        'cyber-emerald': '0 0 20px -5px rgba(16, 185, 129, 0.3)',
        'cyber-amber': '0 0 20px -5px rgba(245, 158, 11, 0.3)',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace', 'ui-monospace'],
      }
    },
  },
  plugins: [],
}
