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
          bg: '#080c14',
          card: '#0f172a',
          surface: '#1e293b',
          border: '#334155',
          primary: '#00f2fe',
          neon: '#00f5a0',
          warning: '#ffb800',
          danger: '#ff3366',
          purple: '#9d4edd',
          blue: '#3b82f6',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
        display: ['Orbitron', 'Inter', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan': 'scan 4s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        },
        glow: {
          '0%': { filter: 'drop-shadow(0 0 5px rgba(0, 242, 254, 0.4))' },
          '100%': { filter: 'drop-shadow(0 0 15px rgba(0, 245, 160, 0.8))' },
        }
      }
    },
  },
  plugins: [],
}
