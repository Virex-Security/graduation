/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'brand-primary': '#9a277d',
        'brand-secondary': '#792b9d',
        'brand-accent': '#852c6f',
        'bg-main': '#191c2b',
        'bg-secondary': '#212538',
        'bg-card': '#212538',
        'bg-layout': '#191c2b',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        info: '#3b82f6',
        text: {
          primary: '#ffffff',
          secondary: 'rgba(255, 255, 255, 0.7)',
          muted: 'rgba(255, 255, 255, 0.45)',
        },
        border: {
          dim: 'rgba(224, 70, 186, 0.15)',
          light: 'rgba(224, 70, 186, 0.3)',
        }
      },
      fontFamily: {
        main: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      backgroundImage: {
        'brand-gradient': 'linear-gradient(135deg, #e046ba 0%, #b347e6 100%)',
        'brand-gradient-hover': 'linear-gradient(135deg, #f05ad2 0%, #c45df5 100%)',
      },
      boxShadow: {
        'glow-purple': '0 0 24px rgba(224, 70, 186, 0.35)',
        'glow-cyan': '0 0 20px rgba(179, 71, 230, 0.25)',
      }
    },
  },
  plugins: [],
}
