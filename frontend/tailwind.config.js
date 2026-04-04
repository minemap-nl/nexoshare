// frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'system-ui', 'sans-serif'],
      },
      colors: {
        app: {
          DEFAULT: '#09090b',
          surface: '#18181b',
          elevated: '#27272a',
        },
        primary: {
          200: '#99f6e4',
          300: '#5eead4',
          400: '#2dd4bf',
          500: '#14b8a6',
          DEFAULT: '#0d9488',
          700: '#0f766e',
          800: '#115e59',
          950: '#042f2e',
        },
      },
      boxShadow: {
        'glow-primary': '0 12px 40px -12px rgba(13, 148, 136, 0.35)',
      },
    },
  },
  plugins: [],
}
