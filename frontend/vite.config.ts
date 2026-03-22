import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Dev: start de backend apart (standaard poort 3001, zie backend/src/index.ts). Zonder draaiende API
// geeft Vite ECONNREFUSED op /api en /site.webmanifest — dat is verwacht gedrag.
// Optioneel: VITE_PROXY_TARGET=http://127.0.0.1:3001 in frontend/.env.local
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const proxyTarget = env.VITE_PROXY_TARGET || 'http://127.0.0.1:3001'

  return {
    plugins: [react()],
    server: {
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
          secure: false,
        },
        '/site.webmanifest': {
          target: proxyTarget,
          changeOrigin: true,
          secure: false,
        },
      },
    },
  }
})