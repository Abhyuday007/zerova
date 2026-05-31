import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/auth': 'http://localhost:8000',
      '/vault': 'http://localhost:8000',
      '/webauthn': 'http://localhost:8000',
    }
  }
})
