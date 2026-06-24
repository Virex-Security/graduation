import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: parseInt(process.env.VITE_DEV_PORT || '3000'),
    proxy: {
      // All /api requests in dev are forwarded to the Flask API server.
      // Override VITE_API_TARGET in your shell if the API runs elsewhere.
      '/api': {
        target: process.env.VITE_API_TARGET || 'http://127.0.0.1:5000',
        changeOrigin: true,
        secure: false,
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,   // disable sourcemaps in production builds
    rollupOptions: {
      output: {
        // Code-split by route for better load performance
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          charts: ['chart.js', 'react-chartjs-2'],
        }
      }
    }
  }
})
