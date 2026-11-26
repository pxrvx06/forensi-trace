import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/health': 'http://127.0.0.1:8000',
      '/events': 'http://127.0.0.1:8000',
      '/timeline': 'http://127.0.0.1:8000',
      '/activities': 'http://127.0.0.1:8000',
      '/report': 'http://127.0.0.1:8000',
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './tests/setupTests.js',
  },
});
