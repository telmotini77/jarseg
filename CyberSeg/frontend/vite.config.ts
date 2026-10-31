import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// In development the API runs on 127.0.0.1:8780; production uses the nginx proxy.
const backend = { target: 'http://127.0.0.1:8780', changeOrigin: true };

export default defineConfig({
  plugins: [react()],
  server: { host: '0.0.0.0', port: 5178, proxy: { '/api': backend, '/health': backend, '/socket.io': { ...backend, ws: true } } },
});
