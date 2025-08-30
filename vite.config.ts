import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
  },
  plugins: [
    react(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          // Vendor chunks
          'react-vendor': ['react', 'react-dom'],
          'ui-vendor': ['@radix-ui/react-dialog', '@radix-ui/react-select', '@radix-ui/react-tabs'],
          'monaco': ['@monaco-editor/react', 'monaco-editor'],
          'crypto': ['crypto-js'],
          
          // Feature chunks
          'analytics': ['src/lib/analytics.ts'],
          'llm-service': ['src/lib/llm-service.ts'],
          'recovery': ['src/lib/recovery-service.ts'],
          'storage': ['src/lib/secure-storage.ts']
        }
      }
    },
    chunkSizeWarningLimit: 1000,
    sourcemap: mode === 'development'
  },
  optimizeDeps: {
    include: ['react', 'react-dom'],
    exclude: ['@monaco-editor/react']
  }
}));
