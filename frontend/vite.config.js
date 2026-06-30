import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // Required for @stellar/stellar-sdk — it uses Node built-ins (Buffer, process)
    // that aren't available natively in the browser.
    nodePolyfills({
      globals: {
        Buffer: true,
        process: true,
        global: true,
      },
      protocolImports: true,
    }),
  ],
  resolve: {
    alias: {
      // Ensure browser-compatible crypto for stellar-sdk
      stream: 'stream-browserify',
    },
  },
  define: {
    // Suppress "global is not defined" errors from older Stellar SDK internals
    'global': 'globalThis',
  },
  build: {
    // stellar-sdk XDR types are large; raise the warning limit
    chunkSizeWarningLimit: 1500,
  },
});
