import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

// Real-browser smoke tests in headless Chromium (`npm run test:browser`). This
// exercises the bundler + WASM path that the Node run cannot cover.
export default defineConfig({
  server: {
    // Some WASM libraries use threads (SharedArrayBuffer), which needs cross-origin
    // isolation. Harmless when unused.
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  test: {
    include: ['browser-test/**/*.browser.test.ts'],
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: 'chromium' }, { browser: 'firefox' }, { browser: 'webkit' }],
    },
  },
});
