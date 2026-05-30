import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

// Browser performance measurement (`npm run bench:browser`). Kept out of the CI
// smoke run because it is timing-sensitive and slower.
export default defineConfig({
  server: {
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  test: {
    include: ['browser-test/perf.bench.ts'],
    testTimeout: 120_000,
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: 'chromium' }],
    },
  },
});
