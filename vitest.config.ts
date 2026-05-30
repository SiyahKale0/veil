import { defineConfig } from 'vitest/config';

// Node test run (`npm test`). Browser-only smoke tests are excluded here and run
// separately via `npm run test:browser`.
export default defineConfig({
  test: {
    exclude: ['**/node_modules/**', '**/dist/**', '**/*.browser.test.ts'],
  },
});
