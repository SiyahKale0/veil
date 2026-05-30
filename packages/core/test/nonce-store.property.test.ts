import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { InMemoryNonceStore } from '../src/index.js';

describe('nonce store properties', () => {
  it('consumes an issued nonce exactly once', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 10 }), async (replays) => {
        const store = new InMemoryNonceStore();
        const nonce = await store.issue();
        expect(await store.consume(nonce)).toBe(true);
        for (let i = 0; i < replays; i += 1) {
          expect(await store.consume(nonce)).toBe(false);
        }
      }),
      { numRuns: 30 },
    );
  });

  it('rejects any nonce it never issued', async () => {
    const store = new InMemoryNonceStore();
    await fc.assert(
      fc.asyncProperty(fc.string(), async (value) => {
        expect(await store.consume(value)).toBe(false);
      }),
      { numRuns: 50 },
    );
  });
});
