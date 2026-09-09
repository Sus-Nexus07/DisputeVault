import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/test/**/*.test.ts'],
    environment: 'node',
    // Security tests must never be silently skipped.
    passOnNoTests: false,
    allowOnly: false,
  },
});
