import { defineConfig } from 'vitest/config'

// Vitest (Vite/rolldown) natively resolves the source tree's `.js` relative
// import specifiers (TypeScript's "rewrite relative import specifiers" pattern,
// used for the ESM/webpack build) to their `.ts` source files, so no custom
// resolve plugin is needed. Jest previously handled this with a
// `moduleNameMapper`; the equivalent is no longer required here.
export default defineConfig({
  test: {
    // Mirrors the old Jest config: testEnvironment 'node' + the same testMatch.
    testEnvironment: 'node',
    // Tests are written with global describe/it/expect/beforeEach (like Jest's
    // default), so expose them as globals. `vi` is also injected this way.
    globals: true,
    include: ['**/__tests__/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts', 'src/**/*.mts'],
      // Exclude test files and ambient type declarations. `.d.ts` files have no
      // runtime code, and the V8 provider's AST parser can't parse their
      // `declare module { ... }` syntax, so we skip them from coverage.
      exclude: ['src/__tests__/**', '**/*.d.ts'],
    },
  },
})
