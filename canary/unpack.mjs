/**
 * Install the current `pnpm pack` tarball into canary/consumer/ the way a
 * real consumer would (via npm), so the package's `exports` map and its
 * dependencies resolve exactly as a published consumer would see them.
 *
 * `npm install <tarball>` places the lib at canary/consumer/node_modules/did-jwt
 * and installs its dependencies (resolving `canonicalize@^5` etc. for it),
 * which is what lets the ESM and CJS canaries import the *packed* lib rather
 * than the local source. It also writes the consumer's package.json +
 * tsconfig.json so a `tsc --noEmit` type-check resolves `did-jwt`'s
 * `.d.ts` the way a real consumer would.
 *
 * Usage: node canary/unpack.mjs
 *
 * Env: CANARY_TARBALL can point at a specific .tgz (defaults to the latest
 *      did-jwt-*.tgz in the repo root, as produced by `pnpm pack`).
 */

import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync } from 'node:fs'
import { rm, mkdir, writeFile } from 'node:fs/promises'
import { join, resolve, dirname } from 'node:path'

const HERE = dirname(new URL(import.meta.url).pathname)
const root = resolve(HERE, '..')
const consumerDir = join(HERE, 'consumer')

// find the tarball
const tarball =
  process.env.CANARY_TARBALL ||
  readdirSync(root)
    .filter((f) => /^did-jwt-.*\.tgz$/.test(f))
    .sort()
    .pop()

if (!tarball) {
  console.error('No did-jwt-*.tgz found. Run `pnpm pack` first, or set CANARY_TARBALL.')
  process.exit(1)
}
console.log(`Using tarball: ${tarball}`)

// fresh consumer dir
await rm(consumerDir, { recursive: true, force: true })
await mkdir(consumerDir, { recursive: true })

// a minimal consumer that pulls in the tarball + its dependencies.
await writeFile(
  join(consumerDir, 'package.json'),
  JSON.stringify({ name: 'did-jwt-canary-consumer', private: true, version: '0.0.0' }, null, 2),
)
await writeFile(
  join(consumerDir, 'tsconfig.json'),
  JSON.stringify(
    {
      compilerOptions: {
        target: 'es2024',
        module: 'nodenext',
        moduleResolution: 'nodenext',
        strict: true,
        skipLibCheck: true,
        noEmit: true,
        types: [],
        lib: ['es2024'],
      },
      include: ['type-check.ts'],
    },
    null,
    2,
  ),
)
console.log('Installing the packaged lib + its dependencies (npm)...')
execFileSync('npm', ['install', join(root, tarball), '--no-audit', '--no-fund'], {
  cwd: consumerDir,
  stdio: 'inherit',
})

// The type-check entry: imports the package by name and exercises a slice of
// the public API's *types*. A breaking type change makes `tsc --noEmit` fail.
// Copy the authoritative type-check canary from canary/ into the installed
// consumer location, so `tsc --noEmit` type-checks the packaged .d.ts the
// same way a real consumer would. Editing canary/type-check.ts is
// enough; no need to duplicate its content here.
await writeFile(
  join(consumerDir, 'type-check.ts'),
  readFileSync(join(HERE, 'type-check.ts'), 'utf-8'),
)

console.log(`\nInstalled the packaged lib + deps into ${consumerDir}`)
console.log('  ESM entry : canary/consumer/node_modules/did-jwt/lib.esm/index.js')
console.log('  CJS entry : canary/consumer/node_modules/did-jwt/lib.commonjs/index.js')
console.log('  type-check: cd canary/consumer && tsc --noEmit  (see package.json "canary:types")')
