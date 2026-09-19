# Canary

A release canary that **exercises the entire public exports map of the
packaged library** and **flags breaking changes** — in runtime behavior, in
the CommonJS build, and in the TypeScript types.

Any change to the canary files should be grounds for reporting a breaking change. Please see ../Contributing.md for the
contribution process.

It does *not* test the local source. It unpacks the `pnpm pack` tarball and
imports/`require`s it the way a real consumer would, so it catches
breakage in the **published artifact** (including its `exports` map and its
dependencies), not just in `src`.

## Why three canaries

The package ships both an ESM build and a CommonJS build, and consumers use
them differently. A single runner cannot exercise both, so the suite is split:

| Canary           | Runner            | What it proves                                                             |
|------------------|-------------------|----------------------------------------------------------------------------|
| `canary.esm.ts`  | `tsx` (ESM)       | The ESM build loads, and **all ~47 named exports** are present and behave. |
| `canary.cjs.cjs` | `node` (CommonJS) | The **CommonJS build loads** and its core functions behave.                |
| `type-check.ts`  | `tsc --noEmit`    | The published **`.d.ts` is compatible** with the expected API.             |

- The **ESM canary** is exhaustive (every named export) and run under `tsx`.
- The **CJS canary must run under Node's CommonJS loader**, not `tsx`/ESM:
  a tsx/ESM process cannot reach the `require()` code path, which is exactly
  the path that breaks (see below).
- **tsx only does a syntax check — it does not type-check.** Type-checking the
  packed `.d.ts` is a separate `tsc --noEmit` pass, so type breakage is caught
  explicitly.

## Usage

```bash
pnpm pack                       # produce did-jwt-<version>.tgz
pnpm canary                     # unpack + run all three (exits non-zero on any failure)
```

Or individually:

```bash
pnpm canary:unpack              # install the tarball + its deps into canary/consumer/
pnpm canary:esm                 # tsx runtime canary (ESM)
pnpm canary:cjs                 # node runtime canary (CommonJS)
pnpm canary:types               # tsc --noEmit type-check against the packed .d.ts
```

`canary:unpack` installs the tarball via `npm` into `canary/consumer/`, so the
package's `exports` map and its dependencies resolve exactly as a published
consumer would see them.

## What it checks

- **Export map** — every named export is present (a removed/renamed export is
  a breaking change).
- **Deterministic goldens** — `createJWS` (plain + canonicalized) and the
  signer outputs are goldened; these are stable across dependency upgrades.
- **Round-trips** — `createJWT` → `verifyJWT` (network-free, via a fake
  resolver + pinned `policies.now`), `decodeJWT`, `verifyJWS`, and JWE
  `createJWE`/`decryptJWE` round-trips across the direct, authenticated (ECDH-1PU + XC20PKW) and anonymous (ECDH-ES +
  XC20PKW) encrypters.
- **Constructors** — `createX25519ECDH`, `createX25519EcdhEsKek`,
  `createFullEncrypter`, `extractPublicKeyBytes`, `genX25519EphemeralKeyPair`.
- **Constants** — `supportedCodecs`, `JWT_ERROR`.
- **Error contracts** — `verifyJWT` rejects a mismatched key with
  `invalid_signature`; `createJWT` rejects an unsupported `alg`.
- **Types** — `tsc --noEmit` over a consumer that imports the package by name.
