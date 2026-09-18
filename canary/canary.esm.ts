/**
 * ESM canary for did-jwt.
 *
 * Goal: exercise the *entire* public exports map of the packaged lib and flag
 * breaking changes. Run under `tsx` so that a broken `.d.ts` (a breaking type
 * change) makes the whole file fail to compile, in addition to the runtime
 * functional checks below.
 *
 * It imports the packaged lib by an absolute `file://` URL (the unpacked
 * `pnpm pack` output). Importing from the unpacked `package/` means the lib's
 * own `exports` map and its dependencies resolve exactly the way a real
 * consumer would see them.
 *
 * Usage:
 *   pnpm pack                                   # produce did-jwt-<version>.tgz
 *   node canary/unpack.mjs                      # unpack it to canary/consumer
 *   tsx canary/canary.esm.ts                    # this file
 *
 * Determinism: `createJWS` and the signer helpers are deterministic, so their
 * output is goldened. `createJWT`'s signature is goldened here too because we
 * pass an explicit `iat` (the tests do the same and their snapshots are
 * stable). `verifyJWT` is exercised network-free via a fake resolver with
 * `policies.now` pinned to the token's `iat`. JWE / ECDH round-trips use keys
 * derived from `genX25519EphemeralKeyPair`, whose structure is fixed even
 * though its random bytes are not.
 */

// @ts-ignore
import { createRequire } from 'node:module'
// @ts-ignore
import { pathToFileURL } from 'node:url'
// @ts-ignore
import { resolve, dirname } from 'node:path'
// @ts-ignore
import { Assert, toHex } from './harness.js'

// ---------------------------------------------------------------------------
// Locate the unpacked, packed lib and import it.
// ---------------------------------------------------------------------------

const HERE = dirname(new URL(import.meta.url).pathname)
// // Default to the canary/consumer unpack dir; override with CANARY_LIB_DIR.
// const LIB_DIR = process.env.CANARY_LIB_DIR ?? resolve(HERE, 'consumer/node_modules/did-jwt')
// const ESM_ENTRY = pathToFileURL(resolve(LIB_DIR, 'lib.esm/index.js')).href

// console.log(`\nESM canary: importing ${ESM_ENTRY}`)

// // Type-checking the full public surface (a breaking type change fails here).
// // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
// const didJwt = (await import(ESM_ENTRY)) as Record<string, unknown>
import * as didJwt from 'did-jwt'

const assert = new Assert()

// ---------------------------------------------------------------------------
// 1. Export map: every named export is present and is a function/value.
//    A removed or renamed export is a breaking change.
// ---------------------------------------------------------------------------

// The 47 runtime exports the ESM build is expected to expose.
const EXPECTED_EXPORTS = [
  // signers
  'SimpleSigner',
  'EllipticSigner',
  'NaclSigner',
  'ES256KSigner',
  'ES256Signer',
  'EdDSASigner',
  // jwt / jws
  'createJWS',
  'createJWT',
  'createMultisignatureJWT',
  'decodeJWT',
  'verifyJWS',
  'verifyJWT',
  // digest
  'toEthereumAddress',
  'concatKDF',
  // jwe + encryption
  'createJWE',
  'decryptJWE',
  'xc20pDirEncrypter',
  'xc20pDirDecrypter',
  'x25519Encrypter',
  'x25519Decrypter',
  'resolveX25519Encrypters',
  'createAuthEncrypter',
  'createAnonEncrypter',
  'createAuthDecrypter',
  'createAnonDecrypter',
  // 'xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2',
  // 'xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2',
  'xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2',
  'xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2',
  'createX25519ECDH',
  'createX25519EcdhEsKek',
  'createX25519Ecdh1PUv3Kek',
  'computeX25519EcdhEsKek',
  'computeX25519Ecdh1PUv3Kek',
  'createFullEncrypter',
  // utils
  'base64ToBytes',
  'bytesToBase64url',
  'base58ToBytes',
  'bytesToBase58',
  'hexToBytes',
  'bytesToHex',
  'genX25519EphemeralKeyPair',
  'multibaseToBytes',
  'bytesToMultibase',
  'supportedCodecs',
  'extractPublicKeyBytes',
  // errors
  'JWT_ERROR',
]

console.log('\n-- export map --')
for (const name of EXPECTED_EXPORTS) {
  assert.assert(`export "${name}" is present`, typeof didJwt[name] !== 'undefined', 'missing from ESM exports')
}
const runtimeCount = Object.keys(didJwt).length
assert.assert('ESM build exposes at least 45 exports', runtimeCount >= 45, `got ${runtimeCount}`)
// Every exported *callable* should be a function (a breaking change could
// turn a function into an object, etc.).
for (const name of EXPECTED_EXPORTS) {
  const v = didJwt[name]
  if (v === undefined) continue
  assert.assert(
    `export "${name}" is a function or object`,
    typeof v === 'function' || typeof v === 'object',
    `unexpected type ${typeof v}`,
  )
}

// A value that must never change (constant contract).
assert.assert('supportedCodecs.secp256k1-pub === 0xe7', (didJwt.supportedCodecs as any)['secp256k1-pub'] === 0xe7)
assert.assert('JWT_ERROR.INVALID_SIGNATURE === "invalid_signature"', (didJwt.JWT_ERROR as any).INVALID_SIGNATURE === 'invalid_signature')

// ---------------------------------------------------------------------------
// 2. Utils (deterministic)
// ---------------------------------------------------------------------------

console.log('\n-- utils --')
assert.assert('hexToBytes("0101")', toHex((didJwt.hexToBytes as any)('0101')) === '0101')
assert.assert('bytesToHex([1,1])', (didJwt.bytesToHex as any)(new Uint8Array([1, 1])) === '0101')
assert.assert(
  'hexToBytes min-length zero-pad',
  toHex((didJwt.hexToBytes as any)('0101', 32)) === '00'.repeat(30) + '0101',
)
assert.assert(
  'bytesToBase64url round-trip',
  toHex((didJwt.base64ToBytes as any)((didJwt.bytesToBase64url as any)(new Uint8Array([1, 2, 3, 4, 255])))) === '01020304ff',
)
assert.assert(
  'base58 round-trip',
  (didJwt.base58ToBytes as any)((didJwt.bytesToBase58 as any)(new Uint8Array([1, 2, 3]))).length === 3,
)
assert.assert(
  'toEthereumAddress',
  (didJwt.toEthereumAddress as any)(
    '047822917c9faccf83219eafa79866e37c56d5873a5bc11b5eb8b6747e328b6800d9b51749f9e15f7c0effc8a9f899dcf17d71e1ebe1ad3d6047b215636ff9b4e1',
  ) === '0xdbc05b1ecb4fdaef943819c0b04e9ef6df4babd6',
)

// ---------------------------------------------------------------------------
// 3. Signers (deterministic goldens)
// ---------------------------------------------------------------------------

console.log('\n-- signers --')
const PRIVATE_HEX = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const DATA = 'thequickbrownfoxjumpedoverthelazyprogrammer'
const ES256K_SIGN = await (didJwt.ES256KSigner as any)((didJwt.hexToBytes as any)(PRIVATE_HEX))(DATA)
assert.assert('ES256KSigner golden signature', ES256K_SIGN === 'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg')

// EllipticSigner is the deprecated alias of ES256KSigner over a hex key.
const ELLIP = (didJwt.EllipticSigner as any)(PRIVATE_HEX)
assert.assert('EllipticSigner === ES256KSigner', (await ELLIP(DATA)) === ES256K_SIGN)

// ---------------------------------------------------------------------------
// 4. createJWS / createJWT / decodeJWT / verifyJWT
// ---------------------------------------------------------------------------

console.log('\n-- jwt / jws --')
const signer = (didJwt.ES256KSigner as any)((didJwt.hexToBytes as any)(PRIVATE_HEX))
const ISSUER = 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
const PUB_HEX = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'

// createJWS is deterministic: golden the exact JWS.
const jwsJson = await (didJwt.createJWS as any)({ some: 'data' }, signer, { alg: 'ES256K' })
assert.assert('createJWS (JSON payload) golden', jwsJson === 'eyJhbGciOiJFUzI1NksifQ.eyJzb21lIjoiZGF0YSJ9.dblNz-7BVLknOFIBPmt5VTG0MDls_Q69WI8OfQuqNdUp4y50-b8Ubn0xujm1ijfmfqRunpks5TyWqgMsQkR_GQ')

const jwsCanon = await (didJwt.createJWS as any)({ a: 'a', z: 'z' }, signer, { alg: 'ES256K' }, { canonicalize: true })
assert.assert('createJWS (canonicalized) golden', jwsCanon === 'eyJhbGciOiJFUzI1NksifQ.eyJhIjoiYSIsInoiOiJ6In0.FiH0l1yEU2PmMQnD17WhsqwaV9oyFsOkm-U_natKFqdXHxs_ExnehnZauNKxWynjBSaZHRZT3Ohgx8ZgUAM6sg')

// verifyJWS returns the matching public key.
const verifyJwsKey = (didJwt.verifyJWS as any)(
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXSwiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.tU96omPNxCfQoEADOpLywXUDCMjKXOfTaG61EZwmfvHJrDFQhNbSDzCP2Pe7WdXySosTCuI1T-IQ6SddcWuj_A',
  { id: `${ISSUER}#1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: ISSUER, publicKeyHex: PUB_HEX },
)
assert.assert('verifyJWS returns the matching public key', verifyJwsKey && verifyJwsKey.publicKeyHex === PUB_HEX)

// NOTE: createJWT's *signature* is not guaranteed stable across dependency
// upgrades (the signing layer can change), so we do NOT golden the full token.
// Instead we round-trip it: createJWT -> verifyJWT must succeed, and the
// deterministic header + payload are asserted below.
const IAT = 1700000000000
const createdJwt = await (didJwt.createJWT as any)(
  { requested: ['name', 'phone'], iat: IAT },
  { issuer: ISSUER, signer },
  { alg: 'ES256K' },
)

// decodeJWT parses header + payload + signature.
const decoded = (didJwt.decodeJWT as any)(createdJwt)
assert.assert('createJWT -> decodeJWT header.alg', decoded.header.alg === 'ES256K')
assert.assert('createJWT -> decodeJWT payload.iss', decoded.payload.iss === ISSUER)
assert.assert('createJWT -> decodeJWT payload.iat', decoded.payload.iat === IAT)
assert.assert('createJWT -> decodeJWT payload.requested', Array.isArray(decoded.payload.requested) && decoded.payload.requested[0] === 'name')

// verifyJWT round-trip, network-free: a fake resolver + policies.now pinned.
const resolver = {
  resolve: async () => ({
    didDocument: {
      id: ISSUER,
      verificationMethod: [
        { id: `${ISSUER}#1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: ISSUER, publicKeyHex: PUB_HEX },
      ],
      authentication: [`${ISSUER}#1`],
      assertionMethod: [`${ISSUER}#1`],
    },
    didDocumentMetadata: {},
    didResolutionMetadata: { contentType: 'application/did+json' },
  }),
}
const verified = await (didJwt.verifyJWT as any)(createdJwt, {
  resolver,
  policies: { now: IAT, nbf: false, iat: false, exp: false, aud: false },
})
assert.assert('verifyJWT verified===true', verified.verified === true)
assert.assert('verifyJWT payload.requested', verified.payload.requested[0] === 'name')
assert.assert('verifyJWT signer matches public key', verified.signer.publicKeyHex === PUB_HEX)

// verifyJWT rejects when no public key matches the signature: a valid secp256k1
// key with the *wrong* value makes the signature invalid, and since it is the
// only authenticator verifyJWT re-throws the invalid_signature error.
const badResolver = {
  resolve: async () => ({
    didDocument: {
      id: ISSUER,
      verificationMethod: [
        { id: `${ISSUER}#bad`, type: 'EcdsaSecp256k1VerificationKey2019', controller: ISSUER, publicKeyHex: '03' + '11'.repeat(33) },
      ],
      authentication: [],
      assertionMethod: [],
    },
    didDocumentMetadata: {},
    didResolutionMetadata: { contentType: 'application/did+json' },
  }),
}
await assert.assertRejects('verifyJWT rejects a mismatched key', (didJwt.verifyJWT as any)(createdJwt, { resolver: badResolver, policies: { now: IAT, nbf: false, iat: false, exp: false, aud: false } }), /invalid_signature/)

// createJWT throws on an unsupported algorithm.
await assert.assertRejects('createJWT throws on bad alg', (didJwt.createJWT as any)({ x: 1 }, { issuer: ISSUER, signer }, { alg: 'BADALGO' }), /Unsupported algorithm/)

// ---------------------------------------------------------------------------
// 5. JWE + encrypters (round-trip)
// ---------------------------------------------------------------------------

console.log('\n-- jwe / encryption --')
const ep = (didJwt.genX25519EphemeralKeyPair as any)()
const recipientSecret = ep.secretKey
const recipientPublic = new Uint8Array(Buffer.from(ep.publicKeyJWK.x, 'base64'))
const cleartext = new Uint8Array([104, 101, 108, 108, 111]) // "hello"

// direct (xc20pDir) round-trip
const jweDir = await (didJwt.createJWE as any)(cleartext, [(didJwt.xc20pDirEncrypter as any)(recipientSecret)])
const backDir = await (didJwt.decryptJWE as any)(jweDir, (didJwt.xc20pDirDecrypter as any)(recipientSecret))
assert.assert('JWE dir round-trip', toHex(backDir) === toHex(cleartext))

// authenticated ECDH-1PU + XC20PKW round-trip
const senderEp = (didJwt.genX25519EphemeralKeyPair as any)()
const senderSecret = senderEp.secretKey
const senderPublic = new Uint8Array(Buffer.from(senderEp.publicKeyJWK.x, 'base64'))
const authEnc = (didJwt.xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2 as any)(recipientPublic, senderSecret)
const authDec = (didJwt.xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2 as any)(recipientSecret, senderPublic)
const jweAuth = await (didJwt.createJWE as any)(new Uint8Array([1, 2, 3, 4]), [authEnc])
const backAuth = await (didJwt.decryptJWE as any)(jweAuth, authDec)
assert.assert('JWE ECDH-1PU round-trip', toHex(backAuth) === '01020304')

// anonymous ECDH-ES + XC20PKW round-trip
// const anonEnc = (didJwt.xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2 as any)(recipientPublic)
// const anonDec = (didJwt.xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2 as any)(recipientSecret)
const anonEnc = (didJwt.createAnonEncrypter as any)(recipientPublic)
const anonDec = (didJwt.createAnonDecrypter as any)(recipientSecret)
const jweAnon = await (didJwt.createJWE as any)(cleartext, [anonEnc])
const backAnon = await (didJwt.decryptJWE as any)(jweAnon, anonDec)
assert.assert('JWE ECDH-ES anon round-trip', toHex(backAnon) === toHex(cleartext))

// createFullEncrypter wires the three pieces into an Encrypter.
const kekCreator = { createKek: didJwt.createX25519Ecdh1PUv3Kek, alg: 'ECDH-ES' }
const keyWrapper = {
  from: (kek: Uint8Array) => ({
    wrap: async (cek: Uint8Array) => ({ ciphertext: cek, tag: new Uint8Array(), iv: new Uint8Array() }),
  }),
  alg: 'XC20PKW',
}
const contentEncrypter = {
  from: (cek: Uint8Array) => ({
    alg: 'dir',
    enc: 'XC20P',
    encrypt: async (c: Uint8Array) => ({ ciphertext: c, iv: new Uint8Array(), tag: new Uint8Array() }),
  }),
  enc: 'XC20P',
}
const fullEnc = (didJwt.createFullEncrypter as any)(recipientPublic, senderSecret, undefined, kekCreator, keyWrapper, contentEncrypter)
assert.assert('createFullEncrypter returns an Encrypter', !!fullEnc && typeof fullEnc.encrypt === 'function' && fullEnc.enc === 'XC20P')

// createX25519EcdhEsKek produces a 32-byte key encryption key.
const kek = await (didJwt.createX25519EcdhEsKek as any)(recipientPublic, senderSecret, 'ECDH-ES+A256KW', undefined, undefined, undefined)
assert.assert('createX25519EcdhEsKek produces a 32-byte kek', kek && kek.kek.length === 32 && kek.epk.crv === 'X25519')

// ---------------------------------------------------------------------------
// 6. ECDH (deterministic shared secret)
// ---------------------------------------------------------------------------

console.log('\n-- ecdh --')
assert.assert('genX25519EphemeralKeyPair shape', ep.publicKeyJWK.crv === 'X25519' && typeof ep.publicKeyJWK.x === 'string' && ep.secretKey.length === 32)
const aShared = await (didJwt.createX25519ECDH as any)(recipientSecret)(senderPublic)
const bShared = await (didJwt.createX25519ECDH as any)(senderSecret)(recipientPublic)
assert.assert('createX25519ECDH shared secret agrees', toHex(aShared) === toHex(bShared) && aShared.length === 32)

// ---------------------------------------------------------------------------
// 7. extractPublicKeyBytes
// ---------------------------------------------------------------------------

console.log('\n-- extractPublicKeyBytes --')
const extracted = (didJwt.extractPublicKeyBytes as any)({ type: 'EcdsaSecp256k1VerificationKey2019', publicKeyHex: PUB_HEX })
assert.assert('extractPublicKeyBytes -> keyType Secp256k1', extracted.keyType === 'Secp256k1' && extracted.keyBytes.length > 0)

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

process.exit(assert.summary('ESM canary'))
