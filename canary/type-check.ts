/**
 * Type-check canary for did-jwt.
 *
 * Compiled with `tsc --noEmit` (see the consumer's tsconfig.json) against the
 * PACKAGED `.d.ts`, so any breaking change to the published types — a removed
 * export, a renamed option, a changed parameter, or a changed shape of an
 * exported type OR one of its *unexported* subtypes/sub-properties — makes
 * this file fail to compile.
 *
 * It is the complement of the runtime canaries (`canary.esm.ts`,
 * `canary.cjs.cjs`), which can only observe runtime values. A type-only
 * breaking change (e.g. a `@deprecated` flag, a removed field, or a widened
 * signature) is invisible to the runtime canaries, so only `tsc` catches it.
 *
 * NOTE: this file is NOT run at runtime — it is only type-checked. The
 * `void`/`await` statements exist so every binding and helper is "used";
 * `tsc` type-checks them, it never executes them.
 */

// --- runtime bindings: exercised so the import is non-trivial; `void` keeps
//     tsc quiet about unused locals. They are never executed at runtime. ---
import * as didJwt from 'did-jwt'

void didJwt.hexToBytes

// --- exported values (runtime presence) ---
import {
  createJWT,
  verifyJWT,
  createJWS,
  verifyJWS,
  createMultisignatureJWT,
  decodeJWT,
  ES256KSigner,
  ES256Signer,
  EdDSASigner,
  EllipticSigner,
  SimpleSigner,
  NaclSigner,
  createJWE,
  decryptJWE,
  createX25519ECDH,
  createX25519EcdhEsKek,
  createX25519Ecdh1PUv3Kek,
  computeX25519EcdhEsKek,
  computeX25519Ecdh1PUv3Kek,
  createFullEncrypter,
  resolveX25519Encrypters,
  x25519Encrypter,
  x25519Decrypter,
  createAuthEncrypter,
  createAnonEncrypter,
  createAuthDecrypter,
  createAnonDecrypter,
  xc20pDirEncrypter,
  xc20pDirDecrypter,
  xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2,
  xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2,
  xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2,
  xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2,
  supportedCodecs,
  JWT_ERROR,
} from 'did-jwt'

// --- exported types ---
import type {
  Signer,
  JWTOptions,
  JWTVerifyOptions,
  JWTVerifyPolicies,
  JWSDecoded,
  JWTHeader,
  JWTPayload,
  JWTVerified,
  ECDH,
  EphemeralKeyPair,
  EphemeralPublicKey,
  Recipient,
  RecipientHeader,
  JWE,
  Encrypter,
  Decrypter,
  KekCreator,
  KeyWrapper,
  ContentEncrypter,
  ProtectedHeader,
  AuthEncryptParams,
  AnonEncryptParams,
} from 'did-jwt'

// --- unexported subtypes reachable through the exported types (from
//     did-resolver, a transitive dependency of did-jwt) ---
import type { DIDDocument, DIDResolutionResult, VerificationMethod } from 'did-resolver'

// --- helpers (type-only; the bodies are never executed at runtime) ---

/** Assert `value` has exactly type `T` (a breaking type change makes this fail). */
function expectType<T>(value: T): T {
  return value
}

// ---------------------------------------------------------------------------
// JWTHeader / JWTPayload — exercise index signatures and known fields
// ---------------------------------------------------------------------------

const header: JWTHeader = {
  typ: 'JWT',
  alg: 'ES256K',
  // index signature allows arbitrary extra fields
  kid: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#k',
  nonce: 'abc',
}
expectType<JWTHeader>(header)
expectType<JWTHeader['alg']>(header.alg)
expectType<string>(header.nonce) // index-signature member

const payload: JWTPayload = {
  iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
  sub: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
  aud: 'did:example:aud',
  iat: 1700000000000,
  nbf: 1700000000000,
  exp: 1700000000000 + 3600,
  rexp: 1700000000000,
  requested: ['name', 'phone'],
  // index signature
  arbitrary: { nested: 1 },
}
expectType<JWTPayload>(payload)
expectType<number | undefined>(payload.iat)
expectType<string | string[] | undefined>(payload.aud)
expectType<string | undefined>(payload.iss)

// ---------------------------------------------------------------------------
// Signer + the create/verify method-parameter surface
// ---------------------------------------------------------------------------

const signer: Signer = ES256KSigner(didJwt.hexToBytes('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))
expectType<Signer>(signer)

// createJWT: options object with a DEPRECATED `alg` (must still type-check),
// `expiresIn`, `canonicalize`, plus a partial `header` — a breaking change to
// any of these is caught here.
const options: JWTOptions = {
  issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
  signer,
  alg: 'ES256K', // @deprecated but still part of JWTOptions
  expiresIn: 3600,
  canonicalize: true,
}
expectType<JWTOptions>(options)
expectType<Promise<string>>(
  createJWT(payload, options, { alg: 'ES256K', typ: 'JWT' }),
)
const created = createJWT(payload, { issuer: 'did:ethr:0x', signer }, { alg: 'ES256K' })
created.then((jwt) => {
  const decoded = decodeJWT(jwt)
  // JWTDecoded is an unexported subtype reachable via the runtime surface
  expectType<JWTHeader>(decoded.header)
  expectType<JWTPayload>(decoded.payload)
  expectType<string>(decoded.signature)
})

// verifyJWT: a full JWTVerifyOptions exercising every field, including the
// DEPRECATED `auth` and the `audience` / `callbackUrl` / `skewTime` /
// `proofPurpose` / `didAuthenticator` parameters.
const verifyOptions: JWTVerifyOptions = {
  resolver: {
    resolve: async () => ({
      didDocument: {
        id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
        verificationMethod: [
          {
            id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#k',
            type: 'EcdsaSecp256k1VerificationKey2019',
            controller: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
            publicKeyHex: '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479',
          },
        ],
        authentication: ['did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#k'],
        assertionMethod: ['did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#k'],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+json' },
    }),
  },
  auth: false, // @deprecated
  audience: 'did:example:aud',
  callbackUrl: 'https://example.com/callback',
  skewTime: 300,
  proofPurpose: 'assertionMethod',
  policies: {
    now: 1700000000,
    nbf: false,
    iat: false,
    exp: false,
    aud: false,
  },
  didAuthenticator: {
    authenticators: [
      {
        id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#k',
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
        publicKeyHex: '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479',
      },
    ],
    issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    didResolutionResult: {
      didDocument: {
        id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+json' },
    },
  },
}
expectType<JWTVerifyOptions>(verifyOptions)
expectType<Promise<JWTVerified>>(verifyJWT('a.b.c', verifyOptions))

// JWTVerified — exercise the shape of its UNEXPORTED sub-properties
// (VerificationMethod, DIDResolutionResult, and the JWTVerifyPolicies echo).
const verified = createJWT(payload, { issuer: 'did:ethr:0x', signer }).then((jwt) =>
  verifyJWT(jwt, { resolver: verifyOptions.resolver }),
)
verified.then((result) => {
  expectType<JWTVerified>(result)
  expectType<true>(result.verified) // literal `true`, not `boolean`
  expectType<string>(result.issuer)
  expectType<string>(result.jwt)
  // signer is a VerificationMethod (from did-resolver) — an unexported subtype
  expectType<VerificationMethod>(result.signer)
  expectType<string>(result.signer.id)
  expectType<string | undefined>(result.signer.type)
  expectType<string | undefined>(result.signer.publicKeyHex)
  // didResolutionResult is a DIDResolutionResult — an unexported subtype,
  // whose sub-shapes DIDDocument / VerificationMethod are themselves unexported.
  expectType<DIDResolutionResult>(result.didResolutionResult)
  expectType<DIDDocument | null>(result.didResolutionResult.didDocument)
  // policies echo is optional
  expectType<JWTVerifyPolicies | undefined>(result.policies)
})

// JWSDecoded — unexported subtype; exercise via verifyJWS's input surface
const jwsDecoded: JWSDecoded = {
  header: { typ: 'JWT', alg: 'ES256K' },
  payload: 'e30',
  signature: 'abc',
  data: 'a.b.c',
}
expectType<JWSDecoded>(jwsDecoded)
expectType<JWTHeader>(jwsDecoded.header)

// ---------------------------------------------------------------------------
// Encryption types and their method-parameter surface
// ---------------------------------------------------------------------------

// A full EphemeralKeyPair: JWK public key + raw secret key.
const ephemeralKeyPair: EphemeralKeyPair = {
  publicKeyJWK: { kty: 'OKP', crv: 'X25519', x: 'abc123' },
  secretKey: new Uint8Array(32),
}
expectType<EphemeralKeyPair>(ephemeralKeyPair)
expectType<EphemeralPublicKey>(ephemeralKeyPair.publicKeyJWK)
expectType<string | undefined>(ephemeralKeyPair.publicKeyJWK.x)

// Recipient + RecipientHeader (sub-shapes reachable from JWE).
const recipient: Recipient = {
  encrypted_key: 'abc',
  header: {
    alg: 'ECDH-ES+XC20PKW',
    iv: 'iv',
    tag: 'tag',
    epk: { kty: 'OKP', crv: 'X25519', x: 'abc123' },
    kid: 'kid',
    apu: 'apu',
    apv: 'apv',
  },
}
expectType<Recipient>(recipient)
expectType<RecipientHeader>(recipient.header)
expectType<string | undefined>(recipient.header.kid)

// JWE — the full object returned by createJWE.
const jwe: JWE = {
  protected: 'prot',
  iv: 'iv',
  ciphertext: 'ct',
  tag: 'tag',
  aad: 'aad',
  recipients: [recipient],
}
expectType<JWE>(jwe)
expectType<Recipient[] | undefined>(jwe.recipients)

// A hand-written Encrypter / Decrypter (the shapes passed to / returned by
// createJWE / decryptJWE).
const encrypter: Encrypter = {
  alg: 'XC20PKW',
  enc: 'XC20P',
  encrypt: (cleartext, protectedHeader, aad, epk) =>
    Promise.resolve({
      ciphertext: cleartext,
      iv: new Uint8Array(),
      tag: new Uint8Array(),
      protectedHeader: JSON.stringify(protectedHeader),
      recipient,
    }),
  encryptCek: (cek) => Promise.resolve(recipient),
  genEpk: () => ephemeralKeyPair,
}
expectType<Encrypter>(encrypter)

const decrypter: Decrypter = {
  alg: 'ECDH-ES+XC20PKW',
  enc: 'XC20P',
  decrypt: (sealed, iv, aad, recipient) => Promise.resolve(sealed),
}
expectType<Decrypter>(decrypter)

// KekCreator / KeyWrapper / ContentEncrypter — the three pieces wired by
// createFullEncrypter.
const kekCreator: KekCreator = {
  alg: 'ECDH-ES',
  createKek: (recipientPublicKey, senderSecret, alg, apu, apv, epk) =>
    Promise.resolve({
      epk: { kty: 'OKP', crv: 'X25519', x: 'abc123' },
      kek: new Uint8Array(32),
    }),
}
expectType<KekCreator>(kekCreator)

const keyWrapper: KeyWrapper = {
  alg: 'XC20PKW',
  from: (kek) => ({
    wrap: (cek) => Promise.resolve({ ciphertext: cek, iv: new Uint8Array(), tag: new Uint8Array() }),
  }),
}
expectType<KeyWrapper>(keyWrapper)

const contentEncrypter: ContentEncrypter = {
  enc: 'XC20P',
  from: (cek) => encrypter,
}
expectType<ContentEncrypter>(contentEncrypter)

// createFullEncrypter wires the three pieces into an Encrypter.
expectType<Encrypter>(
  createFullEncrypter(
    new Uint8Array(32),
    new Uint8Array(32),
    { kid: 'kid', apu: 'apu', apv: 'apv' },
    kekCreator,
    keyWrapper,
    contentEncrypter,
  ),
)

// The named encrypter/decrypter factories + their (optionally parameterised)
// signatures. The @deprecated create*Encrypter / create*Decrypter factories
// must still type-check.
expectType<Encrypter>(createAuthEncrypter(new Uint8Array(32), new Uint8Array(32), { kid: 'kid', apu: 'a', apv: 'v' }))
expectType<Encrypter>(createAnonEncrypter(new Uint8Array(32), { apv: 'v' }))
expectType<Decrypter>(createAuthDecrypter(new Uint8Array(32), new Uint8Array(32)))
expectType<Decrypter>(createAnonDecrypter(new Uint8Array(32)))

expectType<Encrypter>(x25519Encrypter(new Uint8Array(32), 'kid', 'apv'))
expectType<Decrypter>(x25519Decrypter(new Uint8Array(32)))

expectType<Encrypter>(xc20pAnonEncrypterEcdhESx25519WithXc20PkwV2(new Uint8Array(32), { apv: 'v' }))
expectType<Decrypter>(xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2(new Uint8Array(32)))

expectType<Encrypter>(
  xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(new Uint8Array(32), new Uint8Array(32), { kid: 'kid', apu: 'a', apv: 'v' }),
)
expectType<Decrypter>(xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(new Uint8Array(32), new Uint8Array(32)))

// ECDH — the (theirPublicKey) => Promise<Uint8Array> shape that wraps a
// secret key; accepted anywhere a Uint8Array secret key is accepted.
const ecdh: ECDH = (theirPublicKey) => Promise.resolve(new Uint8Array(32))
expectType<ECDH>(ecdh)
expectType<ECDH>(createX25519ECDH(new Uint8Array(32)))

// resolveX25519Encrypters — a DID resolver + a list of DIDs.
expectType<Promise<Encrypter[]>>(
  resolveX25519Encrypters(
    ['did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'],
    {
      resolve: async () => ({
        didDocument: null,
        didDocumentMetadata: {},
        didResolutionMetadata: { contentType: 'application/did+json', error: 'notFound' },
      }),
    },
  ),
)

// ---------------------------------------------------------------------------
// createJWS / createJWE / createMultisignatureJWT parameter surface
// ---------------------------------------------------------------------------

// createJWS: payload may be a string OR an object; header + options.
expectType<Promise<string>>(
  createJWS('string payload', signer, { alg: 'ES256K', kid: 'kid' }, { canonicalize: true }),
)
expectType<Promise<string>>(createJWS({ some: 'data' }, signer, { alg: 'ES256K' }, { canonicalize: true }))

// createJWE: cleartext, an array of Encrypters, an optional ProtectedHeader,
// an optional aad, and the optional useSingleEphemeralKey flag.
expectType<Promise<JWE>>(
  createJWE(
    new Uint8Array([1, 2, 3]),
    [encrypter],
    { alg: 'dir', iv: 'iv', epk: ephemeralKeyPair.publicKeyJWK },
    new Uint8Array([1, 2, 3, 4]),
    false,
  ),
)

// createMultisignatureJWT: payload + partial options + a list of
// {issuer, signer, alg} entries.
expectType<Promise<string>>(
  createMultisignatureJWT(
    { requested: ['name'] },
    { expiresIn: 3600, canonicalize: true },
    [{ issuer: 'did:ethr:0x', signer, alg: 'ES256K' }],
  ),
)

// ---------------------------------------------------------------------------
// Deprecated signers / flags — must still be present and type-check.
// ---------------------------------------------------------------------------

// EllipticSigner / SimpleSigner / NaclSigner are @deprecated aliases but must
// remain exported and type-check.
expectType<Signer>(EllipticSigner('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))
expectType<Signer>(SimpleSigner('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))
expectType<Signer>(NaclSigner('YjhBOjM= // 64-byte base64 secret key'))
expectType<Signer>(ES256Signer(new Uint8Array(32)))
expectType<Signer>(EdDSASigner(new Uint8Array(32)))

// supportedCodecs / JWT_ERROR are constant objects whose shapes must not
// change.
expectType<number>(supportedCodecs['secp256k1-pub'])
expectType<number>(supportedCodecs['x25519-pub'])
expectType<string>(JWT_ERROR.INVALID_SIGNATURE)
expectType<string>(JWT_ERROR.NO_SUITABLE_KEYS)
expectType<string>(JWT_ERROR.NOT_SUPPORTED)
expectType<string>(JWT_ERROR.RESOLVER_ERROR)
expectType<string>(JWT_ERROR.INVALID_JWT)
expectType<string>(JWT_ERROR.INVALID_AUDIENCE)

// ---------------------------------------------------------------------------
// Parameter shapes that must not silently change.
// ---------------------------------------------------------------------------

// ProtectedHeader is `Record<string, any> & Partial<RecipientHeader>` —
// accept both the recipient-header fields and arbitrary extras.
const protectedHeader: ProtectedHeader = {
  alg: 'dir',
  iv: 'iv',
  tag: 'tag',
  epk: ephemeralKeyPair.publicKeyJWK,
  kid: 'kid',
  apu: 'apu',
  apv: 'apv',
  // arbitrary extra field allowed by the Record<string, any> base
  arbitrary: 123,
}
expectType<ProtectedHeader>(protectedHeader)

// AuthEncryptParams / AnonEncryptParams (option bags).
const authParams: AuthEncryptParams = { kid: 'kid', apu: 'apu', apv: 'apv' }
const anonParams: AnonEncryptParams = { kid: 'kid', apv: 'apv' }
expectType<AuthEncryptParams>(authParams)
expectType<AnonEncryptParams>(anonParams)

// createJWE / decryptJWE round-trip types.
const jwePromise = createJWE(new Uint8Array([1, 2, 3]), [encrypter], protectedHeader, new Uint8Array([4, 5, 6]))
void jwePromise.then(async (j) => {
  const decrypted = await decryptJWE(j, decrypter)
  expectType<Uint8Array>(decrypted)
})

// verifyJWS accepts a single VerificationMethod OR an array of them.
verifyJWS('a.b.c', {
  id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#k',
  type: 'EcdsaSecp256k1VerificationKey2019',
  controller: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
  publicKeyHex: '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479',
})
verifyJWS('a.b.c', [
  {
    id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#k',
    type: 'EcdsaSecp256k1VerificationKey2019',
    controller: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    publicKeyHex: '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479',
  },
])

// The whole import is "used" so tsc doesn't drop it.
void expectType
