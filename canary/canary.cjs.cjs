/**
 * CJS canary for did-jwt.
 *
 * This runs under Node's CommonJS loader (plain `node`, NOT tsx/ESM), because
 * the whole point is to exercise the `require()` side of the package. The
 * CommonJS build does `require("canonicalize")`; when `canonicalize` is an
 * ESM-only package (as `canonicalize@5` is) that require fails at *module load
 * time* — so a tsx/ESM canary could not even reach this code path.
 *
 * Run it with plain node:
 *   node canary/canary.cjs.cjs          # see the package.json "canary:cjs" script
 *
 * Like the ESM canary it imports the unpacked `pnpm pack` output, so the
 * package's `exports` map resolves the lib's dependencies exactly as a real
 * CommonJS consumer would see them.
 */

const path = require('node:path')

// --- tiny self-contained assertion harness (the CJS canary must be pure JS) ---
let checks = 0
let failures = 0
const errors = []
const A = {
  assert(name, cond, detail = 'expected true') {
    checks++
    if (cond) console.log(`  \u2713 ${name}`)
    else {
      failures++
      errors.push(`${name}: ${detail}`)
      console.log(`  \u2717 ${name}\n        ${detail}`)
    }
  },
  summary(label) {
    console.log(`\n[${label}] ${checks - failures}/${checks} checks passed, ${failures} failed`)
    for (const e of errors) console.log(`    - ${e}`)
    return failures === 0 ? 0 : 1
  },
}
const toHex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('')

const LIB_DIR = process.env.CANARY_LIB_DIR || path.resolve(__dirname, 'consumer/node_modules/did-jwt')

// --- 1. Load the package the way a CommonJS consumer would. ---
// This is the line that breaks if the CommonJS build cannot load a dependency.
let pkg
try {
  pkg = require(LIB_DIR)
} catch (e) {
  console.error(
    `\n[CJS canary] FAIL: cannot load the CommonJS build of did-jwt from ${LIB_DIR}\n` +
      `  ${e.code || ''}: ${e.message}\n` +
      `  This is a breaking change for CommonJS consumers (e.g. an ESM-only dependency\n` +
      `  such as a newer "canonicalize" that no longer ships a CommonJS build).`,
  )
  process.exit(1)
}

console.log(`\n[CJS canary] loaded did-jwt (require), ${Object.keys(pkg).length} exports`)

;(async () => {
  const signer = pkg.ES256KSigner(pkg.hexToBytes('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))

  A.assert('hexToBytes', toHex(pkg.hexToBytes('0101')) === '0101')
  A.assert('supportedCodecs', pkg.supportedCodecs['secp256k1-pub'] === 0xe7)
  A.assert('JWT_ERROR present', pkg.JWT_ERROR && pkg.JWT_ERROR.INVALID_SIGNATURE === 'invalid_signature')

  // deterministic signer golden
  const sig = await signer('thequickbrownfoxjumpedoverthelazyprogrammer')
  A.assert(
    'ES256KSigner golden signature',
    sig === 'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg',
  )

  // createJWS golden (deterministic)
  const jws = await pkg.createJWS({ some: 'data' }, signer, { alg: 'ES256K' })
  A.assert(
    'createJWS golden',
    jws === 'eyJhbGciOiJFUzI1NksifQ.eyJzb21lIjoiZGF0YSJ9.dblNz-7BVLknOFIBPmt5VTG0MDls_Q69WI8OfQuqNdUp4y50-b8Ubn0xujm1ijfmfqRunpks5TyWqgMsQkR_GQ',
  )

  // createJWT -> decode -> verify round-trip (network-free fake resolver)
  const ISSUER = 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  const PUB = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
  const IAT = 1700000000000
  const jwt = await pkg.createJWT({ requested: ['name', 'phone'], iat: IAT }, { issuer: ISSUER, signer }, { alg: 'ES256K' })
  const dec = pkg.decodeJWT(jwt)
  A.assert('createJWT -> decodeJWT payload.iss', dec.payload.iss === ISSUER)
  A.assert('createJWT -> decodeJWT payload.requested', dec.payload.requested[0] === 'name')

  const resolver = {
    resolve: async () => ({
      didDocument: {
        id: ISSUER,
        verificationMethod: [{ id: `${ISSUER}#1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: ISSUER, publicKeyHex: PUB }],
        authentication: [`${ISSUER}#1`],
        assertionMethod: [`${ISSUER}#1`],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+json' },
    }),
  }
  const verified = await pkg.verifyJWT(jwt, { resolver, policies: { now: IAT, nbf: false, iat: false, exp: false, aud: false } })
  A.assert('verifyJWT verified===true', verified.verified === true)
  A.assert('verifyJWT payload.requested', verified.payload.requested[0] === 'name')
  A.assert('verifyJWT signer', verified.signer.publicKeyHex === PUB)

  // JWE round-trip
  const ep = pkg.genX25519EphemeralKeyPair()
  const jwe = await pkg.createJWE(new Uint8Array([104, 101, 108, 108, 111]), [pkg.xc20pDirEncrypter(ep.secretKey)])
  const back = await pkg.decryptJWE(jwe, pkg.xc20pDirDecrypter(ep.secretKey))
  A.assert('JWE round-trip', back[0] === 104 && back[4] === 111)


  // --- additional signers, algorithms, deprecated aliases & parameters ---
  const ES256_PRIV = '0101010101010101010101010101010101010101010101010101010101010101'
  const ES256_PUB = '026ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca16'
  const ED_PRIV = '0000000000000000000000000000000000000000000000000000000000000001'
  const ED_PUB = '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29'
  const DATA = 'thequickbrownfoxjumpedoverthelazyprogrammer'

  // ES256Signer / EdDSASigner are deterministic (same input -> same output).
  const es256a = await pkg.ES256Signer(pkg.hexToBytes(ES256_PRIV))(DATA)
  const es256b = await pkg.ES256Signer(pkg.hexToBytes(ES256_PRIV))(DATA)
  A.assert('ES256Signer is deterministic', es256a === es256b && es256a.length > 0)
  const eda = await pkg.EdDSASigner(pkg.hexToBytes(ED_PRIV))(DATA)
  const edb = await pkg.EdDSASigner(pkg.hexToBytes(ED_PRIV))(DATA)
  A.assert('EdDSASigner is deterministic', eda === edb && eda.length > 0)

  // createJWT + verifyJWT across the ES256 and EdDSA algorithms (different
  // signer + verificationMethod types).
  const es256Resolver = { resolve: async () => ({ didDocument: { id: ISSUER, verificationMethod: [{ id: `${ISSUER}#k`, type: 'EcdsaSecp256r1VerificationKey2019', controller: ISSUER, publicKeyHex: ES256_PUB }], authentication: [`${ISSUER}#k`], assertionMethod: [`${ISSUER}#k`] }, didDocumentMetadata: {}, didResolutionMetadata: { contentType: 'application/did+json' } }) }
  const es256Jwt = await pkg.createJWT({ requested: ['name'], iat: IAT }, { issuer: ISSUER, signer: pkg.ES256Signer(pkg.hexToBytes(ES256_PRIV)) }, { alg: 'ES256' })
  const es256V = await pkg.verifyJWT(es256Jwt, { resolver: es256Resolver, policies: { now: IAT, nbf: false, iat: false, exp: false, aud: false } })
  A.assert('ES256 create->verify round-trip', es256V.verified === true && es256V.signer.type === 'EcdsaSecp256r1VerificationKey2019')

  const edResolver = { resolve: async () => ({ didDocument: { id: ISSUER, verificationMethod: [{ id: `${ISSUER}#k`, type: 'Ed25519VerificationKey2018', controller: ISSUER, publicKeyHex: ED_PUB }], authentication: [`${ISSUER}#k`], assertionMethod: [`${ISSUER}#k`] }, didDocumentMetadata: {}, didResolutionMetadata: { contentType: 'application/did+json' } }) }
  const edJwt = await pkg.createJWT({ requested: ['name'], iat: IAT }, { issuer: ISSUER, signer: pkg.EdDSASigner(pkg.hexToBytes(ED_PRIV)) }, { alg: 'EdDSA' })
  const edV = await pkg.verifyJWT(edJwt, { resolver: edResolver, policies: { now: IAT, nbf: false, iat: false, exp: false, aud: false } })
  A.assert('EdDSA create->verify round-trip', edV.verified === true && edV.signer.type === 'Ed25519VerificationKey2018')

  // Deprecated aliases must still work: EllipticSigner / SimpleSigner / NaclSigner.
  const ellipJwt = await pkg.createJWT({ requested: ['name'], iat: IAT }, { issuer: ISSUER, signer: pkg.EllipticSigner('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f') }, { alg: 'ES256K' })
  const ellipV = await pkg.verifyJWT(ellipJwt, { resolver, policies: { now: IAT, nbf: false, iat: false, exp: false, aud: false } })
  A.assert('EllipticSigner (deprecated) round-trip', ellipV.verified === true)

  const simpleSig = await pkg.SimpleSigner('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f')(DATA)
  A.assert('SimpleSigner (deprecated) returns {r,s,recoveryParam}', simpleSig && typeof simpleSig === 'object' && 'r' in simpleSig && 's' in simpleSig && 'recoveryParam' in simpleSig)

  const naclJwt = await pkg.createJWT({ requested: ['name'], iat: IAT }, { issuer: ISSUER, signer: pkg.NaclSigner(Buffer.from(ED_PRIV, 'hex').toString('base64')) }, { alg: 'Ed25519' })
  const naclV = await pkg.verifyJWT(naclJwt, { resolver: edResolver, policies: { now: IAT, nbf: false, iat: false, exp: false, aud: false } })
  A.assert('NaclSigner (deprecated) round-trip', naclV.verified === true)

  // createJWT with a custom header (typ + kid) + createJWS with a string payload.
  const jwtHeader = await pkg.createJWT({ requested: ['name'], iat: IAT }, { issuer: ISSUER, signer }, { typ: 'JWT', kid: `${ISSUER}#1` })
  A.assert('createJWT custom header.kid', pkg.decodeJWT(jwtHeader).header.kid === `${ISSUER}#1`)
  const jwsStr = await pkg.createJWS('stringpayload', signer, { alg: 'ES256K' })
  const jwsStrKey = pkg.verifyJWS(jwsStr, { id: `${ISSUER}#1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: ISSUER, publicKeyHex: PUB })
  A.assert('createJWS accepts a string payload', jwsStrKey && jwsStrKey.publicKeyHex === PUB)

  // createMultisignatureJWT round-trips through decodeJWT recursion (cty=JWT).
  const msJwt = await pkg.createMultisignatureJWT({ requested: ['name'], iat: IAT }, {}, [{ issuer: ISSUER, signer, alg: 'ES256K' }])
  const msDec = pkg.decodeJWT(msJwt)
  A.assert('createMultisignatureJWT -> decodeJWT (recurses)', msDec.payload.requested[0] === 'name' && msDec.header.alg === 'ES256K')

  // Error contracts: createJWT requires a signer and an issuer.
  let threwSigner = false
  try { await pkg.createJWT({ x: 1 }, { issuer: ISSUER }, { alg: 'ES256K' }) } catch (e) { threwSigner = /missing_signer/.test(e.message) }
  A.assert('createJWT throws missing_signer', threwSigner)
  let threwIssuer = false
  try { await pkg.createJWT({ x: 1 }, { signer }, { alg: 'ES256K' }) } catch (e) { threwIssuer = /missing_issuer/.test(e.message) }
  A.assert('createJWT throws missing_issuer', threwIssuer)


  process.exit(A.summary('CJS canary'))
})().catch((e) => {
  console.error(`\n[CJS canary] FAIL during checks: ${e && e.stack ? e.stack : e}`)
  process.exit(1)
})
