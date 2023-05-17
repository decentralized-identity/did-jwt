import { jest, describe, expect, it } from '@jest/globals'
import { base64ToBytes, bytesToBase64url, decodeBase64url, hexToBytes } from '../util.js'
import type { Resolvable, VerificationMethod } from 'did-resolver'
import { TokenVerifier } from 'jsontokens'
import MockDate from 'mockdate'
import { getAddress } from '@ethersproject/address'
import {
  createJWS,
  createJWT,
  decodeJWT,
  NBF_SKEW,
  resolveAuthenticator,
  SELF_ISSUED_V0_1,
  SELF_ISSUED_V2,
  verifyJWS,
  verifyJWT,
} from '../JWT.js'
import { EdDSASigner } from '../signers/EdDSASigner.js'
import { ES256KSigner } from '../signers/ES256KSigner.js'

// add declarations for ES256 Tests
import { ES256Signer } from '../signers/ES256Signer'
// @ts-ignore
import jwt from 'jsonwebtoken'
// @ts-ignore
import jwkToPem from 'jwk-to-pem'

const NOW = 1485321133
MockDate.set(NOW * 1000 + 123)

const audAddress = '0x20c769ec9c0996ba7737a4826c2aaff00b1b2040'
const aud = `did:ethr:${audAddress}`
const address = '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
const did = `did:ethr:${address}`
const alg = 'ES256K'

const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
const verifier = new TokenVerifier(alg, publicKey)
const signer = ES256KSigner(hexToBytes(privateKey))
const recoverySigner = ES256KSigner(hexToBytes(privateKey), true)

const publicKeyJwk = {
  crv: 'secp256k1',
  kty: 'EC',
  x: '_dV63sPUOOojf-RrM-4eAW7aa1hcPifqZmhsLqU1hHk',
  y: 'Rjk_gUUlLupor-Z-KHs-2bMWhbpsOwAGCnO5sSQtaPc',
}

const didDocLegacy = {
  '@context': 'https://w3id.org/did/v1',
  id: did,
  publicKey: [
    {
      id: `${did}#keys-1`,
      type: 'Secp256k1VerificationKey2018',
      owner: did,
      publicKeyHex: publicKey,
    },
  ],
  authentication: [
    {
      type: 'Secp256k1SignatureAuthentication2018',
      publicKey: `${did}#keys-1`,
    },
  ],
}

const didDocJwk = {
  '@context': 'https://w3id.org/did/v1',
  id: did,
  verificationMethod: [
    {
      id: `#keys-1`,
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: did,
      publicKeyJwk,
    },
  ],
  authentication: [`#keys-1`],
}

const didDoc = {
  didDocument: {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    verificationMethod: [
      {
        id: `${did}#keys-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: did,
        publicKeyHex: publicKey,
      },
    ],
    authentication: [`${did}#keys-1`],
    assertionMethod: [`${did}#keys-1`],
    capabilityInvocation: [`${did}#keys-1`],
    capabilityDelegation: [`${did}#some-key-that-does-not-exist`],
  },
}

const audDidDoc = {
  didDocument: {
    '@context': 'https://w3id.org/did/v1',
    id: aud,
    verificationMethod: [
      {
        id: `${aud}#keys-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: did,
        publicKeyHex: publicKey,
      },
    ],
    authentication: [`${aud}#keys-1`],
    assertionMethod: [`${aud}#keys-1`],
    capabilityInvocation: [`${aud}#keys-1`],
    capabilityDelegation: [`${aud}#some-key-that-does-not-exist`],
  },
}

describe('createJWT()', () => {
  describe('ES256', () => {
    const privateKey = '736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8'
    const publicKey_x = '14c58e581c7656ba153195669fe4ce53ff78dd5ede60a4039771a90c58cb41de'
    const publicKey_y = 'ec41869995bd661849414c523c7dff9a96f1c8dbc2e5e78172118f91c7199869'

    // construct did:key for secp256r1 (unlike did for secp256k1 which is for an Ethereum Address)
    // This originally was constructed by `encodeDIDfromHextString` imported from `did-key-creator`
    // package, but that dependency was removed, so now `did` is just hardcoded
    // const multicodecName = 'p256-pub';
    // const publicKey = '0314c58e581c7656ba153195669fe4ce53ff78dd5ede60a4039771a90c58cb41de'
    // const did = encodeDIDfromHexString(multicodecName,publicKey)
    const did = 'did:key:zDnaej4NHntda4rNW4FBUJgFzdcgEAXKGRVGE8LuVfRbuMuc1'

    const signer = ES256Signer(hexToBytes(privateKey))

    // verifyTokenFormAndValidity
    function verifyTokenFormAndValidity(token: string, pemPublic: string): boolean {
      let result
      try {
        jwt.verify(token, pemPublic)
        result = true
      } catch (e: any) {
        console.error(e.name + ': ' + e.message)
        result = false
      }
      return result
    }

    // input public key in hex, and export pem
    function publicToJWK(
      publicPointHex_x: string,
      publicPointHex_y: string,
      kty_value: string,
      crv_value: string
    ): JsonWebKey {
      if (publicPointHex_x.length % 2 != 0) {
        publicPointHex_x = '0' + publicPointHex_x
      }
      if (publicPointHex_y.length % 2 != 0) {
        publicPointHex_y = '0' + publicPointHex_y
      }
      const publicPointUint8_x = hexToBytes(publicPointHex_x)
      const publicPointBase64URL_x = bytesToBase64url(publicPointUint8_x)
      const publicPointUint8_y = hexToBytes(publicPointHex_y)
      const publicPointBase64URL_y = bytesToBase64url(publicPointUint8_y)
      return {
        kty: kty_value,
        crv: crv_value,
        x: publicPointBase64URL_x,
        y: publicPointBase64URL_y,
      }
    }

    it('creates a valid JWT', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer }, { alg: 'ES256' })
      const pemPublic = jwkToPem(publicToJWK(publicKey_x, publicKey_y, 'EC', 'P-256') as any)
      expect(verifyTokenFormAndValidity(jwt, pemPublic)).toBe(true)
    })

    it('creates a valid JWT using a MNID', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: address, signer }, { alg: 'ES256' })
      const pemPublic = jwkToPem(publicToJWK(publicKey_x, publicKey_y, 'EC', 'P-256') as any)
      expect(verifyTokenFormAndValidity(jwt, pemPublic)).toBe(true)
    })

    it('creates a JWT with correct format', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer }, { alg: 'ES256' })
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })

    it('creates a JWT with correct legacy format', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: address, signer }, { alg: 'ES256' })
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })

    it('creates a JWT with expiry in 10000 seconds', async () => {
      expect.assertions(1)
      const jwt = await createJWT(
        {
          requested: ['name', 'phone'],
          nbf: Math.floor(new Date().getTime() / 1000),
        },
        { issuer: did, signer, expiresIn: 10000 },
        { alg: 'ES256' }
      )
      const { payload } = decodeJWT(jwt)
      return expect(payload.exp).toEqual(payload.nbf!! + 10000)
    })

    it('Uses iat if nbf is not defined but expiresIn is included', async () => {
      expect.assertions(1)
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer, expiresIn: 10000 }, { alg: 'ES256' })
      )
      return expect(payload.exp).toEqual(payload.iat!! + 10000)
    })

    it('sets iat to the current time by default', async () => {
      expect.assertions(1)
      const timestamp = Math.floor(Date.now() / 1000)
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer }, { alg: 'ES256' })
      )
      return expect(payload.iat).toEqual(timestamp)
    })

    it('sets iat to the value passed in payload', async () => {
      expect.assertions(1)
      const timestamp = 2000000
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'], iat: timestamp }, { issuer: did, signer }, { alg: 'ES256' })
      )
      return expect(payload.iat).toEqual(timestamp)
    })

    it('does not set iat if value in payload is undefined', async () => {
      expect.assertions(1)
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'], iat: undefined }, { issuer: did, signer }, { alg: 'ES256' })
      )
      return expect(payload.iat).toBeUndefined()
    })

    it('throws an error if unsupported algorithm is passed in', async () => {
      expect.assertions(1)
      await expect(
        createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer, alg: 'BADALGO' })
      ).rejects.toThrowError('Unsupported algorithm BADALGO')
    })
  })
})

describe('createJWT()', () => {
  describe('ES256K', () => {
    it('creates a valid JWT', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer })
      expect(verifier.verify(jwt)).toBe(true)
    })

    it('creates a valid JWT using a MNID', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: address, signer })
      expect(verifier.verify(jwt)).toBe(true)
    })

    it('creates a JWT with correct format', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer })
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })

    it('creates a JWT with correct legacy format', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: address, signer })
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })

    it('creates a JWT with expiry in 10000 seconds', async () => {
      expect.assertions(1)
      const jwt = await createJWT(
        {
          requested: ['name', 'phone'],
          nbf: Math.floor(new Date().getTime() / 1000),
        },
        { issuer: did, signer, expiresIn: 10000 }
      )
      const { payload } = decodeJWT(jwt)
      return expect(payload.exp).toEqual(payload.nbf!! + 10000)
    })

    it('Uses iat if nbf is not defined but expiresIn is included', async () => {
      expect.assertions(1)
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer, expiresIn: 10000 })
      )
      return expect(payload.exp).toEqual(payload.iat!! + 10000)
    })

    it('sets iat to the current time by default', async () => {
      expect.assertions(1)
      const timestamp = Math.floor(Date.now() / 1000)
      const { payload } = decodeJWT(await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer }))
      return expect(payload.iat).toEqual(timestamp)
    })

    it('sets iat to the value passed in payload', async () => {
      expect.assertions(1)
      const timestamp = 2000000
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'], iat: timestamp }, { issuer: did, signer })
      )
      return expect(payload.iat).toEqual(timestamp)
    })

    it('does not set iat if value in payload is undefined', async () => {
      expect.assertions(1)
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'], iat: undefined }, { issuer: did, signer })
      )
      return expect(payload.iat).toBeUndefined()
    })

    it('throws an error if unsupported algorithm is passed in', async () => {
      expect.assertions(1)
      await expect(
        createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer, alg: 'BADALGO' })
      ).rejects.toThrowError('Unsupported algorithm BADALGO')
    })
  })

  describe('Ed25519', () => {
    const ed25519PrivateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
    const did = 'did:nacl:BvrB8iJAz_1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU'
    const signer = EdDSASigner(base64ToBytes(ed25519PrivateKey))
    const alg = 'Ed25519'
    const resolver = {
      resolve: jest.fn().mockReturnValue({
        didDocumentMetadata: {},
        didResolutionMetadata: {},
        didDocument: {
          id: 'did:nacl:BvrB8iJAz_1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU',
          publicKey: [
            {
              id: 'did:nacl:BvrB8iJAz_1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU#key1',
              type: 'ED25519SignatureVerification',
              owner: 'did:nacl:BvrB8iJAz_1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU',
              publicKeyBase64: 'BvrB8iJAz/1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU=',
            },
          ],
          authentication: [],
        },
      }),
    } as Resolvable

    it('creates a valid JWT with did:nacl issuer', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { alg, issuer: did, signer })
      const { payload } = await verifyJWT(jwt, { resolver })
      expect(payload).toEqual({
        iat: 1485321133,
        iss: 'did:nacl:BvrB8iJAz_1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU',
        requested: ['name', 'phone'],
      })
    })

    it('can create a jwt in the default non-canonical way', async () => {
      expect.assertions(1)
      // Same payload, slightly different ordering
      const jwtA = await createJWT(
        { reason: 'verification', requested: ['name', 'phone'] },
        { alg, issuer: did, signer }
      )
      const jwtB = await createJWT(
        { requested: ['name', 'phone'], reason: 'verification' },
        { alg, issuer: did, signer }
      )
      expect(jwtA).not.toEqual(jwtB)
    })

    it('can create a jwt in a canonical way', async () => {
      expect.assertions(1)
      // Same payload, slightly different ordering
      const jwtA = await createJWT(
        { reason: 'verification', requested: ['name', 'phone'] },
        { alg, issuer: did, signer, canonicalize: true }
      )
      const jwtB = await createJWT(
        { requested: ['name', 'phone'], reason: 'verification' },
        { alg, issuer: did, signer, canonicalize: true }
      )
      expect(jwtA).toEqual(jwtB)
    })

    it('creates a JWT with correct format', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { alg, issuer: did, signer })
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })

    it('creates a JWT with expiry in 10000 seconds', async () => {
      expect.assertions(1)
      const jwt = await createJWT(
        {
          requested: ['name', 'phone'],
          nbf: Math.floor(new Date().getTime() / 1000),
        },
        { alg, issuer: did, signer, expiresIn: 10000 }
      )
      const { payload } = decodeJWT(jwt)
      return expect(payload.exp).toEqual(payload.nbf!! + 10000)
    })
  })
})

describe('verifyJWT() for ES256', () => {
  // const privateKey = '736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8'
  const publicKey = '0314c58e581c7656ba153195669fe4ce53ff78dd5ede60a4039771a90c58cb41de'
  const did = 'did:key:zDnaej4NHntda4rNW4FBUJgFzdcgEAXKGRVGE8LuVfRbuMuc1'

  const didDoc = {
    didDocument: {
      '@context': 'https://w3id.org/did/v1',
      id: did,
      verificationMethod: [
        {
          id: `${did}#keys-1`,
          type: 'JsonWebKey2020',
          controller: did,
          publicKeyHex: publicKey,
        },
      ],
      authentication: [`${did}#keys-1`],
      assertionMethod: [`${did}#keys-1`],
      capabilityInvocation: [`${did}#keys-1`],
      capabilityDelegation: [`${did}#some-key-that-does-not-exist`],
    },
  }

  const resolver = {
    resolve: jest.fn(async (didUrl: string) => {
      if (didUrl.includes(did)) {
        return {
          didDocument: didDoc.didDocument,
          didDocumentMetadata: {},
          didResolutionMetadata: { contentType: 'application/did+ld+json' },
        }
      }

      return {
        didDocument: null,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: 'notFound',
          message: 'resolver_error: DID document not found',
        },
      }
    }),
  } as Resolvable

  describe('pregenerated JWT', () => {
    const incomingJwt =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXSwiaXNzIjoiZGlkOmtleTp6RG5hZWo0TkhudGRhNHJOVzRGQlVKZ0Z6ZGNnRUFYS0dSVkdFOEx1VmZSYnVNdWMxIn0.aMYFY0jitx2Bq9_wGBhEeIyVvzr2XkouCyEP662P8TbAPTpXOC3UrGQONaPD7wleLrMhGdvfod7idSxKXLl64Q'
    it('verifies the JWT and return correct payload', async () => {
      expect.assertions(1)
      const { payload } = await verifyJWT(incomingJwt, { resolver })
      return expect(payload).toMatchSnapshot()
    })
    it('verifies the JWT and return correct profile', async () => {
      expect.assertions(1)
      const {
        didResolutionResult: { didDocument },
      } = await verifyJWT(incomingJwt, { resolver })
      return expect(didDocument).toEqual(didDoc.didDocument)
    })
    it('verifies the JWT and return correct did for the iss', async () => {
      expect.assertions(1)
      const { issuer } = await verifyJWT(incomingJwt, { resolver })
      return expect(issuer).toEqual(did)
    })
    it('verifies the JWT and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('verifies the JWT requiring authentication and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver, auth: true })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('verifies the JWT requiring authentication proofPurpose and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver, proofPurpose: 'authentication' })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('verifies the JWT requiring assertionMethod and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver, proofPurpose: 'assertionMethod' })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('verifies the JWT requiring capabilityInvocation and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver, proofPurpose: 'capabilityInvocation' })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('rejects the JWT requiring capabilityDelegation when not present in document', async () => {
      expect.assertions(1)
      await expect(() =>
        verifyJWT(incomingJwt, { resolver, proofPurpose: 'capabilityDelegation' })
      ).rejects.toThrowError(
        `DID document for ${did} does not have public keys suitable for ES256 with capabilityDelegation purpose`
      )
    })
    it('rejects the JWT requiring unknown proofPurpose', async () => {
      expect.assertions(1)
      await expect(() => verifyJWT(incomingJwt, { resolver, proofPurpose: 'impossible' as any })).rejects.toThrowError(
        `DID document for ${did} does not have public keys suitable for ES256 with impossible purpose`
      )
    })
  })
})

describe('verifyJWT() for ES256K', () => {
  const resolver = {
    resolve: jest.fn(async (didUrl: string) => {
      if (didUrl.includes(did)) {
        return {
          didDocument: didDoc.didDocument,
          didDocumentMetadata: {},
          didResolutionMetadata: { contentType: 'application/did+ld+json' },
        }
      }

      if (didUrl.includes(aud)) {
        return {
          didDocument: audDidDoc.didDocument,
          didDocumentMetadata: {},
          didResolutionMetadata: { contentType: 'application/did+ld+json' },
        }
      }

      return {
        didDocument: null,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: 'notFound',
          message: 'resolver_error: DID document not found',
        },
      }
    }),
  } as Resolvable

  describe('pregenerated JWT', () => {
    const incomingJwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXSwiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.tU96omPNxCfQoEADOpLywXUDCMjKXOfTaG61EZwmfvHJrDFQhNbSDzCP2Pe7WdXySosTCuI1T-IQ6SddcWuj_A'
    it('verifies the JWT and return correct payload', async () => {
      expect.assertions(1)
      const { payload } = await verifyJWT(incomingJwt, { resolver })
      return expect(payload).toMatchSnapshot()
    })
    it('verifies the JWT and return correct profile', async () => {
      expect.assertions(1)
      const {
        didResolutionResult: { didDocument },
      } = await verifyJWT(incomingJwt, { resolver })
      return expect(didDocument).toEqual(didDoc.didDocument)
    })
    it('verifies the JWT and return correct did for the iss', async () => {
      expect.assertions(1)
      const { issuer } = await verifyJWT(incomingJwt, { resolver })
      return expect(issuer).toEqual(did)
    })
    it('verifies the JWT and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('verifies the JWT requiring authentication and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver, auth: true })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('verifies the JWT requiring authentication proofPurpose and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver, proofPurpose: 'authentication' })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('verifies the JWT requiring assertionMethod and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver, proofPurpose: 'assertionMethod' })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('verifies the JWT requiring capabilityInvocation and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver, proofPurpose: 'capabilityInvocation' })
      return expect(signer).toEqual(didDoc.didDocument.verificationMethod[0])
    })
    it('rejects the JWT requiring capabilityDelegation when not present in document', async () => {
      expect.assertions(1)
      await expect(() =>
        verifyJWT(incomingJwt, { resolver, proofPurpose: 'capabilityDelegation' })
      ).rejects.toThrowError(
        `DID document for ${did} does not have public keys suitable for ES256K with capabilityDelegation purpose`
      )
    })
    it('rejects the JWT requiring unknown proofPurpose', async () => {
      expect.assertions(1)
      await expect(() => verifyJWT(incomingJwt, { resolver, proofPurpose: 'impossible' as any })).rejects.toThrowError(
        `DID document for ${did} does not have public keys suitable for ES256K with impossible purpose`
      )
    })
  })

  describe('pregenerated JWT with publicKeyJwk in DID doc', () => {
    const incomingJwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsImlzcyI6ImRpZDpldGhyOjB4OTBlNDVkNzViZDEyNDZlMDkyNDg3MjAxODY0N2RiYTk5NmE4ZTdiOSIsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.KIG2zUO8Quf3ucb9jIncZ1CmH0v-fAZlsKvesfsd9x4RzU0qrvinVd9d30DOeZOwdwEdXkET_wuPoOECwU0IKA'
    const jwkResolver = { resolve: jest.fn().mockReturnValue(didDocJwk) } as Resolvable

    it('verifies the JWT and return correct payload', async () => {
      expect.assertions(1)
      const { payload } = await verifyJWT(incomingJwt, { resolver: jwkResolver })
      return expect(payload).toMatchObject({
        iat: 1485321133,
        iss: 'did:ethr:0x90e45d75bd1246e0924872018647dba996a8e7b9',
        requested: ['name', 'phone'],
      })
    })

    it('verifies the JWT and return correct payload when using assertionMethod', async () => {
      expect.assertions(1)
      const { payload } = await verifyJWT(incomingJwt, { resolver: jwkResolver, proofPurpose: 'assertionMethod' })
      return expect(payload).toMatchObject({
        iat: 1485321133,
        iss: 'did:ethr:0x90e45d75bd1246e0924872018647dba996a8e7b9',
        requested: ['name', 'phone'],
      })
    })
  })

  describe('pregenerated JWT with legacy resolver', () => {
    const incomingJwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsImlzcyI6ImRpZDpldGhyOjB4OTBlNDVkNzViZDEyNDZlMDkyNDg3MjAxODY0N2RiYTk5NmE4ZTdiOSIsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.KIG2zUO8Quf3ucb9jIncZ1CmH0v-fAZlsKvesfsd9x4RzU0qrvinVd9d30DOeZOwdwEdXkET_wuPoOECwU0IKA'
    const legacyResolver = { resolve: jest.fn().mockReturnValue(didDocLegacy) } as Resolvable

    it('verifies the JWT and return correct payload', async () => {
      expect.assertions(1)
      const { payload } = await verifyJWT(incomingJwt, { resolver: legacyResolver })
      return expect(payload).toMatchSnapshot()
    })
    it('verifies the JWT and return correct profile', async () => {
      expect.assertions(1)
      const {
        didResolutionResult: { didDocument },
      } = await verifyJWT(incomingJwt, { resolver: legacyResolver })
      return expect(didDocument).toEqual(didDocLegacy)
    })
    it('verifies the JWT and return correct did for the iss', async () => {
      expect.assertions(1)
      const { issuer } = await verifyJWT(incomingJwt, { resolver: legacyResolver })
      return expect(issuer).toEqual('did:ethr:0x90e45d75bd1246e0924872018647dba996a8e7b9')
    })
    it('verifies the JWT and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver: legacyResolver })
      return expect(signer).toEqual(didDocLegacy.publicKey[0])
    })
    it('verifies the JWT requiring authentication and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver: legacyResolver, auth: true })
      return expect(signer).toEqual(didDocLegacy.publicKey[0])
    })
    it('verifies the JWT requiring assertionMethod and return correct signer', async () => {
      expect.assertions(1)
      const { signer } = await verifyJWT(incomingJwt, { resolver: legacyResolver, proofPurpose: 'assertionMethod' })
      return expect(signer).toEqual(didDocLegacy.publicKey[0])
    })
  })

  describe('badJwt', () => {
    const badJwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsImlzcyI6ImRpZDpldGhyOjB4MjBjNzY5ZWM5YzA5OTZiYTc3MzdhNDgyNmMyYWFmZjAwYjFiMjA0MCIsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.TTpuw77fUbd_AY3GJcCumd6F6hxnkskMDJYNpJlI2DQi5MKKudXya9NlyM9e8-KFgTLe-WnXgq9EjWLvjpdiXA'
    it('rejects a JWT with bad signature', async () => {
      expect.assertions(1)
      await expect(verifyJWT(badJwt, { resolver })).rejects.toThrowError(
        /invalid_signature: no matching public key found/
      )
    })
  })

  describe('validFrom timestamp', () => {
    it('passes when nbf is in the past', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsIm5iZiI6MTQ4NTI2MTEzMywiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.FUasGkOYqGVxQ7S-QQvh4abGO6Dwr961UjjOxtRTyUDnl6q6ElqHqAK-WMDTmOir21pFPKLYZMtLZ4LTLpm3cQ'
      // const jwt = await createJWT({nbf: PAST}, {issuer:did, signer})
      await expect(verifyJWT(jwt, { resolver })).resolves.not.toThrow()
    })
    it('passes when nbf is in the past and iat is in the future', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzODExMzMsIm5iZiI6MTQ4NTI2MTEzMywiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.8BPiSG2e6UBn1osnJ6PJYbPjtPMPaCeutTA9OCp-ZzI-QvvwPCVrrWqTu2YELbzUPwDIJCQ8v8N77xCEjIYSmQ'
      // const jwt = await createJWT({nbf:PAST,iat:FUTURE},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).resolves.not.toThrow()
    })
    it('fails when nbf is in the future', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsIm5iZiI6MTQ4NTM4MTEzMywiaXNzIjoiZGlkOnVwb3J0OjJuUXRpUUc2Q2dtMUdZVEJhYUtBZ3I3NnVZN2lTZXhVa3FYIn0.rcFuhVHtie3Y09pWxBSf1dnjaVh6FFQLHh-83N-uLty3M5ADJ-jVFFkyt_Eupl8Kr735-oPGn_D1Nj9rl4s_Kw'
      // const jwt = await createJWT({nbf:FUTURE},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError()
    })
    it('passes when nbf is in the future and policy for nbf is false', async () => {
      expect.assertions(2)
      // const jwt = await createJWT({nbf:FUTURE},{issuer:did,signer})

      const jwt = await createJWT(
        { requested: ['name', 'phone'], nbf: new Date().getTime() + 1000000 },
        {
          issuer: did,
          signer,
        }
      )
      expect(verifier.verify(jwt)).toBe(true)

      const { payload } = await verifyJWT(jwt, { resolver, policies: { nbf: false } })
      return expect(payload).toBeDefined()
    })

    it('passes when nbf is in the future and now is provided to be higher than nbf', async () => {
      expect.assertions(2)
      // const jwt = await createJWT({nbf:FUTURE},{issuer:did,signer})

      const jwt = await createJWT(
        { requested: ['name', 'phone'], nbf: new Date().getTime() + 10000 },
        {
          issuer: did,
          signer,
        }
      )
      expect(verifier.verify(jwt)).toBe(true)

      const { payload } = await verifyJWT(jwt, { resolver, policies: { now: new Date().getTime() + 100000 } })
      return expect(payload).toBeDefined()
    })

    it('fails when nbf is in the future and iat is in the past', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUyNjExMzMsIm5iZiI6MTQ4NTM4MTEzMywiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.JjEn_huxI9SsBY_3PlD0ShpXvrRgUGFDKAgxJBc1Q5GToVpUTw007-o9BTt7JNi_G2XWmcu2aXXnDn0QFsRIrg'
      // const jwt = await createJWT({nbf:FUTURE,iat:PAST},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError()
    })
    it('passes when nbf is in the future and iat is in the past with nbf policy false', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUyNjExMzMsIm5iZiI6MTQ4NTM4MTEzMywiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.JjEn_huxI9SsBY_3PlD0ShpXvrRgUGFDKAgxJBc1Q5GToVpUTw007-o9BTt7JNi_G2XWmcu2aXXnDn0QFsRIrg'
      // const jwt = await createJWT({nbf:FUTURE,iat:PAST},{issuer:did,signer})

      const { payload } = await verifyJWT(jwt, { resolver, policies: { nbf: false } })
      expect(payload).toBeDefined()
    })
    it('passes when nbf is missing and iat is in the past', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUyNjExMzMsImlzcyI6ImRpZDpldGhyOjB4ZjNiZWFjMzBjNDk4ZDllMjY4NjVmMzRmY2FhNTdkYmI5MzViMGQ3NCJ9.jkzN5kIVtuRU-Fjte8w5r-ttf9OfhdN38oFJd61CWdI5WnvU1dPCvnx1_kdk2D6Xg-uPqp1VXAb7KA2ZECivmg'
      // const jwt = await createJWT({iat:PAST},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).resolves.not.toThrowError()
    })
    it('fails when nbf is missing and iat is in the future', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzODExMzMsImlzcyI6ImRpZDpldGhyOjB4ZjNiZWFjMzBjNDk4ZDllMjY4NjVmMzRmY2FhNTdkYmI5MzViMGQ3NCJ9.FJuHvf9Tby7b4I54Cm1nh8CvLg4QH2wt2K0WfyQaLqlr3NKKI5hAdLalgZksI25gLhNrZwQFnC-nzEOs9PI1SQ'
      // const jwt = await createJWT({iat:FUTURE},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError()
    })
    it('passes when nbf is missing and iat is in the future with iat policy to be false', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzODExMzMsImlzcyI6ImRpZDpldGhyOjB4ZjNiZWFjMzBjNDk4ZDllMjY4NjVmMzRmY2FhNTdkYmI5MzViMGQ3NCJ9.FJuHvf9Tby7b4I54Cm1nh8CvLg4QH2wt2K0WfyQaLqlr3NKKI5hAdLalgZksI25gLhNrZwQFnC-nzEOs9PI1SQ'
      // const jwt = await createJWT({iat:FUTURE},{issuer:did,signer})
      const { payload } = await verifyJWT(jwt, { resolver, policies: { iat: false } })
      return expect(payload).toBeDefined()
    })
    it('passes when nbf and iat are both missing', async () => {
      expect.assertions(1)
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQifQ.KgnwgMMz-QSOtpba2QMGHMWJoLvhp-H4odjjX1QKnqj4-8dkcK12y7rj7Zq24-1d-1ne86aJCdWtx5VJv3rM7w'
      // const jwt = await createJWT({iat:undefined},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).resolves.not.toThrowError()
    })
  })

  it('handles ES256K-R algorithm', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ hello: 'world' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toMatchSnapshot()
  })

  it('handles ES256K-R algorithm with publicKeyHex address', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ hello: 'world' }, { issuer: aud, signer: recoverySigner, alg: 'ES256K-R' })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toMatchSnapshot()
  })

  it('handles ES256K algorithm with ethereum address - github #14', async () => {
    expect.assertions(1)
    const ethResolver = {
      resolve: jest.fn().mockReturnValue({
        didDocument: {
          id: did,
          publicKey: [
            {
              id: `${did}#keys-1`,
              type: 'Secp256k1VerificationKey2018',
              owner: did,
              ethereumAddress: address,
            },
          ],
        },
      }),
    } as Resolvable
    const jwt = await createJWT({ hello: 'world' }, { issuer: aud, signer, alg: 'ES256K' })
    const { payload } = await verifyJWT(jwt, { resolver: ethResolver })
    return expect(payload).toMatchSnapshot()
  })

  it('handles ES256K algorithm with blockchainAccountId - github #14, #155', async () => {
    expect.assertions(1)
    const ethResolver = {
      resolve: jest.fn().mockReturnValue({
        didDocument: {
          id: did,
          publicKey: [
            {
              id: `${did}#keys-1`,
              type: 'EcdsaSecp256k1RecoveryMethod2020',
              owner: did,
              blockchainAccountId: `${address}@eip155:1`,
            },
          ],
        },
      }),
    } as Resolvable
    const jwt = await createJWT({ hello: 'world' }, { issuer: aud, signer, alg: 'ES256K' })
    const { payload } = await verifyJWT(jwt, { resolver: ethResolver })
    return expect(payload).toMatchSnapshot()
  })

  it('handles ES256K-R algorithm with checksum address in blockchainAccountId - github #231', async () => {
    expect.assertions(1)
    const verificationMethod = {
      id: `${did}#keys-1`,
      type: 'EcdsaSecp256k1RecoveryMethod2020',
      owner: did,
      blockchainAccountId: `eip155:1:${getAddress(address)}`,
    }
    const ethResolver = {
      resolve: jest.fn().mockReturnValue({
        didDocument: {
          id: did,
          verificationMethod: [verificationMethod],
        },
      }),
    } as Resolvable
    const jwt = await createJWT({ hello: 'world' }, { issuer: aud, signer: recoverySigner, alg: 'ES256K-R' })
    const result = await verifyJWT(jwt, { resolver: ethResolver })
    return expect(result.signer).toEqual(verificationMethod)
  })

  it('accepts a valid exp', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ exp: NOW }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toBeDefined()
  })

  it('rejects an expired JWT', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ exp: NOW - NBF_SKEW - 1 }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(/JWT has expired/)
  })

  it('accepts an expired JWT with exp policy false', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ exp: NOW - NBF_SKEW - 1 }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, { resolver, policies: { exp: false } })
    return expect(payload).toBeDefined()
  })

  it('rejects an expired JWT without skew time', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ exp: NOW - 1 }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver, skewTime: 0 })).rejects.toThrowError(/JWT has expired/)
  })

  it('accepts an expired JWT without skew time but exp policy false', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ exp: NOW - 1 }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, { resolver, skewTime: 0, policies: { exp: false } })
    return expect(payload).toBeDefined()
  })

  it('accepts a valid audience', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ aud }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, { resolver, audience: aud })
    return expect(payload).toMatchSnapshot()
  })

  it('accepts multiple audiences', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ aud: [did, aud] }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, { resolver, audience: aud })
    return expect(payload).toMatchSnapshot()
  })

  it('rejects invalid multiple audiences', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ aud: [did, did] }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver, audience: aud })).rejects.toThrowError(
      /JWT audience does not match your DID/
    )
  })

  it('accepts a valid audience using callback_url', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ aud: 'http://pututu.uport.me/unique' }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, {
      resolver,
      callbackUrl: 'http://pututu.uport.me/unique',
    })
    return expect(payload).toMatchSnapshot()
  })

  it('rejects invalid audience', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ aud }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver, audience: did })).rejects.toThrowError(
      /JWT audience does not match your DID or callback url/
    )
  })

  it('accepts invalid audience when override policy is used', async () => {
    expect.assertions(2)
    const jwt = await createJWT({ aud }, { issuer: did, signer })
    const { payload, issuer } = await verifyJWT(jwt, {
      resolver,
      policies: { aud: false },
    })
    expect(payload).toBeDefined()
    expect(issuer).toEqual(did)
  })

  it('rejects an invalid audience using callback_url where callback is wrong', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ aud: 'http://pututu.uport.me/unique' }, { issuer: did, signer })
    await expect(
      verifyJWT(jwt, {
        resolver,
        callbackUrl: 'http://pututu.uport.me/unique/1',
      })
    ).rejects.toThrowError(/JWT audience does not match your DID or callback url/)
  })

  it('rejects an invalid audience using callback_url where callback is missing', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ aud: 'http://pututu.uport.me/unique' }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(
      'JWT audience is required but your app address has not been configured'
    )
  })

  it('rejects invalid audience as no address is present', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ aud }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(
      /JWT audience is required but your app address has not been configured/
    )
  })

  it('rejects a pregenerated JWT without iss or client_id', async () => {
    expect.assertions(1)
    const jwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzN9.aa3_8ZH99MjFoHTrNjOm7Pgq5VL5A13DHR5MTd_dBw2B_pWgNuz4N1tbrocTP0MgDlRbovKmTTDrGNjNMPqH3g'
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(/JWT iss or client_id are required/)
  })

  it('rejects a self-issued v2 JWT without sub', async () => {
    expect.assertions(1)
    const jwt = await createJWT({}, { issuer: SELF_ISSUED_V2, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(/JWT sub is required/)
  })

  it('rejects a self-issued v2 JWT (sub type: did) with an invalid payload.sub DID', async () => {
    expect.assertions(2)
    const jwt = await createJWT({ sub: 'sub' }, { issuer: SELF_ISSUED_V2, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(/DID document not found/)
    expect(resolver.resolve).toHaveBeenCalledWith('sub', { accept: 'application/did+json' })
  })

  it('accepts a self-issued v2 JWT (sub type: did) with a valid payload.sub DID', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ sub: did }, { issuer: SELF_ISSUED_V2, signer })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toBeDefined()
  })
  it('rejects a self-issued v2 JWT (sub type: jkt) without a header.kid DID', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ sub: 'sub', sub_jwk: {} }, { issuer: SELF_ISSUED_V2, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(/No DID has been found in the JWT/)
  })

  it('rejects a self-issued v2 JWT (sub type: jkt) with an invalid header.kid DID', async () => {
    expect.assertions(2)
    const jwt = await createJWT({ sub: 'sub', sub_jwk: {} }, { issuer: SELF_ISSUED_V2, signer }, { kid: 'kid' })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(/DID document not found/)
    expect(resolver.resolve).toHaveBeenCalledWith('kid', { accept: 'application/did+json' })
  })

  it('accepts a self-issued v2 JWT (sub type: jkt) with a valid header.kid DID', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ sub: 'sub', sub_jwk: {} }, { issuer: SELF_ISSUED_V2, signer }, { kid: did })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toBeDefined()
  })

  it('rejects a self-issued v0.1 JWT without did property', async () => {
    expect.assertions(1)
    const jwt = await createJWT({}, { issuer: SELF_ISSUED_V0_1, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrowError(/JWT did is required/)
  })

  it('accepts a self-issued v0.1 JWT with did property', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ did }, { issuer: SELF_ISSUED_V0_1, signer })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toBeDefined()
  })
})

describe('JWS', () => {
  it('createJWS works with JSON payload', async () => {
    expect.assertions(2)
    const payload = { some: 'data' }
    const jws = await createJWS(payload, signer)
    expect(jws).toMatchSnapshot()
    expect(JSON.parse(decodeBase64url(jws.split('.')[1]))).toEqual(payload)
  })

  it('createJWS can canonicalize a JSON payload', async () => {
    expect.assertions(3)
    const payload = { z: 'z', a: 'a' }
    const jws = await createJWS(payload, signer, {}, { canonicalize: true })
    expect(jws).toMatchSnapshot()
    const parsedPayload = JSON.parse(decodeBase64url(jws.split('.')[1]))
    expect(parsedPayload).toEqual(payload)
    expect(JSON.stringify(parsedPayload)).toEqual(JSON.stringify({ a: 'a', z: 'z' }))
  })

  it('createJWS works with base64url payload', async () => {
    expect.assertions(2)
    // use the hex public key as an arbitrary payload
    const encodedPayload = bytesToBase64url(hexToBytes(publicKey))
    const jws = await createJWS(encodedPayload, signer)
    expect(jws).toMatchSnapshot()
    expect(jws.split('.')[1]).toEqual(encodedPayload)
  })

  it('verifyJWS works with JSON payload', async () => {
    expect.assertions(1)
    const payload = { some: 'data' }
    const jws = await createJWS(payload, signer)
    expect(() => verifyJWS(jws, { publicKeyHex: publicKey } as VerificationMethod)).not.toThrow()
  })

  it('verifyJWS works with base64url payload', async () => {
    expect.assertions(1)
    const encodedPayload = bytesToBase64url(hexToBytes(publicKey))
    const jws = await createJWS(encodedPayload, signer)
    expect(() => verifyJWS(jws, { publicKeyHex: publicKey } as VerificationMethod)).not.toThrow()
  })

  it('verifyJWS fails with bad input', async () => {
    expect.assertions(1)
    const badJws = 'abrewguer.fjreoiwfoiew.foirheogu.reoguhwehrg'
    expect(() => verifyJWS(badJws, { publicKeyHex: publicKey } as VerificationMethod)).toThrow('Incorrect format JWS')
  })
})

describe('resolveAuthenticator()', () => {
  const ecKey1 = {
    id: `${did}#keys-1`,
    type: 'Secp256k1VerificationKey2018',
    owner: did,
    publicKeyHex:
      '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab061',
  }

  const ecKey2 = {
    id: `${did}#keys-2`,
    type: 'Secp256k1SignatureVerificationKey2018',
    owner: did,
    publicKeyHex:
      '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062',
  }

  const ecKey3 = {
    id: `${did}#keys-3`,
    type: 'Secp256k1SignatureVerificationKey2018',
    owner: did,
    publicKeyHex:
      '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab063',
  }

  const encKey1 = {
    id: `${did}#keys-4`,
    type: 'Curve25519EncryptionPublicKey',
    owner: did,
    publicKeyBase64: 'QCFPBLm5pwmuTOu+haxv0+Vpmr6Rrz/DEEvbcjktQnQ=',
  }

  const edKey = {
    id: `${did}#keys-5`,
    type: 'ED25519SignatureVerification',
    owner: did,
    publicKeyBase64: 'BvrB8iJAz/1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU=',
  }

  const edKey2 = {
    id: `${did}#keys-6`,
    type: 'ED25519SignatureVerification',
    owner: did,
    publicKeyBase64: 'SI+tzELqRb8XKuRE3Cj7uWGgkEQ86X87ZjhGAok+Ujc=',
  }

  const authKey1 = {
    type: 'Secp256k1SignatureAuthentication2018',
    publicKey: ecKey1.id,
  }

  const authKey2 = {
    type: 'Secp256k1SignatureAuthentication2018',
    publicKey: ecKey2.id,
  }

  const edAuthKey = {
    type: 'ED25519SigningAuthentication',
    publicKey: edKey.id,
  }

  const edKey6 = {
    id: `${did}#keys-auth6`,
    type: 'ED25519SignatureVerification',
    owner: did,
    publicKeyBase58: 'dummyvalue',
  }

  const ecKey7 = {
    id: `${did}#keys-auth7`,
    type: 'EcdsaSecp256k1VerificationKey2019',
    owner: did,
    publicKeyBase58: 'dummyvalue',
  }

  const edKey8 = {
    id: `${did}#keys-auth8`,
    type: 'Ed25519VerificationKey2018',
    owner: did,
    publicKeyBase58: 'dummyvalue',
  }

  const singleKey = {
    didDocument: {
      '@context': 'https://w3id.org/did/v1',
      id: did,
      publicKey: [ecKey1],
    },
  }

  const multipleKeysLegacy = {
    didDocument: {
      '@context': 'https://w3id.org/did/v1',
      id: did,
      publicKey: [ecKey1, ecKey2, ecKey3, encKey1, edKey, edKey2],
      authentication: [authKey1, authKey2, edAuthKey],
    },
  }

  const multipleAuthTypes = {
    didDocument: {
      '@context': 'https://w3id.org/did/v1',
      id: did,
      publicKey: [ecKey1, ecKey2, ecKey3, encKey1, edKey, edKey2, edKey6, ecKey7],
      authentication: [authKey1, authKey2, edAuthKey, `${did}#keys-auth6`, `${did}#keys-auth7`, edKey8],
    },
  }

  const unsupportedFormat = {
    didDocument: {
      '@context': 'https://w3id.org/did/v1',
      id: did,
      publicKey: [encKey1],
    },
  }
  const noPublicKey = {
    didDocument: {
      '@context': 'https://w3id.org/did/v1',
      id: did,
    },
  }

  describe('DID', () => {
    describe('ES256K', () => {
      it('finds public key', async () => {
        expect.assertions(1)
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(singleKey) } as Resolvable,
          alg,
          did
        )
        return expect(authenticators).toEqual({
          authenticators: [ecKey1],
          issuer: did,
          didResolutionResult: singleKey,
        })
      })

      it('filters out irrelevant public keys', async () => {
        expect.assertions(1)
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleKeysLegacy) } as Resolvable,
          alg,
          did
        )
        return expect(authenticators).toEqual({
          authenticators: [ecKey1, ecKey2, ecKey3],
          issuer: did,
          didResolutionResult: multipleKeysLegacy,
        })
      })

      it('only list authenticators able to authenticate a user', async () => {
        expect.assertions(1)
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleKeysLegacy) } as Resolvable,
          alg,
          did,
          'authentication'
        )
        return expect(authenticators).toEqual({
          authenticators: [ecKey1, ecKey2],
          issuer: did,
          didResolutionResult: multipleKeysLegacy,
        })
      })

      it('lists authenticators with multiple key types in doc', async () => {
        expect.assertions(1)
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleAuthTypes) } as Resolvable,
          alg,
          did,
          'authentication'
        )
        return expect(authenticators).toEqual({
          authenticators: [ecKey1, ecKey2, ecKey7],
          issuer: did,
          didResolutionResult: multipleAuthTypes,
        })
      })

      it('errors if no suitable public keys exist', async () => {
        expect.assertions(1)
        return await expect(
          resolveAuthenticator({ resolve: jest.fn().mockReturnValue(unsupportedFormat) } as Resolvable, alg, did)
        ).rejects.toThrowError(`DID document for ${did} does not have public keys for ${alg}`)
      })
    })

    describe('Ed25519', () => {
      const alg = 'Ed25519'
      it('filters out irrelevant public keys', async () => {
        expect.assertions(1)
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleKeysLegacy) } as Resolvable,
          alg,
          did
        )
        return expect(authenticators).toEqual({
          authenticators: [edKey, edKey2],
          issuer: did,
          didResolutionResult: multipleKeysLegacy,
        })
      })

      it('only list authenticators able to authenticate a user', async () => {
        expect.assertions(1)
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleKeysLegacy) } as Resolvable,
          alg,
          did,
          'authentication'
        )
        return expect(authenticators).toEqual({
          authenticators: [edKey],
          issuer: did,
          didResolutionResult: multipleKeysLegacy,
        })
      })

      it('lists authenticators with multiple key types in doc', async () => {
        expect.assertions(1)
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleAuthTypes) } as Resolvable,
          alg,
          did,
          'authentication'
        )
        return expect(authenticators).toEqual({
          authenticators: [edKey, edKey6, edKey8],
          issuer: did,
          didResolutionResult: multipleAuthTypes,
        })
      })

      it('errors if no suitable public keys exist', async () => {
        expect.assertions(1)
        return await expect(
          resolveAuthenticator({ resolve: jest.fn().mockReturnValue(unsupportedFormat) } as Resolvable, alg, did)
        ).rejects.toThrowError(`DID document for ${did} does not have public keys for ${alg}`)
      })
    })

    it('errors if no suitable public keys exist for authentication', async () => {
      expect.assertions(1)
      return await expect(
        resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(singleKey) } as Resolvable,
          alg,
          did,
          'authentication'
        )
      ).rejects.toThrowError(
        `DID document for ${did} does not have public keys suitable for ES256K with authentication purpose`
      )
    })

    it('errors if no public keys exist', async () => {
      expect.assertions(1)
      return await expect(
        resolveAuthenticator({ resolve: jest.fn().mockReturnValue(noPublicKey) } as Resolvable, alg, did)
      ).rejects.toThrowError(`DID document for ${did} does not have public keys for ${alg}`)
    })

    it('errors if no DID document exists', async () => {
      expect.assertions(1)
      return await expect(
        resolveAuthenticator(
          {
            resolve: jest.fn().mockReturnValue({
              didResolutionMetadata: { error: 'notFound' },
              didDocument: null,
            }),
          } as Resolvable,
          alg,
          did
        )
      ).rejects.toThrowError(`Unable to resolve DID document for ${did}: notFound, `)
    })

    it('errors if no supported signature types exist', async () => {
      expect.assertions(1)
      return await expect(
        resolveAuthenticator({ resolve: jest.fn().mockReturnValue(singleKey) } as Resolvable, 'ESBAD', did)
      ).rejects.toThrowError('No supported signature types for algorithm ESBAD')
    })
  })

  describe('incorrect format', () => {
    it('throws if token is not valid JWT format', () => {
      expect.assertions(1)
      expect(() => decodeJWT('not a jwt')).toThrow()
    })
  })
})
