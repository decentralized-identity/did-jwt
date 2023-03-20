import { hexToBytes, base64ToBytes } from '../util'
import { VerificationMethod } from 'did-resolver'
import { TokenVerifier } from 'jsontokens'
import MockDate from 'mockdate'
import { fromString } from 'uint8arrays/from-string'
import { getAddress } from '@ethersproject/address'
import {
  createJWS,
  createJWT,
  createMultisignatureJWT,
  decodeJWT,
  NBF_SKEW,
  resolveAuthenticator,
  SELF_ISSUED_V0_1,
  SELF_ISSUED_V2,
  verifyJWS,
  verifyJWT,
} from '../JWT'
import { EdDSASigner } from '../signers/EdDSASigner'
import { ES256KSigner } from '../signers/ES256KSigner'
import { bytesToBase64url, decodeBase64url } from '../util'

// add declarations for ES256 Tests
import { ES256Signer } from '../signers/ES256Signer'
import * as jwt from 'jsonwebtoken'
import * as u8a from 'uint8arrays'
import * as jwkToPem from 'jwk-to-pem'
import { encodeDIDfromHexString } from  'did-key-creator'
import { createResolver, createSigner } from './ConditionalAlgorithmResolverHelper'
import { PrivateKey } from '@greymass/eosio'
import { JWT_ERROR } from '../Errors'

const NOW = 1485321133
MockDate.set(NOW * 1000 + 123)

const account = 'jack'
const network = 'eos'
const did = `did:antelope:${network}:${account}`

export const privateKeys = [
  '5JAJ7BfYKdRnrSQCsdcBqrCcBVQQSuQ77fuRAJ5fcbQ3UDhuLLZ',
  '5JcKy5rAp4rTnE9za1CNm5xBG4DnJ2T29cYpz87kRVRdQqv1K8x',
  '5JibpxxNpkqdejc38KD9xZF3fKHtTUonKCAYiZbwNPsgoKbw6FQ',
  '5KFVyCULqHQ82PCvCpCa4XGzTs8SGrRnts8t9LQMsv7hiCp7oBq',
  '5JQ8U8WS2isz3fiCXcFyZyiPfUXB4PXwDUK5tvWiqLAmUyqaXpe',
];

const publicKeys = privateKeys.map((privKey) => {
  return PrivateKey.from(privKey).toPublic().toString()
})

describe('createMultisignatureJWT()', () => {
  describe('ConditionalProof - multisignature', () => {

    it('creates a valid signed JWT that satisfies 1 of 1 signature', async () => {
      expect.assertions(1)

      const issuers = [{
        issuer: did,
        signer: createSigner(privateKeys[0]),
        alg: 'ES256K-R'
      }]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone']}, {}, issuers)

      // resolves to a DID Document with 1 verification method that requires 1 of 1 signatures
      const resolver = createResolver({
        threshold: 1,
        keys: [publicKeys[0]].map((key) => { return { key, weight: 1}}),
        accounts: []
      })

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBeTruthy()
    })

    it('creates a valid signed JWT that satisfies 2 of 2 signature', async () => {
      expect.assertions(1)

      const issuers = [{
        issuer: did,
        signer: createSigner(privateKeys[0]),
        alg: 'ES256K-R'
      }, {
        issuer: did,
        signer: createSigner(privateKeys[1]),
        alg: 'ES256K-R'
      }]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone']}, {}, issuers)

      // resolves to a DID Document with 1 verification method that requires 2 of 2 signatures
      const resolver = createResolver({
        threshold: 2,
        keys: [publicKeys[0], publicKeys[1]].map((key) => { return { key, weight: 1}}),
        accounts: []
      })

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBeTruthy()
    })

    it('creates a valid signed JWT that satisfies 2 of 3 signature', async () => {
      expect.assertions(1)

      const issuers = [{
        issuer: did,
        signer: createSigner(privateKeys[0]),
        alg: 'ES256K-R'
      }, {
        issuer: did,
        signer: createSigner(privateKeys[1]),
        alg: 'ES256K-R'
      }]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone']}, {}, issuers)

      // resolves to a DID Document with 1 verification method that requires 2 of 3 signatures
      const resolver = createResolver({
        threshold: 2,
        keys: [publicKeys[0], publicKeys[1], publicKeys[2]].map((key) => { return { key, weight: 1}}),
        accounts: []
      })

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBeTruthy()
    })

    it('creates a valid signed JWT with only one signature that fails to satisfy 2 of 3 signature', async () => {
      expect.assertions(1)

      const issuers = [{
        issuer: did,
        signer: createSigner(privateKeys[0]),
        alg: 'ES256K-R'
      }]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone']}, {}, issuers)

      // resolves to a DID Document with 1 verification method that requires 2 of 3 signatures
      const resolver = createResolver({
        threshold: 2,
        keys: [publicKeys[0], publicKeys[1], publicKeys[2]].map((key) => { return { key, weight: 1}}),
        accounts: []
      })

      await expect(verifyJWT(jwt, { resolver })).rejects.toThrow(JWT_ERROR.INVALID_SIGNATURE)
    })
  })

  describe('ConditionalProof - delegated signatures', () => {

    it('creates a valid signed JWT that satisfies 1 of 1 signature', async () => {
      expect.assertions(1)

      const issuers = [{
        issuer: did,
        signer: createSigner(privateKeys[0]),
        alg: 'ES256K-R'
      }]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone']}, {}, issuers)

      // resolves to a DID Document with 2 verification methods
      // - one that requires 1 of 1 signatures
      // - one that delegates to the first
      const resolver = createResolver([{
        threshold: 1,
        keys: [{
          key: publicKeys[0],
          weight: 1
        }],
        accounts: []
      }, {
        threshold: 1,
        keys: [],
        accounts: [{
          permission: {
            permission: 'permission0',
            actor: account,
          },
          weight: 1
        }]
      }])

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBeTruthy()
    })


  })
})
