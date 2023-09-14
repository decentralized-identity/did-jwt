import MockDate from 'mockdate'
import { createMultisignatureJWT, verifyJWT } from '../JWT.js'

// add declarations for ES256 Tests
import { createResolver, createSigner } from './ConditionalAlgorithmResolverHelper.js'
import { PrivateKey } from '@greymass/eosio'
import { JWT_ERROR } from '../Errors.js'

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
]

const publicKeys = privateKeys.map((privKey) => {
  return PrivateKey.from(privKey).toPublic().toString()
})

describe('createMultisignatureJWT()', () => {
  describe('ConditionalProof - multisignature', () => {
    it('creates a valid signed JWT that satisfies 1 of 1 signature', async () => {
      expect.assertions(2)

      const issuers = [
        {
          issuer: did,
          signer: createSigner(privateKeys[0]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 1 verification method that requires 1 of 1 signatures
      const resolver = createResolver({
        threshold: 1,
        keys: [publicKeys[0]].map((key) => {
          return { key, weight: 1 }
        }),
        accounts: [],
      })

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBe(true)
      expect(verified.payload.requested).toEqual(['name', 'phone'])
    })

    it('creates a valid signed JWT that satisfies 2 of 2 signature', async () => {
      expect.assertions(1)

      const issuers = [
        {
          issuer: did,
          signer: createSigner(privateKeys[0]),
          alg: 'ES256K-R',
        },
        {
          issuer: did,
          signer: createSigner(privateKeys[1]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 1 verification method that requires 2 of 2 signatures
      const resolver = createResolver({
        threshold: 2,
        keys: [publicKeys[0], publicKeys[1]].map((key) => {
          return { key, weight: 1 }
        }),
        accounts: [],
      })

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBe(true)
    })

    it('creates a valid signed JWT that satisfies 2 of 3 signature', async () => {
      expect.assertions(1)

      const issuers = [
        {
          issuer: did,
          signer: createSigner(privateKeys[0]),
          alg: 'ES256K-R',
        },
        {
          issuer: did,
          signer: createSigner(privateKeys[1]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 1 verification method that requires 2 of 3 signatures
      const resolver = createResolver({
        threshold: 2,
        keys: [publicKeys[0], publicKeys[1], publicKeys[2]].map((key) => {
          return { key, weight: 1 }
        }),
        accounts: [],
      })

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBe(true)
    })

    it('creates a valid signed JWT with only one signature that fails to satisfy 2 of 3 signature', async () => {
      expect.assertions(1)

      const issuers = [
        {
          issuer: did,
          signer: createSigner(privateKeys[0]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 1 verification method that requires 2 of 3 signatures
      const resolver = createResolver({
        threshold: 2,
        keys: [publicKeys[0], publicKeys[1], publicKeys[2]].map((key) => {
          return { key, weight: 1 }
        }),
        accounts: [],
      })

      await expect(verifyJWT(jwt, { resolver })).rejects.toThrow(JWT_ERROR.INVALID_SIGNATURE)
    })
  })

  describe('ConditionalProof - delegated signatures', () => {
    it('creates a valid signed JWT that satisfies 1 delegation', async () => {
      expect.assertions(2)

      const issuers = [
        {
          issuer: did + '#permission1',
          signer: createSigner(privateKeys[0]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 2 verification methods
      // - one that requires 1 of 1 signatures
      // - one that delegates to the first
      const resolver = createResolver([
        {
          threshold: 1,
          keys: [
            {
              key: publicKeys[0],
              weight: 1,
            },
          ],
          accounts: [],
        },
        {
          threshold: 1,
          keys: [],
          accounts: [
            {
              permission: {
                permission: 'permission0',
                actor: account,
              },
              weight: 1,
            },
          ],
        },
      ])

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBe(true)
      expect(verified.signer.id).toBe(did + '#permission1')
    })

    it('creates a valid signed JWT that fails satisfies 1 delegation when the signing key is incorrect', async () => {
      expect.assertions(1)

      const issuers = [
        {
          issuer: did,
          signer: createSigner(privateKeys[1]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 2 verification methods
      // - one that requires 1 of 1 signatures
      // - one that delegates to the first
      const resolver = createResolver([
        {
          threshold: 1,
          keys: [
            {
              key: publicKeys[0],
              weight: 1,
            },
          ],
          accounts: [],
        },
        {
          threshold: 1,
          keys: [],
          accounts: [
            {
              permission: {
                permission: 'permission0',
                actor: account,
              },
              weight: 1,
            },
          ],
        },
      ])

      await expect(verifyJWT(jwt, { resolver })).rejects.toThrow(JWT_ERROR.INVALID_SIGNATURE)
    })
  })

  describe('ConditionalProof - combination key and delegated signatures', () => {
    it('creates a valid signed JWT that satisfies 3 threshold and 2 keys and 2 delegated signature check', async () => {
      expect.assertions(2)

      const issuers = [
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[0]),
          alg: 'ES256K-R',
        },
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[1]),
          alg: 'ES256K-R',
        },
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[2]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 3 verification methods
      // - one of 3 threshold with 2 signature (privateKey[0] and privateKey[1]) and 2 delegations to the 2nd and 3rd verification method
      // - one with 1 signature requirement of privateKey[2]
      // - one with 1 signature requirement of privateKey[3]
      const resolver = createResolver([
        {
          threshold: 3,
          keys: [
            {
              key: publicKeys[0],
              weight: 1,
            },
            {
              key: publicKeys[1],
              weight: 1,
            },
          ],
          accounts: [
            {
              permission: {
                permission: 'permission1',
                actor: account,
              },
              weight: 1,
            },
            {
              permission: {
                permission: 'permission2',
                actor: account,
              },
              weight: 1,
            },
          ],
        },
        {
          threshold: 1,
          keys: [
            {
              key: publicKeys[2],
              weight: 1,
            },
          ],
          accounts: [],
        },
        {
          threshold: 1,
          keys: [
            {
              key: publicKeys[3],
              weight: 1,
            },
          ],
          accounts: [],
        },
      ])

      const verified = await verifyJWT(jwt, { resolver })
      expect(verified.verified).toBe(true)
      expect(verified.signer.id).toBe(did + '#permission0')
    })

    it('creates a valid signed JWT that fails satisfies 3 threshold and 2 keys and 2 delegated signature check, with a bad key', async () => {
      expect.assertions(1)

      const issuers = [
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[4]),
          alg: 'ES256K-R',
        },
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[1]),
          alg: 'ES256K-R',
        },
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[2]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 3 verification methods
      // - one of 3 threshold with 2 signature (privateKey[0] and privateKey[1]) and 2 delegations to the 2nd and 3rd verification method
      // - one with 1 signature requirement of privateKey[2]
      // - one with 1 signature requirement of privateKey[3]
      const resolver = createResolver([
        {
          threshold: 3,
          keys: [
            {
              key: publicKeys[0],
              weight: 1,
            },
            {
              key: publicKeys[1],
              weight: 1,
            },
          ],
          accounts: [
            {
              permission: {
                permission: 'permission1',
                actor: account,
              },
              weight: 1,
            },
            {
              permission: {
                permission: 'permission2',
                actor: account,
              },
              weight: 1,
            },
          ],
        },
        {
          threshold: 1,
          keys: [
            {
              key: publicKeys[2],
              weight: 1,
            },
          ],
          accounts: [],
        },
        {
          threshold: 1,
          keys: [
            {
              key: publicKeys[3],
              weight: 1,
            },
          ],
          accounts: [],
        },
      ])

      await expect(verifyJWT(jwt, { resolver })).rejects.toThrow(JWT_ERROR.INVALID_SIGNATURE)
    })

    it('creates a valid signed JWT that fails satisfies 3 threshold and 2 keys and 2 delegated signature check, with a bad delegate', async () => {
      expect.assertions(1)

      const issuers = [
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[0]),
          alg: 'ES256K-R',
        },
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[1]),
          alg: 'ES256K-R',
        },
        {
          issuer: did + '#permission0',
          signer: createSigner(privateKeys[4]),
          alg: 'ES256K-R',
        },
      ]

      const jwt = await createMultisignatureJWT({ requested: ['name', 'phone'] }, {}, issuers)

      // resolves to a DID Document with 3 verification methods
      // - one of 3 threshold with 2 signature (privateKey[0] and privateKey[1]) and 2 delegations to the 2nd and 3rd verification method
      // - one with 1 signature requirement of privateKey[2]
      // - one with 1 signature requirement of privateKey[3]
      const resolver = createResolver([
        {
          threshold: 3,
          keys: [
            {
              key: publicKeys[0],
              weight: 1,
            },
            {
              key: publicKeys[1],
              weight: 1,
            },
          ],
          accounts: [
            {
              permission: {
                permission: 'permission1',
                actor: account,
              },
              weight: 1,
            },
            {
              permission: {
                permission: 'permission2',
                actor: account,
              },
              weight: 1,
            },
          ],
        },
        {
          threshold: 1,
          keys: [
            {
              key: publicKeys[2],
              weight: 1,
            },
          ],
          accounts: [],
        },
        {
          threshold: 1,
          keys: [
            {
              key: publicKeys[3],
              weight: 1,
            },
          ],
          accounts: [],
        },
      ])

      await expect(verifyJWT(jwt, { resolver })).rejects.toThrow(JWT_ERROR.INVALID_SIGNATURE)
    })
  })
})
