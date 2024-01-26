import { DIDResolutionResult, Resolvable } from 'did-resolver'
import { resolveP256a256gcmEncrypters, p256a256gcmDecrypter } from '../encryption/a256gcmEncryption.js'
import { resolveP256a256gcmDirEncrypters, p256DirA256gcmDecrypter } from '../encryption/a256gcmEncryption.js'
import { createJWE, decryptJWE } from '../encryption/JWE.js'
import type { Decrypter } from '../encryption/types.js'
import { createP256ECDH } from '../encryption/ECDH.js'
import { bytesToBase58 } from '../util.js'
import { generateP256KeyPair } from '../util.js'
import { randomBytes } from '@noble/hashes/utils'
import { fromString } from 'uint8arrays/from-string'
import { toString } from 'uint8arrays/to-string'
import { a256gcmAnonDecrypterEcdhESp256WithA256KW, a256gcmAnonEncrypterP256WithA256KW } from '../encryption/a256gcmEncryption.js'
import { decodeBase64url, encodeBase64url } from '../util.js'
import { JWE, Encrypter } from '../encryption/types.js'
import { p256 } from '@noble/curves/p256'

import { jest } from '@jest/globals'

// adapted from xc20pEncrpytion.test.ts
describe('a256gcmEncryption', () => {
  describe('resolveP256a256gcmEncrypters', () => {
    const did1 = 'did:test:1'
    const did2 = 'did:test:2'
    const did3 = 'did:test:3'
    const did4 = 'did:test:4'
    const did5 = 'did:test:5'
    const did6 = 'did:test:6'
    const did7 = 'did:test:7'
    const did8 = 'did:test:8'
    const did9 = 'did:test:9'

    let resolver: Resolvable
    let decrypter1: Decrypter, decrypter2: Decrypter
    let decrypter1remote: Decrypter, decrypter2remote: Decrypter

    let didDocumentResult1: DIDResolutionResult,
      didDocumentResult2: DIDResolutionResult,
      didDocumentResult3: DIDResolutionResult,
      didDocumentResult4: DIDResolutionResult,
      didDocumentResult5: DIDResolutionResult,
      didDocumentResult6: DIDResolutionResult,
      didDocumentResult7: DIDResolutionResult,
      didDocumentResult8: DIDResolutionResult,
      didDocumentResult9: DIDResolutionResult

    beforeEach(() => {
      const kp1 = generateP256KeyPair()
      const kp2 = generateP256KeyPair()
      decrypter1 = p256a256gcmDecrypter(kp1.secretKey)
      decrypter2 = p256a256gcmDecrypter(kp2.secretKey)

      decrypter1remote = p256a256gcmDecrypter(createP256ECDH(kp1.secretKey))
      decrypter2remote = p256a256gcmDecrypter(createP256ECDH(kp2.secretKey))

      didDocumentResult1 = {
        didDocument: {
          verificationMethod: [
            {
              id: did1 + '#abc',
              type: 'P256KeyAgreementKey2023',
              controller: did1,
              publicKeyBase58: bytesToBase58(kp1.publicKey),
            },
          ],
          keyAgreement: [
            {
              id: 'irrelevant key',
            },
            did1 + '#abc',
          ],
        },
      } as DIDResolutionResult

      didDocumentResult2 = {
        didDocument: {
          verificationMethod: [],
          keyAgreement: [
            {
              id: did2 + '#abc',
              type: 'P256KeyAgreementKey2023',
              controller: did2,
              publicKeyBase58: bytesToBase58(kp2.publicKey),
            },
          ],
        },
      } as unknown as DIDResolutionResult

      didDocumentResult3 = { didResolutionMetadata: { error: 'notFound' }, didDocument: null } as DIDResolutionResult
      didDocumentResult4 = {
        didDocument: {
          publicKey: [],
          keyAgreement: [{ type: 'wrong type' }],
        },
      } as unknown as DIDResolutionResult

      didDocumentResult5 = {
        didDocument: {
          controller: did1,
          verificationMethod: [
            {
              id: did5 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did5,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      didDocumentResult6 = {
        didDocument: {
          controller: did5,
          verificationMethod: [
            {
              id: did6 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did6,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      didDocumentResult7 = {
        didDocument: {
          controller: [did4],
          verificationMethod: [
            {
              id: did7 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did7,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      didDocumentResult8 = {
        didDocument: {
          controller: [did2, did9],
          verificationMethod: [
            {
              id: did8 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did8,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      didDocumentResult9 = {
        didDocument: {
          controller: [did8],
          verificationMethod: [
            {
              id: did9 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did9,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      resolver = {
        resolve: jest.fn(async (did) => {
          switch (did) {
            case did1:
              return didDocumentResult1
            case did2:
              return didDocumentResult2
            case did3:
              return didDocumentResult3
            case did4:
              return didDocumentResult4
            case did5:
              return didDocumentResult5
            case did6:
              return didDocumentResult6
            case did7:
              return didDocumentResult7
            case did8:
              return didDocumentResult8
            case did9:
              return didDocumentResult9
          }
        }),
      } as Resolvable
    })

    it('correctly resolves encrypters for DIDs', async () => {
      expect.assertions(6)
      const encrypters = await resolveP256a256gcmEncrypters([did1, did2], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients!![0].header.kid).toEqual(did1 + '#abc')
      expect(jwe.recipients!![1].header.kid).toEqual(did2 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2remote)).toEqual(cleartext)
    })

    it('throws error if key is not found', async () => {
      expect.assertions(3)
      await expect(resolveP256a256gcmEncrypters([did3], resolver)).rejects.toThrowError(
        'resolver_error: Could not resolve did:test:3'
      )
      await expect(resolveP256a256gcmEncrypters([did4], resolver)).rejects.toThrowError(
        'no_suitable_keys: Could not find p256 key for did:test:4'
      )
      await expect(resolveP256a256gcmEncrypters([did7], resolver)).rejects.toThrowError(
        'no_suitable_keys: Could not find p256 key for did:test:7'
      )
    })

    it('resolves encrypters for DIDs with multiple valid keys ', async () => {
      expect.assertions(8)

      const secondKp1 = generateP256KeyPair()
      const secondKp2 = generateP256KeyPair()

      const newDecrypter1 = p256a256gcmDecrypter(secondKp1.secretKey)
      const newDecrypter2 = p256a256gcmDecrypter(secondKp2.secretKey)
      const newDecrypter1remote = p256a256gcmDecrypter(createP256ECDH(secondKp1.secretKey))
      const newDecrypter2remote = p256a256gcmDecrypter(createP256ECDH(secondKp2.secretKey))

      didDocumentResult1.didDocument?.verificationMethod?.push({
        id: did1 + '#def',
        type: 'P256KeyAgreementKey2023',
        controller: did1,
        publicKeyBase58: bytesToBase58(secondKp1.publicKey),
      })
      didDocumentResult1.didDocument?.keyAgreement?.push(did1 + '#def')

      didDocumentResult2.didDocument?.keyAgreement?.push({
        id: did2 + '#def',
        type: 'P256KeyAgreementKey2023',
        controller: did2,
        publicKeyBase58: bytesToBase58(secondKp2.publicKey),
      })

      const encrypters = await resolveP256a256gcmEncrypters([did1, did2], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)

      expect(jwe.recipients!![0].header.kid).toEqual(did1 + '#abc')
      expect(jwe.recipients!![1].header.kid).toEqual(did1 + '#def')
      expect(jwe.recipients!![2].header.kid).toEqual(did2 + '#abc')
      expect(jwe.recipients!![3].header.kid).toEqual(did2 + '#def')
      expect(await decryptJWE(jwe, newDecrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter1remote)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter2remote)).toEqual(cleartext)
    })

    it('resolves encrypters for DIDs where only controllers have valid key exchange keys', async () => {
      expect.assertions(3)
      const encrypters = await resolveP256a256gcmEncrypters([did5], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients!![0].header.kid).toEqual(did1 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
    })

    it("resolved encrypters for DIDs where controller's controller has valid key exchange keys", async () => {
      expect.assertions(3)
      const encrypters = await resolveP256a256gcmEncrypters([did6], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients!![0].header.kid).toEqual(did1 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
    })

    it('does not enter an infinite loop when DIDs controllers refer each other', async () => {
      expect.assertions(4)
      const encrypters = await resolveP256a256gcmEncrypters([did9], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients!![0].header.kid).toEqual(did2 + '#abc')
      expect(jwe.recipients!!.length).toEqual(1)
      expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2remote)).toEqual(cleartext)
    })
  })

  describe('resolveP256a256gcmDirEncrypters', () => {
    const did1 = 'did:test:1'
    const did2 = 'did:test:2'
    const did3 = 'did:test:3'
    const did4 = 'did:test:4'
    const did5 = 'did:test:5'
    const did6 = 'did:test:6'
    const did7 = 'did:test:7'
    const did8 = 'did:test:8'
    const did9 = 'did:test:9'

    let resolver: Resolvable
    let decrypter1: Decrypter, decrypter2: Decrypter
    let decrypter1remote: Decrypter, decrypter2remote: Decrypter

    let didDocumentResult1: DIDResolutionResult,
      didDocumentResult2: DIDResolutionResult,
      didDocumentResult3: DIDResolutionResult,
      didDocumentResult4: DIDResolutionResult,
      didDocumentResult5: DIDResolutionResult,
      didDocumentResult6: DIDResolutionResult,
      didDocumentResult7: DIDResolutionResult,
      didDocumentResult8: DIDResolutionResult,
      didDocumentResult9: DIDResolutionResult

    beforeEach(() => {
      const kp1 = generateP256KeyPair()
      const kp2 = generateP256KeyPair()
      decrypter1 = p256DirA256gcmDecrypter(kp1.secretKey)
      decrypter2 = p256DirA256gcmDecrypter(kp2.secretKey)

      decrypter1remote = p256DirA256gcmDecrypter(createP256ECDH(kp1.secretKey))
      decrypter2remote = p256DirA256gcmDecrypter(createP256ECDH(kp2.secretKey))

      didDocumentResult1 = {
        didDocument: {
          verificationMethod: [
            {
              id: did1 + '#abc',
              type: 'P256KeyAgreementKey2023',
              controller: did1,
              publicKeyBase58: bytesToBase58(kp1.publicKey),
            },
          ],
          keyAgreement: [
            {
              id: 'irrelevant key',
            },
            did1 + '#abc',
          ],
        },
      } as DIDResolutionResult

      didDocumentResult2 = {
        didDocument: {
          verificationMethod: [],
          keyAgreement: [
            {
              id: did2 + '#abc',
              type: 'P256KeyAgreementKey2023',
              controller: did2,
              publicKeyBase58: bytesToBase58(kp2.publicKey),
            },
          ],
        },
      } as unknown as DIDResolutionResult

      didDocumentResult3 = { didResolutionMetadata: { error: 'notFound' }, didDocument: null } as DIDResolutionResult
      didDocumentResult4 = {
        didDocument: {
          publicKey: [],
          keyAgreement: [{ type: 'wrong type' }],
        },
      } as unknown as DIDResolutionResult

      didDocumentResult5 = {
        didDocument: {
          controller: did1,
          verificationMethod: [
            {
              id: did5 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did5,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      didDocumentResult6 = {
        didDocument: {
          controller: did5,
          verificationMethod: [
            {
              id: did6 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did6,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      didDocumentResult7 = {
        didDocument: {
          controller: [did4],
          verificationMethod: [
            {
              id: did7 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did7,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      didDocumentResult8 = {
        didDocument: {
          controller: [did2, did9],
          verificationMethod: [
            {
              id: did8 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did8,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      didDocumentResult9 = {
        didDocument: {
          controller: [did8],
          verificationMethod: [
            {
              id: did9 + '#owner',
              type: 'BlockchainVerificationMethod2021',
              controller: did9,
              blockchainAccountId: '0xabc123',
            },
          ],
        },
      } as DIDResolutionResult

      resolver = {
        resolve: jest.fn(async (did) => {
          switch (did) {
            case did1:
              return didDocumentResult1
            case did2:
              return didDocumentResult2
            case did3:
              return didDocumentResult3
            case did4:
              return didDocumentResult4
            case did5:
              return didDocumentResult5
            case did6:
              return didDocumentResult6
            case did7:
              return didDocumentResult7
            case did8:
              return didDocumentResult8
            case did9:
              return didDocumentResult9
          }
        }),
      } as Resolvable
    })

    it('correctly resolves encrypters for DIDs', async () => {
      expect.assertions(6)
      const encrypters = await resolveP256a256gcmDirEncrypters([did1, did2], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients!![0].header.kid).toEqual(did1 + '#abc')
      expect(jwe.recipients!![1].header.kid).toEqual(did2 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2remote)).toEqual(cleartext)
    })

    it('throws error if key is not found', async () => {
      expect.assertions(3)
      await expect(resolveP256a256gcmDirEncrypters([did3], resolver)).rejects.toThrowError(
        'resolver_error: Could not resolve did:test:3'
      )
      await expect(resolveP256a256gcmDirEncrypters([did4], resolver)).rejects.toThrowError(
        'no_suitable_keys: Could not find p256 key for did:test:4'
      )
      await expect(resolveP256a256gcmDirEncrypters([did7], resolver)).rejects.toThrowError(
        'no_suitable_keys: Could not find p256 key for did:test:7'
      )
    })

    it('resolves encrypters for DIDs with multiple valid keys ', async () => {
      expect.assertions(8)

      const secondKp1 = generateP256KeyPair()
      const secondKp2 = generateP256KeyPair()

      const newDecrypter1 = p256DirA256gcmDecrypter(secondKp1.secretKey)
      const newDecrypter2 = p256DirA256gcmDecrypter(secondKp2.secretKey)
      const newDecrypter1remote = p256DirA256gcmDecrypter(createP256ECDH(secondKp1.secretKey))
      const newDecrypter2remote = p256DirA256gcmDecrypter(createP256ECDH(secondKp2.secretKey))

      didDocumentResult1.didDocument?.verificationMethod?.push({
        id: did1 + '#def',
        type: 'P256KeyAgreementKey2023',
        controller: did1,
        publicKeyBase58: bytesToBase58(secondKp1.publicKey),
      })
      didDocumentResult1.didDocument?.keyAgreement?.push(did1 + '#def')

      didDocumentResult2.didDocument?.keyAgreement?.push({
        id: did2 + '#def',
        type: 'P256KeyAgreementKey2023',
        controller: did2,
        publicKeyBase58: bytesToBase58(secondKp2.publicKey),
      })

      const encrypters = await resolveP256a256gcmDirEncrypters([did1, did2], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)

      expect(jwe.recipients!![0].header.kid).toEqual(did1 + '#abc')
      expect(jwe.recipients!![1].header.kid).toEqual(did1 + '#def')
      expect(jwe.recipients!![2].header.kid).toEqual(did2 + '#abc')
      expect(jwe.recipients!![3].header.kid).toEqual(did2 + '#def')
      expect(await decryptJWE(jwe, newDecrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter1remote)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter2remote)).toEqual(cleartext)
    })

    it('resolves encrypters for DIDs where only controllers have valid key exchange keys', async () => {
      expect.assertions(3)
      const encrypters = await resolveP256a256gcmDirEncrypters([did5], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients!![0].header.kid).toEqual(did1 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
    })

    it("resolved encrypters for DIDs where controller's controller has valid key exchange keys", async () => {
      expect.assertions(3)
      const encrypters = await resolveP256a256gcmDirEncrypters([did6], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients!![0].header.kid).toEqual(did1 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
    })

    it('does not enter an infinite loop when DIDs controllers refer each other', async () => {
      expect.assertions(4)
      const encrypters = await resolveP256a256gcmDirEncrypters([did9], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients!![0].header.kid).toEqual(did2 + '#abc')
      expect(jwe.recipients!!.length).toEqual(1)
      expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2remote)).toEqual(cleartext)
    })
  })
})

// Adapted from:
// https://github.com/decentralized-identity/veramo/blob/next/packages/did-comm/src/__tests__/encryption.test.ts#L492-L674
// changes X25519 to P256
describe('ECDH-ES+A256KW (P-256) Anon, Key Wrapping Mode with A256GCM content encryption', () => {
  describe('One recipient', () => {
    let cleartext: Uint8Array, recipientKey: any, senderKey: any, decrypter: Decrypter

    beforeEach(() => {
      recipientKey = generateP256KeyPair()
      senderKey = generateP256KeyPair()
      cleartext = fromString('my secret message')
      decrypter = a256gcmAnonDecrypterEcdhESp256WithA256KW(recipientKey.secretKey)
    })

    it('Creates with only ciphertext', async () => {
      const encrypter = a256gcmAnonEncrypterP256WithA256KW(recipientKey.publicKey)
      expect.assertions(3)
      const jwe = await createJWE(cleartext, [encrypter])
      expect(jwe.aad).toBeUndefined()
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
      expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
    })

    it('Creates with kid, no apu and no apv', async () => {
      const kid = 'did:example:receiver#key-1'
      const encrypter = a256gcmAnonEncrypterP256WithA256KW(recipientKey.publicKey, {kid: kid})
      expect.assertions(6)
      const jwe = await createJWE(cleartext, [encrypter])
      expect(jwe.aad).toBeUndefined()
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
      expect(jwe.recipients!![0].header.kid).toEqual(kid)
      expect(jwe.recipients!![0].header.apu).toBeUndefined()
      expect(jwe.recipients!![0].header.apv).toBeUndefined()
      expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
    })

    it('Creates with no kid, with apv', async () => {
      const apv = encodeBase64url('Bob')
      const encrypter = a256gcmAnonEncrypterP256WithA256KW(recipientKey.publicKey, {kid: undefined, apv: apv})
      expect.assertions(5)
      const jwe = await createJWE(cleartext, [encrypter])
      expect(jwe.aad).toBeUndefined()
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
      expect(jwe.recipients!![0].header.kid).toBeUndefined()
      expect(jwe.recipients!![0].header.apv).toEqual(apv)
      expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
    })

    it('Creates with kid and apv', async () => {
      const kid = 'did:example:receiver#key-1'
      const apv = encodeBase64url('Bob')
      const encrypter = a256gcmAnonEncrypterP256WithA256KW(recipientKey.publicKey, {kid: kid, apv: apv})
      expect.assertions(5)
      const jwe = await createJWE(cleartext, [encrypter])
      expect(jwe.aad).toBeUndefined()
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
      expect(jwe.recipients!![0].header.kid).toEqual(kid)
      expect(jwe.recipients!![0].header.apv).toEqual(apv)
      expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
    })

    it('Creates with data in protected header', async () => {
      const encrypter = a256gcmAnonEncrypterP256WithA256KW(recipientKey.publicKey)
      const skid = 'did:example:sender#key-1'
      expect.assertions(3)
      const jwe = await createJWE(cleartext, [encrypter], { skid, more: 'protected' })
      expect(jwe.aad).toBeUndefined()
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM', skid, more: 'protected' })
      expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
    })

    it('Creates with aad', async () => {
      const encrypter = a256gcmAnonEncrypterP256WithA256KW(recipientKey.publicKey)
      expect.assertions(4)
      const aad = fromString('this data is authenticated')
      const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
      expect(fromString(jwe.aad!!, 'base64url')).toEqual(aad)
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM', more: 'protected' })
      expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      delete jwe.aad
      await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
    })

    describe('using remote ECDH', () => {
      const message = 'hello world'
      const receiverPair = generateP256KeyPair()
      const receiverRemoteECDH = createP256ECDH(receiverPair.secretKey)

      it('creates JWE with remote ECDH', async () => {
        const encrypter = a256gcmAnonEncrypterP256WithA256KW(receiverPair.publicKey)
        const jwe: JWE = await createJWE(fromString(message), [encrypter])
        const decrypter = a256gcmAnonDecrypterEcdhESp256WithA256KW(receiverRemoteECDH)
        const decryptedBytes = await decryptJWE(jwe, decrypter)
        const receivedMessage = toString(decryptedBytes)
        expect(receivedMessage).toEqual(message)
      })
    })
  })

  describe('Multiple recipients', () => {
    let cleartext: any, senderkey: any
    const recipients: any[] = []

    beforeEach(() => {
      senderkey = generateP256KeyPair()
      cleartext = fromString('my secret message')

      recipients[0] = {
        kid: 'did:example:receiver1#key-1',
        recipientkey: generateP256KeyPair(),
      }
      recipients[0] = {
        ...recipients[0],
        ...{
          encrypter: a256gcmAnonEncrypterP256WithA256KW(
            recipients[0].recipientkey.publicKey,
            recipients[0].kid,
          ),
          decrypter: a256gcmAnonDecrypterEcdhESp256WithA256KW(recipients[0].recipientkey.secretKey),
        },
      }

      recipients[1] = {
        kid: 'did:example:receiver2#key-1',
        recipientkey: generateP256KeyPair(),
      }
      recipients[1] = {
        ...recipients[1],
        ...{
          encrypter: a256gcmAnonEncrypterP256WithA256KW(
            recipients[1].recipientkey.publicKey,
            recipients[1].kid,
          ),
          decrypter: a256gcmAnonDecrypterEcdhESp256WithA256KW(recipients[1].recipientkey.secretKey),
        },
      }
    })

    it('Creates with only ciphertext', async () => {
      expect.assertions(4)
      const jwe = await createJWE(cleartext, [recipients[0].encrypter, recipients[1].encrypter])
      expect(jwe.aad).toBeUndefined()
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
      expect(await decryptJWE(jwe, recipients[0].decrypter)).toEqual(cleartext)
      expect(await decryptJWE(jwe, recipients[1].decrypter)).toEqual(cleartext)
    })

    it('Creates with data in protected header', async () => {
      expect.assertions(4)
      const skid = 'did:example:sender#key-1'
      const jwe = await createJWE(cleartext, [recipients[0].encrypter, recipients[1].encrypter], {
        more: 'protected',
        skid,
      })
      expect(jwe.aad).toBeUndefined()
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM', more: 'protected', skid })
      expect(await decryptJWE(jwe, recipients[0].decrypter)).toEqual(cleartext)
      expect(await decryptJWE(jwe, recipients[0].decrypter)).toEqual(cleartext)
    })

    it('Creates with aad', async () => {
      expect.assertions(6)
      const aad = fromString('this data is authenticated')
      const jwe = await createJWE(
        cleartext,
        [recipients[0].encrypter, recipients[1].encrypter],
        { more: 'protected' },
        aad,
      )
      expect(fromString(jwe.aad!!, 'base64url')).toEqual(aad)
      expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM', more: 'protected' })
      expect(await decryptJWE(jwe, recipients[0].decrypter)).toEqual(cleartext)
      expect(await decryptJWE(jwe, recipients[1].decrypter)).toEqual(cleartext)
      delete jwe.aad
      await expect(decryptJWE(jwe, recipients[0].decrypter)).rejects.toThrowError('Failed to decrypt')
      await expect(decryptJWE(jwe, recipients[0].decrypter)).rejects.toThrowError('Failed to decrypt')
    })

    it('Incompatible encrypters throw', async () => {
      expect.assertions(1)
      const enc1 = { enc: 'cool enc alg1' } as Encrypter
      const enc2 = { enc: 'cool enc alg2' } as Encrypter
      await expect(createJWE(cleartext, [enc1, enc2])).rejects.toThrowError('Incompatible encrypters passed')
    })
  })
})
