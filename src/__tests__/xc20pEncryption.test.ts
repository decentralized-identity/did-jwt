import { x25519Decrypter, resolveX25519Encrypters } from '../xc20pEncryption'
import { decryptJWE, createJWE } from '../JWE'
import * as u8a from 'uint8arrays'
import { randomBytes } from '@stablelib/random'
import { generateKeyPair } from '@stablelib/x25519'
import { createX25519ECDH } from '../ECDH'

describe('xc20pEncryption', () => {
  describe('resolveX25519Encrypters', () => {
    const did1 = 'did:test:1'
    const did2 = 'did:test:2'
    const did3 = 'did:test:3'
    const did4 = 'did:test:4'
    const did5 = 'did:test:5'
    const did6 = 'did:test:6'
    const did7 = 'did:test:7'
    const did8 = 'did:test:8'
    const did9 = 'did:test:9'

    let resolver
    let decrypter1, decrypter2
    let decrypter1remote, decrypter2remote

    let didDocumentResult1,
      didDocumentResult2,
      didDocumentResult3,
      didDocumentResult4,
      didDocumentResult5,
      didDocumentResult6,
      didDocumentResult7,
      didDocumentResult8,
      didDocumentResult9

    beforeEach(() => {
      const kp1 = generateKeyPair()
      const kp2 = generateKeyPair()
      decrypter1 = x25519Decrypter(kp1.secretKey)
      decrypter2 = x25519Decrypter(kp2.secretKey)

      decrypter1remote = x25519Decrypter(createX25519ECDH(kp1.secretKey))
      decrypter2remote = x25519Decrypter(createX25519ECDH(kp2.secretKey))

      didDocumentResult1 = {
        didDocument: {
          verificationMethod: [
            {
              id: did1 + '#abc',
              type: 'X25519KeyAgreementKey2019',
              controller: did1,
              publicKeyBase58: u8a.toString(kp1.publicKey, 'base58btc'),
            },
          ],
          keyAgreement: [
            {
              id: 'irrelevant key',
            },
            did1 + '#abc',
          ],
        },
      }

      didDocumentResult2 = {
        didDocument: {
          verificationMethod: [],
          keyAgreement: [
            {
              id: did2 + '#abc',
              type: 'X25519KeyAgreementKey2019',
              controller: did2,
              publicKeyBase58: u8a.toString(kp2.publicKey, 'base58btc'),
            },
          ],
        },
      }

      didDocumentResult3 = { didResolutionMetadata: { error: 'notFound' }, didDocument: null }
      didDocumentResult4 = { didDocument: { publicKey: [], keyAgreement: [{ type: 'wrong type' }] } }

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
      }

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
      }

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
      }

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
      }

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
      }

      resolver = {
        resolve: jest.fn((did) => {
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
      }
    })

    it('correctly resolves encrypters for DIDs', async () => {
      expect.assertions(6)
      const encrypters = await resolveX25519Encrypters([did1, did2], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients[0].header.kid).toEqual(did1 + '#abc')
      expect(jwe.recipients[1].header.kid).toEqual(did2 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2remote)).toEqual(cleartext)
    })

    it('throws error if key is not found', async () => {
      expect.assertions(3)
      await expect(resolveX25519Encrypters([did3], resolver)).rejects.toThrowError(
        'resolver_error: Could not resolve did:test:3'
      )
      await expect(resolveX25519Encrypters([did4], resolver)).rejects.toThrowError(
        'no_suitable_keys: Could not find x25519 key for did:test:4'
      )
      await expect(resolveX25519Encrypters([did7], resolver)).rejects.toThrowError(
        'no_suitable_keys: Could not find x25519 key for did:test:7'
      )
    })

    it('resolves encrypters for DIDs with multiple valid keys ', async () => {
      expect.assertions(8)

      const secondKp1 = generateKeyPair()
      const secondKp2 = generateKeyPair()

      const newDecrypter1 = x25519Decrypter(secondKp1.secretKey)
      const newDecrypter2 = x25519Decrypter(secondKp2.secretKey)
      const newDecrypter1remote = x25519Decrypter(createX25519ECDH(secondKp1.secretKey))
      const newDecrypter2remote = x25519Decrypter(createX25519ECDH(secondKp2.secretKey))

      didDocumentResult1.didDocument.verificationMethod.push({
        id: did1 + '#def',
        type: 'X25519KeyAgreementKey2019',
        controller: did1,
        publicKeyBase58: u8a.toString(secondKp1.publicKey, 'base58btc'),
      })
      didDocumentResult1.didDocument.keyAgreement.push(did1 + '#def')

      didDocumentResult2.didDocument.keyAgreement.push({
        id: did2 + '#def',
        type: 'X25519KeyAgreementKey2019',
        controller: did2,
        publicKeyBase58: u8a.toString(secondKp2.publicKey, 'base58btc'),
      })

      const encrypters = await resolveX25519Encrypters([did1, did2], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)

      expect(jwe.recipients[0].header.kid).toEqual(did1 + '#abc')
      expect(jwe.recipients[1].header.kid).toEqual(did1 + '#def')
      expect(jwe.recipients[2].header.kid).toEqual(did2 + '#abc')
      expect(jwe.recipients[3].header.kid).toEqual(did2 + '#def')
      expect(await decryptJWE(jwe, newDecrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter1remote)).toEqual(cleartext)
      expect(await decryptJWE(jwe, newDecrypter2remote)).toEqual(cleartext)
    })

    it('resolves encrypters for DIDs where only controllers have valid key exchange keys', async () => {
      expect.assertions(3)
      const encrypters = await resolveX25519Encrypters([did5], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients[0].header.kid).toEqual(did1 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
    })

    it("resolved encrypters for DIDs where controller's controller has valid key exchange keys", async () => {
      expect.assertions(3)
      const encrypters = await resolveX25519Encrypters([did6], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients[0].header.kid).toEqual(did1 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter1remote)).toEqual(cleartext)
    })

    it('does not enter an infinite loop when DIDs controllers refer each other', async () => {
      expect.assertions(4)
      const encrypters = await resolveX25519Encrypters([did9], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)
      expect(jwe.recipients[0].header.kid).toEqual(did2 + '#abc')
      expect(jwe.recipients.length).toEqual(1)
      expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2remote)).toEqual(cleartext)
    })
  })
})
