import {
  x25519Decrypter,
  resolveX25519Encrypters
} from '../xc20pEncryption'
import { decryptJWE, createJWE } from '../JWE'
import * as u8a from 'uint8arrays'
import { randomBytes } from '@stablelib/random'
import { generateKeyPair } from '@stablelib/x25519'

describe('xc20pEncryption', () => {
  describe('resolveX25519Encrypters', () => {
    let resolver, did1, did2, did3, did4
    let decrypter1, decrypter2

    beforeAll(() => {
      did1 = 'did:test:1'
      did2 = 'did:test:2'
      did3 = 'did:test:3'
      did4 = 'did:test:4'
      const kp1 = generateKeyPair()
      const kp2 = generateKeyPair()
      decrypter1 = x25519Decrypter(kp1.secretKey)
      decrypter2 = x25519Decrypter(kp2.secretKey)
      resolver = {
        resolve: jest.fn(did => {
          if (did === did1) {
            return {
              publicKey: [{
                id: did1 + '#abc',
                type: 'X25519KeyAgreementKey2019',
                controller: did1,
                publicKeyBase58: u8a.toString(kp1.publicKey, 'base58btc')
              }],
              keyAgreement: [{
                id: 'irrelevant key'
              },
              did1 + '#abc'
              ]
            }
          } else if (did === did2) {
            return {
              publicKey: [],
              keyAgreement: [{
                id: did2 + '#abc',
                type: 'X25519KeyAgreementKey2019',
                controller: did2,
                publicKeyBase58: u8a.toString(kp2.publicKey, 'base58btc')
              }]
            }
          } else if (did === did3) {
            return { publicKey: [] }
          } else if (did === did4) {
            return { publicKey: [], keyAgreement: [{ type: 'wrong type' }] }
          }
        })
      }
    })

    it('correctly resolves encrypters for DIDs', async () => {
      const encrypters = await resolveX25519Encrypters([did1, did2], resolver)
      const cleartext = randomBytes(8)
      const jwe = await createJWE(cleartext, encrypters)

      expect(jwe.recipients[0].header.kid).toEqual(did1 + '#abc')
      expect(jwe.recipients[1].header.kid).toEqual(did2 + '#abc')
      expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
      expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
    })

    it('throws error if key is not found', async () => {
      await expect(resolveX25519Encrypters([did3], resolver)).rejects.toThrow('Could not find x25519 key for did:test:3')
      await expect(resolveX25519Encrypters([did4], resolver)).rejects.toThrow('Could not find x25519 key for did:test:4')
    })
  })
})
