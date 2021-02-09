import { decryptJWE, createJWE, Encrypter } from '../JWE'
import vectors from './jwe-vectors.js'
import {
  xc20pDirEncrypter,
  xc20pDirDecrypter,
  x25519Encrypter,
  x25519Decrypter
} from '../xc20pEncryption'
import { decodeBase64url } from '../util'
import * as u8a from 'uint8arrays'
import { randomBytes } from '@stablelib/random'
import { generateKeyPairFromSeed } from '@stablelib/x25519'

describe('JWE', () => {
  describe('decryptJWE', () => {
    describe('Direct encryption', () => {
      test.each(vectors.dir.pass)('decrypts valid jwe', async ({ key, cleartext, jwe }) => {
        const decrypter = xc20pDirDecrypter(u8a.fromString(key, 'base64pad'))
        const cleartextU8a = await decryptJWE(jwe, decrypter)
        expect(u8a.toString(cleartextU8a)).toEqual(cleartext)
      })

      test.each(vectors.dir.fail)('fails to decrypt bad jwe', async ({ key, jwe }) => {
        const decrypter = xc20pDirDecrypter(u8a.fromString(key, 'base64pad'))
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrow('Failed to decrypt')
      })

      test.each(vectors.dir.invalid)('throws on invalid jwe', async ({ jwe }) => {
        const decrypter = xc20pDirDecrypter(randomBytes(32))
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrow('Invalid JWE')
      })
    })

    describe('X25519 key exchange', () => {
      test.each(vectors.x25519.pass)('decrypts valid jwe', async ({ key, cleartext, jwe }) => {
        const decrypter = x25519Decrypter(u8a.fromString(key, 'base64pad'))
        const cleartextU8a = await decryptJWE(jwe as any, decrypter)
        expect(u8a.toString(cleartextU8a)).toEqual(cleartext)
      })

      test.each(vectors.x25519.fail)('fails to decrypt bad jwe', async ({ key, jwe }) => {
        const decrypter = x25519Decrypter(u8a.fromString(key, 'base64pad'))
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrow('Failed to decrypt')
      })

      test.each(vectors.x25519.invalid)('throws on invalid jwe', async ({ jwe }) => {
        const decrypter = x25519Decrypter(randomBytes(32))
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrow('Invalid JWE')
      })
    })
  })

  describe('createJWE', () => {
    describe('Direct encryption', () => {
      let key, cleartext, encrypter, decrypter

      beforeEach(() => {
        key = randomBytes(32)
        cleartext = u8a.fromString('my secret message')
        encrypter = xc20pDirEncrypter(key)
        decrypter = xc20pDirDecrypter(key)
      })

      it('Creates with only ciphertext', async () => {
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ alg:'dir', enc:'XC20P' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with data in protected header', async () => {
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' })
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ alg:'dir', enc:'XC20P', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
        expect(u8a.fromString(jwe.aad, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ alg:'dir', enc:'XC20P', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrow('Failed to decrypt')
      })
    })

    describe('X25519 key exchange encryption', () => {
      describe('One recipient', () => {
        let pubkey, secretkey, cleartext, encrypter, decrypter

        beforeEach(() => {
          secretkey = randomBytes(32)
          pubkey = generateKeyPairFromSeed(secretkey).publicKey
          cleartext = u8a.fromString('my secret message')
          encrypter = x25519Encrypter(pubkey)
          decrypter = x25519Decrypter(secretkey)
        })

        it('Creates with only ciphertext', async () => {
          const jwe = await createJWE(cleartext, [encrypter])
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc:'XC20P' })
          expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        })

        it('Creates with data in protected header', async () => {
          const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' })
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc:'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        })

        it('Creates with aad', async () => {
          const aad = u8a.fromString('this data is authenticated')
          const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
          expect(u8a.fromString(jwe.aad, 'base64url')).toEqual(aad)
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc:'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
          delete jwe.aad
          await expect(decryptJWE(jwe, decrypter)).rejects.toThrow('Failed to decrypt')
        })
      })

      describe('Multiple recipients', () => {
        let pubkey1, secretkey1, pubkey2, secretkey2, cleartext
        let encrypter1, decrypter1, encrypter2, decrypter2

        beforeEach(() => {
          secretkey1 = randomBytes(32)
          pubkey1 = generateKeyPairFromSeed(secretkey1).publicKey
          secretkey2 = randomBytes(32)
          pubkey2 = generateKeyPairFromSeed(secretkey2).publicKey
          cleartext = u8a.fromString('my secret message')
          encrypter1 = x25519Encrypter(pubkey1)
          decrypter1 = x25519Decrypter(secretkey1)
          encrypter2 = x25519Encrypter(pubkey2)
          decrypter2 = x25519Decrypter(secretkey2)
        })

        it('Creates with only ciphertext', async () => {
          const jwe = await createJWE(cleartext, [encrypter1, encrypter2])
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc:'XC20P' })
          expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
          expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
        })

        it('Creates with data in protected header', async () => {
          const jwe = await createJWE(cleartext, [encrypter1, encrypter2], { more: 'protected' })
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc:'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
          expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
        })

        it('Creates with aad', async () => {
          const aad = u8a.fromString('this data is authenticated')
          const jwe = await createJWE(cleartext, [encrypter1, encrypter2], { more: 'protected' }, aad)
          expect(u8a.fromString(jwe.aad, 'base64url')).toEqual(aad)
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc:'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
          expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
          delete jwe.aad
          await expect(decryptJWE(jwe, decrypter1)).rejects.toThrow('Failed to decrypt')
          await expect(decryptJWE(jwe, decrypter2)).rejects.toThrow('Failed to decrypt')
        })

        it('Incompatible encrypters throw', async () => {
          const enc1 = { enc: 'cool enc alg1' } as Encrypter
          const enc2 = { enc: 'cool enc alg2' } as Encrypter
          await expect(createJWE(cleartext, [enc1, enc2])).rejects.toThrow('Incompatible encrypters passed')
        })
      })
    })
  })
})
