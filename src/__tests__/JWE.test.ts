import { decryptJWE, createJWE, Encrypter } from '../JWE'
import vectors from './jwe-vectors.js'
import { xc20pDirEncrypter, xc20pDirDecrypter, x25519Encrypter, x25519Decrypter,
         x25519AuthEncrypter, x25519AuthDecrypter } from '../xc20pEncryption'
import { decodeBase64url } from '../util'
import * as u8a from 'uint8arrays'
import { randomBytes } from '@stablelib/random'
import { generateKeyPairFromSeed } from '@stablelib/x25519'

describe('JWE', () => {
  describe('decryptJWE', () => {
    describe('ECDH-ES (X25519), Direct Mode with XChacha20Poly1305 content encryption', () => {
      test.each(vectors.dir.pass)('decrypts valid jwe', async ({ key, cleartext, jwe }) => {
        expect.assertions(1)
        const decrypter = xc20pDirDecrypter(u8a.fromString(key, 'base64pad'))
        const cleartextU8a = await decryptJWE(jwe, decrypter)
        expect(u8a.toString(cleartextU8a)).toEqual(cleartext)
      })

      test.each(vectors.dir.fail)('fails to decrypt bad jwe', async ({ key, jwe }) => {
        expect.assertions(1)
        const decrypter = xc20pDirDecrypter(u8a.fromString(key, 'base64pad'))
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
      })

      test.each(vectors.dir.invalid)('throws on invalid jwe', async ({ jwe }) => {
        expect.assertions(1)
        const decrypter = xc20pDirDecrypter(randomBytes(32))
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrowError('Invalid JWE')
      })
    })

    describe('ECDH-ES+XC20PKW (X25519), Key Wrapping Mode with with XChacha20Poly1305 content encryption', () => {
      test.each(vectors.x25519.pass)('decrypts valid jwe', async ({ key, cleartext, jwe }) => {
        expect.assertions(1)
        const decrypter = x25519Decrypter(u8a.fromString(key, 'base64pad'))
        const cleartextU8a = await decryptJWE(jwe as any, decrypter)
        expect(u8a.toString(cleartextU8a)).toEqual(cleartext)
      })

      test.each(vectors.x25519.fail)('fails to decrypt bad jwe', async ({ key, jwe }) => {
        expect.assertions(1)
        const decrypter = x25519Decrypter(u8a.fromString(key, 'base64pad'))
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrowError('Failed to decrypt')
      })

      test.each(vectors.x25519.invalid)('throws on invalid jwe', async ({ jwe }) => {
        expect.assertions(1)
        const decrypter = x25519Decrypter(randomBytes(32))
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrowError('Invalid JWE')
      })
    })
  })

  describe('createJWE', () => {
    describe('ECDH-ES (X25519), Direct Mode with XChacha20Poly1305 content encryption', () => {
      let key, cleartext, encrypter, decrypter

      beforeEach(() => {
        key = randomBytes(32)
        cleartext = u8a.fromString('my secret message')
        encrypter = xc20pDirEncrypter(key)
        decrypter = xc20pDirDecrypter(key)
      })

      it('Creates with only ciphertext', async () => {
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ alg: 'dir', enc: 'XC20P' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with data in protected header', async () => {
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' })
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ alg: 'dir', enc: 'XC20P', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        expect.assertions(4)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
        expect(u8a.fromString(jwe.aad, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ alg: 'dir', enc: 'XC20P', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
      })
    })

    describe('ECDH-ES+XC20PKW (X25519), Key Wrapping Mode with XChacha20Poly1305 content encryption', () => {
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
          expect.assertions(3)
          const jwe = await createJWE(cleartext, [encrypter])
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
          expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        })

        it('Creates with data in protected header', async () => {
          expect.assertions(3)
          const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' })
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        })

        it('Creates with aad', async () => {
          expect.assertions(4)
          const aad = u8a.fromString('this data is authenticated')
          const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
          expect(u8a.fromString(jwe.aad, 'base64url')).toEqual(aad)
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
          delete jwe.aad
          await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
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
          expect.assertions(4)
          const jwe = await createJWE(cleartext, [encrypter1, encrypter2])
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
          expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
          expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
        })

        it('Creates with data in protected header', async () => {
          expect.assertions(4)
          const jwe = await createJWE(cleartext, [encrypter1, encrypter2], { more: 'protected' })
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
          expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
        })

        it('Creates with aad', async () => {
          expect.assertions(6)
          const aad = u8a.fromString('this data is authenticated')
          const jwe = await createJWE(cleartext, [encrypter1, encrypter2], { more: 'protected' }, aad)
          expect(u8a.fromString(jwe.aad, 'base64url')).toEqual(aad)
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
          expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
          delete jwe.aad
          await expect(decryptJWE(jwe, decrypter1)).rejects.toThrowError('Failed to decrypt')
          await expect(decryptJWE(jwe, decrypter2)).rejects.toThrowError('Failed to decrypt')
        })

        it('Incompatible encrypters throw', async () => {
          expect.assertions(1)
          const enc1 = { enc: 'cool enc alg1' } as Encrypter
          const enc2 = { enc: 'cool enc alg2' } as Encrypter
          await expect(createJWE(cleartext, [enc1, enc2])).rejects.toThrowError('Incompatible encrypters passed')
        })
      })
    })
  })

  describe('ECDH-1PU+XC20PKW (X25519), Key Wrapping Mode with XChacha20Poly1305 content encryption', () => {
    describe('One recipient', () => {
      let cleartext, recipientKey, senderKey, encrypter, decrypter
      let kid = 'did:example:receiver#key-1'
      let skid = 'did:example:sender#key-1'

      beforeEach(() => {
        recipientKey = generateKeyPairFromSeed(randomBytes(32))
        senderKey = generateKeyPairFromSeed(randomBytes(32))        
        cleartext = u8a.fromString('my secret message')
        encrypter = x25519AuthEncrypter(recipientKey.publicKey, senderKey.secretKey, kid, skid)
        decrypter = x25519AuthDecrypter(recipientKey.secretKey, senderKey.publicKey)
      })

      it('Creates with only ciphertext', async () => {
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid: skid })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with sender kid', async () => {
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid: skid })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with data in protected header', async () => {
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' })
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid: skid, more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        expect.assertions(4)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
        expect(u8a.fromString(jwe.aad, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid: skid, more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')        
      })
    })

    describe('Multiple recipients', () => {
      let cleartext, recipientKey1, recipientKey2, senderKey, encrypter1,
          encrypter2, decrypter1, decrypter2
      let kid1 = 'did:example:receiver1#key-1'
      let kid2 = 'did:example:receiver2#key-1'
      let skid = 'did:example:sender#key-1'

      beforeEach(() => {
        senderKey = generateKeyPairFromSeed(randomBytes(32))        
        recipientKey1 = generateKeyPairFromSeed(randomBytes(32))
        recipientKey2 = generateKeyPairFromSeed(randomBytes(32))        
        cleartext = u8a.fromString('my secret message')
        encrypter1 = x25519AuthEncrypter(recipientKey1.publicKey, senderKey.secretKey, kid1, skid)
        encrypter2 = x25519AuthEncrypter(recipientKey2.publicKey, senderKey.secretKey, kid2, skid)
        decrypter1 = x25519AuthDecrypter(recipientKey1.secretKey, senderKey.publicKey)
        decrypter2 = x25519AuthDecrypter(recipientKey2.secretKey, senderKey.publicKey)
      })

      it('Creates with only ciphertext', async () => {
        expect.assertions(4)
        const jwe = await createJWE(cleartext, [encrypter1, encrypter2])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid: skid })
        expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
        expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
      })

      it('Creates with data in protected header', async () => {
        expect.assertions(4)
        const jwe = await createJWE(cleartext, [encrypter1, encrypter2], { more: 'protected' })
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid: skid, more: 'protected' })
        expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
        expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        expect.assertions(6)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(cleartext, [encrypter1, encrypter2], { more: 'protected' }, aad)
        expect(u8a.fromString(jwe.aad, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid: skid, more: 'protected' })
        expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
        expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter1)).rejects.toThrowError('Failed to decrypt')
        await expect(decryptJWE(jwe, decrypter2)).rejects.toThrowError('Failed to decrypt')
      })

      it('Incompatible encrypters throw', async () => {
        expect.assertions(1)
        const enc1 = { enc: 'cool enc alg1' } as Encrypter
        const enc2 = { enc: 'cool enc alg2' } as Encrypter
        await expect(createJWE(cleartext, [enc1, enc2])).rejects.toThrowError('Incompatible encrypters passed')
      })
    })
  })
})