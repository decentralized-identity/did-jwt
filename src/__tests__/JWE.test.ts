import { randomBytes } from '@noble/hashes/utils'
import { base64ToBytes, decodeBase64url, encodeBase64url, generateKeyPairFromSeed } from '../util.js'
import { createJWE, decryptJWE } from '../encryption/JWE.js'
import { vectors } from './jwe-vectors.js'
import {
  createAnonDecrypter,
  createAnonEncrypter,
  createAuthDecrypter,
  createAuthEncrypter,
  x25519Decrypter,
  x25519Encrypter,
  xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2,
  xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2,
} from '../encryption/xc20pEncryption.js'
import { createX25519ECDH } from '../encryption/ECDH.js'
import {
  a256gcmAnonDecrypterX25519WithA256KW,
  a256gcmAnonEncrypterX25519WithA256KW,
  a256gcmAuthDecrypterEcdh1PuV3x25519WithA256KW,
  a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW,
  xc20pAnonDecrypterX25519WithA256KW,
  xc20pAnonEncrypterX25519WithA256KW,
  xc20pAuthDecrypterEcdh1PuV3x25519WithA256KW,
  xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW,
} from '../encryption/aesEncryption.js'
import { xc20pDirDecrypter, xc20pDirEncrypter } from '../encryption/xc20pDir.js'
import { fromString, toString } from 'uint8arrays'
import type { Decrypter, ECDH, Encrypter, JWE } from '../encryption/types.js'

const u8a = { toString, fromString }

describe('JWE', () => {
  describe('decryptJWE', () => {
    describe('Direct encryption', () => {
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
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrowError('bad_jwe: missing properties')
      })
    })

    describe('X25519 key exchange', () => {
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
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrowError('bad_jwe:')
      })
    })

    describe('ECDH-1PU+XC20PKW (X25519), Key Wrapping Mode with XC20P content encryption', () => {
      test.each(vectors.ecdh1PuV3Xc20PkwV2.pass)(
        'decrypts valid jwe',
        async ({ senderkey, recipientkeys, cleartext, jwe }) => {
          expect.assertions(recipientkeys.length)
          for (const recipientkey of recipientkeys) {
            const decrypter = xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(
              u8a.fromString(recipientkey, 'base64pad'),
              u8a.fromString(senderkey, 'base64pad')
            )
            const cleartextU8a = await decryptJWE(jwe, decrypter)
            expect(u8a.toString(cleartextU8a)).toEqual(cleartext)
          }
        }
      )

      test.each(vectors.ecdh1PuV3Xc20PkwV2.fail)(
        'fails to decrypt bad jwe',
        async ({ senderkey, recipientkeys, jwe }) => {
          expect.assertions(recipientkeys.length)
          for (const recipientkey of recipientkeys) {
            const decrypter = xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(
              u8a.fromString(recipientkey, 'base64pad'),
              u8a.fromString(senderkey, 'base64pad')
            )
            await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrowError('Failed to decrypt')
          }
        }
      )

      test.each(vectors.ecdh1PuV3Xc20PkwV2.invalid)('throws on invalid jwe', async ({ jwe }) => {
        expect.assertions(1)
        const decrypter = xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(randomBytes(32), randomBytes(32))
        await expect(decryptJWE(jwe as any, decrypter)).rejects.toThrowError('bad_jwe:')
      })
    })

    describe('XC20P with X25519-ECDH-ES+A256KW', () => {
      test.each(vectors['XC20P with X25519-ECDH-ES+A256KW'].pass)(
        'decrypts valid jwe',
        async ({ key, cleartext, jwe }) => {
          expect.assertions(1)
          const receiverSecret = base64ToBytes(key)
          const decrypter = xc20pAnonDecrypterX25519WithA256KW(receiverSecret)
          const cleartextU8a = await decryptJWE(jwe as any, decrypter)
          expect(u8a.toString(cleartextU8a)).toEqual(cleartext)
        }
      )
    })
  })

  describe('createJWE', () => {
    describe('Direct encryption', () => {
      let key: Uint8Array, cleartext: Uint8Array, encrypter: Encrypter, decrypter: Decrypter

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
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ alg: 'dir', enc: 'XC20P', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
      })
    })

    describe('ECDH-ES (X25519) key exchange encryption', () => {
      describe('One recipient XC20PKW', () => {
        let pubkey, secretkey, cleartext: Uint8Array, encrypter: Encrypter, decrypter: Decrypter

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
          expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
          delete jwe.aad
          await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
        })
      })

      describe('One recipient A256KW', () => {
        let pubkey, secretkey, cleartext: Uint8Array, encrypter: Encrypter, decrypter: Decrypter

        beforeEach(() => {
          secretkey = randomBytes(32)
          pubkey = generateKeyPairFromSeed(secretkey).publicKey
          cleartext = u8a.fromString('hello world')
          encrypter = xc20pAnonEncrypterX25519WithA256KW(pubkey)
          decrypter = xc20pAnonDecrypterX25519WithA256KW(secretkey)
        })

        it('Creates with only ciphertext', async () => {
          expect.assertions(3)
          const jwe = await createJWE(cleartext, [encrypter], {}, undefined, true)
          expect(jwe.aad).toBeUndefined()
          expect(JSON.parse(decodeBase64url(jwe.protected)).enc).toEqual('XC20P')
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
          expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
          expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
          expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
          delete jwe.aad
          await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
        })
      })

      describe('Multiple recipients XC20PKW', () => {
        let pubkey1, secretkey1, pubkey2, secretkey2, cleartext: Uint8Array
        let encrypter1: Encrypter, decrypter1: Decrypter, encrypter2: Encrypter, decrypter2: Decrypter

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
          expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
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

      describe('Multiple recipients A256KW', () => {
        let pubkey1, secretkey1, pubkey2, secretkey2, cleartext: Uint8Array
        let encrypter1: Encrypter, decrypter1: Decrypter, encrypter2: Encrypter, decrypter2: Decrypter

        beforeEach(() => {
          secretkey1 = randomBytes(32)
          pubkey1 = generateKeyPairFromSeed(secretkey1).publicKey
          secretkey2 = randomBytes(32)
          pubkey2 = generateKeyPairFromSeed(secretkey2).publicKey
          cleartext = u8a.fromString('my secret message')
          encrypter1 = xc20pAnonEncrypterX25519WithA256KW(pubkey1)
          decrypter1 = xc20pAnonDecrypterX25519WithA256KW(secretkey1)
          encrypter2 = xc20pAnonEncrypterX25519WithA256KW(pubkey2)
          decrypter2 = xc20pAnonDecrypterX25519WithA256KW(secretkey2)
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
          expect(await decryptJWE(jwe, decrypter2)).toEqual(cleartext)
          expect(await decryptJWE(jwe, decrypter1)).toEqual(cleartext)
        })

        it('Creates with aad', async () => {
          expect.assertions(6)
          const aad = u8a.fromString('this data is authenticated')
          const jwe = await createJWE(cleartext, [encrypter1, encrypter2], { more: 'protected' }, aad)
          expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
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

  describe('ECDH-1PU+XC20PKW (X25519), Key Wrapping Mode with XC20P content encryption', () => {
    describe('One recipient', () => {
      let cleartext: Uint8Array, recipientKey: any, senderKey: any, decrypter: Decrypter

      beforeEach(() => {
        recipientKey = generateKeyPairFromSeed(randomBytes(32))
        senderKey = generateKeyPairFromSeed(randomBytes(32))
        cleartext = u8a.fromString('my secret message')
        decrypter = xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(recipientKey.secretKey, senderKey.publicKey)
      })

      it('Creates with only ciphertext', async () => {
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientKey.publicKey, senderKey.secretKey)
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with kid, no apu and no apv', async () => {
        const kid = 'did:example:receiver#key-1'
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientKey.publicKey, senderKey.secretKey, {
          kid,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
        expect(jwe.recipients!![0].header.kid).toEqual(kid)
        expect(jwe.recipients!![0].header.apu).toBeUndefined()
        expect(jwe.recipients!![0].header.apv).toBeUndefined()
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with no kid, apu and apv', async () => {
        const apu = encodeBase64url('Alice')
        const apv = encodeBase64url('Bob')
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientKey.publicKey, senderKey.secretKey, {
          apu,
          apv,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
        expect(jwe.recipients!![0].header.kid).toBeUndefined()
        expect(jwe.recipients!![0].header.apu).toEqual(apu)
        expect(jwe.recipients!![0].header.apv).toEqual(apv)
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with kid, apu and apv', async () => {
        const kid = 'did:example:receiver#key-1'
        const apu = encodeBase64url('Alice')
        const apv = encodeBase64url('Bob')
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientKey.publicKey, senderKey.secretKey, {
          kid,
          apu,
          apv,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
        expect(jwe.recipients!![0].header.kid).toEqual(kid)
        expect(jwe.recipients!![0].header.apu).toEqual(apu)
        expect(jwe.recipients!![0].header.apv).toEqual(apv)
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with data in protected header', async () => {
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientKey.publicKey, senderKey.secretKey)
        const skid = 'did:example:sender#key-1'
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter], { skid, more: 'protected' })
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid, more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(recipientKey.publicKey, senderKey.secretKey)
        expect.assertions(4)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
      })

      describe('using remote ECDH', () => {
        const message = 'hello world'
        const receiverPair = generateKeyPairFromSeed(randomBytes(32))
        const receiverRemoteECDH = createX25519ECDH(receiverPair.secretKey)
        const senderPair = generateKeyPairFromSeed(randomBytes(32))
        const senderRemoteECDH: ECDH = createX25519ECDH(senderPair.secretKey)

        it('creates anon JWE with remote ECDH', async () => {
          const encrypter = createAnonEncrypter(receiverPair.publicKey)
          const jwe: JWE = await createJWE(u8a.fromString(message), [encrypter])
          const decrypter = createAnonDecrypter(receiverRemoteECDH)
          const decryptedBytes = await decryptJWE(jwe, decrypter)
          const receivedMessage = u8a.toString(decryptedBytes)
          expect(receivedMessage).toEqual(message)
        })

        it('creates and decrypts auth JWE', async () => {
          const encrypter = createAuthEncrypter(receiverPair.publicKey, senderRemoteECDH)
          const jwe: JWE = await createJWE(u8a.fromString(message), [encrypter])
          const decrypter = createAuthDecrypter(receiverRemoteECDH, senderPair.publicKey)
          const decryptedBytes = await decryptJWE(jwe, decrypter)
          const receivedMessage = u8a.toString(decryptedBytes)
          expect(receivedMessage).toEqual(message)
        })

        it(`throws error when using bad secret key size`, async () => {
          expect.assertions(1)
          const badSecretKey = randomBytes(64)
          expect(() => {
            createX25519ECDH(badSecretKey)
          }).toThrow('invalid_argument')
        })

        it(`throws error when using bad public key size`, async () => {
          expect.assertions(1)
          const ecdh: ECDH = createX25519ECDH(randomBytes(32))
          const badPublicKey = randomBytes(64)
          expect(ecdh(badPublicKey)).rejects.toThrow('invalid_argument')
        })
      })
    })

    describe('Multiple recipients', () => {
      let cleartext: any, senderkey: any
      const recipients: any[] = []

      beforeEach(() => {
        senderkey = generateKeyPairFromSeed(randomBytes(32))
        cleartext = u8a.fromString('my secret message')

        recipients[0] = { kid: 'did:example:receiver1#key-1', recipientkey: generateKeyPairFromSeed(randomBytes(32)) }
        recipients[0] = {
          ...recipients[0],
          ...{
            encrypter: xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(
              recipients[0].recipientkey.publicKey,
              senderkey.secretKey,
              { kid: recipients[0].kid }
            ),
            decrypter: xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(
              recipients[0].recipientkey.secretKey,
              senderkey.publicKey
            ),
          },
        }

        recipients[1] = { kid: 'did:example:receiver2#key-1', recipientkey: generateKeyPairFromSeed(randomBytes(32)) }
        recipients[1] = {
          ...recipients[1],
          ...{
            encrypter: xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2(
              recipients[1].recipientkey.publicKey,
              senderkey.secretKey,
              { kid: recipients[1].kid }
            ),
            decrypter: xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2(
              recipients[1].recipientkey.secretKey,
              senderkey.publicKey
            ),
          },
        }
      })

      it('Creates with only ciphertext', async () => {
        expect.assertions(4)
        const jwe = await createJWE(cleartext, [recipients[0].encrypter, recipients[1].encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
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
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected', skid })
        expect(await decryptJWE(jwe, recipients[0].decrypter)).toEqual(cleartext)
        expect(await decryptJWE(jwe, recipients[0].decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        expect.assertions(6)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(
          cleartext,
          [recipients[0].encrypter, recipients[1].encrypter],
          { more: 'protected' },
          aad
        )
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
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

  describe('ECDH-1PU+A256KW (X25519), Key Wrapping Mode with XC20P content encryption', () => {
    describe('One recipient', () => {
      let cleartext: Uint8Array, recipientKey: any, senderKey: any, decrypter: Decrypter

      beforeEach(() => {
        recipientKey = generateKeyPairFromSeed(randomBytes(32))
        senderKey = generateKeyPairFromSeed(randomBytes(32))
        cleartext = u8a.fromString('my secret message')
        decrypter = xc20pAuthDecrypterEcdh1PuV3x25519WithA256KW(recipientKey.secretKey, senderKey.publicKey)
      })

      it('Creates with only ciphertext', async () => {
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey)
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with kid, no apu and no apv', async () => {
        const kid = 'did:example:receiver#key-1'
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey, {
          kid,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
        expect(jwe.recipients!![0].header.kid).toEqual(kid)
        expect(jwe.recipients!![0].header.apu).toBeUndefined()
        expect(jwe.recipients!![0].header.apv).toBeUndefined()
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with no kid, apu and apv', async () => {
        const apu = encodeBase64url('Alice')
        const apv = encodeBase64url('Bob')
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey, {
          apu,
          apv,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
        expect(jwe.recipients!![0].header.kid).toBeUndefined()
        expect(jwe.recipients!![0].header.apu).toEqual(apu)
        expect(jwe.recipients!![0].header.apv).toEqual(apv)
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with kid, apu and apv', async () => {
        const kid = 'did:example:receiver#key-1'
        const apu = encodeBase64url('Alice')
        const apv = encodeBase64url('Bob')
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey, {
          kid,
          apu,
          apv,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
        expect(jwe.recipients!![0].header.kid).toEqual(kid)
        expect(jwe.recipients!![0].header.apu).toEqual(apu)
        expect(jwe.recipients!![0].header.apv).toEqual(apv)
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with data in protected header', async () => {
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey)
        const skid = 'did:example:sender#key-1'
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter], { skid, more: 'protected' })
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', skid, more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey)
        expect.assertions(4)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
      })

      describe('using remote ECDH', () => {
        const message = 'hello world'
        const receiverPair = generateKeyPairFromSeed(randomBytes(32))
        const receiverRemoteECDH = createX25519ECDH(receiverPair.secretKey)
        const senderPair = generateKeyPairFromSeed(randomBytes(32))
        const senderRemoteECDH: ECDH = createX25519ECDH(senderPair.secretKey)

        it('creates anon JWE with remote ECDH', async () => {
          const encrypter = xc20pAnonEncrypterX25519WithA256KW(receiverPair.publicKey)
          const jwe: JWE = await createJWE(u8a.fromString(message), [encrypter])
          const decrypter = xc20pAnonDecrypterX25519WithA256KW(receiverRemoteECDH)
          const decryptedBytes = await decryptJWE(jwe, decrypter)
          const receivedMessage = u8a.toString(decryptedBytes)
          expect(receivedMessage).toEqual(message)
        })

        it('creates and decrypts auth JWE', async () => {
          const encrypter = xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(receiverPair.publicKey, senderRemoteECDH)
          const jwe: JWE = await createJWE(u8a.fromString(message), [encrypter])
          const decrypter = xc20pAuthDecrypterEcdh1PuV3x25519WithA256KW(receiverRemoteECDH, senderPair.publicKey)
          const decryptedBytes = await decryptJWE(jwe, decrypter)
          const receivedMessage = u8a.toString(decryptedBytes)
          expect(receivedMessage).toEqual(message)
        })

        it(`throws error when using bad secret key size`, async () => {
          expect.assertions(1)
          const badSecretKey = randomBytes(64)
          expect(() => {
            createX25519ECDH(badSecretKey)
          }).toThrow('invalid_argument')
        })

        it(`throws error when using bad public key size`, async () => {
          expect.assertions(1)
          const ecdh: ECDH = createX25519ECDH(randomBytes(32))
          const badPublicKey = randomBytes(64)
          expect(ecdh(badPublicKey)).rejects.toThrow('invalid_argument')
        })
      })
    })

    describe('Multiple recipients', () => {
      let cleartext: any, senderkey: any
      const recipients: any[] = []

      beforeEach(() => {
        senderkey = generateKeyPairFromSeed(randomBytes(32))
        cleartext = u8a.fromString('my secret message')

        recipients[0] = { kid: 'did:example:receiver1#key-1', recipientkey: generateKeyPairFromSeed(randomBytes(32)) }
        recipients[0] = {
          ...recipients[0],
          ...{
            encrypter: xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(
              recipients[0].recipientkey.publicKey,
              senderkey.secretKey,
              { kid: recipients[0].kid }
            ),
            decrypter: xc20pAuthDecrypterEcdh1PuV3x25519WithA256KW(
              recipients[0].recipientkey.secretKey,
              senderkey.publicKey
            ),
          },
        }

        recipients[1] = { kid: 'did:example:receiver2#key-1', recipientkey: generateKeyPairFromSeed(randomBytes(32)) }
        recipients[1] = {
          ...recipients[1],
          ...{
            encrypter: xc20pAuthEncrypterEcdh1PuV3x25519WithA256KW(
              recipients[1].recipientkey.publicKey,
              senderkey.secretKey,
              { kid: recipients[1].kid }
            ),
            decrypter: xc20pAuthDecrypterEcdh1PuV3x25519WithA256KW(
              recipients[1].recipientkey.secretKey,
              senderkey.publicKey
            ),
          },
        }
      })

      it('Creates with only ciphertext', async () => {
        expect.assertions(4)
        const jwe = await createJWE(cleartext, [recipients[0].encrypter, recipients[1].encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P' })
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
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected', skid })
        expect(await decryptJWE(jwe, recipients[0].decrypter)).toEqual(cleartext)
        expect(await decryptJWE(jwe, recipients[0].decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        expect.assertions(6)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(
          cleartext,
          [recipients[0].encrypter, recipients[1].encrypter],
          { more: 'protected' },
          aad
        )
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'XC20P', more: 'protected' })
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

  describe('ECDH-ES+A256KW (X25519), Key Wrapping Mode with A256GCM content encryption', () => {
    describe('One recipient', () => {
      let cleartext: Uint8Array, recipientKey: any, senderKey: any, decrypter: Decrypter

      beforeEach(() => {
        recipientKey = generateKeyPairFromSeed(randomBytes(32))
        senderKey = generateKeyPairFromSeed(randomBytes(32))
        cleartext = u8a.fromString('my secret message')
        decrypter = a256gcmAnonDecrypterX25519WithA256KW(recipientKey.secretKey)
      })

      it('Creates with only ciphertext', async () => {
        const encrypter = a256gcmAnonEncrypterX25519WithA256KW(recipientKey.publicKey)
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with kid, no apu and no apv', async () => {
        const kid = 'did:example:receiver#key-1'
        const encrypter = a256gcmAnonEncrypterX25519WithA256KW(recipientKey.publicKey, kid)
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
        const encrypter = a256gcmAnonEncrypterX25519WithA256KW(recipientKey.publicKey, undefined, apv)
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
        const encrypter = a256gcmAnonEncrypterX25519WithA256KW(recipientKey.publicKey, kid, apv)
        expect.assertions(5)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
        expect(jwe.recipients!![0].header.kid).toEqual(kid)
        expect(jwe.recipients!![0].header.apv).toEqual(apv)
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with data in protected header', async () => {
        const encrypter = a256gcmAnonEncrypterX25519WithA256KW(recipientKey.publicKey)
        const skid = 'did:example:sender#key-1'
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter], { skid, more: 'protected' })
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM', skid, more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        const encrypter = a256gcmAnonEncrypterX25519WithA256KW(recipientKey.publicKey)
        expect.assertions(4)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
      })

      describe('using remote ECDH', () => {
        const message = 'hello world'
        const receiverPair = generateKeyPairFromSeed(randomBytes(32))
        const receiverRemoteECDH = createX25519ECDH(receiverPair.secretKey)

        it('creates JWE with remote ECDH', async () => {
          const encrypter = a256gcmAnonEncrypterX25519WithA256KW(receiverPair.publicKey)
          const jwe: JWE = await createJWE(u8a.fromString(message), [encrypter])
          const decrypter = a256gcmAnonDecrypterX25519WithA256KW(receiverRemoteECDH)
          const decryptedBytes = await decryptJWE(jwe, decrypter)
          const receivedMessage = u8a.toString(decryptedBytes)
          expect(receivedMessage).toEqual(message)
        })
      })
    })

    describe('Multiple recipients', () => {
      let cleartext: any, senderkey: any
      const recipients: any[] = []

      beforeEach(() => {
        senderkey = generateKeyPairFromSeed(randomBytes(32))
        cleartext = u8a.fromString('my secret message')

        recipients[0] = { kid: 'did:example:receiver1#key-1', recipientkey: generateKeyPairFromSeed(randomBytes(32)) }
        recipients[0] = {
          ...recipients[0],
          ...{
            encrypter: a256gcmAnonEncrypterX25519WithA256KW(recipients[0].recipientkey.publicKey, recipients[0].kid),
            decrypter: a256gcmAnonDecrypterX25519WithA256KW(recipients[0].recipientkey.secretKey),
          },
        }

        recipients[1] = { kid: 'did:example:receiver2#key-1', recipientkey: generateKeyPairFromSeed(randomBytes(32)) }
        recipients[1] = {
          ...recipients[1],
          ...{
            encrypter: a256gcmAnonEncrypterX25519WithA256KW(recipients[1].recipientkey.publicKey, recipients[1].kid),
            decrypter: a256gcmAnonDecrypterX25519WithA256KW(recipients[1].recipientkey.secretKey),
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
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(
          cleartext,
          [recipients[0].encrypter, recipients[1].encrypter],
          { more: 'protected' },
          aad
        )
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
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

  describe('ECDH-1PU+A256KW (X25519), Key Wrapping Mode with A256GCM content encryption', () => {
    describe('One recipient', () => {
      let cleartext: Uint8Array, recipientKey: any, senderKey: any, decrypter: Decrypter

      beforeEach(() => {
        recipientKey = generateKeyPairFromSeed(randomBytes(32))
        senderKey = generateKeyPairFromSeed(randomBytes(32))
        cleartext = u8a.fromString('my secret message')
        decrypter = a256gcmAuthDecrypterEcdh1PuV3x25519WithA256KW(recipientKey.secretKey, senderKey.publicKey)
      })

      it('Creates with only ciphertext', async () => {
        const encrypter = a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey)
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with kid, no apu and no apv', async () => {
        const kid = 'did:example:receiver#key-1'
        const encrypter = a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey, {
          kid,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
        expect(jwe.recipients!![0].header.kid).toEqual(kid)
        expect(jwe.recipients!![0].header.apu).toBeUndefined()
        expect(jwe.recipients!![0].header.apv).toBeUndefined()
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with no kid, with apu and apv', async () => {
        const apu = encodeBase64url('Alice')
        const apv = encodeBase64url('Bob')
        const encrypter = a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey, {
          apu,
          apv,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
        expect(jwe.recipients!![0].header.kid).toBeUndefined()
        expect(jwe.recipients!![0].header.apu).toEqual(apu)
        expect(jwe.recipients!![0].header.apv).toEqual(apv)
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with kid and apu and apv', async () => {
        const kid = 'did:example:receiver#key-1'
        const apu = encodeBase64url('Alice')
        const apv = encodeBase64url('Bob')
        const encrypter = a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey, {
          kid,
          apu,
          apv,
        })
        expect.assertions(6)
        const jwe = await createJWE(cleartext, [encrypter])
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM' })
        expect(jwe.recipients!![0].header.kid).toEqual(kid)
        expect(jwe.recipients!![0].header.apu).toEqual(apu)
        expect(jwe.recipients!![0].header.apv).toEqual(apv)
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with data in protected header', async () => {
        const encrypter = a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey)
        const skid = 'did:example:sender#key-1'
        expect.assertions(3)
        const jwe = await createJWE(cleartext, [encrypter], { skid, more: 'protected' })
        expect(jwe.aad).toBeUndefined()
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM', skid, more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
      })

      it('Creates with aad', async () => {
        const encrypter = a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(recipientKey.publicKey, senderKey.secretKey)
        expect.assertions(4)
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(cleartext, [encrypter], { more: 'protected' }, aad)
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
        expect(JSON.parse(decodeBase64url(jwe.protected))).toEqual({ enc: 'A256GCM', more: 'protected' })
        expect(await decryptJWE(jwe, decrypter)).toEqual(cleartext)
        delete jwe.aad
        await expect(decryptJWE(jwe, decrypter)).rejects.toThrowError('Failed to decrypt')
      })

      describe('using remote ECDH', () => {
        const message = 'hello world'
        const receiverPair = generateKeyPairFromSeed(randomBytes(32))
        const receiverRemoteECDH = createX25519ECDH(receiverPair.secretKey)
        const senderPair = generateKeyPairFromSeed(randomBytes(32))
        const senderRemoteECDH: ECDH = createX25519ECDH(senderPair.secretKey)

        it('creates JWE with remote ECDH', async () => {
          const encrypter = a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(receiverPair.publicKey, senderRemoteECDH)
          const jwe: JWE = await createJWE(u8a.fromString(message), [encrypter])
          const decrypter = a256gcmAuthDecrypterEcdh1PuV3x25519WithA256KW(receiverRemoteECDH, senderPair.publicKey)
          const decryptedBytes = await decryptJWE(jwe, decrypter)
          const receivedMessage = u8a.toString(decryptedBytes)
          expect(receivedMessage).toEqual(message)
        })
      })
    })

    describe('Multiple recipients', () => {
      let cleartext: any, senderkey: any
      const recipients: any[] = []

      beforeEach(() => {
        senderkey = generateKeyPairFromSeed(randomBytes(32))
        cleartext = u8a.fromString('my secret message')

        recipients[0] = { kid: 'did:example:receiver1#key-1', recipientkey: generateKeyPairFromSeed(randomBytes(32)) }
        recipients[0] = {
          ...recipients[0],
          ...{
            encrypter: a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(
              recipients[0].recipientkey.publicKey,
              senderkey.secretKey,
              { kid: recipients[0].kid }
            ),
            decrypter: a256gcmAuthDecrypterEcdh1PuV3x25519WithA256KW(
              recipients[0].recipientkey.secretKey,
              senderkey.publicKey
            ),
          },
        }

        recipients[1] = { kid: 'did:example:receiver2#key-1', recipientkey: generateKeyPairFromSeed(randomBytes(32)) }
        recipients[1] = {
          ...recipients[1],
          ...{
            encrypter: a256gcmAuthEncrypterEcdh1PuV3x25519WithA256KW(
              recipients[1].recipientkey.publicKey,
              senderkey.secretKey,
              { kid: recipients[1].kid }
            ),
            decrypter: a256gcmAuthDecrypterEcdh1PuV3x25519WithA256KW(
              recipients[1].recipientkey.secretKey,
              senderkey.publicKey
            ),
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
        const aad = u8a.fromString('this data is authenticated')
        const jwe = await createJWE(
          cleartext,
          [recipients[0].encrypter, recipients[1].encrypter],
          { more: 'protected' },
          aad
        )
        expect(u8a.fromString(jwe.aad!!, 'base64url')).toEqual(aad)
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
})
