import type {
  AuthEncryptParams,
  ContentEncrypter,
  ECDH,
  Encrypter,
  EncryptionResult,
  EphemeralKeyPair,
  KekCreator,
  KeyWrapper,
  ProtectedHeader,
  Recipient,
} from './types.js'
import { bytesToBase64url, genX25519EphemeralKeyPair } from '../util.js'
import { randomBytes } from '@noble/hashes/utils'

export function createFullEncrypter(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH | undefined,
  options: Partial<AuthEncryptParams> = {},
  kekCreator: KekCreator,
  keyWrapper: KeyWrapper,
  contentEncrypter: ContentEncrypter
): Encrypter {
  async function encryptCek(cek: Uint8Array, ephemeralKeyPair?: EphemeralKeyPair): Promise<Recipient> {
    const { epk, kek } = await kekCreator.createKek(
      recipientPublicKey,
      senderSecret,
      `${kekCreator.alg}+${keyWrapper.alg}`,
      options.apu,
      options.apv,
      ephemeralKeyPair
    )
    const res = await keyWrapper.from(kek).wrap(cek)
    const recipient: Recipient = {
      encrypted_key: bytesToBase64url(res.ciphertext),
      header: {},
    }
    if (res.iv) recipient.header.iv = bytesToBase64url(res.iv)
    if (res.tag) recipient.header.tag = bytesToBase64url(res.tag)
    if (options.kid) recipient.header.kid = options.kid
    if (options.apu) recipient.header.apu = options.apu
    if (options.apv) recipient.header.apv = options.apv
    if (!ephemeralKeyPair) {
      recipient.header.alg = `${kekCreator.alg}+${keyWrapper.alg}`
      recipient.header.epk = epk
    }

    return recipient
  }

  async function encrypt(
    cleartext: Uint8Array,
    protectedHeader: ProtectedHeader = {},
    aad?: Uint8Array,
    ephemeralKeyPair?: EphemeralKeyPair
  ): Promise<EncryptionResult> {
    // we won't want alg to be set to dir from xc20pDirEncrypter
    Object.assign(protectedHeader, { alg: undefined })
    // Content Encryption Key
    const cek = randomBytes(32)
    const recipient: Recipient = await encryptCek(cek, ephemeralKeyPair)
    // getting an ephemeral key means the epk is set only once per all recipients
    if (ephemeralKeyPair) {
      protectedHeader.alg = `${kekCreator.alg}+${keyWrapper.alg}`
      protectedHeader.epk = ephemeralKeyPair.publicKeyJWK
    }
    return {
      ...(await contentEncrypter.from(cek).encrypt(cleartext, protectedHeader, aad)),
      recipient,
      cek,
    }
  }

  return { alg: keyWrapper.alg, enc: contentEncrypter.enc, encrypt, encryptCek, genEpk: genX25519EphemeralKeyPair }
}
