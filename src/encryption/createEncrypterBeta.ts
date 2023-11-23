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
import { bytesToBase64url, genP256EphemeralKeyPair, genX25519EphemeralKeyPair } from '../util.js'
import { randomBytes } from '@noble/hashes/utils'

const prefixToDriverMap: any = {
  'P-256': genP256EphemeralKeyPair,
  'X25519': genX25519EphemeralKeyPair,
}

// const epk = await prefixToDriverMap['P256']

export function createFullEncrypter(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH | undefined,
  options: Partial<AuthEncryptParams> = {},
  kekCreator: KekCreator,
  keyWrapper: KeyWrapper,
  contentEncrypter: ContentEncrypter
): Encrypter {

  //const epk = await prefixToDriverMap['P256']

  const ephemeralKeyPair: EphemeralKeyPair

  // I need some way for these to be equivalent:

  return { alg: keyWrapper.alg, enc: contentEncrypter.enc, encrypt, encryptCek, genEpk: prefixToDriverMap['P256'] }

  return { alg: keyWrapper.alg, enc: contentEncrypter.enc, encrypt, encryptCek, genEpk: prefixToDriverMap[ephemeralKeyPair.publicKeyJWK.crv] }

  return { alg: keyWrapper.alg, enc: contentEncrypter.enc, encrypt, encryptCek, genEpk: genP256EphemeralKeyPair }
}