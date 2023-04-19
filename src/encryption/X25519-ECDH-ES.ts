import { EphemeralKeyPair, Recipient } from './JWE.js'
import { base64ToBytes, bytesToBase64url } from '../util.js'
import { concatKDF } from '../Digest.js'
import { generateKeyPair, generateKeyPairFromSeed, KeyPair as X25519KeyPair, sharedKey } from '@stablelib/x25519'
import { ECDH } from './ECDH.js'

export async function computeX25519EcdhEsKek(recipient: Recipient, receiverSecret: Uint8Array | ECDH, alg: string) {
  const crv = 'X25519'
  const keyLen = 256
  const header = recipient.header
  if (header.epk?.crv !== crv || typeof header.epk.x == 'undefined') return null
  const publicKey = base64ToBytes(header.epk.x)
  let sharedSecret
  if (receiverSecret instanceof Uint8Array) {
    sharedSecret = sharedKey(receiverSecret, publicKey)
  } else {
    sharedSecret = await receiverSecret(publicKey)
  }

  // Key Encryption Key
  let producerInfo: Uint8Array | undefined = undefined
  let consumerInfo: Uint8Array | undefined = undefined
  if (recipient.header.apu) producerInfo = base64ToBytes(recipient.header.apu)
  if (recipient.header.apv) consumerInfo = base64ToBytes(recipient.header.apv)
  return concatKDF(sharedSecret, keyLen, alg, producerInfo, consumerInfo)
}

export function createX25519EcdhEsKek(
  ephemeralKeyPair: EphemeralKeyPair | undefined,
  recipientPublicKey: Uint8Array,
  apv: string | undefined,
  alg: string
) {
  const crv = 'X25519'
  const keyLen = 256
  const ephemeral: X25519KeyPair = ephemeralKeyPair
    ? generateKeyPairFromSeed(ephemeralKeyPair.secretKey)
    : generateKeyPair()
  const epk = { kty: 'OKP', crv, x: bytesToBase64url(ephemeral.publicKey) }
  const sharedSecret = sharedKey(ephemeral.secretKey, recipientPublicKey)
  // Key Encryption Key
  const consumerInfo = base64ToBytes(apv ?? '')
  const kek = concatKDF(sharedSecret, keyLen, alg, undefined, consumerInfo)
  return { epk, kek }
}
