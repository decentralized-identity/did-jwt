import type { ECDH, EphemeralKeyPair, Recipient } from './types.js'
import { base64ToBytes, bytesToBase64url } from '../util.js'
import { generateP256KeyPairFromSeed, generateP256KeyPair } from '../util.js'
import { concatKDF } from '../Digest.js'
import { p256 } from '@noble/curves/p256'

export async function computeP256EcdhEsKek(recipient: Recipient, receiverSecret: Uint8Array | ECDH, alg: string) {
  const crv = 'P-256'
  const keyLen = 256
  const header = recipient.header
  if (header.epk?.crv !== crv || typeof header.epk.x == 'undefined') return null
  const publicKey = base64ToBytes(header.epk.x)
  let sharedSecret
  if (receiverSecret instanceof Uint8Array) {
    sharedSecret = p256.getSharedSecret(receiverSecret, publicKey)
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

export async function createP256EcdhEsKek(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH | undefined, // unused
  alg: string,
  apu: string | undefined, // unused
  apv: string | undefined,
  ephemeralKeyPair: EphemeralKeyPair | undefined
) {
  const crv = 'P-256'
  const keyLen = 256
  const ephemeral = ephemeralKeyPair ? generateP256KeyPairFromSeed(ephemeralKeyPair.secretKey) : generateP256KeyPair()
  const epk = { kty: 'EC', crv, x: bytesToBase64url(ephemeral.publicKey) }
 // console.log(recipientPublicKey);
  // src/util.ts : bytesToHex
 // const sharedSecret = p256.getSharedSecret(ephemeral.secretKey, bytesToHex(recipientPublicKey)) fails, might need public key in different format...maybe 64 bytes
  const sharedSecret = p256.getSharedSecret(ephemeral.secretKey, recipientPublicKey)
  // Key Encryption Key
  const consumerInfo = base64ToBytes(apv ?? '')
  const kek = concatKDF(sharedSecret, keyLen, alg, undefined, consumerInfo)
  return { epk, kek }
}
