import type { ECDH, EphemeralKeyPair, Recipient } from './types.js'
import { base64ToBytes, bytesToBase64url } from '../util.js'
import { concatKDF } from '../Digest.js'
import { p256 } from '@noble/curves/p256'
import { generateP256KeyPairFromSeed, generateP256KeyPair } from '../util.js'

export async function computeP256Ecdh1PUv3Kek(
  recipient: Recipient,
  recipientSecret: Uint8Array | ECDH,
  senderPublicKey: Uint8Array,
  alg: string
) {
  const crv = 'P-256'
  const keyLen = 256
  const header = recipient.header
  if (header.epk?.crv !== crv || typeof header.epk.x == 'undefined') return null
  // ECDH-1PU requires additional shared secret between
  // static key of sender and static key of recipient
  const publicKey = base64ToBytes(header.epk.x)
  let zE: Uint8Array
  let zS: Uint8Array

  if (recipientSecret instanceof Uint8Array) {
    zE = p256.getSharedSecret(recipientSecret, publicKey)
    zS = p256.getSharedSecret(recipientSecret, senderPublicKey)
  } else {
    zE = await recipientSecret(publicKey)
    zS = await recipientSecret(senderPublicKey)
  }

  const sharedSecret = new Uint8Array(zE.length + zS.length)
  sharedSecret.set(zE)
  sharedSecret.set(zS, zE.length)

  // Key Encryption Key
  let producerInfo
  let consumerInfo
  if (recipient.header.apu) producerInfo = base64ToBytes(recipient.header.apu)
  if (recipient.header.apv) consumerInfo = base64ToBytes(recipient.header.apv)

  return concatKDF(sharedSecret, keyLen, alg, producerInfo, consumerInfo)
}

export async function createP256Ecdh1PUv3Kek(
  recipientPublicKey: Uint8Array,
  senderSecret: Uint8Array | ECDH,
  alg: string, // must be provided as this is the key agreement alg + the key wrapper alg, Example: 'ECDH-ES+A256KW'
  apu: string | undefined,
  apv: string | undefined,
  ephemeralKeyPair: EphemeralKeyPair | undefined
) {
  const crv = 'P-256'
  const keyLen = 256
  const ephemeral = ephemeralKeyPair ? generateP256KeyPairFromSeed(ephemeralKeyPair.secretKey) : generateP256KeyPair()
  const epk = { kty: 'EC', crv, x: bytesToBase64url(ephemeral.publicKey) }
  const zE = p256.getSharedSecret(ephemeral.secretKey, recipientPublicKey)

  // ECDH-1PU requires additional shared secret between
  // static key of sender and static key of recipient
  let zS
  if (senderSecret instanceof Uint8Array) {
    zS = p256.getSharedSecret(senderSecret, recipientPublicKey)
  } else {
    zS = await senderSecret(recipientPublicKey)
  }

  const sharedSecret = new Uint8Array(zE.length + zS.length)
  sharedSecret.set(zE)
  sharedSecret.set(zS, zE.length)

  let partyUInfo: Uint8Array = new Uint8Array(0)
  let partyVInfo: Uint8Array = new Uint8Array(0)
  if (apu) partyUInfo = base64ToBytes(apu)
  if (apv) partyVInfo = base64ToBytes(apv)

  // Key Encryption Key
  const kek = concatKDF(sharedSecret, keyLen, alg, partyUInfo, partyVInfo)
  return { epk, kek }
}
