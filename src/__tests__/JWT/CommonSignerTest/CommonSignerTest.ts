import * as jwt from 'jsonwebtoken'
import * as u8a from 'uint8arrays'
import { Extensible, ServiceEndpoint, DIDDocument } from 'did-resolver'

// redeclare non-exported interface from did-resolver
interface JsonWebKey extends Extensible {
  alg?: string
  crv?: string
  e?: string
  ext?: boolean
  key_ops?: string[]
  kid?: string
  kty: string
  n?: string
  use?: string
  x?: string
  y?: string
}

interface privateJsonWebKey extends JsonWebKey {
  d?: string
}

interface VerificationMethodLegacyCommonSigner {
  id?: string
  type: string
  owner?: string
  publicKey?: string
  publicKeyBase58?: string
  publicKeyBase64?: string
  publicKeyJwk?: JsonWebKey
  publicKeyHex?: string
  publicKeyMultibase?: string
  blockchainAccountId?: string
  ethereumAddress?: string
}

type DIDDocumentLegacyCommonSigner = {
  '@context'?: 'https://www.w3.org/ns/did/v1' | string | string[]
  id: string
  alsoKnownAs?: string[]
  controller?: string | string[]
  verificationMethod?: VerificationMethodLegacyCommonSigner[]
  service?: ServiceEndpoint[]
  publicKey?: VerificationMethodLegacyCommonSigner[]
  authentication?: VerificationMethodLegacyCommonSigner[]
}

type DIDDocumentCommonSigner = {
  didDocument: DIDDocument
}

const audAddress = '0x20c769ec9c0996ba7737a4826c2aaff00b1b2040'
export const aud = `did:ethr:${audAddress}`
export const address = '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
export const did = `did:ethr:${address}`

export function CreatedidDocLegacy(
  did: string,
  publicKey: string,
  keyTypeVer: string,
  keyTypeAuth: string
): DIDDocumentLegacyCommonSigner {
  return {
    ['@context']: 'https://w3id.org/did/v1',
    id: did,
    publicKey: [
      {
        id: `${did}#keys-1`,
        type: keyTypeVer,
        owner: did,
        publicKeyHex: publicKey,
      },
    ],
    authentication: [
      {
        type: keyTypeAuth,
        publicKey: `${did}#keys-1`,
      },
    ],
  }
}

export function CreatedidDoc(did: string, publicKey: string, keyTypeVer: string): DIDDocumentCommonSigner {
  return {
    didDocument: {
      ['@context']: 'https://w3id.org/did/v1',
      id: did,
      verificationMethod: [
        {
          id: `${did}#keys-1`,
          type: keyTypeVer,
          controller: did,
          publicKeyHex: publicKey,
        },
      ],
      authentication: [`${did}#keys-1`],
      assertionMethod: [`${did}#keys-1`],
      capabilityInvocation: [`${did}#keys-1`],
      capabilityDelegation: [`${did}#some-key-that-does-not-exist`],
    },
  }
}

export function CreateauddidDoc(
  did: string,
  aud: string,
  publicKey: string,
  keyTypeVer: string
): DIDDocumentCommonSigner {
  return {
    didDocument: {
      ['@context']: 'https://w3id.org/did/v1',
      id: aud,
      verificationMethod: [
        {
          id: `${aud}#keys-1`,
          type: keyTypeVer,
          controller: did,
          publicKeyHex: publicKey,
        },
      ],
      authentication: [`${aud}#keys-1`],
      assertionMethod: [`${aud}#keys-1`],
      capabilityInvocation: [`${aud}#keys-1`],
      capabilityDelegation: [`${aud}#some-key-that-does-not-exist`],
    },
  }
}

// verify that the token is both a valid JWT and constains a signature that resolves with a public Key
export function verifyTokenFormAndValidity(token: string, pemPublic: string): boolean {
  let result
  try {
    jwt.verify(token, pemPublic)
    result = true
  } catch (e) {
    console.error(e.name + ': ' + e.message)
    result = false
  }
  return result
}

// input public key in hex, and export pem
export function publicToJWK(
  publicPointHex_x: string,
  publicPointHex_y: string,
  kty_value: string,
  crv_value: string
): JsonWebKey {
  if (publicPointHex_x.length % 2 != 0) {
    publicPointHex_x = '0' + publicPointHex_x
  }
  if (publicPointHex_y.length % 2 != 0) {
    publicPointHex_y = '0' + publicPointHex_y
  }
  const publicPointUint8_x = u8a.fromString(publicPointHex_x, 'hex')
  const publicPointBase64URL_x = u8a.toString(publicPointUint8_x, 'base64url')
  const publicPointUint8_y = u8a.fromString(publicPointHex_y, 'hex')
  const publicPointBase64URL_y = u8a.toString(publicPointUint8_y, 'base64url')
  return {
    kty: kty_value,
    crv: crv_value,
    x: publicPointBase64URL_x,
    y: publicPointBase64URL_y,
  }
}

// input private key in hex, and export pem
export function privateToJWK(privatePointHex: string, kty_value: string, crv_value: string): privateJsonWebKey {
  if (privatePointHex.length % 2 != 0) {
    privatePointHex = '0' + privatePointHex
  }
  const privatePointUint8 = u8a.fromString(privatePointHex, 'hex')
  const privatePointBase64URL = u8a.toString(privatePointUint8, 'base64url')
  return {
    kty: kty_value,
    crv: crv_value,
    d: privatePointBase64URL,
  }
}
