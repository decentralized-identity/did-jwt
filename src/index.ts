import SimpleSigner from './signers/SimpleSigner.js'
import EllipticSigner from './signers/EllipticSigner.js'
import NaclSigner from './signers/NaclSigner.js'
import { ES256KSigner } from './signers/ES256KSigner.js'
import { ES256Signer } from './signers/ES256Signer.js'
import { EdDSASigner } from './signers/EdDSASigner.js'
import {
  createJWS,
  createJWT,
  decodeJWT,
  type JWTHeader,
  type JWTPayload,
  type JWTVerified,
  type Signer,
  verifyJWS,
  verifyJWT,
} from './JWT.js'
import { toEthereumAddress } from './Digest.js'

export {
  type JWE,
  createJWE,
  decryptJWE,
  type Encrypter,
  type Decrypter,
  type ProtectedHeader,
  type Recipient,
  type RecipientHeader,
} from './JWE.js'
export { type ECDH, createX25519ECDH } from './ECDH.js'
export {
  xc20pDirEncrypter,
  xc20pDirDecrypter,
  x25519Encrypter,
  x25519Decrypter,
  resolveX25519Encrypters,
  createAuthEncrypter,
  createAnonEncrypter,
  createAuthDecrypter,
  createAnonDecrypter,
  xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2,
  xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2,
} from './xc20pEncryption.js'

export {
  SimpleSigner,
  EllipticSigner,
  NaclSigner,
  ES256Signer,
  ES256KSigner,
  EdDSASigner,
  verifyJWT,
  createJWT,
  decodeJWT,
  verifyJWS,
  createJWS,
  toEthereumAddress,
  type Signer,
  type JWTHeader,
  type JWTPayload,
  type JWTVerified,
}

export { type JWTOptions, type JWTVerifyOptions } from './JWT.js'

export { base64ToBytes, base58ToBytes, hexToBytes } from './util.js'

export * from './Errors.js'
