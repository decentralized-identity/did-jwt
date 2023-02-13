import SimpleSigner from './signers/SimpleSigner'
import EllipticSigner from './signers/EllipticSigner'
import NaclSigner from './signers/NaclSigner'
import { ES256KSigner } from './signers/ES256KSigner'
import { ES256Signer } from './signers/ES256Signer'
import { EdDSASigner } from './signers/EdDSASigner'
import {
  createJWS,
  createJWT,
  decodeJWT,
  JWTHeader,
  JWTPayload,
  JWTVerified,
  Signer,
  verifyJWS,
  verifyJWT,
} from './JWT'
import { toEthereumAddress } from './Digest'

export { JWE, createJWE, decryptJWE, Encrypter, Decrypter, ProtectedHeader, Recipient, RecipientHeader } from './JWE'
export { ECDH, createX25519ECDH } from './ECDH'
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
} from './xc20pEncryption'

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
  Signer,
  JWTHeader,
  JWTPayload,
  JWTVerified,
}

export { JWTOptions, JWTVerifyOptions } from './JWT'

export { base64ToBytes, base58ToBytes, hexToBytes } from './util'

export * from './Errors'
