import SimpleSigner from './signers/SimpleSigner.js'
import EllipticSigner from './signers/EllipticSigner.js'
import NaclSigner from './signers/NaclSigner.js'
import { ES256KSigner } from './signers/ES256KSigner.js'
import { ES256Signer } from './signers/ES256Signer.js'
import { EdDSASigner } from './signers/EdDSASigner.js'
import {
  createJWS,
  createJWT,
  createMultisignatureJWT,
  decodeJWT,
  type JWTHeader,
  type JWTPayload,
  type JWTVerified,
  type Signer,
  verifyJWS,
  verifyJWT,
} from './JWT.js'

export { toEthereumAddress, concatKDF } from './Digest.js'

export { createJWE, decryptJWE } from './encryption/JWE.js'
export { xc20pDirDecrypter, xc20pDirEncrypter } from './encryption/xc20pDir.js'
export { a256gcmDirEncrypter, a256gcmDirDecrypter } from './encryption/a256gcm-dir.js'
export { a256gcmEncrypter, a256gcmDecrypter } from './encryption/a256gcm.js'
export { a256KeyWrapper, a256KeyUnwrapper } from './encryption/a256kw.js'
export * from './encryption/types.js'
export * from './encryption/X25519-ECDH-ES.js'
export * from './encryption/X25519-ECDH-1PU.js'
export * from './encryption/P256-ECDH-ES.js'
export * from './encryption/P256-ECDH-1PU.js'

export { createX25519ECDH, createP256ECDH } from './encryption/ECDH.js'
export {
  x25519Encrypter,
  x25519Decrypter,
  resolveX25519Encrypters,
  createAuthEncrypter,
  createAnonEncrypter,
  createAuthDecrypter,
  createAnonDecrypter,
  xc20pAuthEncrypterEcdh1PuV3x25519WithXc20PkwV2,
  xc20pAuthDecrypterEcdh1PuV3x25519WithXc20PkwV2,
  p256Encrypter,
  p256Decrypter,
  resolveP256Encrypters,
  xc20pAnonEncrypterEcdhESp256WithXc20PkwV2,
  xc20pAuthEncrypterEcdh1PuV3p256WithXc20PkwV2,
  xc20pAnonDecrypterEcdhESx25519WithXc20PkwV2,
  xc20pAuthDecrypterEcdh1PuV3p256WithXc20PkwV2,
} from './encryption/xc20pEncryption.js'

export {
  a256gcmAuthEncrypterEcdhP256WithA256KW, 
  a256gcmAnonEncrypterP256WithA256KW, 
  p256a256gcmEncrypter, 
  resolveP256a256gcmEncrypters, 
  a256gcmAuthDecrypterEcdhP256WithA256KW, 
  a256gcmAnonDecrypterEcdhESp256WithA256KW, 
  p256a256gcmDecrypter,
  a256gcmAuthDirEncrypterEcdhP256WithA256KW,
  a256gcmAnonDirEncrypterP256WithA256KW,
  a256gcmAuthDirDecrypterEcdhP256WithA256KW,
  a256gcmAnonDirDecrypterEcdhESp256WithA256KW,
  p256DirA256gcmDecrypter,
  p256DirA256GCMEncrypter,
  resolveP256a256gcmDirEncrypters
} from './encryption/a256gcmEncryption.js'

export { createFullEncrypter } from './encryption/createEncrypter.js'

export {
  SimpleSigner,
  EllipticSigner,
  NaclSigner,
  ES256Signer,
  ES256KSigner,
  EdDSASigner,
  verifyJWT,
  createJWT,
  createMultisignatureJWT,
  decodeJWT,
  verifyJWS,
  createJWS,
  type Signer,
  type JWTHeader,
  type JWTPayload,
  type JWTVerified,
}

export { type JWTOptions, type JWTVerifyOptions } from './JWT.js'

export {
  base64ToBytes,
  bytesToBase64url,
  base58ToBytes,
  bytesToBase58,
  hexToBytes,
  bytesToHex,
  genX25519EphemeralKeyPair,
  multibaseToBytes,
  bytesToMultibase,
  supportedCodecs,
  generateP256KeyPairFromSeed,
  genP256EphemeralKeyPair
} from './util.js'

export { extractPublicKeyBytes } from './VerifierAlgorithm.js'

export * from './Errors.js'
