import { concat, fromString, toString } from 'uint8arrays'
import { x25519 } from '@noble/curves/ed25519.js'
import type { EphemeralKeyPair } from './encryption/types.js'
import type { VerificationMethod } from 'did-resolver'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'

const u8a = { toString, fromString, concat }

/**
 * Names of the base encodings supported for multibase encoding/decoding.
 * These are exactly the encodings `uint8arrays` understands, which is where the
 * actual base codec lives; multibase is only a prefix character layered on top.
 */
export type BaseName =
  | 'identity'
  | 'base2'
  | 'base8'
  | 'base10'
  | 'base16'
  | 'base16upper'
  | 'base32hex'
  | 'base32hexupper'
  | 'base32hexpad'
  | 'base32hexpadupper'
  | 'base32'
  | 'base32upper'
  | 'base32pad'
  | 'base32padupper'
  | 'base32z'
  | 'base36'
  | 'base36upper'
  | 'base58btc'
  | 'base58flickr'
  | 'base64'
  | 'base64pad'
  | 'base64url'
  | 'base64urlpad'

/**
 * Local multibase encode/decode.
 *
 * A multibase string is a single base-designator prefix character followed by
 * the base-encoded payload (e.g. `"z" + base58btc(b)`). `uint8arrays` (already a
 * dependency) implements the same base codecs and is prefix-aware: `toString`
 * returns the payload with the prefix stripped, and `fromString` re-adds the
 * prefix internally before decoding. So multibase encoding is the base codec's
 * output prefixed with its designator character, and multibase decoding is the
 * payload (prefix stripped) handed to `fromString`. This is byte-for-byte
 * identical to the `multibase` package and lets us drop that dependency.
 */

/** Multibase designator character for each supported base name. */
const BASE_TO_PREFIX: Record<BaseName, string> = {
  identity: '\x00',
  base2: '0',
  base8: '7',
  base10: '9',
  base16: 'f',
  base16upper: 'F',
  base32hex: 'v',
  base32hexupper: 'V',
  base32hexpad: 't',
  base32hexpadupper: 'T',
  base32: 'b',
  base32upper: 'B',
  base32pad: 'c',
  base32padupper: 'C',
  base32z: 'h',
  base36: 'k',
  base36upper: 'K',
  base58btc: 'z',
  base58flickr: 'Z',
  base64: 'm',
  base64pad: 'M',
  base64url: 'u',
  base64urlpad: 'U',
}

/** Map a multibase designator character back to its base name. */
const PREFIX_TO_BASE: Record<string, BaseName> = {
  '\x00': 'identity',
  '0': 'base2',
  '7': 'base8',
  '9': 'base10',
  f: 'base16',
  F: 'base16upper',
  v: 'base32hex',
  V: 'base32hexupper',
  t: 'base32hexpad',
  T: 'base32hexpadupper',
  b: 'base32',
  B: 'base32upper',
  c: 'base32pad',
  C: 'base32padupper',
  h: 'base32z',
  k: 'base36',
  K: 'base36upper',
  z: 'base58btc',
  Z: 'base58flickr',
  m: 'base64',
  M: 'base64pad',
  u: 'base64url',
  U: 'base64urlpad',
}

/** Encode bytes to a multibase string (designator prefix + base-encoded payload). */
function encode(base: BaseName, b: Uint8Array): Uint8Array {
  // Prefix the base-encoded payload with the base's designator character, then
  // hand it to `uint8arrays` (prefix-aware) to yield the multibase bytes.
  return u8a.fromString(`${BASE_TO_PREFIX[base]}${u8a.toString(b, base)}`)
}

/**
 * Decode a multibase string back to its raw bytes. `uint8arrays`'s `fromString`
 * re-adds the base designator internally before decoding, so the designator must
 * be stripped here and the base resolved from it — this reproduces
 * `multibase.decode` byte-for-byte.
 */
function decode(s: string): Uint8Array {
  const base = PREFIX_TO_BASE[s[0]]
  if (!base) {
    throw new Error(`Unsupported encoding: ${s[0]}`)
  }
  return u8a.fromString(s.slice(1), base)
}

/**
 * Varint (variable-length integer) codec, used to read and write the multicodec
 * prefix in a multibase-encoded public key. Ported from the reference `varint`
 * implementation that `multiformats` re-exported; `encodingLength` is derived
 * from the same `encode` algorithm so it agrees with it exactly.
 */
const MSB = 0x80
const REST = 0x7f

/**
 * Write `int` into `out` and return the number of bytes written.
 * Mirrors the reference `varint.encode`/`encodeTo`.
 */
function varintEncodeTo(int: number, out: Uint8Array): number {
  let offset = 0
  let n = int
  while (n >= Math.pow(2, 31)) {
    out[offset++] = (n & 0xff) | MSB
    n = Math.floor(n / 128)
  }
  while (n & ~REST) {
    out[offset++] = (n & 0xff) | MSB
    n >>>= 7
  }
  out[offset] = n
  return offset + 1
}

/** Number of bytes `int` needs when varint-encoded. */
function varintEncodingLength(int: number): number {
  return varintEncodeTo(int, new Uint8Array(10))
}

/**
 * Decode a varint from `data`. Returns the decoded integer and the number of
 * bytes consumed, matching the reference `varint.decode` signature.
 */
function varintDecode(data: Uint8Array): [number, number] {
  let n = 0
  let offset = 0
  let shift = 0
  let b: number
  do {
    b = data[offset++]
    n += (b & REST) * Math.pow(2, shift)
    shift += 7
  } while (b >= MSB)

  return [n, offset]
}

const varint = {
  encodeTo: varintEncodeTo,
  encodingLength: varintEncodingLength,
  decode: varintDecode,
}

/**
 * @deprecated Signers will be expected to return base64url `string` signatures.
 */
export interface EcdsaSignature {
  r: string
  s: string
  recoveryParam?: number
}

/**
 * @deprecated Signers will be expected to return base64url `string` signatures.
 */
export type ECDSASignature = {
  compact: Uint8Array
  recovery?: number
}

export type JsonWebKey = {
  crv: string
  kty: string
  x?: string
  y?: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any
}

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, 'base64url')
}

export function base64ToBytes(s: string): Uint8Array {
  const inputBase64Url = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  return u8a.fromString(inputBase64Url, 'base64url')
}

export function bytesToBase64(b: Uint8Array): string {
  return u8a.toString(b, 'base64pad')
}

export function base58ToBytes(s: string): Uint8Array {
  return u8a.fromString(s, 'base58btc')
}

export function bytesToBase58(b: Uint8Array): string {
  return u8a.toString(b, 'base58btc')
}

export type KNOWN_JWA = 'ES256' | 'ES256K' | 'ES256K-R' | 'Ed25519' | 'EdDSA'

type KNOWN_VERIFICATION_METHOD =
  | 'JsonWebKey2020'
  | 'Multikey'
  | 'Secp256k1SignatureVerificationKey2018' // deprecated in favor of EcdsaSecp256k1VerificationKey2019
  | 'Secp256k1VerificationKey2018' // deprecated in favor of EcdsaSecp256k1VerificationKey2019
  | 'EcdsaSecp256k1VerificationKey2019' // ES256K / ES256K-R
  | 'EcdsaPublicKeySecp256k1' // deprecated in favor of EcdsaSecp256k1VerificationKey2019
  | 'EcdsaSecp256k1RecoveryMethod2020' // ES256K-R (ES256K also supported with 1 less bit of security)
  | 'EcdsaSecp256r1VerificationKey2019' // ES256 / P-256
  | 'Ed25519VerificationKey2018'
  | 'Ed25519VerificationKey2020'
  | 'ED25519SignatureVerification' // deprecated
  | 'ConditionalProof2022'
  | 'X25519KeyAgreementKey2019' // deprecated
  | 'X25519KeyAgreementKey2020'

export type KNOWN_KEY_TYPE = 'Secp256k1' | 'Ed25519' | 'X25519' | 'Bls12381G1' | 'Bls12381G2' | 'P-256'

export type PublicKeyTypes = Record<KNOWN_JWA, KNOWN_VERIFICATION_METHOD[]>

export const SUPPORTED_PUBLIC_KEY_TYPES: PublicKeyTypes = {
  ES256: ['JsonWebKey2020', 'Multikey', 'EcdsaSecp256r1VerificationKey2019'],
  ES256K: [
    'EcdsaSecp256k1VerificationKey2019',
    /**
     * Equivalent to EcdsaSecp256k1VerificationKey2019 when key is an ethereumAddress
     */
    'EcdsaSecp256k1RecoveryMethod2020',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
     *   not an ethereumAddress
     */
    'Secp256k1VerificationKey2018',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
     *   not an ethereumAddress
     */
    'Secp256k1SignatureVerificationKey2018',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
     *   not an ethereumAddress
     */
    'EcdsaPublicKeySecp256k1',
    /**
     *  TODO - support R1 key as well
     *   'ConditionalProof2022',
     */
    'JsonWebKey2020',
    'Multikey',
  ],
  'ES256K-R': [
    'EcdsaSecp256k1VerificationKey2019',
    /**
     * Equivalent to EcdsaSecp256k1VerificationKey2019 when key is an ethereumAddress
     */
    'EcdsaSecp256k1RecoveryMethod2020',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
     *   not an ethereumAddress
     */
    'Secp256k1VerificationKey2018',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
     *   not an ethereumAddress
     */
    'Secp256k1SignatureVerificationKey2018',
    /**
     * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
     *   not an ethereumAddress
     */
    'EcdsaPublicKeySecp256k1',
    'ConditionalProof2022',
    'JsonWebKey2020',
    'Multikey',
  ],
  Ed25519: [
    'ED25519SignatureVerification',
    'Ed25519VerificationKey2018',
    'Ed25519VerificationKey2020',
    'JsonWebKey2020',
    'Multikey',
  ],
  EdDSA: [
    'ED25519SignatureVerification',
    'Ed25519VerificationKey2018',
    'Ed25519VerificationKey2020',
    'JsonWebKey2020',
    'Multikey',
  ],
}

const VM_TO_KEY_TYPE: Record<KNOWN_VERIFICATION_METHOD, KNOWN_KEY_TYPE | undefined> = {
  Secp256k1SignatureVerificationKey2018: 'Secp256k1',
  Secp256k1VerificationKey2018: 'Secp256k1',
  EcdsaSecp256k1VerificationKey2019: 'Secp256k1',
  EcdsaPublicKeySecp256k1: 'Secp256k1',
  EcdsaSecp256k1RecoveryMethod2020: 'Secp256k1',
  EcdsaSecp256r1VerificationKey2019: 'P-256',
  Ed25519VerificationKey2018: 'Ed25519',
  Ed25519VerificationKey2020: 'Ed25519',
  ED25519SignatureVerification: 'Ed25519',
  X25519KeyAgreementKey2019: 'X25519',
  X25519KeyAgreementKey2020: 'X25519',
  ConditionalProof2022: undefined,
  JsonWebKey2020: undefined, // key type must be specified in the JWK
  Multikey: undefined, // key type must be extracted from the multicodec
}

export type KNOWN_CODECS =
  'ed25519-pub' | 'x25519-pub' | 'secp256k1-pub' | 'bls12_381-g1-pub' | 'bls12_381-g2-pub' | 'p256-pub'

// this is from the multicodec table https://github.com/multiformats/multicodec/blob/master/table.csv
export const supportedCodecs: Record<KNOWN_CODECS, number> = {
  'ed25519-pub': 0xed,
  'x25519-pub': 0xec,
  'secp256k1-pub': 0xe7,
  'bls12_381-g1-pub': 0xea,
  'bls12_381-g2-pub': 0xeb,
  'p256-pub': 0x1200,
} as const

export const CODEC_TO_KEY_TYPE: Record<KNOWN_CODECS, KNOWN_KEY_TYPE> = {
  'bls12_381-g1-pub': 'Bls12381G1',
  'bls12_381-g2-pub': 'Bls12381G2',
  'ed25519-pub': 'Ed25519',
  'p256-pub': 'P-256',
  'secp256k1-pub': 'Secp256k1',
  'x25519-pub': 'X25519',
} as const

/**
 * Extracts the raw byte representation of a public key from a VerificationMethod along with an inferred key type
 * @param pk a VerificationMethod entry from a DIDDocument
 * @return an object containing the `keyBytes` of the public key and an inferred `keyType`
 */
export function extractPublicKeyBytes(pk: VerificationMethod): { keyBytes: Uint8Array; keyType?: KNOWN_KEY_TYPE } {
  if (pk.publicKeyBase58) {
    return {
      keyBytes: base58ToBytes(pk.publicKeyBase58),
      keyType: VM_TO_KEY_TYPE[pk.type as KNOWN_VERIFICATION_METHOD],
    }
  } else if (pk.publicKeyBase64) {
    return {
      keyBytes: base64ToBytes(pk.publicKeyBase64),
      keyType: VM_TO_KEY_TYPE[pk.type as KNOWN_VERIFICATION_METHOD],
    }
  } else if (pk.publicKeyHex) {
    return { keyBytes: hexToBytes(pk.publicKeyHex), keyType: VM_TO_KEY_TYPE[pk.type as KNOWN_VERIFICATION_METHOD] }
  } else if (pk.publicKeyJwk && pk.publicKeyJwk.crv === 'secp256k1' && pk.publicKeyJwk.x && pk.publicKeyJwk.y) {
    return {
      keyBytes: secp256k1.Point.fromAffine({
        x: bytesToBigInt(base64ToBytes(pk.publicKeyJwk.x)),
        y: bytesToBigInt(base64ToBytes(pk.publicKeyJwk.y)),
      }).toBytes(false),
      keyType: 'Secp256k1',
    }
  } else if (pk.publicKeyJwk && pk.publicKeyJwk.crv === 'P-256' && pk.publicKeyJwk.x && pk.publicKeyJwk.y) {
    return {
      keyBytes: p256.Point.fromAffine({
        x: bytesToBigInt(base64ToBytes(pk.publicKeyJwk.x)),
        y: bytesToBigInt(base64ToBytes(pk.publicKeyJwk.y)),
      }).toBytes(false),
      keyType: 'P-256',
    }
  } else if (
    pk.publicKeyJwk &&
    pk.publicKeyJwk.kty === 'OKP' &&
    ['Ed25519', 'X25519'].includes(pk.publicKeyJwk.crv ?? '') &&
    pk.publicKeyJwk.x
  ) {
    return { keyBytes: base64ToBytes(pk.publicKeyJwk.x), keyType: pk.publicKeyJwk.crv as KNOWN_KEY_TYPE }
  } else if (pk.publicKeyMultibase) {
    const { keyBytes, keyType } = multibaseToBytes(pk.publicKeyMultibase)
    return { keyBytes, keyType: keyType ?? VM_TO_KEY_TYPE[pk.type as KNOWN_VERIFICATION_METHOD] }
  }
  return { keyBytes: new Uint8Array() }
}

/**
 * Encodes the given byte array to a multibase string (defaulting to base58btc).
 * If a codec is provided, the corresponding multicodec prefix will be added.
 *
 * @param b - the Uint8Array to be encoded
 * @param base - the base to use for encoding (defaults to base58btc)
 * @param codec - the codec to use for encoding (defaults to no codec)
 *
 * @returns the multibase encoded string
 *
 * @public
 */
export function bytesToMultibase(
  b: Uint8Array,
  base: BaseName = 'base58btc',
  codec?: keyof typeof supportedCodecs | number
): string {
  if (!codec) {
    return u8a.toString(encode(base, b), 'utf-8')
  } else {
    const codecCode = typeof codec === 'string' ? supportedCodecs[codec] : codec
    const prefixLength = varint.encodingLength(codecCode)
    const multicodecEncoding = new Uint8Array(prefixLength + b.length)
    varint.encodeTo(codecCode, multicodecEncoding) // set prefix
    multicodecEncoding.set(b, prefixLength) // add the original bytes
    return u8a.toString(encode(base, multicodecEncoding), 'utf-8')
  }
}

/**
 * Converts a multibase string to the Uint8Array it represents.
 * This method will assume the byte array that is multibase encoded is a multicodec and will attempt to decode it.
 *
 * @param s - the string to be converted
 *
 * @throws if the string is not formatted correctly.
 *
 * @public
 */
export function multibaseToBytes(s: string): { keyBytes: Uint8Array; keyType?: KNOWN_KEY_TYPE } {
  const bytes = decode(s)

  // look for known key lengths first
  // Ed25519/X25519, secp256k1/P256 compressed or not, BLS12-381 G1/G2 compressed
  if ([32, 33, 48, 64, 65, 96].includes(bytes.length)) {
    return { keyBytes: bytes }
  }

  // then assume multicodec, otherwise return the bytes
  try {
    const [codec, length] = varint.decode(bytes)
    const possibleCodec: string | undefined =
      Object.entries(supportedCodecs).filter(([, code]) => code === codec)?.[0][0] ?? ''
    return { keyBytes: bytes.slice(length), keyType: CODEC_TO_KEY_TYPE[possibleCodec as KNOWN_CODECS] }
  } catch {
    // not a multicodec, return the bytes
    return { keyBytes: bytes }
  }
}

export function hexToBytes(s: string, minLength?: number): Uint8Array {
  let input = s.startsWith('0x') ? s.substring(2) : s

  if (input.length % 2 !== 0) {
    input = `0${input}`
  }

  if (minLength) {
    const paddedLength = Math.max(input.length, minLength * 2)
    input = input.padStart(paddedLength, '00')
  }

  return u8a.fromString(input.toLowerCase(), 'base16')
}

export function encodeBase64url(s: string): string {
  return bytesToBase64url(u8a.fromString(s))
}

export function decodeBase64url(s: string): string {
  return u8a.toString(base64ToBytes(s))
}

export function bytesToHex(b: Uint8Array): string {
  return u8a.toString(b, 'base16')
}

function bytesToBigInt(b: Uint8Array): bigint {
  return BigInt(`0x` + u8a.toString(b, 'base16'))
}

export function bigintToBytes(n: bigint, minLength?: number): Uint8Array {
  return hexToBytes(n.toString(16), minLength)
}

export function stringToBytes(s: string): Uint8Array {
  return u8a.fromString(s, 'utf-8')
}

export function toJose({ r, s, recoveryParam }: EcdsaSignature, recoverable?: boolean): string {
  const jose = new Uint8Array(recoverable ? 65 : 64)
  jose.set(u8a.fromString(r, 'base16'), 0)
  jose.set(u8a.fromString(s, 'base16'), 32)
  if (recoverable) {
    if (typeof recoveryParam === 'undefined') {
      throw new Error('Signer did not return a recoveryParam')
    }
    jose[64] = <number>recoveryParam
  }
  return bytesToBase64url(jose)
}

export function fromJose(signature: string): { r: string; s: string; recoveryParam?: number } {
  const signatureBytes: Uint8Array = base64ToBytes(signature)
  if (signatureBytes.length < 64 || signatureBytes.length > 65) {
    throw new TypeError(`Wrong size for signature. Expected 64 or 65 bytes, but got ${signatureBytes.length}`)
  }
  const r = bytesToHex(signatureBytes.slice(0, 32))
  const s = bytesToHex(signatureBytes.slice(32, 64))
  const recoveryParam = signatureBytes.length === 65 ? signatureBytes[64] : undefined
  return { r, s, recoveryParam }
}

export function toSealed(ciphertext: string, tag?: string): Uint8Array {
  return u8a.concat([base64ToBytes(ciphertext), tag ? base64ToBytes(tag) : new Uint8Array(0)])
}

/**
 * Generate random x25519 key pair.
 */
export function generateKeyPair(): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const secretKey = x25519.utils.randomSecretKey()
  const publicKey = x25519.getPublicKey(secretKey)
  return {
    secretKey: secretKey,
    publicKey: publicKey,
  }
}

/**
 * Generate private-public x25519 key pair from `seed`.
 */
export function generateKeyPairFromSeed(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
  if (seed.length !== 32) {
    throw new Error(`x25519: seed must be ${32} bytes`)
  }
  return {
    publicKey: x25519.getPublicKey(seed),
    secretKey: seed,
  }
}

export function genX25519EphemeralKeyPair(): EphemeralKeyPair {
  const epk = generateKeyPair()
  return {
    publicKeyJWK: { kty: 'OKP', crv: 'X25519', x: bytesToBase64url(epk.publicKey) },
    secretKey: epk.secretKey,
  }
}

/**
 * Checks if a variable is defined and not null.
 * After this check, typescript sees the variable as defined.
 *
 * @param arg - The input to be verified
 *
 * @returns true if the input variable is defined.
 */
export function isDefined<T>(arg: T): arg is Exclude<T, null | undefined> {
  return arg !== null && typeof arg !== 'undefined'
}
