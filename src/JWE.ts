import { base64ToBytes, bytesToBase64url, decodeBase64url, toSealed } from './util'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ProtectedHeader = Record<string, any> & Partial<RecipientHeader>

/**
 * The JWK representation of an ephemeral public key.
 * See https://www.rfc-editor.org/rfc/rfc7518.html#section-6
 */
interface EphemeralPublicKey {
  kty?: string
  //ECC
  crv?: string
  x?: string
  y?: string
  //RSA
  n?: string
  e?: string
}

export interface RecipientHeader {
  alg: string
  iv: string
  tag: string
  epk?: EphemeralPublicKey
  kid?: string
  apv?: string
  apu?: string
}

export interface Recipient {
  header: RecipientHeader
  encrypted_key: string
}

export interface JWE {
  protected: string
  iv: string
  ciphertext: string
  tag: string
  aad?: string
  recipients?: Recipient[]
}

export interface EncryptionResult {
  ciphertext: Uint8Array
  tag: Uint8Array
  iv: Uint8Array
  protectedHeader?: string
  recipient?: Recipient
  cek?: Uint8Array
}

export interface Encrypter {
  alg: string
  enc: string
  encrypt: (cleartext: Uint8Array, protectedHeader: ProtectedHeader, aad?: Uint8Array) => Promise<EncryptionResult>
  encryptCek?: (cek: Uint8Array) => Promise<Recipient>
}

export interface Decrypter {
  alg: string
  enc: string
  decrypt: (sealed: Uint8Array, iv: Uint8Array, aad?: Uint8Array, recipient?: Recipient) => Promise<Uint8Array | null>
}

function validateJWE(jwe: JWE) {
  if (!(jwe.protected && jwe.iv && jwe.ciphertext && jwe.tag)) {
    throw new Error('bad_jwe: missing properties')
  }
  if (jwe.recipients) {
    jwe.recipients.map((rec) => {
      if (!(rec.header && rec.encrypted_key)) {
        throw new Error('bad_jwe: malformed recipients')
      }
    })
  }
}

function encodeJWE({ ciphertext, tag, iv, protectedHeader, recipient }: EncryptionResult, aad?: Uint8Array): JWE {
  const jwe: JWE = {
    protected: <string>protectedHeader,
    iv: bytesToBase64url(iv),
    ciphertext: bytesToBase64url(ciphertext),
    tag: bytesToBase64url(tag),
  }
  if (aad) jwe.aad = bytesToBase64url(aad)
  if (recipient) jwe.recipients = [recipient]
  return jwe
}

export async function createJWE(
  cleartext: Uint8Array,
  encrypters: Encrypter[],
  protectedHeader = {},
  aad?: Uint8Array
): Promise<JWE> {
  if (encrypters[0].alg === 'dir') {
    if (encrypters.length > 1) throw new Error('not_supported: Can only do "dir" encryption to one key.')
    const encryptionResult = await encrypters[0].encrypt(cleartext, protectedHeader, aad)
    return encodeJWE(encryptionResult, aad)
  } else {
    const tmpEnc = encrypters[0].enc
    if (!encrypters.reduce((acc, encrypter) => acc && encrypter.enc === tmpEnc, true)) {
      throw new Error('invalid_argument: Incompatible encrypters passed')
    }
    let cek
    let jwe
    for (const encrypter of encrypters) {
      if (!cek) {
        const encryptionResult = await encrypter.encrypt(cleartext, protectedHeader, aad)
        cek = encryptionResult.cek
        jwe = encodeJWE(encryptionResult, aad)
      } else {
        const recipient = await encrypter.encryptCek?.(cek)
        if (recipient) {
          jwe?.recipients?.push(recipient)
        }
      }
    }
    return <JWE>jwe
  }
}

export async function decryptJWE(jwe: JWE, decrypter: Decrypter): Promise<Uint8Array> {
  validateJWE(jwe)
  const protHeader = JSON.parse(decodeBase64url(jwe.protected))
  if (protHeader.enc !== decrypter.enc)
    throw new Error(`not_supported: Decrypter does not supported: '${protHeader.enc}'`)
  const sealed = toSealed(jwe.ciphertext, jwe.tag)
  const aad = new Uint8Array(Buffer.from(jwe.aad ? `${jwe.protected}.${jwe.aad}` : jwe.protected))
  let cleartext = null
  if (protHeader.alg === 'dir' && decrypter.alg === 'dir') {
    cleartext = await decrypter.decrypt(sealed, base64ToBytes(jwe.iv), aad)
  } else if (!jwe.recipients || jwe.recipients.length === 0) {
    throw new Error('bad_jwe: missing recipients')
  } else {
    for (let i = 0; !cleartext && i < jwe.recipients.length; i++) {
      const recipient = jwe.recipients[i]
      Object.assign(recipient.header, protHeader)
      if (recipient.header.alg === decrypter.alg) {
        cleartext = await decrypter.decrypt(sealed, base64ToBytes(jwe.iv), aad, recipient)
      }
    }
  }
  if (cleartext === null) throw new Error('failure: Failed to decrypt')
  return cleartext
}
