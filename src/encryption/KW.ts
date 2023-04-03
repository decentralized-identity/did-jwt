import { EncryptionResult } from './JWE.js'

export type KeyWrapper = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  wrap(key: Uint8Array, options?: any): Promise<EncryptionResult>
  alg: string
}

export type KeyUnwrapper = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  unwrap(ciphertext: Uint8Array, options?: any): Promise<Uint8Array | null>
  alg: string
}
