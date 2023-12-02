import { AESKW } from '@stablelib/aes-kw'
import type { KeyWrapper, WrappingResult } from './types.js'

// copied from:
// https://github.com/decentralized-identity/veramo/blob/next/packages/did-comm/src/encryption/a256kw.ts , do I need the key unwrapper too?
export const a256KeyWrapper: KeyWrapper = {
  from: (wrappingKey: Uint8Array) => {
    const wrap = async (cek: Uint8Array): Promise<WrappingResult> => { 
      return { ciphertext: new AESKW(wrappingKey).wrapKey(cek) }    // ECDH-ES+A256KW: ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    }
    return { wrap }
  },

  alg: 'A256KW',
}

// copied from:
// https://github.com/decentralized-identity/veramo/blob/next/packages/did-comm/src/encryption/a256kw.ts 
export function a256KeyUnwrapper(wrappingKey: Uint8Array) {
  const unwrap = async (wrappedCek: Uint8Array): Promise<Uint8Array | null> => {
    try {
      return new AESKW(wrappingKey).unwrapKey(wrappedCek)
    } catch (e) {
      return null
    }
  }
  return { unwrap, alg: 'A256KW' }
}