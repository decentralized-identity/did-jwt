declare module 'ipld-dag-cbor' {
  import type CID from 'cids'

  export type UserOptions = { cidVersion?: number; hashAlg?: number }

  export namespace util {
    function cid(binaryBlob: any, userOptions?: UserOptions): Promise<CID>
    function serialize(node: any): Uint8Array
    function deserialize(b: Uint8Array): Record<string, any>
  }
}

declare module 'multihashes' {
  interface DecodeResult {
    code: number
    digest: Uint8Array
  }
  export function encode(digest: Uint8Array, code: number | string, length?: number): Uint8Array
  export function decode(mh: Uint8Array): DecodeResult
}
