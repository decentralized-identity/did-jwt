declare module 'uint8arrays' {
  export function compare(a: Uint8Array, b: Uint8Array): 0 | 1 | -1
  export function concat(arrays: Array<ArrayLike<number>>, length?: number | undefined): Uint8Array
  export type SupportedEncodings =
    | 'utf8'
    | 'utf-8'
    | 'hex'
    | 'ascii'
    | 'base10'
    | 'base16'
    | 'base16upper'
    | 'base58btc'
    | 'base64'
    | 'base64url'
    | 'base64pad'
  export function fromString(string: string, encoding?: SupportedEncodings | undefined): Uint8Array
  export function toString(array: Uint8Array, encoding?: SupportedEncodings | undefined): string
}

declare module 'multiformats' {
  declare namespace varint {
    export function decode(data: Uint8Array, offset?: number | undefined): [number, number]
    export function encodeTo(int: number, target: Uint8Array, offset?: number | undefined): Uint8Array
    export function encodingLength(int: number): number
  }
}
