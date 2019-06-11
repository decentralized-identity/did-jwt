export function base64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Array.prototype.slice.call(Buffer.from(s, 'base64'), 0))
}

export function bytesToBase64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64')
}
