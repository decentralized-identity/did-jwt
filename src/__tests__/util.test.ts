import { bigintToBytes, hexToBytes } from '../util'

describe('bigintToBytes', () => {
  it('should convert a bigint to bytes', () => {
    const bn = BigInt(65535)
    const bytes = bigintToBytes(bn)
    expect(bytes).toEqual(new Uint8Array([255, 255]))
  })

  it('should convert a bigint to bytes given a minimum length', () => {
    const bn = BigInt(65535)
    const bytes = bigintToBytes(bn, 32)
    expect(bytes).toEqual(
      new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
      ])
    )
  })

  it('should convert a bigint to bytes given a minimum length less than the number', () => {
    const bn = BigInt('0x112233445566778899')
    const bytes = bigintToBytes(bn, 5)
    expect(bytes).toEqual(new Uint8Array([17, 34, 51, 68, 85, 102, 119, 136, 153]))
  })

  it('should convert a bigint to bytes given an odd number of bytes', () => {
    const bn = BigInt('0x101010101010101')
    const bytes = bigintToBytes(bn)
    expect(bytes).toEqual(new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1]))
  })
})

describe('hexToBytes', () => {
  it('should convert a hex string to bytes', () => {
    const bn = '0101'
    const bytes = hexToBytes(bn)
    expect(bytes).toEqual(new Uint8Array([1, 1]))
  })

  it('should convert a hex string with a prefix to bytes', () => {
    const bn = '0x0101'
    const bytes = hexToBytes(bn)
    expect(bytes).toEqual(new Uint8Array([1, 1]))
  })

  it('should convert a hex string to bytes given a minimum length', () => {
    const bn = '0101'
    const bytes = hexToBytes(bn, 32)
    expect(bytes).toEqual(
      new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1])
    )
  })

  it('should convert a hex string to bytes given a minimum length less than the number', () => {
    const bn = '0x112233445566778899'
    const bytes = hexToBytes(bn, 5)
    expect(bytes).toEqual(new Uint8Array([17, 34, 51, 68, 85, 102, 119, 136, 153]))
  })

  it('should convert a hexString to bytes given an odd number of bytes', () => {
    const bn = '0x101010101010101'
    const bytes = hexToBytes(bn)
    expect(bytes).toEqual(new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1]))
  })
})
