import { keccak, ripemd160, sha256, toEthereumAddress } from '../Digest.js'
import { toString, fromString } from 'uint8arrays'

const u8a = { toString, fromString }

// https://www.di-mgt.com.au/sha_testvectors.html
describe('sha256', () => {
  it('message: "" (empty string)', async () => {
    expect.assertions(2)
    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    expect(u8a.toString(sha256(''), 'hex')).toBe(hash)
    expect(u8a.toString(sha256(new Uint8Array(0)), 'hex')).toBe(hash)
  })
  it('message: "abc" (length 3)', async () => {
    expect.assertions(2)
    const hash = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    expect(u8a.toString(sha256('abc'), 'hex')).toBe(hash)
    expect(u8a.toString(sha256(new Uint8Array([0x61, 0x62, 0x63])), 'hex')).toBe(hash)
  })
  it('message: "abc..." (length 56)', async () => {
    expect.assertions(2)
    const message = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    const hash = '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
    expect(u8a.toString(sha256(message), 'hex')).toBe(hash)
    expect(u8a.toString(sha256(u8a.fromString(message)), 'hex')).toBe(hash)
  })
  it('message: "abc..." (length 112)', async () => {
    expect.assertions(2)
    const message =
      'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'
    const hash = 'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1'
    expect(u8a.toString(sha256(message), 'hex')).toBe(hash)
    expect(u8a.toString(sha256(u8a.fromString(message)), 'hex')).toBe(hash)
  })
})

// https://keccak-256.4tools.net/
describe('keccak', () => {
  it('message: "" (empty string)', async () => {
    expect.assertions(1)
    const hash = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    expect(u8a.toString(keccak(new Uint8Array(0)), 'hex')).toBe(hash)
  })
  it('message: "abc" (length 3)', async () => {
    expect.assertions(1)
    const hash = '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    expect(u8a.toString(keccak(new Uint8Array([0x61, 0x62, 0x63])), 'hex')).toBe(hash)
  })
})

// https://mycrypto.tools/sample_ethaddresses.html
describe('Ethereum addresses', () => {
  it('public key: "04782291..."', async () => {
    expect.assertions(1)
    const publicKey =
      '047822917c9faccf83219eafa79866e37c56d5873a5bc11b5eb8b6747e328b6800d9b51749f9e15f7c0effc8a9f899dcf17d71e1ebe1ad3d6047b215636ff9b4e1'
    const ethereumAddress = '0xDBC05B1ECB4FDAEF943819C0B04E9EF6DF4BABD6'
    expect(toEthereumAddress(publicKey)).toBe(ethereumAddress.toLowerCase())
  })
  it('public key: "04bbe06c..."', async () => {
    expect.assertions(1)
    const publicKey =
      '04bbe06c9dd095cdf0aded667ea17621e8c1fdcd36ffe112a9c94e47aa6be1406a666e1001cf0067d0f9a541043dfc5438ead7be3ecbcdc328b67d8f966bceea63'
    const ethereumAddress = '0x721B68FA152A930F3DF71F54AC1CE7ED3AC5F867'
    expect(toEthereumAddress(publicKey)).toBe(ethereumAddress.toLowerCase())
  })
})

// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
describe('Ripemd160', () => {
  it('message: "" (empty string)', () => {
    expect.assertions(1)
    const rawString = ''
    const expectedHash = '9c1185a5c5e9fc54612808977ee8f548b2258d31'
    const actualHash = u8a.toString(ripemd160(u8a.fromString(rawString, 'ascii')), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "a"', () => {
    expect.assertions(1)
    const rawString = 'a'
    const expectedHash = '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'
    const actualHash = u8a.toString(ripemd160(u8a.fromString(rawString, 'ascii')), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "abc"', () => {
    expect.assertions(1)
    const rawString = 'abc'
    const expectedHash = '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
    const actualHash = u8a.toString(ripemd160(u8a.fromString(rawString, 'ascii')), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "message digest"', () => {
    expect.assertions(1)
    const rawString = 'message digest'
    const expectedHash = '5d0689ef49d2fae572b881b123a85ffa21595f36'
    const actualHash = u8a.toString(ripemd160(u8a.fromString(rawString, 'ascii')), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "abcdefghijklmnopqrstuvwxyz"', () => {
    expect.assertions(1)
    const rawString = 'abcdefghijklmnopqrstuvwxyz'
    const expectedHash = 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc'
    const actualHash = u8a.toString(ripemd160(u8a.fromString(rawString, 'ascii')), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"', () => {
    expect.assertions(1)
    const rawString = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    const expectedHash = '12a053384a9c0c88e405a06c27dcf49ada62eb2b'
    const actualHash = u8a.toString(ripemd160(u8a.fromString(rawString, 'ascii')), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"', () => {
    expect.assertions(1)
    const rawString = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    const expectedHash = 'b0e20b6e3116640286ed3a87a5713079b21f5189'
    const actualHash = u8a.toString(ripemd160(u8a.fromString(rawString, 'ascii')), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: 8 times "1234567890"', () => {
    expect.assertions(1)
    const rawString = '1234567890'.repeat(8)
    const expectedHash = '9b752e45573d4b39f4dbd3323cab82bf63326bfb'
    const actualHash = u8a.toString(ripemd160(u8a.fromString(rawString, 'ascii')), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
})
