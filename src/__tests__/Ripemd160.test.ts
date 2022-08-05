// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html

import * as u8a from 'uint8arrays'
import { Ripemd160 } from '../blockchains/utils/ripemd160'

describe('Ripemd160', () => {
  it('message: "" (empty string)', () => {
    expect.assertions(1)
    const rawString = ''
    const expectedHash = '9c1185a5c5e9fc54612808977ee8f548b2258d31'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "a"', () => {
    expect.assertions(1)
    const rawString = 'a'
    const expectedHash = '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "abc"', () => {
    expect.assertions(1)
    const rawString = 'abc'
    const expectedHash = '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "message digest"', () => {
    expect.assertions(1)
    const rawString = 'message digest'
    const expectedHash = '5d0689ef49d2fae572b881b123a85ffa21595f36'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "abcdefghijklmnopqrstuvwxyz"', () => {
    expect.assertions(1)
    const rawString = 'abcdefghijklmnopqrstuvwxyz'
    const expectedHash = 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"', () => {
    expect.assertions(1)
    const rawString = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    const expectedHash = '12a053384a9c0c88e405a06c27dcf49ada62eb2b'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"', () => {
    expect.assertions(1)
    const rawString = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    const expectedHash = 'b0e20b6e3116640286ed3a87a5713079b21f5189'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: 8 times "1234567890"', () => {
    expect.assertions(1)
    const rawString = '1234567890'.repeat(8)
    const expectedHash = '9b752e45573d4b39f4dbd3323cab82bf63326bfb'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
  it('message: 1 million times "a"', () => {
    expect.assertions(1)
    const rawString = 'a'.repeat(1000000)
    const expectedHash = '52783243c1697bdbe16d37f97f68f08325dc1528'
    const actualHash = u8a.toString(new Ripemd160().update(u8a.fromString(rawString, 'ascii')).digest(), 'hex')
    return expect(actualHash).toBe(expectedHash)
  })
})
