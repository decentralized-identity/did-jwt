import { base64ToBytes, base58ToBytes, hexToBytes } from '../util.js'
import { EdDSASigner } from '../signers/EdDSASigner.js'

describe('EdDSASigner', () => {
  it('signs data with base64 key', async () => {
    expect.assertions(1)
    const privKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
    const signer = EdDSASigner(base64ToBytes(privKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return expect(signer(plaintext)).resolves.toEqual(
      '1y_N9v6xI4DyG9vIuloivxm91EV96nDM3HXBUI4P2Owk0IxazqX63rQ5jlBih6tP_4H5QhkHHqbree7ExmTBCw'
    )
  })

  it('signs data with base64url key', async () => {
    expect.assertions(1)
    const privKey = 'nlXR4aofRVuLqtn9-XVQNlX4s1nVQvp-TOhBBtYls1IG-sHyIkDP_WN-rWZHGIQp-v2pyct-rkM4asF_YRFQdQ'
    const signer = EdDSASigner(base64ToBytes(privKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return expect(signer(plaintext)).resolves.toEqual(
      '1y_N9v6xI4DyG9vIuloivxm91EV96nDM3HXBUI4P2Owk0IxazqX63rQ5jlBih6tP_4H5QhkHHqbree7ExmTBCw'
    )
  })

  it('signs data with base58 key', async () => {
    expect.assertions(1)
    const privKey = '4AcB6rb1mUBf82U7pBzPZ53ZAQycdi4Q1LWoUREvHSRXBRo9Sus9bzCJPKVTQQeDpjHMJN7fBAGWKEnJw5SPbaC4'
    const signer = EdDSASigner(base58ToBytes(privKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return expect(signer(plaintext)).resolves.toEqual(
      '1y_N9v6xI4DyG9vIuloivxm91EV96nDM3HXBUI4P2Owk0IxazqX63rQ5jlBih6tP_4H5QhkHHqbree7ExmTBCw'
    )
  })

  it('signs data with hex key', async () => {
    expect.assertions(1)
    const privKey =
      '9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b35206fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075'
    const signer = EdDSASigner(hexToBytes(privKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return expect(signer(plaintext)).resolves.toEqual(
      '1y_N9v6xI4DyG9vIuloivxm91EV96nDM3HXBUI4P2Owk0IxazqX63rQ5jlBih6tP_4H5QhkHHqbree7ExmTBCw'
    )
  })

  it('signs data with prefixed hex key', async () => {
    expect.assertions(1)
    const privKey =
      '0x9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b35206fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075'
    const signer = EdDSASigner(hexToBytes(privKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return expect(signer(plaintext)).resolves.toEqual(
      '1y_N9v6xI4DyG9vIuloivxm91EV96nDM3HXBUI4P2Owk0IxazqX63rQ5jlBih6tP_4H5QhkHHqbree7ExmTBCw'
    )
  })

  it('accepts 32 byte keys size (github #289)', async () => {
    expect.assertions(1)
    const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    expect(() => {
      EdDSASigner(hexToBytes(privateKey))
    }).not.toThrow()
  })

  it('refuses wrong key size', async () => {
    expect.assertions(1)
    const privateKey =
      '9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b35206fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f611150'
    expect(() => {
      EdDSASigner(hexToBytes(privateKey))
    }).toThrowError(/^bad_key: Invalid private key format.*/)
  })
})
