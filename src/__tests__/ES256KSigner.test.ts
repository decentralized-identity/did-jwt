import { hexToBytes, base58ToBytes, base64ToBytes } from '../util.js'
import { ES256KSigner } from '../signers/ES256KSigner.js'

describe('Secp256k1 Signer', () => {
  it('signs data, given a hex private key', async () => {
    expect.assertions(1)
    const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    const signer = ES256KSigner(hexToBytes(privateKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg'
    )
  })

  it('signs data: privateKey with 0x prefix', async () => {
    expect.assertions(1)
    const privateKey = '0x278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    const signer = ES256KSigner(hexToBytes(privateKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg'
    )
  })

  it('signs data: privateKey base58', async () => {
    expect.assertions(1)
    const privateKey = '3fMGokRKc5yGVqbCXyGNTrp3vP1cXs86tsVSVwzhNvXQ'
    const signer = ES256KSigner(base58ToBytes(privateKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg'
    )
  })

  it('signs data: privateKey base64url', async () => {
    expect.assertions(1)
    const privateKey = 'J4pd5wDin6ro5A42bsUBK17GPTbsd-iiQXFUzB0lOD8'
    const signer = ES256KSigner(base64ToBytes(privateKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg'
    )
  })

  it('signs data: privateKey base64', async () => {
    expect.assertions(1)
    const privateKey = 'J4pd5wDin6ro5A42bsUBK17GPTbsd+iiQXFUzB0lOD8='
    const signer = ES256KSigner(base64ToBytes(privateKey))
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg'
    )
  })

  it('refuses wrong key size (too short)', async () => {
    expect.assertions(1)
    const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d2538'
    expect(() => {
      ES256KSigner(hexToBytes(privateKey))
    }).toThrowError(/^bad_key: Invalid private key format.*/)
  })

  it('refuses wrong key size (double)', async () => {
    expect.assertions(1)
    const privateKey =
      '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    expect(() => {
      ES256KSigner(hexToBytes(privateKey))
    }).toThrowError(/^bad_key: Invalid private key format.*/)
  })
})
