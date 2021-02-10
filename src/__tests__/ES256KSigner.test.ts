import { ES256KSigner } from '../signers/ES256KSigner'

describe('Secp256k1 Signer', () => {
  it('signs data, given a hex private key', async () => {
    const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    const signer = ES256KSigner(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return await expect(signer(plaintext)).resolves.toMatchSnapshot()
  })

  it('signs data: privateKey with 0x prefix', async () => {
    const privateKey = '0x278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    const signer2 = ES256KSigner(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return await expect(signer2(plaintext)).resolves.toMatchSnapshot()
  })

  it('signs data: privateKey base58', async () => {
    const privateKey = '3fMGokRKc5yGVqbCXyGNTrp3vP1cXs86tsVSVwzhNvXQ'
    const signer2 = ES256KSigner(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return await expect(signer2(plaintext)).resolves.toMatchSnapshot()
  })

  it('signs data: privateKey base64url', async () => {
    const privateKey = 'J4pd5wDin6ro5A42bsUBK17GPTbsd-iiQXFUzB0lOD8'
    const signer2 = ES256KSigner(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return await expect(signer2(plaintext)).resolves.toMatchSnapshot()
  })

  it('signs data: privateKey base64', async () => {
    const privateKey = 'J4pd5wDin6ro5A42bsUBK17GPTbsd+iiQXFUzB0lOD8='
    const signer2 = ES256KSigner(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    return await expect(signer2(plaintext)).resolves.toMatchSnapshot()
  })

  it('refuses wrong key size (too short)', async () => {
    const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d2538'
    expect(() => {
      ES256KSigner(privateKey)
    }).toThrowError(/^Invalid private key format.*/)
  })

  it('refuses wrong key size (double)', async () => {
    const privateKey =
      '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    expect(() => {
      ES256KSigner(privateKey)
    }).toThrowError(/^Invalid private key format.*/)
  })
})
