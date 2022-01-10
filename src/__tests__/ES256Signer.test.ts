import { ES256Signer } from '../signers/ES256Signer'

describe('Secp256r1 Signer', () => {
  it('signs data, given a hex private key', async () => {
    expect.assertions(1)
    const privateKey = '040f1dbf0a2ca86875447a7c010b0fc6d39d76859c458fbe8f2bf775a40ad74a'
    const signer = ES256Signer(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'vOTe64WujVUjEiQrAlwaPJtNADx4usSlCfe8OXHS6Np1BqJdqdJX912pVwVlAjmbqR_TMVE5i5TWB_GJVgrHgg'
    )
  })

  it('signs data: privateKey with 0x prefix', async () => {
    expect.assertions(1)
    const privateKey = '0x040f1dbf0a2ca86875447a7c010b0fc6d39d76859c458fbe8f2bf775a40ad74a'
    const signer = ES256Signer(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'vOTe64WujVUjEiQrAlwaPJtNADx4usSlCfe8OXHS6Np1BqJdqdJX912pVwVlAjmbqR_TMVE5i5TWB_GJVgrHgg'
    )
  })

  it('signs data: privateKey base58', async () => {
    expect.assertions(1)
    const privateKey = 'Gqzym8nfnxR5ZYZ3wZo8rvTwKTqGn5cJsbHnEhUZDPo'
    const signer = ES256Signer(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
       'ct2U01GqM4IQvnAwFrAyDanWJdGFLRgBASBRulVBkN-KUnz7ilCT0h5Hog32doSeUzoegnQdUDbvy0Mnqfc1Zw'
    )
  })

  it('signs data: privateKey base64url', async () => {
    expect.assertions(1)
    const privateKey = 'BA8dvwosqGh1RHp8AQsPxtOddoWcRY--jyv3daQK10o'
    const signer = ES256Signer(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'vOTe64WujVUjEiQrAlwaPJtNADx4usSlCfe8OXHS6Np1BqJdqdJX912pVwVlAjmbqR_TMVE5i5TWB_GJVgrHgg'
    )
  })

  it('signs data: privateKey base64', async () => {
    expect.assertions(1)
    const privateKey = 'BA8dvwosqGh1RHp8AQsPxtOddoWcRY++jyv3daQK10o'
    const signer = ES256Signer(privateKey)
    const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
    await expect(signer(plaintext)).resolves.toEqual(
      'vOTe64WujVUjEiQrAlwaPJtNADx4usSlCfe8OXHS6Np1BqJdqdJX912pVwVlAjmbqR_TMVE5i5TWB_GJVgrHgg'
    )
  })

  it('refuses wrong key size (too short)', async () => {
    expect.assertions(1)
    const privateKey = 'f1dbf0a2ca86875447a7c010b0fc6d39d76859c458fbe8f2bf775a40ad74a'
    expect(() => {
      ES256Signer(privateKey)
    }).toThrowError(/^bad_key: Invalid private key format.*/)
  })

  it('refuses wrong key size (double)', async () => {
    expect.assertions(1)
    const privateKey = '040f1dbf0a2ca86875447a7c010b0fc6d39d76859c458fbe8f2bf775a40ad74af1dbf0a2ca86875447a7c010b0fc6d39d76859c458fbe8f2bf775a40ad74a'
    expect(() => {
      ES256Signer(privateKey)
    }).toThrowError(/^bad_key: Invalid private key format.*/)
  })
})
