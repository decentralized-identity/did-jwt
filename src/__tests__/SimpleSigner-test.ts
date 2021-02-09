import SimpleSigner from '../signers/SimpleSigner'

const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const signer = SimpleSigner(privateKey)
it('signs data', async () => {
  const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
  return await expect(signer(plaintext)).resolves.toMatchSnapshot()
})

const privateKey0x = '0x278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
it('signs data: privateKey with 0x prefix', async () => {
  const signer2 = SimpleSigner(privateKey0x)
  const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
  return await expect(signer2(plaintext)).resolves.toMatchSnapshot()
})
