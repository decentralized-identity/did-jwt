import SimpleSigner from '../SimpleSigner'

const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const signer = SimpleSigner(privateKey)
it('signs data', async () => {
  const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
  return expect(signer(plaintext)).resolves.toMatchSnapshot()
})
