import EllipticSigner from '../signers/EllipticSigner.js'

const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const signer = EllipticSigner(privateKey)
it('signs data', async () => {
  expect.assertions(1)
  const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
  await expect(signer(plaintext)).resolves.toEqual(
    'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg'
  )
})

const privateKey0x = '0x278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
it('signs data: privateKey with 0x prefix', async () => {
  expect.assertions(1)
  const signer = EllipticSigner(privateKey0x)
  const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
  await expect(signer(plaintext)).resolves.toEqual(
    'jsvdLwqr-O206hkegoq6pbo7LJjCaflEKHCvfohBP9U2H9EZ5Jsw0CncN17WntoUEGmxaZVF2zQjtUEXfhdyBg'
  )
})
