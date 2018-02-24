import SimpleSigner from '../SimpleSigner'

const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const signer = SimpleSigner(privateKey)
const signature = {
  r: 'dd8369e9a435ce784dc2a881aef04851251133fc4d66aa74a951a780ee0b60f8',
  s: '4eb3807bd179295aa65b18c4d9c34cc0fe026dc03bd9ecbdaeb1f1b0893befa7',
  recoveryParam: 1
}
it('signs data', () => {
  const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
  return new Promise((resolve, reject) => {
    signer(plaintext, (error, signature) => {
      if (error) return reject(error)
      resolve(signature)
    })
  }).then(result => expect(result).toEqual(signature))
})