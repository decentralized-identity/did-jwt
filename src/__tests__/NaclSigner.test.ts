import NaclSigner from '../signers/NaclSigner'

const privateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
const signer = NaclSigner(privateKey)
it('signs data', async () => {
  expect.assertions(1)
  const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'
  return expect(signer(plaintext)).resolves.toEqual(
    '1y_N9v6xI4DyG9vIuloivxm91EV96nDM3HXBUI4P2Owk0IxazqX63rQ5jlBih6tP_4H5QhkHHqbree7ExmTBCw'
  )
})
