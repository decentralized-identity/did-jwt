import SignerAlgorithm from '../../SignerAlgorithm'
import NaclSigner from '../../signers/NaclSigner'
import nacl from 'tweetnacl'
import { base64ToBytes, stringToBytes } from '../../util'
const ed25519PrivateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
const edSigner = NaclSigner(ed25519PrivateKey)
const edKp = nacl.sign.keyPair.fromSecretKey(base64ToBytes(ed25519PrivateKey))

describe('SignerAlgorithm', () => {

  it('supports Ed25519', () => {
    expect(typeof SignerAlgorithm('Ed25519')).toEqual('function')
  })

})

describe('Ed25519', () => {
  const jwtSigner = SignerAlgorithm('Ed25519')
  it('returns correct signature', async () => {
    expect.assertions(1)
    return await expect(jwtSigner('hello', edSigner)).resolves.toEqual(
      'lLY_SeplJc_4tgMP1BHmjfxS0UEi-Xvonzbss4GT7yuFz--H28uCwsRjlIwXL4I0ugCrM-zQoA2gW2JdnFRkDQ'
    )
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', edSigner)
    expect(nacl.sign.detached.verify(stringToBytes('hello'), base64ToBytes(signature), edKp.publicKey)).toBeTruthy()
  })
})
