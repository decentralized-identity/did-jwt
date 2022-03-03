import { ES256Signer } from '../../signers/ES256Signer'
import SignerAlgorithm from '../../SignerAlgorithm'
import { toSignatureObject } from '../../VerifierAlgorithm'
import { ec as EC } from 'elliptic'
import { base64ToBytes, stringToBytes } from '../../util'
import { sha256 } from '../../Digest'
const secp256r1 = new EC('p256')
const privateKey = '736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8'
const kp = secp256r1.keyFromPrivate(privateKey)
const signer = ES256Signer(privateKey)

describe('SignerAlgorithm', () => {
  it('supports ES256', () => {
    expect(typeof SignerAlgorithm('ES256')).toEqual('function')
  })

  it('supports ES256-R', () => {
    expect(typeof SignerAlgorithm('ES256-R')).toEqual('function')
  })

})

describe('ES256', () => {
  const jwtSigner = SignerAlgorithm('ES256')
  it('returns correct signature', async () => {
    expect.assertions(1)
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      'Zks0QO1ma5pHHtNbpb0qDap0VJSvQvA775N0GZsAp3PQjmDGbsfyKlUVcU9PFueIXksioSTsPXiOCgAHIOe4WA'
    )
  })
  
  it('returns signature of 64 bytes', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(base64ToBytes(signature).length).toEqual(64)
  })
  
  it('contains only r and s of signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(toSignatureObject(signature)).toEqual({
      r: '664b3440ed666b9a471ed35ba5bd2a0daa745494af42f03bef9374199b00a773',
      s: 'd08e60c66ec7f22a5515714f4f16e7885e4b22a124ec3d788e0a000720e7b858',
    })
  })
  
  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature))).toBeTruthy()
  })
   
})

describe('ES256-R', () => {
  const jwtSigner = SignerAlgorithm('ES256-R')
 
  expect.assertions(1)
  it('returns correct signature', async () => {
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      'Zks0QO1ma5pHHtNbpb0qDap0VJSvQvA775N0GZsAp3PQjmDGbsfyKlUVcU9PFueIXksioSTsPXiOCgAHIOe4WA'
    )
  })
  /* 
  it('returns signature of 64 bytes', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(base64ToBytes(signature).length).toEqual(65)
  })
  
  it('contains r, s and recoveryParam of signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(toSignatureObject(signature, true)).toEqual({
      r: '31a08f708ca94bbe939ef2926e16cf306d35049be343aa2e21357e995b7bfdb7',
      s: 'd365f1a411dc28a12a9bccf0470256571b3618beb4e71f833d945dce64c76945',
      recoveryParam: 1,
    })
  })
  */
  /*  
  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature, true))).toBeTruthy()
  })
  */
})
