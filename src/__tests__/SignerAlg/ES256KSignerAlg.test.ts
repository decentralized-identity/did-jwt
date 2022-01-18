import SignerAlgorithm from '../../SignerAlgorithm'
import { toSignatureObject } from '../../VerifierAlgorithm'
import SimpleSigner from '../../signers/SimpleSigner'
import EllipticSigner from '../../signers/EllipticSigner'
import { ec as EC } from 'elliptic'
import { base64ToBytes, stringToBytes } from '../../util'
import { sha256 } from '../../Digest'
const secp256k1 = new EC('secp256k1')
const privateKey = '0278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a241154cc1d25383f'
const kp = secp256k1.keyFromPrivate(privateKey)
const signer = SimpleSigner(privateKey)
const ecSigner = EllipticSigner(privateKey)

describe('SignerAlgorithm', () => {
  it('supports ES256K', () => {
    expect(typeof SignerAlgorithm('ES256K')).toEqual('function')
  })

  it('supports ES256K-R', () => {
    expect(typeof SignerAlgorithm('ES256K-R')).toEqual('function')
  })

})

describe('ES256K', () => {
  const jwtSigner = SignerAlgorithm('ES256K')
  it('returns correct signature', async () => {
    expect.assertions(1)
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      'MaCPcIypS76TnvKSbhbPMG01BJvjQ6ouITV-mVt7_bfTZfGkEdwooSqbzPBHAlZXGzYYvrTnH4M9lF3OZMdpRQ'
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
      r: '31a08f708ca94bbe939ef2926e16cf306d35049be343aa2e21357e995b7bfdb7',
      s: 'd365f1a411dc28a12a9bccf0470256571b3618beb4e71f833d945dce64c76945',
    })
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature))).toBeTruthy()
  })
})

describe('ES256K signer which returns signature as string ', () => {
  const jwtSigner = SignerAlgorithm('ES256K')
  it('returns correct signature', async () => {
    expect.assertions(1)
    return await expect(jwtSigner('hello', ecSigner)).resolves.toEqual(
      'MaCPcIypS76TnvKSbhbPMG01BJvjQ6ouITV-mVt7_bfTZfGkEdwooSqbzPBHAlZXGzYYvrTnH4M9lF3OZMdpRQ'
    )
  })

  it('returns signature of 64 bytes', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', ecSigner)
    expect(base64ToBytes(signature).length).toEqual(64)
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', ecSigner)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature))).toBeTruthy()
  })
})

describe('ES256K-R', () => {
  const jwtSigner = SignerAlgorithm('ES256K-R')
  expect.assertions(1)
  it('returns correct signature', async () => {
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      'MaCPcIypS76TnvKSbhbPMG01BJvjQ6ouITV-mVt7_bfTZfGkEdwooSqbzPBHAlZXGzYYvrTnH4M9lF3OZMdpRQE'
    )
  })

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

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature, true))).toBeTruthy()
  })
})
