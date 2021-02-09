import SignerAlgorithm from '../SignerAlgorithm'
import { toSignatureObject } from '../VerifierAlgorithm'
import SimpleSigner from '../signers/SimpleSigner'
import EllipticSigner from '../signers/EllipticSigner'
import NaclSigner from '../signers/NaclSigner'
import { ec as EC } from 'elliptic'
import nacl from 'tweetnacl'
import { base64ToBytes, base64urlToBytes, stringToBytes } from '../util'
import { sha256 } from '../Digest'
const secp256k1 = new EC('secp256k1')
const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const ed25519PrivateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
const kp = secp256k1.keyFromPrivate(privateKey)
const signer = SimpleSigner(privateKey)
const edSigner = NaclSigner(ed25519PrivateKey)
const ecSigner = EllipticSigner(privateKey)
const edKp = nacl.sign.keyPair.fromSecretKey(base64ToBytes(ed25519PrivateKey))

describe('SignerAlgorithm', () => {
  it('supports ES256K', () => {
    expect(typeof SignerAlgorithm('ES256K')).toEqual('function')
  })

  it('supports ES256K-R', () => {
    expect(typeof SignerAlgorithm('ES256K-R')).toEqual('function')
  })

  it('supports Ed25519', () => {
    expect(typeof SignerAlgorithm('Ed25519')).toEqual('function')
  })

  it('supports EdDSA', () => {
    expect(typeof SignerAlgorithm('EdDSA')).toEqual('function')
  })

  it('fails on unsupported algorithm', () => {
    expect(() => SignerAlgorithm('BADALGO')).toThrowError('Unsupported algorithm BADALGO')
  })
})

describe('ES256K', () => {
  const jwtSigner = SignerAlgorithm('ES256K')
  it('returns correct signature', async () => {
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      'kusriMloyA3ygS-Z7Lhqa0YatZA4l2UYtn39Fe8u6IWgopkV_RdK7WvjVp2k3I-08O9ZoDpWJcniSpuwukuoEw'
    )
  })

  it('returns signature of 64 bytes', async () => {
    const signature = await jwtSigner('hello', signer)
    expect(base64urlToBytes(signature).length).toEqual(64)
  })

  it('contains only r and s of signature', async () => {
    const signature = await jwtSigner('hello', signer)
    expect(toSignatureObject(signature)).toEqual({
      r: '92eb2b88c968c80df2812f99ecb86a6b461ab59038976518b67dfd15ef2ee885',
      s: 'a0a29915fd174aed6be3569da4dc8fb4f0ef59a03a5625c9e24a9bb0ba4ba813'
    })
  })

  it('can verify the signature', async () => {
    const signature = await jwtSigner('hello', signer)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature))).toBeTruthy()
  })
})

describe('ES256K signer which returns signature as string ', () => {
  const jwtSigner = SignerAlgorithm('ES256K')
  it('returns correct signature', async () => {
    return await expect(jwtSigner('hello', ecSigner)).resolves.toEqual(
      'kusriMloyA3ygS-Z7Lhqa0YatZA4l2UYtn39Fe8u6IWgopkV_RdK7WvjVp2k3I-08O9ZoDpWJcniSpuwukuoEw'
    )
  })

  it('returns signature of 64 bytes', async () => {
    const signature = await jwtSigner('hello', ecSigner)
    expect(base64urlToBytes(signature).length).toEqual(64)
  })

  it('can verify the signature', async () => {
    const signature = await jwtSigner('hello', ecSigner)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature))).toBeTruthy()
  })
})

describe('ES256K-R', () => {
  const jwtSigner = SignerAlgorithm('ES256K-R')
  it('returns correct signature', async () => {
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      'kusriMloyA3ygS-Z7Lhqa0YatZA4l2UYtn39Fe8u6IWgopkV_RdK7WvjVp2k3I-08O9ZoDpWJcniSpuwukuoEwE'
    )
  })

  it('returns signature of 64 bytes', async () => {
    const signature = await jwtSigner('hello', signer)
    expect(base64urlToBytes(signature).length).toEqual(65)
  })

  it('contains r, s and recoveryParam of signature', async () => {
    const signature = await jwtSigner('hello', signer)
    expect(toSignatureObject(signature, true)).toEqual({
      r: '92eb2b88c968c80df2812f99ecb86a6b461ab59038976518b67dfd15ef2ee885',
      s: 'a0a29915fd174aed6be3569da4dc8fb4f0ef59a03a5625c9e24a9bb0ba4ba813',
      recoveryParam: 1
    })
  })

  it('can verify the signature', async () => {
    const signature = await jwtSigner('hello', signer)
    expect(kp.verify(sha256('hello'), toSignatureObject(signature, true))).toBeTruthy()
  })
})

describe('Ed25519', () => {
  const jwtSigner = SignerAlgorithm('Ed25519')
  it('returns correct signature', async () => {
    return await expect(jwtSigner('hello', edSigner)).resolves.toEqual(
      'lLY_SeplJc_4tgMP1BHmjfxS0UEi-Xvonzbss4GT7yuFz--H28uCwsRjlIwXL4I0ugCrM-zQoA2gW2JdnFRkDQ'
    )
  })

  it('can verify the signature', async () => {
    const signature = await jwtSigner('hello', edSigner)
    expect(nacl.sign.detached.verify(stringToBytes('hello'), base64urlToBytes(signature), edKp.publicKey)).toBeTruthy()
  })
})
