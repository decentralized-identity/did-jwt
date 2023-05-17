import SignerAlgorithm from '../SignerAlgorithm.js'
import { toSignatureObject, toSignatureObject2 } from '../VerifierAlgorithm.js'
import SimpleSigner from '../signers/SimpleSigner.js'
import EllipticSigner from '../signers/EllipticSigner.js'
import NaclSigner from '../signers/NaclSigner.js'
// @ts-ignore
import nacl from 'tweetnacl'
import { base64ToBytes, hexToBytes, stringToBytes } from '../util.js'
import { sha256 } from '../Digest.js'
import { ES256Signer } from '../signers/ES256Signer.js'
import { p256 } from '@noble/curves/p256'
import { secp256k1 } from '@noble/curves/secp256k1'

const privateKey = '0278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a241154cc1d25383f'
const scp256k1PublicKey = secp256k1.getPublicKey(privateKey)
const ed25519PrivateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
const signer = SimpleSigner(privateKey)
const edSigner = NaclSigner(ed25519PrivateKey)
const ecSigner = EllipticSigner(privateKey)
const edKp = nacl.sign.keyPair.fromSecretKey(base64ToBytes(ed25519PrivateKey))

// Add tests specific to new ES256 signer for curve secp256r1 / P-256
const p256privateKey = hexToBytes('736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8')
const p256publicKey = p256.getPublicKey(p256privateKey)
const p256signer = ES256Signer(p256privateKey)

describe('SignerAlgorithm', () => {
  it('supports ES256', () => {
    expect(typeof SignerAlgorithm('ES256')).toEqual('function')
  })
})

describe('ES256', () => {
  const jwtSigner = SignerAlgorithm('ES256')
  it('returns correct signature', async () => {
    expect.assertions(1)
    return await expect(jwtSigner('hello', p256signer)).resolves.toEqual(
      'Zks0QO1ma5pHHtNbpb0qDap0VJSvQvA775N0GZsAp3PQjmDGbsfyKlUVcU9PFueIXksioSTsPXiOCgAHIOe4WA'
    )
  })

  it('returns signature of 64 bytes', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', p256signer)
    expect(base64ToBytes(signature).length).toEqual(64)
  })

  it('contains only r and s of signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', p256signer)
    expect(toSignatureObject(signature)).toEqual({
      r: '664b3440ed666b9a471ed35ba5bd2a0daa745494af42f03bef9374199b00a773',
      s: 'd08e60c66ec7f22a5515714f4f16e7885e4b22a124ec3d788e0a000720e7b858',
    })
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', p256signer)
    expect(p256.verify(toSignatureObject2(signature).compact, sha256('hello'), p256publicKey)).toBeTruthy()
  })
})
// end of tests added for P-256

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
    expect.assertions(1)
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      'MaCPcIypS76TnvKSbhbPMG01BJvjQ6ouITV-mVt7_bcsmg5b7iPXXtVkMw-4_amnn3jEJ_phgLiCPgC-a27X_A'
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
      s: '2c9a0e5bee23d75ed564330fb8fda9a79f78c427fa6180b8823e00be6b6ed7fc',
    })
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    const sig = secp256k1.Signature.fromCompact(toSignatureObject2(signature).compact).normalizeS()
    expect(secp256k1.verify(sig, sha256('hello'), scp256k1PublicKey)).toBeTruthy()
  })
})

describe('ES256K signer which returns signature as string ', () => {
  const jwtSigner = SignerAlgorithm('ES256K')
  it('returns correct signature', async () => {
    expect.assertions(1)
    return await expect(jwtSigner('hello', ecSigner)).resolves.toEqual(
      'MaCPcIypS76TnvKSbhbPMG01BJvjQ6ouITV-mVt7_bcsmg5b7iPXXtVkMw-4_amnn3jEJ_phgLiCPgC-a27X_A'
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
    const sig = secp256k1.Signature.fromCompact(toSignatureObject2(signature).compact).normalizeS()
    expect(secp256k1.verify(sig, sha256('hello'), scp256k1PublicKey)).toBeTruthy()
  })
})

describe('ES256K-R', () => {
  const jwtSigner = SignerAlgorithm('ES256K-R')
  expect.assertions(1)
  it('returns correct signature', async () => {
    return await expect(jwtSigner('hello', signer)).resolves.toEqual(
      'MaCPcIypS76TnvKSbhbPMG01BJvjQ6ouITV-mVt7_bcsmg5b7iPXXtVkMw-4_amnn3jEJ_phgLiCPgC-a27X_AA'
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
      s: '2c9a0e5bee23d75ed564330fb8fda9a79f78c427fa6180b8823e00be6b6ed7fc',
      recoveryParam: 0,
    })
  })

  it('can verify the signature', async () => {
    expect.assertions(1)
    const signature = await jwtSigner('hello', signer)
    const sig = secp256k1.Signature.fromCompact(toSignatureObject2(signature, true).compact).normalizeS()
    expect(secp256k1.verify(sig, sha256('hello'), scp256k1PublicKey)).toBeTruthy()
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
