import VerifierAlgorithm from '../VerifierAlgorithm'
import { createJWT } from '../JWT'
import SimpleSigner from '../signers/SimpleSigner'
import NaclSigner from '../signers/NaclSigner'
import { toEthereumAddress } from '../Digest'
import nacl from 'tweetnacl'
import { ec as EC } from 'elliptic'
import { base64ToBytes, bytesToBase64 } from '../util'
import * as u8a from 'uint8arrays'

const secp256k1 = new EC('secp256k1')

describe('VerifierAlgorithm', () => {
  it('supports ES256K', () => {
    expect(typeof VerifierAlgorithm('ES256K')).toEqual('function')
  })

  it('supports ES256K-R', () => {
    expect(typeof VerifierAlgorithm('ES256K-R')).toEqual('function')
  })

  it('fails on unsupported algorithm', () => {
    expect(() => VerifierAlgorithm('BADALGO')).toThrowError('Unsupported algorithm BADALGO')
  })

  it('supports EdDSA', () => {
    expect(typeof VerifierAlgorithm('EdDSA')).toEqual('function')
  })
})

const mnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX'
const did = `did:uport:${mnid}`
const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const kp = secp256k1.keyFromPrivate(privateKey)
const publicKey = String(kp.getPublic('hex'))
const compressedPublicKey = String(kp.getPublic().encode('hex', true))
const address = toEthereumAddress(publicKey)
const signer = SimpleSigner(privateKey)

const ed25519PrivateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
const edSigner = NaclSigner(ed25519PrivateKey)
const edKp = nacl.sign.keyPair.fromSecretKey(base64ToBytes(ed25519PrivateKey))
const edPublicKey = bytesToBase64(edKp.publicKey)
const edPublicKey2 = bytesToBase64(nacl.sign.keyPair().publicKey)

const ecKey1 = {
  id: `${did}#keys-1`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex:
    '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062'
}

const ecKey2 = {
  id: `${did}#keys-2`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex: publicKey
}

const ethAddress = {
  id: `${did}#keys-3`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  ethereumAddress: address
}

const compressedKey = {
  id: `${did}#keys-4`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex: compressedPublicKey
}

const edKey = {
  id: `${did}#keys-5`,
  type: 'ED25519SignatureVerification',
  controller: did,
  publicKeyBase64: edPublicKey
}

const edKey2 = {
  id: `${did}#keys-6`,
  type: 'ED25519SignatureVerification',
  controller: did,
  publicKeyBase64: edPublicKey2
}

const malformedKey1 = {
  id: `${did}#keys-7`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex:
    '05613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062'
}

const malformedKey2 = {
  id: `${did}#keys-8`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex:
    '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062aabbccdd'
}

const malformedKey3 = {
  id: `${did}#keys-8`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex:
    '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06'
}

describe('ES256K', () => {
  const verifier = VerifierAlgorithm('ES256K')
  it('validates signature and picks correct public key', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates with publicKeyBase58', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const publicKeyBase58 = u8a.toString(u8a.fromString(ecKey2.publicKeyHex, 'base16'), 'base58btc')
    const pubkey = Object.assign({ publicKeyBase58 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates signature with compressed public key and picks correct public key', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('throws error if invalid signature', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(new Error('Signature invalid for JWT'))
  })

  it('throws error if invalid signature length', async () => {
    const jwt = (await createJWT({ bla: 'bla' }, { issuer: did, signer })) + 'aa'
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(new Error('wrong signature length'))
  })

  it('validates signature with compressed public key and picks correct public key when malformed keys are encountered first', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [malformedKey1, malformedKey2, malformedKey3, compressedKey])).toEqual(
      compressedKey
    )
  })

  it('validates signature produced by ethAddress - github #14', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ethAddress])).toEqual(ethAddress)
  })
})

describe('ES256K-R', () => {
  const verifier = VerifierAlgorithm('ES256K-R')

  it('validates signature and picks correct public key', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates signature and picks correct compressed public key', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('validates signature with ethereum address', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ethAddress])).toEqual(ethAddress)
  })

  it('throws error if invalid signature', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(new Error('Signature invalid for JWT'))
  })
})

describe('Ed25519', () => {
  const verifier = VerifierAlgorithm('Ed25519')
  it('validates signature and picks correct public key', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [edKey, edKey2])).toEqual(edKey)
  })

  it('validates with publicKeyBase58', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const publicKeyBase58 = u8a.toString(u8a.fromString(edKey.publicKeyBase64, 'base64pad'), 'base58btc')
    const pubkey = Object.assign({ publicKeyBase58 }, edKey)
    delete pubkey.publicKeyBase64
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('throws error if invalid signature', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [edKey2])).toThrowError(new Error('Signature invalid for JWT'))
  })
})
