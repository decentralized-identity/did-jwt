import VerifierAlgorithm, { toSignatureObject } from '../VerifierAlgorithm'
import { decodeJWT, createJWT } from '../JWT'
import SimpleSigner from '../SimpleSigner'
import base64url from 'base64url'
import { toEthereumAddress } from '../Digest'
import { ec as EC } from 'elliptic'

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
})

const mnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX'
const did = `did:uport:${mnid}`
const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const kp = secp256k1.keyFromPrivate(privateKey)
const publicKey = kp.getPublic('hex')
const compressedPublicKey = kp.getPublic().encode('hex', true)
const address = toEthereumAddress(publicKey)
const signer = SimpleSigner(privateKey)

const ecKey1 = {
  id: `${did}#keys-1`,
  type: 'Secp256k1VerificationKey2018',
  owner: did,
  publicKeyHex: '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062'
}

const ecKey2 = {
  id: `${did}#keys-2`,
  type: 'Secp256k1VerificationKey2018',
  owner: did,
  publicKeyHex: publicKey
}

const ethAddress = {
  id: `${did}#keys-3`,
  type: 'Secp256k1VerificationKey2018',
  owner: did,
  ethereumAddress: address
}

const compressedKey = {
  id: `${did}#keys-4`,
  type: 'Secp256k1VerificationKey2018',
  owner: did,
  publicKeyHex: compressedPublicKey
}

describe('ES256K', () => {
  const verifier = VerifierAlgorithm('ES256K')
  it('validates signature and picks correct public key', async () => {
    const jwt = await createJWT({bla: 'bla'}, {issuer: did, signer})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates signature with compressed public key and picks correct public key', async () => {
    const jwt = await createJWT({bla: 'bla'}, {issuer: did, signer})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('throws error if invalid signature', async () => {
    const jwt = await createJWT({bla: 'bla'}, {issuer: did, signer})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(new Error('Signature invalid for JWT'))
  })
})

describe('ES256K-R', async () => {
  const verifier = VerifierAlgorithm('ES256K-R')

  it('validates signature and picks correct public key', async () => {
    const jwt = await createJWT({bla: 'bla'}, {issuer: did, signer, alg: 'ES256K-R'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates signature and picks correct compressed public key', async () => {
    const jwt = await createJWT({bla: 'bla'}, {issuer: did, signer, alg: 'ES256K-R'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('validates signature with ethereum address', async () => {
    const jwt = await createJWT({bla: 'bla'}, {issuer: did, signer, alg: 'ES256K-R'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ethAddress])).toEqual(ethAddress)
  })

  it('throws error if invalid signature', async () => {
    const jwt = await createJWT({bla: 'bla'}, {issuer: did, signer, alg: 'ES256K-R'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(new Error('Signature invalid for JWT'))
  })

})
