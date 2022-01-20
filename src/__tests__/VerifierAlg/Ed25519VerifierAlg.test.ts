import VerifierAlgorithm from '../../VerifierAlgorithm'
import { createJWT } from '../../JWT'
import nacl from 'tweetnacl'
import { base64ToBytes, bytesToBase64 } from '../../util'
import * as u8a from 'uint8arrays'
import { EdDSASigner } from '../../signers/EdDSASigner'

const mnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX'
const did = `did:uport:${mnid}`

const ed25519PrivateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
const edSigner = EdDSASigner(ed25519PrivateKey)
const edKp = nacl.sign.keyPair.fromSecretKey(base64ToBytes(ed25519PrivateKey))
const edPublicKey = bytesToBase64(edKp.publicKey)
const edPublicKey2 = bytesToBase64(nacl.sign.keyPair().publicKey)

const edKey = {
  id: `${did}#keys-5`,
  type: 'ED25519SignatureVerification',
  controller: did,
  publicKeyBase64: edPublicKey,
}

const edKey2 = {
  id: `${did}#keys-6`,
  type: 'ED25519SignatureVerification',
  controller: did,
  publicKeyBase64: edPublicKey2,
}

describe('Ed25519', () => {
  const verifier = VerifierAlgorithm('Ed25519')
  it('validates signature and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [edKey, edKey2])).toEqual(edKey)
  })

  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const publicKeyBase58 = u8a.toString(u8a.fromString(edKey.publicKeyBase64, 'base64pad'), 'base58btc')
    const pubkey = Object.assign({ publicKeyBase58 }, edKey)
    delete pubkey.publicKeyBase64
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [edKey2])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })
})
