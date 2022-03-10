import VerifierAlgorithm from '../../VerifierAlgorithm'
import { createJWT } from '../../JWT'
import { ec as EC } from 'elliptic'
import { bytesToBase58, bytesToBase64, hexToBytes, bytesToBase64url, bytesToMultibase } from '../../util'
import { ES256Signer } from '../../signers/ES256Signer'
import { toEthereumAddress } from '../../Digest'
import { publicKeyToAddress as toBip122Address } from '../../blockchains/bip122'
import { publicKeyToAddress as toCosmosAddressWithoutPrefix } from '../../blockchains/cosmos'

const secp256r1 = new EC('p256')

describe('VerifierAlgorithm', () => {
  it('supports ES256', () => {
    expect(typeof VerifierAlgorithm('ES256')).toEqual('function')
  })

  it('supports ES256-R', () => {
    expect(typeof VerifierAlgorithm('ES256-R')).toEqual('function')
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

const privateKey = '736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8'
const kp = secp256r1.keyFromPrivate(privateKey)
const publicKey = String(kp.getPublic('hex'))
const compressedPublicKey = String(kp.getPublic().encode('hex', true))
const publicKeyBase64 = bytesToBase64(hexToBytes(publicKey))
const publicKeyBase58 = bytesToBase58(hexToBytes(publicKey))
const publicKeyJwk = {
  crv: 'P-256',
  kty: 'EC',
  x: bytesToBase64url(hexToBytes(kp.getPublic().getX().toString('hex'))),
  y: bytesToBase64url(hexToBytes(kp.getPublic().getY().toString('hex'))),
}
const publicKeyMultibase = bytesToMultibase(hexToBytes(publicKey), 'base58btc')
const eip155 = toEthereumAddress(publicKey)
const bip122 = toBip122Address(publicKey)
const cosmosPrefix = 'example'
const cosmos = toCosmosAddressWithoutPrefix(publicKey, cosmosPrefix,'p256-pub')
const signer = ES256Signer(privateKey)
const recoverySigner = ES256Signer(privateKey, true)

const ecKey1 = {
  id: `${did}#keys-1`,
  type: 'JsonWebKey2020',
  controller: did,
  publicKeyHex:
    '04f9c36f8964623378bdc068d4bce07ed17c8fa486f9ac0c2613ca3c8c306d7bb61cd36717b8ac5e4fea8ad23dc8d0783c2318ee4ad7a80db6e0026ad0b072a24f',
}

const ecKey2 = {
  id: `${did}#keys-2`,
  type: 'JsonWebKey2020',
  controller: did,
  publicKeyHex: publicKey,
}

const ethAddress = {
  id: `${did}#keys-3`,
  type: 'JsonWebKey2020',
  controller: did,
  ethereumAddress: eip155,
}

const blockchainAddress = {
  id: `${did}#keys-blockchain`,
  type: 'JsonWebKey2020',
  controller: did,
  blockchainAccountId: `${eip155}@eip155:1`,
}

const blockchainAddressCaip10 = {
  id: `${did}#keys-blockchain`,
  type: 'JsonWebKey2020',
  controller: did,
  blockchainAccountId: `eip155:1:${eip155}`,
}

const blockchainAddressBip122 = {
  id: `${did}#keys-blockchain`,
  type: 'JsonWebKey2020',
  controller: did,
  blockchainAccountId: `bip122:000000000019d6689c085ae165831e93:${bip122}`,
}

const blockchainAddressCosmos = {
  id: `${did}#keys-blockchain`,
  type: 'JsonWebKey2020',
  controller: did,
  blockchainAccountId: `cosmos:${cosmosPrefix}:${cosmos}`,
}

const compressedKey = {
  id: `${did}#keys-4`,
  type: 'JsonWebKey2020',
  controller: did,
  publicKeyHex: compressedPublicKey,
}

const recoveryMethod2020Key = {
  id: `${did}#keys-recovery`,
  type: 'JsonWebKey2020',
  controller: did,
  ethereumAddress: eip155,
}

const malformedKey1 = {
  id: `${did}#keys-7`,
  type: 'JsonWebKey2020',
  controller: did,
  publicKeyHex:
    '05f9c36f8964623378bdc068d4bce07ed17c8fa486f9ac0c2613ca3c8c306d7bb6',
}

const malformedKey2 = {
  id: `${did}#keys-8`,
  type: 'JsonWebKey2020',
  controller: did,
  publicKeyHex:
     '04f9c36f8964623378bdc068d4bce07ed17c8fa486f9ac0c2613ca3c8c306d7bb61cd36717b8ac5e4fea8ad23dc8d0783c2318ee4ad7a80db6e0026ad0b072a24f07',
}

const malformedKey3 = {
  id: `${did}#keys-8`,
  type: 'JsonWebKey2020',
  controller: did,
  publicKeyHex:
    '0404f9c36f8964623378bdc068d4bce07ed17c8fa486f9ac0c2613ca3c8c306d7bb61cd36717b8ac5e4fea8ad23dc8d0783c2318ee4ad7a80db6e0026ad0b072a24f',
}

describe('ES256', () => {
  const verifier = VerifierAlgorithm('ES256')
  it('validates signature and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{ alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })
  
  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{ alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase58 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })
  
  it('validates with publicKeyBase64', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{ alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase64 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })
  
  it('validates with publicKeyJwk', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' },{ issuer: did, signer },{ alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyJwk }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })
  
  it('validates with publicKeyMultibase', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{ alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyMultibase }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })
  
  it('validates signature with compressed public key and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{ alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })
  
  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{ alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })
  
  it('throws error if invalid signature length', async () => {
    expect.assertions(1)
    const jwt = (await createJWT({ bla: 'bla' }, { issuer: did, signer },{ alg: 'ES256'})) + 'aa'
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(new Error('wrong signature length'))
  })
  
  it('validates signature with compressed public key and picks correct public key when malformed keys are encountered first', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [malformedKey1, malformedKey2, malformedKey3, compressedKey])).toEqual(
      compressedKey
    )
  })
  
  it('validates signature produced by ethAddress - github #14', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ethAddress])).toEqual(ethAddress)
  })
  
  it('validates signature produced by blockchainAccountId - github #14, #155', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [blockchainAddress])).toEqual(blockchainAddress)
  })
  
  it('validates signature produced by blockchainAccountId - CAIP 10 (EIP 155)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [blockchainAddressCaip10])).toEqual(blockchainAddressCaip10)
  })
  
  it('validates signature produced by blockchainAccountId - CAIP 10 (BIP 122)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [blockchainAddressBip122])).toEqual(blockchainAddressBip122)
  })
  
  it('validates signature produced by blockchainAccountId - CAIP 10 (Cosmos)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [blockchainAddressCosmos])).toEqual(blockchainAddressCosmos)
  })
  
  it('validates signature produced by JsonWebKey2020 (Recovery Method) - github #152', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer },{alg: 'ES256'})
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [recoveryMethod2020Key])).toEqual(recoveryMethod2020Key)
  })
  
})


describe('ES256-R', () => {
  const verifier = VerifierAlgorithm('ES256-R')

  it('validates signature and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })
  
  it('validates signature and picks correct compressed public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })
  
  it('validates signature with ethereum address', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ethAddress])).toEqual(ethAddress)
  })
  
  it('validates signature with blockchainAccountId - github #155', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddress])).toEqual(blockchainAddress)
  })
  
  it('validates signature with blockchainAccountId - CAIP 10 (EIP 155)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressCaip10])).toEqual(blockchainAddressCaip10)
  })
  
  it('validates signature with blockchainAccountId - CAIP 10 (BIP 122)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressBip122])).toEqual(blockchainAddressBip122)
  })
  
  it('validates signature with blockchainAccountId - CAIP 10 (COSMOS)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressCosmos])).toEqual(blockchainAddressCosmos)
  })
  
  it('validates signature with JsonWebKey2020 (Recovery Method) - github #152', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, recoveryMethod2020Key])).toEqual(recoveryMethod2020Key)
  })
  
  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase58 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })
  
  it('validates with publicKeyBase64', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase64 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })
  
  it('validates with publicKeyJwk', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyJwk }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })
  
  it('validates with publicKeyMultibase', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyMultibase }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })
})

