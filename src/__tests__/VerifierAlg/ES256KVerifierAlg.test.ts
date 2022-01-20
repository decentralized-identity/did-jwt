import VerifierAlgorithm from '../../VerifierAlgorithm'
import { createJWT } from '../../JWT'
import { ec as EC } from 'elliptic'
import { bytesToBase58, bytesToBase64, hexToBytes, bytesToBase64url, bytesToMultibase } from '../../util'
import { ES256KSigner } from '../../signers/ES256KSigner'
import { toEthereumAddress } from '../../Digest'
import { publicKeyToAddress as toBip122Address } from '../../blockchains/bip122'
import { publicKeyToAddress as toCosmosAddressWithoutPrefix } from '../../blockchains/cosmos'

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
const publicKeyBase64 = bytesToBase64(hexToBytes(publicKey))
const publicKeyBase58 = bytesToBase58(hexToBytes(publicKey))
const publicKeyJwk = {
  crv: 'secp256k1',
  kty: 'EC',
  x: bytesToBase64url(hexToBytes(kp.getPublic().getX().toString('hex'))),
  y: bytesToBase64url(hexToBytes(kp.getPublic().getY().toString('hex'))),
}
const publicKeyMultibase = bytesToMultibase(hexToBytes(publicKey), 'base58btc')
const eip155 = toEthereumAddress(publicKey)
const bip122 = toBip122Address(publicKey)
const cosmosPrefix = 'example'
const cosmos = toCosmosAddressWithoutPrefix(publicKey, cosmosPrefix)
const signer = ES256KSigner(privateKey)
const recoverySigner = ES256KSigner(privateKey, true)

const ecKey1 = {
  id: `${did}#keys-1`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex:
    '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062',
}

const ecKey2 = {
  id: `${did}#keys-2`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex: publicKey,
}

const ethAddress = {
  id: `${did}#keys-3`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  ethereumAddress: eip155,
}

const blockchainAddress = {
  id: `${did}#keys-blockchain`,
  type: 'EcdsaSecp256k1RecoveryMethod2020',
  controller: did,
  blockchainAccountId: `${eip155}@eip155:1`,
}

const blockchainAddressCaip10 = {
  id: `${did}#keys-blockchain`,
  type: 'EcdsaSecp256k1RecoveryMethod2020',
  controller: did,
  blockchainAccountId: `eip155:1:${eip155}`,
}

const blockchainAddressBip122 = {
  id: `${did}#keys-blockchain`,
  type: 'EcdsaSecp256k1RecoveryMethod2020',
  controller: did,
  blockchainAccountId: `bip122:000000000019d6689c085ae165831e93:${bip122}`,
}

const blockchainAddressCosmos = {
  id: `${did}#keys-blockchain`,
  type: 'EcdsaSecp256k1RecoveryMethod2020',
  controller: did,
  blockchainAccountId: `cosmos:${cosmosPrefix}:${cosmos}`,
}

const compressedKey = {
  id: `${did}#keys-4`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex: compressedPublicKey,
}

const recoveryMethod2020Key = {
  id: `${did}#keys-recovery`,
  type: 'EcdsaSecp256k1RecoveryMethod2020',
  controller: did,
  ethereumAddress: eip155,
}

const malformedKey1 = {
  id: `${did}#keys-7`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex:
    '05613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062',
}

const malformedKey2 = {
  id: `${did}#keys-8`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex:
    '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062aabbccdd',
}

const malformedKey3 = {
  id: `${did}#keys-8`,
  type: 'Secp256k1VerificationKey2018',
  controller: did,
  publicKeyHex:
    '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06',
}

describe('ES256K', () => {
  const verifier = VerifierAlgorithm('ES256K')
  it('validates signature and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase58 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyBase64', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase64 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyJwk', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyJwk }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyMultibase', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyMultibase }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates signature with compressed public key and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })

  it('throws error if invalid signature length', async () => {
    expect.assertions(1)
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
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ethAddress])).toEqual(ethAddress)
  })

  it('validates signature produced by blockchainAccountId - github #14, #155', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [blockchainAddress])).toEqual(blockchainAddress)
  })

  it('validates signature produced by blockchainAccountId - CAIP 10 (EIP 155)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [blockchainAddressCaip10])).toEqual(blockchainAddressCaip10)
  })

  it('validates signature produced by blockchainAccountId - CAIP 10 (BIP 122)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [blockchainAddressBip122])).toEqual(blockchainAddressBip122)
  })

  it('validates signature produced by blockchainAccountId - CAIP 10 (Cosmos)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [blockchainAddressCosmos])).toEqual(blockchainAddressCosmos)
  })

  it('validates signature produced by EcdsaSecp256k1RecoveryMethod2020 - github #152', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [recoveryMethod2020Key])).toEqual(recoveryMethod2020Key)
  })
})

describe('ES256K-R', () => {
  const verifier = VerifierAlgorithm('ES256K-R')

  it('validates signature and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates signature and picks correct compressed public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('validates signature with ethereum address', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, ethAddress])).toEqual(ethAddress)
  })

  it('validates signature with blockchainAccountId - github #155', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddress])).toEqual(blockchainAddress)
  })

  it('validates signature with blockchainAccountId - CAIP 10 (EIP 155)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressCaip10])).toEqual(blockchainAddressCaip10)
  })

  it('validates signature with blockchainAccountId - CAIP 10 (BIP 122)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressBip122])).toEqual(blockchainAddressBip122)
  })

  it('validates signature with blockchainAccountId - CAIP 10 (COSMOS)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressCosmos])).toEqual(blockchainAddressCosmos)
  })

  it('validates signature with EcdsaSecp256k1RecoveryMethod2020 - github #152', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts[1], parts[2], [ecKey1, recoveryMethod2020Key])).toEqual(recoveryMethod2020Key)
  })

  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase58 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyBase64', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase64 }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyJwk', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyJwk }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyMultibase', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyMultibase }, ecKey2)
    delete pubkey.publicKeyHex
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })
})
