// @ts-ignore
import nacl from 'tweetnacl'
import {
  base64ToBytes,
  bigintToBytes,
  bytesToBase58,
  bytesToBase64,
  bytesToBase64url,
  bytesToHex,
  bytesToMultibase,
  hexToBytes,
} from '../util.js'
import { EdDSASigner } from '../signers/EdDSASigner.js'
import { ES256KSigner } from '../signers/ES256KSigner.js'
import { toEthereumAddress } from '../Digest.js'
import { publicKeyToAddress as toBip122Address } from '../blockchains/bip122.js'
import { publicKeyToAddress as toCosmosAddressWithoutPrefix } from '../blockchains/cosmos.js'
import { p256 } from '@noble/curves/p256'
import { secp256k1 } from '@noble/curves/secp256k1'

import { ES256Signer } from '../signers/ES256Signer.js'
import VerifierAlgorithm from '../VerifierAlgorithm.js'
import { createJWT } from '../JWT.js'

describe('VerifierAlgorithm', () => {
  it('supports ES256', () => {
    expect(typeof VerifierAlgorithm('ES256')).toEqual('function')
  })

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

describe('ES256', () => {
  const mnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX'
  const did = `did:uport:${mnid}`
  const privateKey = hexToBytes('736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8')
  const kp = p256.ProjectivePoint.fromPrivateKey(privateKey)
  const publicKeyBytes = kp.toRawBytes(false)
  const publicKey = kp.toHex(false)
  const compressedPublicKey = kp.toHex(true)
  const publicKeyBase64 = bytesToBase64(publicKeyBytes)
  const publicKeyBase58 = bytesToBase58(publicKeyBytes)

  const publicKeyJwk = {
    crv: 'P-256',
    kty: 'EC',
    x: bytesToBase64url(hexToBytes(kp.x.toString(16))),
    y: bytesToBase64url(hexToBytes(kp.y.toString(16))),
  }
  const signer = ES256Signer(privateKey)
  const publicKeyMultibase = bytesToMultibase(hexToBytes(compressedPublicKey), 'base58btc', 'p256-pub')
  const publicKeyMultibaseNoCodec = bytesToMultibase(hexToBytes(compressedPublicKey), 'base58btc')

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

  const ecKey3 = {
    id: `${did}#keys-3`,
    type: 'Multikey',
    controller: did,
    publicKeyMultibase,
  }

  const ecKey4 = {
    id: `${did}#keys-4`,
    type: 'Multikey',
    controller: did,
    publicKeyMultibase: publicKeyMultibaseNoCodec,
  }

  const compressedKey = {
    id: `${did}#keys-4`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyHex: compressedPublicKey,
  }

  const malformedKey1 = {
    id: `${did}#keys-7`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyHex: '05f9c36f8964623378bdc068d4bce07ed17c8fa486f9ac0c2613ca3c8c306d7bb6',
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

  const verifier = VerifierAlgorithm('ES256')
  it('validates signature and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase58 }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyBase64', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase64 }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyJwk', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyJwk }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyMultibase', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = ecKey3
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyMultibase Multikey', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = ecKey3
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyMultibase Multikey without codec', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = ecKey4
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates signature with compressed public key and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })

  it('throws error if invalid signature length', async () => {
    expect.assertions(1)
    const jwt = (await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })) + 'aa'
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(new Error('wrong signature length'))
  })

  it('validates signature with compressed public key and picks correct public key when malformed keys are encountered first', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer }, { alg: 'ES256' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [malformedKey1, malformedKey2, malformedKey3, compressedKey])).toEqual(
      compressedKey
    )
  })
})

const mnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX'
const did = `did:uport:${mnid}`
const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const publicKeyBytes = secp256k1.getPublicKey(privateKey, false)
const publicKeyPoint = secp256k1.ProjectivePoint.fromHex(publicKeyBytes)
const publicKeyHex = bytesToHex(publicKeyBytes)
const compressedPublicKeyBytes = secp256k1.getPublicKey(privateKey, true)
const compressedPublicKey = bytesToHex(compressedPublicKeyBytes)
const publicKeyBase64 = bytesToBase64(publicKeyBytes)
const publicKeyBase58 = bytesToBase58(publicKeyBytes)
const publicKeyJwk = {
  crv: 'secp256k1',
  kty: 'EC',
  x: bytesToBase64url(bigintToBytes(publicKeyPoint.x, 32)),
  y: bytesToBase64url(bigintToBytes(publicKeyPoint.y, 32)),
}
const publicKeyMultibase = bytesToMultibase(publicKeyBytes, 'base58btc')
const publicKeyMultibaseMulticodec = bytesToMultibase(publicKeyBytes, 'base58btc', 'secp256k1-pub')
const eip155 = toEthereumAddress(publicKeyHex)
const bip122 = toBip122Address(publicKeyHex, 'undefined')
const cosmosPrefix = 'example'
const cosmos = toCosmosAddressWithoutPrefix(publicKeyHex, cosmosPrefix)
const signer = ES256KSigner(hexToBytes(privateKey))
const recoverySigner = ES256KSigner(hexToBytes(privateKey), true)

const ed25519PrivateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
const edSigner = EdDSASigner(base64ToBytes(ed25519PrivateKey))
const edKp = nacl.sign.keyPair.fromSecretKey(base64ToBytes(ed25519PrivateKey))
const edPublicKey = bytesToBase64(edKp.publicKey)
const edPublicKey2 = bytesToBase64(nacl.sign.keyPair().publicKey)

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
  publicKeyHex: publicKeyHex,
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
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase58 }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyBase64', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase64 }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyJwk', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyJwk }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyMultibase', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyMultibase }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyMultibase multicodec', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyMultibase: publicKeyMultibaseMulticodec }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates signature with compressed public key and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })

  it('throws error if invalid signature length', async () => {
    expect.assertions(1)
    const jwt = (await createJWT({ bla: 'bla' }, { issuer: did, signer })) + 'aa'
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(() => verifier(parts!![1], parts!![2], [ecKey1])).toThrowError(
      new Error('compactSignature of length 64 expected, got 66')
    )
  })

  it('validates signature with compressed public key and picks correct public key when malformed keys are encountered first', async () => {
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [malformedKey1, malformedKey2, malformedKey3, compressedKey])).toEqual(
      compressedKey
    )
  })

  it('validates signature produced by ethAddress - github #14', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ethAddress])).toEqual(ethAddress)
  })

  it('validates signature produced by blockchainAccountId - github #14, #155', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [blockchainAddress])).toEqual(blockchainAddress)
  })

  it('validates signature produced by blockchainAccountId - CAIP 10 (EIP 155)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [blockchainAddressCaip10])).toEqual(blockchainAddressCaip10)
  })

  it('validates signature produced by blockchainAccountId - CAIP 10 (BIP 122)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [blockchainAddressBip122])).toEqual(blockchainAddressBip122)
  })

  it('validates signature produced by blockchainAccountId - CAIP 10 (Cosmos)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [blockchainAddressCosmos])).toEqual(blockchainAddressCosmos)
  })

  it('validates signature produced by EcdsaSecp256k1RecoveryMethod2020 - github #152', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [recoveryMethod2020Key])).toEqual(recoveryMethod2020Key)
  })
})

describe('ES256K-R', () => {
  const verifier = VerifierAlgorithm('ES256K-R')

  it('validates signature and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, ecKey2])).toEqual(ecKey2)
  })

  it('validates signature and picks correct compressed public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, compressedKey])).toEqual(compressedKey)
  })

  it('validates signature with ethereum address', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, ethAddress])).toEqual(ethAddress)
  })

  it('validates signature with blockchainAccountId - github #155', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddress])).toEqual(blockchainAddress)
  })

  it('validates signature with blockchainAccountId - CAIP 10 (EIP 155)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressCaip10])).toEqual(blockchainAddressCaip10)
  })

  it('validates signature with blockchainAccountId - CAIP 10 (BIP 122)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressBip122])).toEqual(blockchainAddressBip122)
  })

  it('validates signature with blockchainAccountId - CAIP 10 (COSMOS)', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, blockchainAddressCosmos])).toEqual(blockchainAddressCosmos)
  })

  it('validates signature with EcdsaSecp256k1RecoveryMethod2020 - github #152', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [ecKey1, recoveryMethod2020Key])).toEqual(recoveryMethod2020Key)
  })

  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase58 }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyBase64', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyBase64 }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyJwk', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyJwk }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyMultibase', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const pubkey = Object.assign({ publicKeyMultibase }, ecKey2)
    // @ts-ignore
    delete pubkey.publicKeyHex
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { issuer: did, signer: recoverySigner, alg: 'ES256K-R' })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(() => verifier(parts[1], parts[2], [ecKey1])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })
})

describe('Ed25519', () => {
  const verifier = VerifierAlgorithm('Ed25519')
  it('validates signature and picks correct public key', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [edKey, edKey2])).toEqual(edKey)
  })

  it('validates with publicKeyBase58', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const publicKeyBase58 = bytesToBase58(base64ToBytes(edKey.publicKeyBase64))
    const pubkey = Object.assign({ publicKeyBase58 }, edKey)
    // @ts-ignore
    delete pubkey.publicKeyBase64
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('validates with publicKeyJwk', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    const publicKeyJwk = {
      crv: 'Ed25519',
      kty: 'OKP',
      x: bytesToBase64url(base64ToBytes(edKey.publicKeyBase64)),
    }
    const pubkey = Object.assign({ publicKeyJwk }, edKey)
    // @ts-ignore
    delete pubkey.publicKeyBase64
    // @ts-ignore
    return expect(verifier(parts[1], parts[2], [pubkey])).toEqual(pubkey)
  })

  it('throws error if invalid signature', async () => {
    expect.assertions(1)
    const jwt = await createJWT({ bla: 'bla' }, { alg: 'Ed25519', issuer: did, signer: edSigner })
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    // @ts-ignore
    return expect(() => verifier(parts[1], parts[2], [edKey2])).toThrowError(
      new Error('invalid_signature: Signature invalid for JWT')
    )
  })
})
