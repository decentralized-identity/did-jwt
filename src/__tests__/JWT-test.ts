import { createJWT, verifyJWT, decodeJWT, createJWS, verifyJWS, resolveAuthenticator, NBF_SKEW } from '../JWT'
import { TokenVerifier } from 'jsontokens'
import SimpleSigner from '../signers/SimpleSigner'
import NaclSigner from '../signers/NaclSigner'
import { bytesToBase64url, decodeBase64url } from '../util'
import { verifyJWT as naclVerifyJWT } from 'nacl-did'
import MockDate from 'mockdate'
import { PublicKey } from 'did-resolver'

const NOW = 1485321133
MockDate.set(NOW * 1000 + 123)

const audAddress = '0x20c769ec9c0996ba7737a4826c2aaff00b1b2040'
const aud = `did:ethr:${audAddress}`
const address = '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
const did = `did:ethr:${address}`
const alg = 'ES256K'

const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
const verifier = new TokenVerifier(alg, publicKey)
const signer = SimpleSigner(privateKey)

const didDoc = {
  '@context': 'https://w3id.org/did/v1',
  id: did,
  publicKey: [
    {
      id: `${did}#keys-1`,
      type: 'Secp256k1VerificationKey2018',
      owner: did,
      publicKeyHex: publicKey
    }
  ],
  authentication: [
    {
      type: 'Secp256k1SignatureAuthentication2018',
      publicKey: `${did}#keys-1`
    }
  ]
}

const didDocDefault = {
  '@context': 'https://w3id.org/did/v1',
  id: did,
  publicKey: [
    {
      id: `${did}#keys-1`,
      type: 'Secp256k1VerificationKey2018',
      owner: did,
      ethereumAddress: address
    }
  ],
  authentication: [
    {
      type: 'Secp256k1SignatureAuthentication2018',
      publicKey: `${did}#keys-1`
    }
  ]
}

describe('createJWT()', () => {
  describe('ES256K', () => {
    it('creates a valid JWT', async () => {
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer })
      return expect(verifier.verify(jwt)).toBeTruthy()
    })

    it('creates a valid JWT using a MNID', async () => {
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: address, signer })
      return expect(verifier.verify(jwt)).toBeTruthy()
    })

    it('creates a JWT with correct format', async () => {
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer })
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })

    it('creates a JWT with correct legacy format', async () => {
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: address, signer })
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })

    it('creates a JWT with expiry in 10000 seconds', async () => {
      const jwt = await createJWT(
        {
          requested: ['name', 'phone'],
          nbf: Math.floor(new Date().getTime() / 1000)
        },
        { issuer: did, signer, expiresIn: 10000 }
      )
      const { payload } = decodeJWT(jwt)
      return expect(payload.exp).toEqual(payload.nbf + 10000)
    })

    it('Uses iat if nbf is not defined but expiresIn is included', async () => {
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer, expiresIn: 10000 })
      )
      return expect(payload.exp).toEqual(payload.iat + 10000)
    })

    it('sets iat to the current time by default', async () => {
      const timestamp = Math.floor(Date.now() / 1000)
      const { payload } = decodeJWT(await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer }))
      return expect(payload.iat).toEqual(timestamp)
    })

    it('sets iat to the value passed in payload', async () => {
      const timestamp = 2000000
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'], iat: timestamp }, { issuer: did, signer })
      )
      return expect(payload.iat).toEqual(timestamp)
    })

    it('does not set iat if value in payload is undefined', async () => {
      const { payload } = decodeJWT(
        await createJWT({ requested: ['name', 'phone'], iat: undefined }, { issuer: did, signer })
      )
      return expect(payload.iat).toBeUndefined()
    })

    it('throws an error if unsupported algorithm is passed in', async () => {
      await expect(
        createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer, alg: 'BADALGO' })
      ).rejects.toThrow('Unsupported algorithm BADALGO')
    })
  })

  describe('Ed25519', () => {
    const ed25519PrivateKey = 'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
    const did = 'did:nacl:BvrB8iJAz_1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU'
    const signer = NaclSigner(ed25519PrivateKey)
    const alg = 'Ed25519'

    it('creates a valid JWT', async () => {
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { alg, issuer: did, signer })
      return await expect(naclVerifyJWT(jwt)).toBeTruthy()
    })

    it('creates a JWT with correct format', async () => {
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { alg, issuer: did, signer })
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })

    it('creates a JWT with expiry in 10000 seconds', async () => {
      const jwt = await createJWT(
        {
          requested: ['name', 'phone'],
          nbf: Math.floor(new Date().getTime() / 1000)
        },
        { alg, issuer: did, signer, expiresIn: 10000 }
      )
      const { payload } = decodeJWT(jwt)
      return expect(payload.exp).toEqual(payload.nbf + 10000)
    })
  })
})

describe('verifyJWT()', () => {
  const resolver = { resolve: jest.fn().mockReturnValue(didDoc) }

  describe('pregenerated JWT', () => {
    // tslint:disable-next-line: max-line-length
    const incomingJwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsImlzcyI6ImRpZDpldGhyOjB4OTBlNDVkNzViZDEyNDZlMDkyNDg3MjAxODY0N2RiYTk5NmE4ZTdiOSIsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.KIG2zUO8Quf3ucb9jIncZ1CmH0v-fAZlsKvesfsd9x4RzU0qrvinVd9d30DOeZOwdwEdXkET_wuPoOECwU0IKA'
    it('verifies the JWT and return correct payload', async () => {
      const { payload } = await verifyJWT(incomingJwt, { resolver })
      return expect(payload).toMatchSnapshot()
    })
    it('verifies the JWT and return correct profile', async () => {
      const { doc } = await verifyJWT(incomingJwt, { resolver })
      return expect(doc).toEqual(didDoc)
    })
    it('verifies the JWT and return correct did for the iss', async () => {
      const { issuer } = await verifyJWT(incomingJwt, { resolver })
      return expect(issuer).toEqual('did:ethr:0x90e45d75bd1246e0924872018647dba996a8e7b9')
    })
    it('verifies the JWT and return correct signer', async () => {
      const { signer } = await verifyJWT(incomingJwt, { resolver })
      return expect(signer).toEqual(didDoc.publicKey[0])
    })
    it('verifies the JWT requiring authentication and return correct signer', async () => {
      const { signer } = await verifyJWT(incomingJwt, { resolver, auth: true })
      return expect(signer).toEqual(didDoc.publicKey[0])
    })
  })

  describe('badJwt', () => {
    // tslint:disable-next-line: max-line-length
    const badJwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsImlzcyI6ImRpZDpldGhyOjB4MjBjNzY5ZWM5YzA5OTZiYTc3MzdhNDgyNmMyYWFmZjAwYjFiMjA0MCIsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.TTpuw77fUbd_AY3GJcCumd6F6hxnkskMDJYNpJlI2DQi5MKKudXya9NlyM9e8-KFgTLe-WnXgq9EjWLvjpdiXA'
    it('rejects a JWT with bad signature', async () => {
      await expect(verifyJWT(badJwt, { resolver })).rejects.toThrowError(/Signature invalid for JWT/)
    })
  })

  describe('validFrom timestamp', () => {
    it('passes when nbf is in the past', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsIm5iZiI6MTQ4NTI2MTEzMywiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.FUasGkOYqGVxQ7S-QQvh4abGO6Dwr961UjjOxtRTyUDnl6q6ElqHqAK-WMDTmOir21pFPKLYZMtLZ4LTLpm3cQ'
      // const jwt = await createJWT({nbf: PAST}, {issuer:did, signer})
      await expect(verifyJWT(jwt, { resolver })).resolves.not.toThrow()
    })
    it('passes when nbf is in the past and iat is in the future', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzODExMzMsIm5iZiI6MTQ4NTI2MTEzMywiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.8BPiSG2e6UBn1osnJ6PJYbPjtPMPaCeutTA9OCp-ZzI-QvvwPCVrrWqTu2YELbzUPwDIJCQ8v8N77xCEjIYSmQ'
      // const jwt = await createJWT({nbf:PAST,iat:FUTURE},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).resolves.not.toThrow()
    })
    it('fails when nbf is in the future', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsIm5iZiI6MTQ4NTM4MTEzMywiaXNzIjoiZGlkOnVwb3J0OjJuUXRpUUc2Q2dtMUdZVEJhYUtBZ3I3NnVZN2lTZXhVa3FYIn0.rcFuhVHtie3Y09pWxBSf1dnjaVh6FFQLHh-83N-uLty3M5ADJ-jVFFkyt_Eupl8Kr735-oPGn_D1Nj9rl4s_Kw'
      // const jwt = await createJWT({nbf:FUTURE},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).rejects.toThrow()
    })
    it('fails when nbf is in the future and iat is in the past', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUyNjExMzMsIm5iZiI6MTQ4NTM4MTEzMywiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.JjEn_huxI9SsBY_3PlD0ShpXvrRgUGFDKAgxJBc1Q5GToVpUTw007-o9BTt7JNi_G2XWmcu2aXXnDn0QFsRIrg'
      // const jwt = await createJWT({nbf:FUTURE,iat:PAST},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).rejects.toThrow()
    })
    it('passes when nbf is missing and iat is in the past', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUyNjExMzMsImlzcyI6ImRpZDpldGhyOjB4ZjNiZWFjMzBjNDk4ZDllMjY4NjVmMzRmY2FhNTdkYmI5MzViMGQ3NCJ9.jkzN5kIVtuRU-Fjte8w5r-ttf9OfhdN38oFJd61CWdI5WnvU1dPCvnx1_kdk2D6Xg-uPqp1VXAb7KA2ZECivmg'
      // const jwt = await createJWT({iat:PAST},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).resolves.not.toThrow()
    })
    it('fails when nbf is missing and iat is in the future', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzODExMzMsImlzcyI6ImRpZDpldGhyOjB4ZjNiZWFjMzBjNDk4ZDllMjY4NjVmMzRmY2FhNTdkYmI5MzViMGQ3NCJ9.FJuHvf9Tby7b4I54Cm1nh8CvLg4QH2wt2K0WfyQaLqlr3NKKI5hAdLalgZksI25gLhNrZwQFnC-nzEOs9PI1SQ'
      // const jwt = await createJWT({iat:FUTURE},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).rejects.toThrow()
    })
    it('passes when nbf and iat are both missing', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQifQ.KgnwgMMz-QSOtpba2QMGHMWJoLvhp-H4odjjX1QKnqj4-8dkcK12y7rj7Zq24-1d-1ne86aJCdWtx5VJv3rM7w'
      // const jwt = await createJWT({iat:undefined},{issuer:did,signer})
      await expect(verifyJWT(jwt, { resolver })).resolves.not.toThrow()
    })
  })

  it('handles ES256K-R algorithm', async () => {
    const jwt = await createJWT({ hello: 'world' }, { issuer: did, signer, alg: 'ES256K-R' })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toMatchSnapshot()
  })

  it('handles ES256K-R algorithm with ethereum address', async () => {
    const jwt = await createJWT({ hello: 'world' }, { issuer: aud, signer, alg: 'ES256K-R' })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toMatchSnapshot()
  })

  it('handles ES256K algorithm with ethereum address - github #14', async () => {
    const ethResolver = { resolve: jest.fn().mockReturnValue(didDocDefault) }
    const jwt = await createJWT({ hello: 'world' }, { issuer: aud, signer, alg: 'ES256K' })
    const { payload } = await verifyJWT(jwt, { resolver: ethResolver })
    return expect(payload).toMatchSnapshot()
  })

  it('accepts a valid exp', async () => {
    const jwt = await createJWT({ exp: NOW }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toBeDefined()
  })

  it('rejects an expired JWT', async () => {
    const jwt = await createJWT({ exp: NOW - NBF_SKEW - 1 }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrow(/JWT has expired/)
  })

  it('rejects an expired JWT without skew time', async () => {
    const jwt = await createJWT({ exp: NOW - 1 }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver, skewTime: 0 })).rejects.toThrow(/JWT has expired/)
  })

  it('accepts a valid audience', async () => {
    const jwt = await createJWT({ aud }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, { resolver, audience: aud })
    return expect(payload).toMatchSnapshot()
  })

  it('accepts multiple audiences', async () => {
    const jwt = await createJWT({ aud: [did, aud] }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, { resolver, audience: aud })
    return expect(payload).toMatchSnapshot()
  })

  it('rejects invalid multiple audiences', async () => {
    const jwt = await createJWT({ aud: [did, did] }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver, audience: aud })).rejects.toThrow(/JWT audience does not match your DID/)
  })

  it('accepts a valid audience using callback_url', async () => {
    const jwt = await createJWT({ aud: 'http://pututu.uport.me/unique' }, { issuer: did, signer })
    const { payload } = await verifyJWT(jwt, {
      resolver,
      callbackUrl: 'http://pututu.uport.me/unique'
    })
    return expect(payload).toMatchSnapshot()
  })

  it('rejects invalid audience', async () => {
    const jwt = await createJWT({ aud }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver, audience: did })).rejects.toThrow(
      /JWT audience does not match your DID or callback url/
    )
  })

  it('rejects an invalid audience using callback_url where callback is wrong', async () => {
    const jwt = await createJWT({ aud: 'http://pututu.uport.me/unique' }, { issuer: did, signer })
    await expect(
      verifyJWT(jwt, {
        resolver,
        callbackUrl: 'http://pututu.uport.me/unique/1'
      })
    ).rejects.toThrow(/JWT audience does not match your DID or callback url/)
  })

  it('rejects an invalid audience using callback_url where callback is missing', async () => {
    const jwt = await createJWT({ aud: 'http://pututu.uport.me/unique' }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrow(
      'JWT audience is required but your app address has not been configured'
    )
  })

  it('rejects invalid audience as no address is present', async () => {
    const jwt = await createJWT({ aud }, { issuer: did, signer })
    await expect(verifyJWT(jwt, { resolver })).rejects.toThrow(
      /JWT audience is required but your app address has not been configured/
    )
  })
})

describe('JWS', () => {
  it('createJWS works with JSON payload', async () => {
    const payload = { some: 'data' }
    const jws = await createJWS(payload, signer)
    expect(jws).toMatchSnapshot()
    expect(JSON.parse(decodeBase64url(jws.split('.')[1]))).toEqual(payload)
  })

  it('createJWS works with base64url payload', async () => {
    // use the hex public key as an arbitrary payload
    const encodedPayload = bytesToBase64url(Buffer.from(publicKey, 'hex'))
    const jws = await createJWS(encodedPayload, signer)
    expect(jws).toMatchSnapshot()
    expect(jws.split('.')[1]).toEqual(encodedPayload)
  })

  it('verifyJWS works with JSON payload', async () => {
    const payload = { some: 'data' }
    const jws = await createJWS(payload, signer)
    expect(verifyJWS(jws, { publicKeyHex: publicKey } as PublicKey))
  })

  it('verifyJWS works with base64url payload', async () => {
    const encodedPayload = bytesToBase64url(Buffer.from(publicKey, 'hex'))
    const jws = await createJWS(encodedPayload, signer)
    expect(verifyJWS(jws, { publicKeyHex: publicKey } as PublicKey))
  })

  it('verifyJWS fails with bad input', async () => {
    const badJws = 'abrewguer.fjreoiwfoiew.foirheogu.reoguhwehrg'
    expect(() => verifyJWS(badJws, { publicKeyHex: publicKey } as PublicKey)).toThrow('Incorrect format JWS')
  })
})

describe('resolveAuthenticator()', () => {
  const ecKey1 = {
    id: `${did}#keys-1`,
    type: 'Secp256k1VerificationKey2018',
    owner: did,
    publicKeyHex:
      '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab061'
  }

  const ecKey2 = {
    id: `${did}#keys-2`,
    type: 'Secp256k1SignatureVerificationKey2018',
    owner: did,
    publicKeyHex:
      '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062'
  }

  const ecKey3 = {
    id: `${did}#keys-3`,
    type: 'Secp256k1SignatureVerificationKey2018',
    owner: did,
    publicKeyHex:
      '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab063'
  }

  const encKey1 = {
    id: `${did}#keys-4`,
    type: 'Curve25519EncryptionPublicKey',
    owner: did,
    publicKeyBase64: 'QCFPBLm5pwmuTOu+haxv0+Vpmr6Rrz/DEEvbcjktQnQ='
  }

  const edKey = {
    id: `${did}#keys-5`,
    type: 'ED25519SignatureVerification',
    owner: did,
    publicKeyBase64: 'BvrB8iJAz/1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU='
  }

  const edKey2 = {
    id: `${did}#keys-6`,
    type: 'ED25519SignatureVerification',
    owner: did,
    publicKeyBase64: 'SI+tzELqRb8XKuRE3Cj7uWGgkEQ86X87ZjhGAok+Ujc='
  }

  const authKey1 = {
    type: 'Secp256k1SignatureAuthentication2018',
    publicKey: ecKey1.id
  }

  const authKey2 = {
    type: 'Secp256k1SignatureAuthentication2018',
    publicKey: ecKey2.id
  }

  const edAuthKey = {
    type: 'ED25519SigningAuthentication',
    publicKey: edKey.id
  }

  const edKey6 = {
    id: `${did}#keys-auth6`,
    type: 'ED25519SignatureVerification',
    owner: did,
    publicKeyBase58: 'dummyvalue'
  }
  
  const ecKey7 = {
    id: `${did}#keys-auth7`,
    type: 'EcdsaSecp256k1VerificationKey2019',
    owner: did,
    publicKeyBase58: 'dummyvalue'
  }

  const edKey8 = {
    id: `${did}#keys-auth8`,
    type: 'Ed25519VerificationKey2018',
    owner: did,
    publicKeyBase58: 'dummyvalue'
  }

  const singleKey = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [ecKey1]
  }

  const multipleKeys = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [ecKey1, ecKey2, ecKey3, encKey1, edKey, edKey2],
    authentication: [authKey1, authKey2, edAuthKey]
  }

  const multipleAuthTypes = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [ecKey1, ecKey2, ecKey3, encKey1, edKey, edKey2, edKey6, ecKey7],
    authentication: [authKey1, authKey2, edAuthKey, `${did}#keys-auth6`, `${did}#keys-auth7`, edKey8]
  }

  const unsupportedFormat = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [encKey1]
  }
  const noPublicKey = {
    '@context': 'https://w3id.org/did/v1',
    id: did
  }

  describe('DID', () => {
    describe('ES256K', () => {
      it('finds public key', async () => {
        const authenticators = await resolveAuthenticator({ resolve: jest.fn().mockReturnValue(singleKey) }, alg, did)
        return expect(authenticators).toEqual({
          authenticators: [ecKey1],
          issuer: did,
          doc: singleKey
        })
      })

      it('filters out irrelevant public keys', async () => {
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleKeys) },
          alg,
          did
        )
        return expect(authenticators).toEqual({
          authenticators: [ecKey1, ecKey2, ecKey3],
          issuer: did,
          doc: multipleKeys
        })
      })

      it('only list authenticators able to authenticate a user', async () => {
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleKeys) },
          alg,
          did,
          true
        )
        return expect(authenticators).toEqual({
          authenticators: [ecKey1, ecKey2],
          issuer: did,
          doc: multipleKeys
        })
      })

      it('lists authenticators with multiple key types in doc', async () => {
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleAuthTypes) },
          alg,
          did,
          true
        )
        return expect(authenticators).toEqual({
          authenticators: [ecKey1, ecKey2, ecKey7],
          issuer: did,
          doc: multipleAuthTypes
        })
      })

      it('errors if no suitable public keys exist', async () => {
        return await expect(
          resolveAuthenticator({ resolve: jest.fn().mockReturnValue(unsupportedFormat) }, alg, did)
        ).rejects.toEqual(new Error(`DID document for ${did} does not have public keys for ${alg}`))
      })
    })

    describe('Ed25519', () => {
      const alg = 'Ed25519'
      it('filters out irrelevant public keys', async () => {
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleKeys) },
          alg,
          did
        )
        return expect(authenticators).toEqual({
          authenticators: [edKey, edKey2],
          issuer: did,
          doc: multipleKeys
        })
      })

      it('only list authenticators able to authenticate a user', async () => {
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleKeys) },
          alg,
          did,
          true
        )
        return expect(authenticators).toEqual({
          authenticators: [edKey],
          issuer: did,
          doc: multipleKeys
        })
      })

      it('lists authenticators with multiple key types in doc', async () => {
        const authenticators = await resolveAuthenticator(
          { resolve: jest.fn().mockReturnValue(multipleAuthTypes) },
          alg,
          did,
          true
        )
        return expect(authenticators).toEqual({
          authenticators: [edKey, edKey6, edKey8],
          issuer: did,
          doc: multipleAuthTypes
        })
      })

      it('errors if no suitable public keys exist', async () => {
        return await expect(
          resolveAuthenticator({ resolve: jest.fn().mockReturnValue(unsupportedFormat) }, alg, did)
        ).rejects.toEqual(new Error(`DID document for ${did} does not have public keys for ${alg}`))
      })
    })

    it('errors if no suitable public keys exist for authentication', async () => {
      return await expect(
        resolveAuthenticator({ resolve: jest.fn().mockReturnValue(singleKey) }, alg, did, true)
      ).rejects.toEqual(
        new Error(`DID document for ${did} does not have public keys suitable for authenticating user`)
      )
    })

    it('errors if no public keys exist', async () => {
      return await expect(
        resolveAuthenticator({ resolve: jest.fn().mockReturnValue(noPublicKey) }, alg, did)
      ).rejects.toEqual(new Error(`DID document for ${did} does not have public keys for ${alg}`))
    })

    it('errors if no DID document exists', async () => {
      return await expect(resolveAuthenticator({ resolve: jest.fn().mockReturnValue(null) }, alg, did)).rejects.toEqual(
        new Error(`Unable to resolve DID document for ${did}`)
      )
    })

    it('errors if no supported signature types exist', async () => {
      return await expect(
        resolveAuthenticator({ resolve: jest.fn().mockReturnValue(singleKey) }, 'ESBAD', did)
      ).rejects.toEqual(new Error('No supported signature types for algorithm ESBAD'))
    })
  })

  describe('incorrect format', () => {
    it('throws if token is not valid JWT format', () => {
      expect(() => decodeJWT('not a jwt')).toThrow()
    })
  })
})
