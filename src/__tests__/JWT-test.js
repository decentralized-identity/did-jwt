import { createJWT, verifyJWT, decodeJWT, resolveAuthenticator, IAT_SKEW } from '../JWT'
import { TokenVerifier } from 'jsontokens'
import registerResolver from 'uport-did-resolver'
import SimpleSigner from '../SimpleSigner'
import MockDate from 'mockdate'
const NOW = 1485321133
MockDate.set(NOW * 1000 + 123)

const audMnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqY'
const aud = `did:uport:${audMnid}`
const mnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX'
const did = `did:uport:${mnid}`
const alg = 'ES256K'

const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
const verifier = new TokenVerifier(alg, publicKey)
const signer = SimpleSigner(privateKey)

const didDoc = {
  '@context': 'https://w3id.org/did/v1',
  id: did,
  publicKey: [{
    id: `${did}#keys-1`,
    type: 'Secp256k1VerificationKey2018',
    owner: did,
    publicKeyHex: publicKey
  }],
  authentication: [
    {
      type: 'Secp256k1SignatureAuthentication2018',
      publicKey: `${did}#keys-1`
    }
  ]
}

const ethDidDoc = {
  '@context': 'https://w3id.org/did/v1',
  id: did,
  publicKey: [{
    id: `${did}#keys-1`,
    type: 'Secp256k1VerificationKey2018',
    owner: did,
    ethereumAddress: '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  }]
}
        
describe('createJWT()', () => {
  it('creates a valid JWT', () => {
    return createJWT({requested: ['name', 'phone']}, {issuer: did, signer}).then((jwt) => {
      return expect(verifier.verify(jwt)).toBeTruthy()
    })
  })

  it('creates a valid JWT using a MNID', () => {
    return createJWT({requested: ['name', 'phone']}, {issuer: mnid, signer}).then((jwt) => {
      return expect(verifier.verify(jwt)).toBeTruthy()
    })
  })

  it('creates a JWT with correct format', () => {
    return createJWT({requested: ['name', 'phone']}, {issuer: did, signer}).then((jwt) => {
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })
  })

  it('creates a JWT with correct legacy format', () => {
    return createJWT({requested: ['name', 'phone']}, {issuer: mnid, signer}).then((jwt) => {
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })
  })

  it('creates a JWT with expiry in 10000 seconds', () => {
    return createJWT({requested: ['name', 'phone']}, {issuer: did, signer, expiresIn: 10000}).then((jwt) => {
      const {payload} = decodeJWT(jwt)
      return expect(payload.exp).toEqual(payload.iat + 10000)
    })
  })

  it('throws an error if no signer is configured', () => {
    return createJWT({ requested: ['name', 'phone'] }, {issuer: did}).catch(error => {
      return expect(error.message).toEqual('No Signer functionality has been configured')
    })
  })

  it('throws an error if no address is configured', () => {
    return createJWT({ requested: ['name', 'phone'] }, {signer}).catch(error => {
      return expect(error.message).toEqual('No issuing DID has been configured')
    })
  })

  it('throws an error if unsupported algorithm is passed in', () => {
    return createJWT({ requested: ['name', 'phone'] }, {issuer: did, signer, alg: 'BADALGO'}).catch(error => {
      return expect(error.message).toEqual('Unsupported algorithm BADALGO')
    })
  })
})

describe('verifyJWT()', () => {
  registerResolver((id, cb) => { 
    if (mnid === id) cb(null, didDoc)
    if (audMnid === id) cb(null, ethDidDoc)
  })
  const incomingJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6dXBvcnQ6Mm5RdGlRRzZDZ20xR1lUQmFhS0Fncjc2dVk3aVNleFVrcVgiLCJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.1hyeUGRBb-cgvjD5KKbpVJBF4TfDjYxrI8SWRJ-GyrJrNLAxt4MutKMFQyF1k_YkxbVozGJ_4XmgZqNaW4OvCw'

  it('verifies the JWT and return correct payload', () => {
    return verifyJWT(incomingJwt).then(({payload}) => {
      return expect(payload).toMatchSnapshot()
    })
  })

  it('verifies the JWT and return correct profile', () => {
    return verifyJWT(incomingJwt).then(({doc}) => {
      return expect(doc).toEqual(didDoc)
    })
  })

  it('verifies the JWT and return correct did for the iss', () => {
    return verifyJWT(incomingJwt).then(({issuer}) => {
      return expect(issuer).toEqual(did)
    })
  })

  it('verifies the JWT and return correct signer', () => {
    return verifyJWT(incomingJwt).then(({signer}) => expect(signer).toEqual(didDoc.publicKey[0]))
  })

  it('verifies the JWT requiring authentication and return correct signer', () => {
    return verifyJWT(incomingJwt, {auth: true}).then(({signer}) => expect(signer).toEqual(didDoc.publicKey[0]))
  })

  const badJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6dXBvcnQ6Mm5RdGlRRzZDZ20xR1lUQmFhS0Fncjc2dVk3aVNleFVrcVgiLCJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.1hyeUGRBb-cgvjD5KKbpVJBF4TfDjYxrI8SWRJ-GyrJrNLAxt4MutKMFQyF1k_YkxbVozGJ_4XmgZqNaW4OvCX'
  it('rejects a JWT with bad signature', () => {
    return verifyJWT(badJwt).catch(error =>
      expect(error.message).toEqual('Signature invalid for JWT')
    ).then((p) => expect(p).toBeFalsy())
  })

  it('accepts a valid iat', () => {
    return createJWT({iat: NOW + IAT_SKEW}, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt).then(({payload}) => expect(payload).toMatchSnapshot(), error => expect(error).toBeNull())
    )
  })

  it('handles ES256K-R algorithm', () => {
    return createJWT({hello: 'world'}, {issuer: did, signer, alg: 'ES256K-R'}).then(jwt =>
      verifyJWT(jwt).then(({payload}) => expect(payload).toMatchSnapshot(), error => expect(error).toBeNull())
    )
  })

  it('handles ES256K-R algorithm with ethereum address', () => {
    return createJWT({hello: 'world'}, {issuer: aud, signer, alg: 'ES256K-R'}).then(jwt =>
      verifyJWT(jwt).then(({payload}) => expect(payload).toMatchSnapshot(), error => expect(error).toBeNull())
    )
  })

  it('rejects an iat in the future', () => {
    return createJWT({iat: NOW + IAT_SKEW + 1}, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt).catch(error =>
        expect(error.message).toEqual('JWT not valid yet (issued in the future): iat: 1485321194 > now: 1485321133')
      ).then((p) => expect(p).toBeFalsy())
    )
  })

  it('accepts a valid exp', () => {
    return createJWT({exp: NOW - IAT_SKEW + 1}, {issuer: did, signer, expiresIn: 1}).then(jwt =>
      verifyJWT(jwt).then(({payload}) =>
        expect(payload).toMatchSnapshot()
      )
    )
  })

  it('rejects an expired JWT', () => {
    return createJWT({exp: NOW - IAT_SKEW - 1}, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt).catch(error =>
        expect(error.message).toEqual('JWT has expired: exp: 1485321072 < now: 1485321133')
      ).then((p) => expect(p).toBeFalsy())
    )
  })

  it('accepts a valid audience', () => {
    return createJWT({aud}, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt, {audience: aud}).then(({payload}) => expect(payload).toMatchSnapshot())
    )
  })

  it('accepts a valid MNID audience', () => {
    return createJWT({aud}, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt, {audience: audMnid}).then(({payload}) => expect(payload).toMatchSnapshot())
    )
  })

  it('accepts a valid audience using callback_url', () => {
    return createJWT({ aud: 'http://pututu.uport.me/unique' }, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt, {callbackUrl: 'http://pututu.uport.me/unique'}).then(({payload}) =>
        expect(payload).toMatchSnapshot()
      )
    )
  })

  it('rejects invalid audience', () => {
    return createJWT({aud}, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt, {audience: did}).catch(error =>
        expect(error.message).toEqual('JWT audience does not match your DID: aud: did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqY !== yours: did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX')
      ).then((p) => expect(p).toBeFalsy())
    )
  })

  it('rejects an invalid audience using callback_url where callback is wrong', () => {
    return createJWT({ aud: 'http://pututu.uport.me/unique' }, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt, {callbackUrl: 'http://pututu.uport.me/unique/1'}).catch(error =>
        expect(error.message).toEqual('JWT audience does not match the callback url: aud: http://pututu.uport.me/unique !== url: http://pututu.uport.me/unique/1')
      )
    )
  })

  it('rejects an invalid audience using callback_url where callback is missing', () => {
    return createJWT({ aud: 'http://pututu.uport.me/unique' }, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt).catch(error =>
        expect(error.message).toEqual('JWT audience matching your callback url is required but one wasn\'t passed in')
      )
    )
  })

  it('rejects invalid audience as no address is present', () => {
    return createJWT({ aud }, {issuer: did, signer}).then(jwt =>
      verifyJWT(jwt).catch(error =>
        expect(error.message).toEqual('JWT audience is required but your app address has not been configured')
      ).then((p) => expect(p).toBeFalsy())
    )
  })
})

describe('resolveAuthenticator()', () => {
  const ecKey1 = {
    id: `${did}#keys-1`,
    type: 'Secp256k1VerificationKey2018',
    owner: did,
    publicKeyHex: '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab061'
  }

  const ecKey2 = {
    id: `${did}#keys-2`,
    type: 'Secp256k1SignatureVerificationKey2018',
    owner: did,
    publicKeyHex: '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062'
  }

  const ecKey3 = {
    id: `${did}#keys-3`,
    type: 'Secp256k1SignatureVerificationKey2018',
    owner: did,
    publicKeyHex: '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab063'
  }

  const encKey1 = {
    id: `${did}#keys-3`,
    type: 'Curve25519EncryptionPublicKey',
    owner: did,
    publicKeyBase64: 'QCFPBLm5pwmuTOu+haxv0+Vpmr6Rrz/DEEvbcjktQnQ='
  }

  const authKey1 = {
    type: 'Secp256k1SignatureAuthentication2018',
    publicKey: ecKey1.id
  }

  const authKey2 = {
    type: 'Secp256k1SignatureAuthentication2018',
    publicKey: ecKey2.id
  }

  const singleKey = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [ecKey1]
  }

  const multipleKeys = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [ecKey1, ecKey2, ecKey3, encKey1],
    authentication: [authKey1, authKey2]
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
    it('finds public key', async () => {
      registerResolver((mnid, cb) => cb(null, singleKey))
      const authenticators = await resolveAuthenticator(alg, did)
      return expect(authenticators).toEqual({authenticators: [ecKey1], issuer: did, doc: singleKey})
    })

    it('filters out irrelevant public keys', async () => {
      registerResolver((mnid, cb) => cb(null, multipleKeys))
      const authenticators = await resolveAuthenticator(alg, did)
      return expect(authenticators).toEqual({authenticators: [ecKey1, ecKey2, ecKey3], issuer: did, doc: multipleKeys})
    })

    it('only list authenticators able to authenticate a user', async () => {
      registerResolver((mnid, cb) => cb(null, multipleKeys))
      const authenticators = await resolveAuthenticator(alg, did, true)
      return expect(authenticators).toEqual({authenticators: [ecKey1, ecKey2], issuer: did, doc: multipleKeys})
    })

    it('errors if no suitable public keys exist', async () => {
      registerResolver((mnid, cb) => cb(null, unsupportedFormat))
      return expect(resolveAuthenticator(alg, did)).rejects.toEqual(new Error(`DID document for ${did} does not have public keys for ${alg}`))
    })

    it('errors if no suitable public keys exist for authentication', async () => {
      registerResolver((mnid, cb) => cb(null, singleKey))
      return expect(resolveAuthenticator(alg, did, true)).rejects.toEqual(new Error(`DID document for ${did} does not have public keys suitable for authenticationg user`))
    })

    it('errors if no public keys exist', async () => {
      registerResolver((mnid, cb) => cb(null, noPublicKey))
      return expect(resolveAuthenticator(alg, did)).rejects.toEqual(new Error(`DID document for ${did} does not have public keys for ${alg}`))
    })

    it('errors if no DID document exists', async () => {
      registerResolver((mnid, cb) => cb(null, null))
      return expect(resolveAuthenticator(alg, did)).rejects.toEqual(new Error(`Unable to resolve DID document for ${did}`))
    })

    it('errors if no supported signature types exist', async () => {
      registerResolver((mnid, cb) => cb(null, singleKey))
      return expect(resolveAuthenticator('ESBAD', did)).rejects.toEqual(new Error(`No supported signature types for algorithm ESBAD`))
    })
  })

  describe('MNID', () => {
    it('converts MNID to DID and finds public key', async () => {
      registerResolver((mnid, cb) => cb(null, singleKey))
      const authenticators = await resolveAuthenticator(alg, mnid)
      return expect(authenticators).toEqual({authenticators: [ecKey1], issuer: did, doc: singleKey})
    })
  })
})
