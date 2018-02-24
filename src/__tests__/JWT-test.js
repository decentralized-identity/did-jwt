import { createJWT, verifyJWT, decodeJWT, resolveAuthenticator, IAT_SKEW } from '../JWT'
import { TokenVerifier } from 'jsontokens'
import registerResolver from 'uport-did-resolver'
import SimpleSigner from '../SimpleSigner'
import MockDate from 'mockdate'
const NOW = 1485321133
MockDate.set(NOW * 1000)

const aud = `did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqY`
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
    type: 'EcdsaPublicKeySecp256k1',
    owner: did,
    publicKeyHex: publicKey
  }]
}
describe('createJWT()', () => {
  it('creates a valid JWT', () => {
    return createJWT({address: did, signer}, {requested: ['name', 'phone']}).then((jwt) => {
      return expect(verifier.verify(jwt)).toBeTruthy()
    })
  })

  it('creates a JWT with correct format', () => {
    return createJWT({address: did, signer}, {requested: ['name', 'phone']}).then((jwt) => {
      return expect(decodeJWT(jwt)).toMatchSnapshot()
    })
  })

  it('throws an error if no signer is configured', () => {
    return createJWT({address: did}, { requested: ['name', 'phone'] }).catch(error => {
      return expect(error.message).toEqual('No Signer functionality has been configured')
    })
  })

  it('throws an error if no address is configured', () => {
    return createJWT({signer}, { requested: ['name', 'phone'] }).catch(error => {
      return expect(error.message).toEqual('No application identity address has been configured')
    })
  })
})

describe('verifyJWT()', () => {
  registerResolver((id, cb) => { if (mnid === id) cb(null, didDoc) })
  const incomingJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6dXBvcnQ6Mm5RdGlRRzZDZ20xR1lUQmFhS0Fncjc2dVk3aVNleFVrcVgiLCJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.1hyeUGRBb-cgvjD5KKbpVJBF4TfDjYxrI8SWRJ-GyrJrNLAxt4MutKMFQyF1k_YkxbVozGJ_4XmgZqNaW4OvCw'

  it('verifies the JWT and return correct payload', () => {
    return verifyJWT({address: did}, incomingJwt).then(({payload}) => {
      return expect(payload).toMatchSnapshot()
    })
  })

  it('verifies the JWT and return correct profile', () => {
    return verifyJWT({address: did}, incomingJwt).then(({doc}) => {
      return expect(doc).toEqual(didDoc)
    })
  })

  it('verifies the JWT and return correct did', () => {
    return verifyJWT({address: did}, incomingJwt).then(response => {
      return expect(response.did).toEqual(did)
    })
  })

  it('verifies the JWT and return correct signer', () => {
    return verifyJWT({address: did}, incomingJwt).then(({signer}) => expect(signer).toEqual(didDoc.publicKey[0]))
  })

  const badJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6dXBvcnQ6Mm5RdGlRRzZDZ20xR1lUQmFhS0Fncjc2dVk3aVNleFVrcVgiLCJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.1hyeUGRBb-cgvjD5KKbpVJBF4TfDjYxrI8SWRJ-GyrJrNLAxt4MutKMFQyF1k_YkxbVozGJ_4XmgZqNaW4OvCX'
  it('rejects a JWT with bad signature', () => {
    return verifyJWT({address: did}, badJwt).catch(error =>
      expect(error.message).toEqual('Signature invalid for JWT')
    ).then((p) => expect(p).toBeFalsy())
  })

  it('accepts a valid iat', () => {
    return createJWT({address: did, signer}, {iat: NOW + IAT_SKEW}).then(jwt =>
      verifyJWT({address: did}, jwt).then(({payload}) => expect(payload).toMatchSnapshot(), error => expect(error).toBeNull())
    )
  })

  it('rejects an iat in the future', () => {
    return createJWT({address: did, signer}, {iat: NOW + IAT_SKEW + 1}).then(jwt =>
      verifyJWT({address: did}, jwt).catch(error =>
        expect(error.message).toEqual('JWT not valid yet (issued in the future): iat: 1485321194 > now: 1485321133')
      ).then((p) => expect(p).toBeFalsy())
    )
  })

  it('accepts a valid exp', () => {
    return createJWT({address: did, signer}, {exp: NOW + 1}).then(jwt =>
      verifyJWT({address: did}, jwt).then(({payload}) =>
        expect(payload).toMatchSnapshot()
      )
    )
  })

  it('rejects an expired JWT', () => {
    return createJWT({address: did, signer}, {exp: NOW - 1}).then(jwt =>
      verifyJWT({address: did}, jwt).catch(error =>
        expect(error.message).toEqual('JWT has expired: exp: 1485321132 < now: 1485321133')
      ).then((p) => expect(p).toBeFalsy())
    )
  })

  it('accepts a valid audience', () => {
    return createJWT({address: did, signer}, {aud}).then(jwt =>
      verifyJWT({address: aud}, jwt).then(({payload}) => expect(payload).toMatchSnapshot())
    )
  })

  it('accepts a valid audience using callback_url', () => {
    return createJWT({ address: did, signer }, { aud: 'http://pututu.uport.me/unique' }).then(jwt =>
      verifyJWT({}, jwt, 'http://pututu.uport.me/unique').then(({payload}) =>
        expect(payload).toMatchSnapshot()
      )
    )
  })

  it('rejects invalid audience', () => {
    return createJWT({address: did, signer}, {aud}).then(jwt =>
      verifyJWT({address: did}, jwt).catch(error =>
        expect(error.message).toEqual('JWT audience does not match your DID: aud: did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqY !== yours: did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX')
      ).then((p) => expect(p).toBeFalsy())
    )
  })

  it('rejects an invalid audience using callback_url where callback is wrong', () => {
    return createJWT({ address: did, signer }, { aud: 'http://pututu.uport.me/unique' }).then(jwt =>
      verifyJWT({}, jwt, 'http://pututu.uport.me/unique/1').catch(error =>
        expect(error.message).toEqual('JWT audience does not match the callback url: aud: http://pututu.uport.me/unique !== url: http://pututu.uport.me/unique/1')
      )
    )
  })

  it('rejects an invalid audience using callback_url where callback is missing', () => {
    return createJWT({ address: did, signer }, { aud: 'http://pututu.uport.me/unique' }).then(jwt =>
      verifyJWT({}, jwt).catch(error =>
        expect(error.message).toEqual('JWT audience matching your callback url is required but one wasn\'t passed in')
      )
    )
  })

  it('rejects invalid audience as no address is present', () => {
    return createJWT({ address: did, signer }, { aud }).then(jwt =>
      verifyJWT({}, jwt).catch(error =>
        expect(error.message).toEqual('JWT audience is required but your app address has not been configured')
      ).then((p) => expect(p).toBeFalsy())
    )
  })
})

describe('resolveAuthenticator()', () => {
  const ecKey1 = {
    id: `${did}#keys-1`,
    type: 'EcdsaPublicKeySecp256k1',
    owner: did,
    publicKeyHex: '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062'
  }
  const ecKey2 = {
    id: `${did}#keys-2`,
    type: 'Secp256k1SignatureVerificationKey2018',
    owner: did,
    publicKeyHex: '04613bb3a4874d27032618f020614c21cbe4c4e4781687525f6674089f9bd3d6c7f6eb13569053d31715a3ba32e0b791b97922af6387f087d6b5548c06944ab062'
  }
  const encKey1 = {
    id: `${did}#keys-3`,
    type: 'Curve25519EncryptionPublicKey',
    owner: did,
    publicKeyBase64: 'QCFPBLm5pwmuTOu+haxv0+Vpmr6Rrz/DEEvbcjktQnQ='
  }

  const singleKey = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [ecKey1]
  }

  const multipleKeys = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: [ecKey1, ecKey2, encKey1]
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
      return expect(authenticators).toEqual({authenticators: [ecKey1], did, doc: singleKey})
    })

    it('filters out irrelevant public keys', async () => {
      registerResolver((mnid, cb) => cb(null, multipleKeys))
      const authenticators = await resolveAuthenticator(alg, did)
      return expect(authenticators).toEqual({authenticators: [ecKey1, ecKey2], did, doc: multipleKeys})
    })

    it('errors if no suitable public keys exist', async () => {
      registerResolver((mnid, cb) => cb(null, unsupportedFormat))
      return expect(resolveAuthenticator(alg, did)).rejects.toEqual(new Error(`DID document for ${did} does not have public keys for ${alg}`))
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
      return expect(authenticators).toEqual({authenticators: [ecKey1], did, doc: singleKey})
    })
  })

})
