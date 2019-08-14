import {
  createJWT,
  verifyJWT,
  decodeJWT,
  resolveAuthenticator,
  NBF_SKEW
} from '../JWT'
import { TokenVerifier } from 'jsontokens'
import registerResolver from 'uport-did-resolver'
import SimpleSigner from '../SimpleSigner'
import NaclSigner from '../NaclSigner'
import {
  registerNaclDID,
  loadIdentity,
  verifyJWT as naclVerifyJWT
} from 'nacl-did'
import MockDate from 'mockdate'

registerResolver()
registerNaclDID()

const NOW = 1485321133
MockDate.set(NOW * 1000 + 123)

const audMnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqY'
const aud = `did:uport:${audMnid}`
const mnid = '2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX'
const did = `did:uport:${mnid}`
const alg = 'ES256K'

const privateKey =
  '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const publicKey =
  '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
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

const ethDidDoc = {
  '@context': 'https://w3id.org/did/v1',
  id: did,
  publicKey: [
    {
      id: `${did}#keys-1`,
      type: 'Secp256k1VerificationKey2018',
      owner: did,
      ethereumAddress: '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
    }
  ]
}

describe('createJWT()', () => {
  describe('ES256K', () => {
    it('creates a valid JWT', () => {
      return createJWT(
        { requested: ['name', 'phone'] },
        { issuer: did, signer }
      ).then(jwt => {
        return expect(verifier.verify(jwt)).toBeTruthy()
      })
    })

    it('creates a valid JWT using a MNID', () => {
      return createJWT(
        { requested: ['name', 'phone'] },
        { issuer: mnid, signer }
      ).then(jwt => {
        return expect(verifier.verify(jwt)).toBeTruthy()
      })
    })

    it('creates a JWT with correct format', () => {
      return createJWT(
        { requested: ['name', 'phone'] },
        { issuer: did, signer }
      ).then(jwt => {
        return expect(decodeJWT(jwt)).toMatchSnapshot()
      })
    })

    it('creates a JWT with correct legacy format', () => {
      return createJWT(
        { requested: ['name', 'phone'] },
        { issuer: mnid, signer }
      ).then(jwt => {
        return expect(decodeJWT(jwt)).toMatchSnapshot()
      })
    })

    it('creates a JWT with expiry in 10000 seconds', () => {
      return createJWT(
        { requested: ['name', 'phone'], nbf: Math.floor(new Date().getTime() / 1000) },
        { issuer: did, signer, expiresIn: 10000 }
      ).then(jwt => {
        const { payload } = decodeJWT(jwt)
        return expect(payload.exp).toEqual(payload.nbf + 10000)
      })
    })

    it('ignores expiresIn if nbf is not set', async () => {
      const { payload } = decodeJWT(await createJWT(
        { requested: ['name', 'phone'] },
        { issuer: did, signer, expiresIn: 10000 }
      ))
      return expect(payload.exp).toBeUndefined()
    })

    it('sets iat to the current time by default', async () => {
      const timestamp = Math.floor(Date.now() / 1000)
      const { payload } = decodeJWT(await createJWT(
        { requested: ['name', 'phone'] },
        { issuer: did, signer }
      ))
      return expect(payload.iat).toEqual(timestamp)
    })

    it('sets iat to the value passed in payload', async () => {
      const timestamp = 2000000
      const { payload } = decodeJWT(await createJWT(
        { requested: ['name', 'phone'], iat: timestamp },
        { issuer: did, signer }
      ))
      return expect(payload.iat).toEqual(timestamp)
    })

    it('does not set iat if value in payload is undefined', async () => {
      const { payload } = decodeJWT(await createJWT(
        { requested: ['name', 'phone'], iat: undefined },
        { issuer: did, signer }
      ))
      return expect(payload.iat).toBeUndefined()
    })

    it('throws an error if unsupported algorithm is passed in', () => {
      return createJWT(
        { requested: ['name', 'phone'] },
        { issuer: did, signer, alg: 'BADALGO' }
      ).catch(error => {
        return expect(error.message).toEqual('Unsupported algorithm BADALGO')
      })
    })
  })

  describe('Ed25519', () => {
    const ed25519PrivateKey =
      'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
    const did = 'did:nacl:BvrB8iJAz_1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU'
    const signer = NaclSigner(ed25519PrivateKey)
    const alg = 'Ed25519'

    it('creates a valid JWT', () => {
      return createJWT(
        { requested: ['name', 'phone'] },
        { alg, issuer: did, signer }
      ).then(jwt => {
        return expect(naclVerifyJWT(jwt)).toBeTruthy()
      })
    })

    it('creates a JWT with correct format', () => {
      return createJWT(
        { requested: ['name', 'phone'] },
        { alg, issuer: did, signer }
      ).then(jwt => {
        return expect(decodeJWT(jwt)).toMatchSnapshot()
      })
    })

    it('creates a JWT with expiry in 10000 seconds', () => {
      return createJWT(
        { requested: ['name', 'phone'], nbf: Math.floor(new Date().getTime() / 1000) },
        { alg, issuer: did, signer, expiresIn: 10000 }
      ).then(jwt => {
        const { payload } = decodeJWT(jwt)
        return expect(payload.exp).toEqual(payload.nbf + 10000)
      })
    })
  })
})

describe('verifyJWT()', () => {
  registerResolver((id, cb) => {
    if (mnid === id) cb(null, didDoc)
    if (audMnid === id) cb(null, ethDidDoc)
  })

  describe('pregenerated JWT', () => {
    const incomingJwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6dXBvcnQ6Mm5RdGlRRzZDZ20xR1lUQmFhS0Fncjc2dVk3aVNleFVrcVg' +
      'iLCJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.1hyeUGRBb-cgvjD5KKbpVJBF4TfDjYxrI8SWRJ-GyrJrN' +
      'LAxt4MutKMFQyF1k_YkxbVozGJ_4XmgZqNaW4OvCw'

    it('verifies the JWT and return correct payload', () => {
      return verifyJWT(incomingJwt).then(({ payload }) => {
        return expect(payload).toMatchSnapshot()
      })
    })

    it('verifies the JWT and return correct profile', () => {
      return verifyJWT(incomingJwt).then(({ doc }) => {
        return expect(doc).toEqual(didDoc)
      })
    })

    it('verifies the JWT and return correct did for the iss', () => {
      return verifyJWT(incomingJwt).then(({ issuer }) => {
        return expect(issuer).toEqual(did)
      })
    })

    it('verifies the JWT and return correct signer', () => {
      return verifyJWT(incomingJwt).then(({ signer }) =>
        expect(signer).toEqual(didDoc.publicKey[0])
      )
    })

    it('verifies the JWT requiring authentication and return correct signer', () => {
      return verifyJWT(incomingJwt, { auth: true }).then(({ signer }) =>
        expect(signer).toEqual(didDoc.publicKey[0])
      )
    })
  })

  describe('nacl-did jwt', () => {
    const privateKey =
      'nlXR4aofRVuLqtn9+XVQNlX4s1nVQvp+TOhBBtYls1IG+sHyIkDP/WN+rWZHGIQp+v2pyct+rkM4asF/YRFQdQ=='
    const did = 'did:nacl:BvrB8iJAz_1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU'
    const naclId = loadIdentity({ privateKey, did })
    const payload = { sub: aud, claim: { superChap: true } }
    const incomingJwt = naclId.createJWT(payload)
    const publicKey = {
      id: `${did}#key1`,
      type: 'ED25519SignatureVerification',
      owner: did,
      publicKeyBase64: 'BvrB8iJAz/1jfq1mRxiEKfr9qcnLfq5DOGrBf2ERUHU='
    }
    it('verifies the JWT and return correct payload', () => {
      return verifyJWT(incomingJwt).then(({ payload }) => {
        return expect(payload).toEqual(payload)
      })
    })

    it('verifies the JWT and return correct profile', () => {
      return verifyJWT(incomingJwt).then(({ doc }) => {
        return expect(doc).toMatchSnapshot()
      })
    })

    it('verifies the JWT and return correct did for the iss', () => {
      return verifyJWT(incomingJwt).then(({ issuer }) => {
        return expect(issuer).toEqual(naclId.did)
      })
    })

    it('verifies the JWT and return correct signer', () => {
      return verifyJWT(incomingJwt).then(({ signer }) =>
        expect(signer).toEqual(publicKey)
      )
    })

    it('verifies the JWT requiring authentication and return correct signer', () => {
      return verifyJWT(incomingJwt, { auth: true }).then(({ signer }) =>
        expect(signer).toEqual(publicKey)
      )
    })
  })

  describe('badJwt', () => {
    const badJwt =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6dXBvcnQ6Mm5RdGlRRzZDZ20xR1lUQmFhS0Fncjc2dVk3aVNleFVrcVg' +
      'iLCJpYXQiOjE0ODUzMjExMzMsInJlcXVlc3RlZCI6WyJuYW1lIiwicGhvbmUiXX0.1hyeUGRBb-cgvjD5KKbpVJBF4TfDjYxrI8SWRJ-GyrJrN' +
      'LAxt4MutKMFQyF1k_YkxbVozGJ_4XmgZqNaW4OvCX'
    it('rejects a JWT with bad signature', () => {
      return verifyJWT(badJwt)
        .catch(error =>
          expect(error.message).toEqual('Signature invalid for JWT')
        )
        .then(p => expect(p).toBeFalsy())
    })
  })

  describe('validFrom timestamp', () => {
    it('passes when nbf is in the past', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsIm5iZiI6MTQ4NTI2MTEzMywiaXNzIjoiZGlkOnVwb3J0OjJuUXRpUUc2Q2dtMUdZVEJhYUtBZ3I3NnVZN2lTZXhVa3FYIn0.btzVz7fZsoSEDa7JyWo3cYWL63pkWTKTz8OUzepIesfSFeBozUjX2oq1xOJ2OyzuinnLGwtSqY303VoyALrafA'
      expect(verifyJWT(jwt)).resolves.not.toThrow()
    })
    it('passes when nbf is in the past and iat is in the future', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzODExMzMsIm5iZiI6MTQ4NTI2MTEzMywiaXNzIjoiZGlkOnVwb3J0OjJuUXRpUUc2Q2dtMUdZVEJhYUtBZ3I3NnVZN2lTZXhVa3FYIn0.ELsPnDC_YTTkT5hxw09UCLSjWVje9mDs1n_mpvlo2Wk5VJONSy-FDAzm5TunzzCeLixU04m6dD4w6Uk3-OVkww'
      expect(verifyJWT(jwt)).resolves.not.toThrow()
    })
    it('fails when nbf is in the future', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzMjExMzMsIm5iZiI6MTQ4NTM4MTEzMywiaXNzIjoiZGlkOnVwb3J0OjJuUXRpUUc2Q2dtMUdZVEJhYUtBZ3I3NnVZN2lTZXhVa3FYIn0.rcFuhVHtie3Y09pWxBSf1dnjaVh6FFQLHh-83N-uLty3M5ADJ-jVFFkyt_Eupl8Kr735-oPGn_D1Nj9rl4s_Kw'
      expect(verifyJWT(jwt)).rejects.toThrow()
    })
    it('fails when nbf is in the future and iat is in the past', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUyNjExMzMsIm5iZiI6MTQ4NTM4MTEzMywiaXNzIjoiZGlkOnVwb3J0OjJuUXRpUUc2Q2dtMUdZVEJhYUtBZ3I3NnVZN2lTZXhVa3FYIn0.jiVI11IcKNOvnDrJBzojKtNAGaZbEcafcqW-wfP78g6-6RucjYPBi5qvKje35IOvITWvvpXpK48IW-17Srh02w'
      expect(verifyJWT(jwt)).rejects.toThrow()
    })
    it('passes when nbf is missing and iat is in the past', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUyNjExMzMsImlzcyI6ImRpZDp1cG9ydDoyblF0aVFHNkNnbTFHWVRCYWFLQWdyNzZ1WTdpU2V4VWtxWCJ9.1VwGHDm7f9V-1Fa545uAwF9NfU3RI8yqRFW6XAHOg0FBeM7krC_rEf0PwqbKFO8MiIBELBwUhW_fT4oZsuggUA'
      expect(verifyJWT(jwt)).resolves.not.toThrow()
    })
    it('fails when nbf is missing and iat is in the future', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE0ODUzODExMzMsImlzcyI6ImRpZDp1cG9ydDoyblF0aVFHNkNnbTFHWVRCYWFLQWdyNzZ1WTdpU2V4VWtxWCJ9.jU0R8qP3aUX_3DiFt9tIONiq_P5OooFc-ypUwpqK4plGyw6WiI0FTGfZvq7pOarKrjmSojE9Sm_3ETfMpdQckg'
      expect(verifyJWT(jwt)).rejects.toThrow()
    })
    it('passes when nbf and iat are both missing', async () => {
      // tslint:disable-next-line: max-line-length
      const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6dXBvcnQ6Mm5RdGlRRzZDZ20xR1lUQmFhS0Fncjc2dVk3aVNleFVrcVgifQ.5kGKU9ljebhTqvfVDu9MH7vGAqRH0GDTbZNGH45YmhUySgBTyI7u-MkkRit72eFvQAqBfzw6wNUbGf9FPC5AtQ'
      expect(verifyJWT(jwt)).resolves.not.toThrow()
    })
  })

  it('handles ES256K-R algorithm', () => {
    return createJWT(
      { hello: 'world' },
      { issuer: did, signer, alg: 'ES256K-R' }
    ).then(jwt =>
      verifyJWT(jwt).then(
        ({ payload }) => expect(payload).toMatchSnapshot(),
        error => expect(error).toBeNull()
      )
    )
  })

  it('handles ES256K-R algorithm with ethereum address', () => {
    return createJWT(
      { hello: 'world' },
      { issuer: aud, signer, alg: 'ES256K-R' }
    ).then(jwt =>
      verifyJWT(jwt).then(
        ({ payload }) => expect(payload).toMatchSnapshot(),
        error => expect(error).toBeNull()
      )
    )
  })

  it('accepts a valid exp', () => {
    return createJWT(
      { exp: NOW },
      { issuer: did, signer }
    ).then(jwt =>
      verifyJWT(jwt).then(({ payload }) => expect(payload).toBeDefined())
    )
  })

  it('rejects an expired JWT', () => {
    return createJWT({ exp: NOW - NBF_SKEW - 1 }, { issuer: did, signer }).then(
      jwt =>
        verifyJWT(jwt)
          .catch(error =>
            expect(error.message).toEqual(
              'JWT has expired: exp: 1485320832 < now: 1485321133'
            )
          )
          .then(p => expect(p).toBeFalsy())
    )
  })

  it('accepts a valid audience', () => {
    return createJWT({ aud }, { issuer: did, signer }).then(jwt =>
      verifyJWT(jwt, { audience: aud }).then(({ payload }) =>
        expect(payload).toMatchSnapshot()
      )
    )
  })

  it('accepts a valid MNID audience', () => {
    return createJWT({ aud }, { issuer: did, signer }).then(jwt =>
      verifyJWT(jwt, { audience: audMnid }).then(({ payload }) =>
        expect(payload).toMatchSnapshot()
      )
    )
  })

  it('accepts a valid audience using callback_url', () => {
    return createJWT(
      { aud: 'http://pututu.uport.me/unique' },
      { issuer: did, signer }
    ).then(jwt =>
      verifyJWT(jwt, { callbackUrl: 'http://pututu.uport.me/unique' }).then(
        ({ payload }) => expect(payload).toMatchSnapshot()
      )
    )
  })

  it('rejects invalid audience', () => {
    return createJWT({ aud }, { issuer: did, signer }).then(jwt =>
      verifyJWT(jwt, { audience: did })
        .catch(error =>
          expect(error.message).toEqual(
            'JWT audience does not match your DID: aud: did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqY !== yours: did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX'
          )
        )
        .then(p => expect(p).toBeFalsy())
    )
  })

  it('rejects an invalid audience using callback_url where callback is wrong', () => {
    return createJWT(
      { aud: 'http://pututu.uport.me/unique' },
      { issuer: did, signer }
    ).then(jwt =>
      verifyJWT(jwt, { callbackUrl: 'http://pututu.uport.me/unique/1' }).catch(
        error =>
          expect(error.message).toEqual(
            'JWT audience does not match the callback url: aud: http://pututu.uport.me/unique !== url: http://pututu.uport.me/unique/1'
          )
      )
    )
  })

  it('rejects an invalid audience using callback_url where callback is missing', () => {
    return createJWT(
      { aud: 'http://pututu.uport.me/unique' },
      { issuer: did, signer }
    ).then(jwt =>
      verifyJWT(jwt).catch(error =>
        expect(error.message).toEqual(
          "JWT audience matching your callback url is required but one wasn't passed in"
        )
      )
    )
  })

  it('rejects invalid audience as no address is present', () => {
    return createJWT({ aud }, { issuer: did, signer }).then(jwt =>
      verifyJWT(jwt)
        .catch(error =>
          expect(error.message).toEqual(
            'JWT audience is required but your app address has not been configured'
          )
        )
        .then(p => expect(p).toBeFalsy())
    )
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
        registerResolver((mnid, cb) => cb(null, singleKey))
        const authenticators = await resolveAuthenticator(alg, did)
        return expect(authenticators).toEqual({
          authenticators: [ecKey1],
          issuer: did,
          doc: singleKey
        })
      })

      it('filters out irrelevant public keys', async () => {
        registerResolver((mnid, cb) => cb(null, multipleKeys))
        const authenticators = await resolveAuthenticator(alg, did)
        return expect(authenticators).toEqual({
          authenticators: [ecKey1, ecKey2, ecKey3],
          issuer: did,
          doc: multipleKeys
        })
      })

      it('only list authenticators able to authenticate a user', async () => {
        registerResolver((mnid, cb) => cb(null, multipleKeys))
        const authenticators = await resolveAuthenticator(alg, did, true)
        return expect(authenticators).toEqual({
          authenticators: [ecKey1, ecKey2],
          issuer: did,
          doc: multipleKeys
        })
      })

      it('errors if no suitable public keys exist', async () => {
        registerResolver((mnid, cb) => cb(null, unsupportedFormat))
        return expect(resolveAuthenticator(alg, did)).rejects.toEqual(
          new Error(
            `DID document for ${did} does not have public keys for ${alg}`
          )
        )
      })
    })

    describe('Ed25519', () => {
      const alg = 'Ed25519'
      it('filters out irrelevant public keys', async () => {
        registerResolver((mnid, cb) => cb(null, multipleKeys))
        const authenticators = await resolveAuthenticator(alg, did)
        return expect(authenticators).toEqual({
          authenticators: [edKey, edKey2],
          issuer: did,
          doc: multipleKeys
        })
      })

      it('only list authenticators able to authenticate a user', async () => {
        registerResolver((mnid, cb) => cb(null, multipleKeys))
        const authenticators = await resolveAuthenticator(alg, did, true)
        return expect(authenticators).toEqual({
          authenticators: [edKey],
          issuer: did,
          doc: multipleKeys
        })
      })

      it('errors if no suitable public keys exist', async () => {
        registerResolver((mnid, cb) => cb(null, unsupportedFormat))
        return expect(resolveAuthenticator(alg, did)).rejects.toEqual(
          new Error(
            `DID document for ${did} does not have public keys for ${alg}`
          )
        )
      })
    })

    it('errors if no suitable public keys exist for authentication', async () => {
      registerResolver((mnid, cb) => cb(null, singleKey))
      return expect(resolveAuthenticator(alg, did, true)).rejects.toEqual(
        new Error(
          `DID document for ${did} does not have public keys suitable for authenticationg user`
        )
      )
    })

    it('errors if no public keys exist', async () => {
      registerResolver((mnid, cb) => cb(null, noPublicKey))
      return expect(resolveAuthenticator(alg, did)).rejects.toEqual(
        new Error(
          `DID document for ${did} does not have public keys for ${alg}`
        )
      )
    })

    it('errors if no DID document exists', async () => {
      registerResolver((mnid, cb) => cb(null, null))
      return expect(resolveAuthenticator(alg, did)).rejects.toEqual(
        new Error(`Unable to resolve DID document for ${did}`)
      )
    })

    it('errors if no supported signature types exist', async () => {
      registerResolver((mnid, cb) => cb(null, singleKey))
      return expect(resolveAuthenticator('ESBAD', did)).rejects.toEqual(
        new Error(`No supported signature types for algorithm ESBAD`)
      )
    })
  })

  describe('MNID', () => {
    it('converts MNID to DID and finds public key', async () => {
      registerResolver((mnid, cb) => cb(null, singleKey))
      const authenticators = await resolveAuthenticator(alg, mnid)
      return expect(authenticators).toEqual({
        authenticators: [ecKey1],
        issuer: did,
        doc: singleKey
      })
    })
  })
})
