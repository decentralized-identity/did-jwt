import { VerificationMethod } from 'did-resolver'
//import { TokenVerifier } from 'jsontokens'  /// only supports secp256k1
import MockDate from 'mockdate'
import {
  createJWS,
  createJWT,
  decodeJWT,
  NBF_SKEW,
  resolveAuthenticator,
  SELF_ISSUED_V2,
  SELF_ISSUED_V0_1,
  verifyJWS,
  verifyJWT,
} from '../../JWT'
import { EdDSASigner } from '../../signers/EdDSASigner'
import { ES256Signer } from '../../signers/ES256Signer'
import { bytesToBase64url, decodeBase64url } from '../../util'
import { aud, address, did, CreatedidDocLegacy, CreatedidDoc, CreateauddidDoc } from './common_Signer_test/common_Signer_test'
import { publicToJWK } from './common_Signer_test/common_Signer_test'
import { verifyTokenFormAndValidity } from './common_Signer_test/common_Signer_test'
import * as jwkToPem from 'jwk-to-pem'

const NOW = 1485321133
MockDate.set(NOW * 1000 + 123)

const alg = 'ES256'

const privateKey = '736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8'
const publicKey = '0314c58e581c7656ba153195669fe4ce53ff78dd5ede60a4039771a90c58cb41de'
const publicKey_x = '14c58e581c7656ba153195669fe4ce53ff78dd5ede60a4039771a90c58cb41de'
const publicKey_y = 'ec41869995bd661849414c523c7dff9a96f1c8dbc2e5e78172118f91c7199869'

// this needs to be refactored with your custom code
// const verifier = new TokenVerifier(alg, publicKey)

const signer = ES256Signer(privateKey)
const recoverySigner = ES256Signer(privateKey, true)

const keyTypeVerLegacy = 'JsonWebKey2020'
const keyTypeAuthLegacy = 'JsonWebKey2020'
const keyTypeVer = 'JsonWebKey2020'

const didDocLegacy = CreatedidDocLegacy(did, publicKey, keyTypeVerLegacy, keyTypeAuthLegacy)

const didDoc = CreatedidDoc(did,publicKey,keyTypeVer)

const audDidDoc = CreateauddidDoc(did,aud,publicKey,keyTypeVer)

describe('createJWT()', () => {
  describe('ES256', () => {
    it('creates a valid JWT', async () => {
      expect.assertions(1)
      const jwt = await createJWT({ requested: ['name', 'phone'] }, { issuer: did, signer },{alg: 'ES256'})
      const pemPublic = jwkToPem.default(publicToJWK(publicKey_x,publicKey_y,'EC','P-256'))
      expect(verifyTokenFormAndValidity(jwt,pemPublic)).toBe(true)
     })
  })
})

