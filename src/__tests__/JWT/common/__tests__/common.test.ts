import { greet } from '../common'
import { CreatedidDocLegacy } from '../common'
import { CreatedidDoc } from '../common'
import { CreateauddidDoc } from '../common'
import { did } from '../common'
import { aud } from '../common'

const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
const keyTypeVerLegacy = 'Secp256k1VerificationKey2018'
const keyTypeAuthLegacy = 'Secp256k1SignatureAuthentication2018'
const keyTypeVer = 'EcdsaSecp256k1VerificationKey2019'

describe('SignerAlgorithm', () => {

  it("returns a did doc legacy", () => {
     expect(CreatedidDocLegacy(did, publicKey, keyTypeVerLegacy, keyTypeAuthLegacy)).toEqual({"@context": "https://w3id.org/did/v1", "authentication": [{"publicKey": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#keys-1", "type": "Secp256k1SignatureAuthentication2018"}], "id": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74", "publicKey": [{"id": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#keys-1", "owner": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74", "publicKeyHex": "03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479", "type": "Secp256k1VerificationKey2018"}]});
   })

  it("returns a did doc", () => {
     expect(CreatedidDoc(did,publicKey,keyTypeVer)).toEqual({"didDocument": {"@context": "https://w3id.org/did/v1", "assertionMethod": ["did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#keys-1"], "authentication": ["did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#keys-1"], "capabilityDelegation": ["did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#some-key-that-does-not-exist"], "capabilityInvocation": ["did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#keys-1"], "id": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74", "verificationMethod": [{"controller": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74", "id": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#keys-1", "publicKeyHex": "03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479", "type": "EcdsaSecp256k1VerificationKey2019"}]}});
  })

  it("returns a aud did doc", () => {
     expect(CreateauddidDoc(did,aud,publicKey,keyTypeVer)).toEqual({"didDocument": {"@context": "https://w3id.org/did/v1", "assertionMethod": ["did:ethr:0x20c769ec9c0996ba7737a4826c2aaff00b1b2040#keys-1"], "authentication": ["did:ethr:0x20c769ec9c0996ba7737a4826c2aaff00b1b2040#keys-1"], "capabilityDelegation": ["did:ethr:0x20c769ec9c0996ba7737a4826c2aaff00b1b2040#some-key-that-does-not-exist"], "capabilityInvocation": ["did:ethr:0x20c769ec9c0996ba7737a4826c2aaff00b1b2040#keys-1"], "id": "did:ethr:0x20c769ec9c0996ba7737a4826c2aaff00b1b2040", "verificationMethod": [{"controller": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74", "id": "did:ethr:0x20c769ec9c0996ba7737a4826c2aaff00b1b2040#keys-1", "publicKeyHex": "03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479", "type": "EcdsaSecp256k1VerificationKey2019"}]}});
  })

})

