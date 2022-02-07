import { greet } from '../common_Signer_test'
import { CreatedidDocLegacy } from '../common_Signer_test'
import { CreatedidDoc } from '../common_Signer_test'
import { CreateauddidDoc } from '../common_Signer_test'
import { did } from '../common_Signer_test'
import { aud } from '../common_Signer_test'
import { verifyTokenFormAndValidity } from '../common_Signer_test'
import { publicToJWK } from '../common_Signer_test'
import { privateToJWK } from '../common_Signer_test'
import * as jwkToPem from 'jwk-to-pem'
import * as jwt from 'jsonwebtoken'

// secp256r1 keys
import { ec as EC } from 'elliptic'
const secp256r1 = new EC('p256')
// end of secp256r1 keys

const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
const keyTypeVerLegacy = 'Secp256k1VerificationKey2018'
const keyTypeAuthLegacy = 'Secp256k1SignatureAuthentication2018'
const keyTypeVer = 'EcdsaSecp256k1VerificationKey2019'

describe('test verifyToken and public and private JWK', () => {
   const publicPointHex_x_2 = 'e2bc6e7c4223f5e2f2fd69736216e71348d122ae644ca8a0cca1d2598938b048';
   const publicPointHex_y_2 = '3da04cfd906ea27a0b54e4094cf54a8dcc7cfce9a3bab2e3ea9e00eae2d27782'
   const privatePointHex_2 = '9532c1aa21aad885b3fd1792d9e42dace4298f3aef6cfd60198ac9c563265c04'
  
  // test a private key to JWT
   expect(privateToJWK(privatePointHex_2,'EC','P-256')).toEqual({kty: 'EC',crv: 'P-256',d: 'lTLBqiGq2IWz_ReS2eQtrOQpjzrvbP1gGYrJxWMmXAQ'});

   it('test a private key to JWT to PEM by using a SNAPSHOT', async () => {
      expect(jwkToPem.default(privateToJWK(privatePointHex_2,'EC','P-256'),{private: true})).toMatchSnapshot();
   })

   // test a public key to JWT
   expect(publicToJWK(publicPointHex_x_2,publicPointHex_y_2,'EC','P-256')).toEqual({kty: 'EC',crv: 'P-256',x: '4rxufEIj9eLy_WlzYhbnE0jRIq5kTKigzKHSWYk4sEg',y: 'PaBM_ZBuonoLVOQJTPVKjcx8_OmjurLj6p4A6uLSd4I'})

   // test a public key to JWT to PEM by using a SNAPSHOT 
    it('test a public key to JWT to PEM by using a SNAPSHOT', async () => {
      expect(jwkToPem.default(publicToJWK(publicPointHex_x_2,publicPointHex_y_2,'EC','P-256'))).toMatchSnapshot();   
    })     
 })

 describe('test verifyTokenFormAndValidity', () => {
     var key = secp256r1.genKeyPair();

     var privatePoint = key.getPrivate();
     const privatePointHex = privatePoint.toString('hex')
     console.log('privatePointHex: '+privatePointHex);
     const pemPrivate = jwkToPem.default(privateToJWK(privatePointHex,'EC','P-256'),{private: true})
     var token = jwt.sign({foo:'bar'},pemPrivate,{algorithm:'ES256'})

     var pubPoint = key.getPublic();
     var x = pubPoint.getX();
     var y = pubPoint.getY();
     const publicPointHex_x = x.toString('hex')
     const publicPointHex_y = y.toString('hex')  
     console.log('publicPointHex_x: '+publicPointHex_x+'   '+'publicPointHex_y: '+publicPointHex_y);
     const pemPublic = jwkToPem.default(publicToJWK(publicPointHex_x,publicPointHex_y,'EC','P-256'));
   
     const isvalid  = verifyTokenFormAndValidity(token,pemPublic)
     
     expect(verifyTokenFormAndValidity(token,pemPublic)).toBe(true); 
 })

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
