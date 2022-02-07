import * as jwkToPem from 'jwk-to-pem'
import * as jwt from 'jsonwebtoken'
import * as u8a from 'uint8arrays'

const audAddress = '0x20c769ec9c0996ba7737a4826c2aaff00b1b2040'
export const aud = `did:ethr:${audAddress}`
export const address = '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
export const did = `did:ethr:${address}`

export function CreatedidDocLegacy(did: string, publicKey: string, keyTypeVer: string, keyTypeAuth: string) {
   return {['@context'] : 'https://w3id.org/did/v1',
        id: did,
        publicKey: [
            {
             id: `${did}#keys-1`,
             type: keyTypeVer,
             owner: did,
             publicKeyHex: publicKey
            }
        ],
        authentication: [
            {
              type: keyTypeAuth,
              publicKey: `${did}#keys-1`
            }
        ]
      }
}

export function CreatedidDoc(did: string, publicKey: string, keyTypeVer: string) {
   return { didDocument: { 
            ['@context'] : 'https://w3id.org/did/v1',
	          id: did,
	          verificationMethod : [
	           {
                id: `${did}#keys-1`,
                type: keyTypeVer,
                controller: did,
                publicKeyHex: publicKey,
	           }
	          ],
	          authentication: [`${did}#keys-1`],
             assertionMethod: [`${did}#keys-1`],
             capabilityInvocation: [`${did}#keys-1`],
             capabilityDelegation: [`${did}#some-key-that-does-not-exist`],
            }       
         }
}

export function CreateauddidDoc(did: string, aud: string, publicKey: string, keyTypeVer: string) {
  return { didDocument: { 
           ['@context'] : 'https://w3id.org/did/v1',
           id: aud,
           verificationMethod : [
            {
               id: `${aud}#keys-1`,
               type: keyTypeVer,
               controller: did,
               publicKeyHex: publicKey,
            }
           ],
           authentication: [`${aud}#keys-1`],
           assertionMethod: [`${aud}#keys-1`],
           capabilityInvocation: [`${aud}#keys-1`],
           capabilityDelegation: [`${aud}#some-key-that-does-not-exist`],
           }       
        }
}

// verify that the token is both a valid JWT and constains a signature that resolves with a public Key
export function verifyTokenFormAndValidity(token,pemPublic) {
  let result;
  try {
     jwt.verify(token,pemPublic)
    result = true;
   } catch (e) {
    console.error(e.name + ': ' + e.message)
    result = false;
  }
  return result;
}

// input public key in hex, and export pem
export function publicToJWK(publicPointHex_x,publicPointHex_y,kty_value,crv_value) {
   if(publicPointHex_x.length % 2 != 0) { '0'+publicPointHex_x  }
   if(publicPointHex_y.length % 2 != 0) { '0'+publicPointHex_y  }
   const publicPointUint8_x = u8a.fromString(publicPointHex_x,'hex')
   const publicPointBase64URL_x = u8a.toString(publicPointUint8_x,'base64url')
   const publicPointUint8_y = u8a.fromString(publicPointHex_y,'hex')
   const publicPointBase64URL_y = u8a.toString(publicPointUint8_y,'base64url')
   return {
       kty: kty_value,
       crv: crv_value,
       x: publicPointBase64URL_x,
       y: publicPointBase64URL_y
   };
}

// input private key in hex, and export pem
export function privateToJWK(privatePointHex,kty_value,crv_value) {
  if(privatePointHex.length % 2 != 0) { '0'+privatePointHex  } 
  const privatePointUint8 = u8a.fromString(privatePointHex,'hex')
  const privatePointBase64URL = u8a.toString(privatePointUint8,'base64url')
  return  {
         kty: kty_value,
         crv: crv_value,
           d: privatePointBase64URL
  };
}

