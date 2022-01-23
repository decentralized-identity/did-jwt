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
