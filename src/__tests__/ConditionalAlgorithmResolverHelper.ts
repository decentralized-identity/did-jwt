import { createDIDDocument, antelopeChainRegistry, checkDID } from '@tonomy/antelope-did'
import { parse } from 'did-resolver'
import { Signer } from '../JWT'
import { PrivateKey, KeyType } from '@greymass/eosio'
import { ES256KSigner } from '../signers/ES256KSigner'

type AntelopePermission = {
  threshold: number
  keys: {
    key: string
    weight: number
  }[]
  accounts: {
    permission: {
      permission: string
      actor: string
    }
    weight: number
  }[]
}

export function createResolver(required_auth: AntelopePermission | AntelopePermission[]) {
  return {
    resolve: async (did: string) => {
      const parsed = parse(did)
      if (!parsed) throw new Error('could not parse did')
      const methodId = checkDID(parsed, antelopeChainRegistry)
      if (!methodId) throw new Error('invalid did')

      let auth: AntelopePermission[]
      if (!Array.isArray(required_auth)) {
        auth = [required_auth]
      } else {
        auth = required_auth
      }
      const mockAccountResponse = {
        permissions: auth.map((permission, index) => {
          return {
            perm_name: 'permission' + index,
            parent: 'owner',
            required_auth: permission,
          }
        }),
      }
      const didDoc = createDIDDocument(methodId, parsed.did, mockAccountResponse)

      return {
        didResolutionMetadata: {},
        didDocument: didDoc,
        didDocumentMetadata: {},
      }
    },
  }
}

export function createSigner(privKey: string): Signer {
  const privateKey = PrivateKey.from(privKey)
  if (privateKey.type !== KeyType.K1) {
    throw new Error('Unsupported key type')
  }
  return ES256KSigner(privateKey.data.array, true)
}
