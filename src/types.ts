import type CID from 'cids'
import type { RPCClient, RPCConnection, RPCRequest, RPCResponse } from 'rpc-utils'
import { JWE } from './JWE'

export type CreateJWSParams = {
  payload: Record<string, any>
  protected?: Record<string, any>
  revocable?: boolean
  did: string
}

export type DecryptJWEParams = {
  jwe: JWE
  did?: string
}

export type AuthParams = {
  paths: Array<string>
  nonce: string
  aud?: string
}

export type JWSSignature = {
  protected: string
  signature: string
}

export type DagJWS = {
  payload: string
  signatures: Array<JWSSignature>
  link?: CID
}

export type GeneralJWS = {
  payload: string
  signatures: Array<JWSSignature>
}

export type DIDProviderMethods = {
  did_authenticate: { params: AuthParams; result: GeneralJWS }
  did_createJWS: { params: CreateJWSParams; result: { jws: GeneralJWS } }
  did_decryptJWE: { params: DecryptJWEParams; result: { cleartext: string } }
}
export type DIDMethodName = keyof DIDProviderMethods

export type DIDRequest<K extends DIDMethodName = DIDMethodName> = RPCRequest<DIDProviderMethods, K>
export type DIDResponse<K extends DIDMethodName = DIDMethodName> = RPCResponse<
  DIDProviderMethods,
  K
>

export type DIDProvider = RPCConnection<DIDProviderMethods>
export type DIDProviderClient = RPCClient<DIDProviderMethods>
export type DIDProviderOrClient = DIDProvider | DIDProviderClient
