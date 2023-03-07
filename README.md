[![npm](https://img.shields.io/npm/dt/did-jwt.svg)](https://www.npmjs.com/package/did-jwt)
[![npm](https://img.shields.io/npm/v/did-jwt.svg)](https://www.npmjs.com/package/did-jwt)
[![Twitter Follow](https://img.shields.io/twitter/follow/veramolabs.svg?style=social&label=Follow)](https://twitter.com/veramolabs)
[![codecov](https://codecov.io/gh/decentralized-identity/did-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/decentralized-identity/did-jwt)

# did-jwt

The did-JWT library allows you to sign and verify [JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519)
using `ES256K` and `EdDSA` algorithms. The non-standard `ES256K-R` is also supported for backward compatibility
reasons, as well as the `Ed25519` legacy name for `EdDSA`.

Public keys are resolved using the [Decentralized ID (DID)](https://w3c.github.io/did-core/#identifier) of the signing
identity of the token, which is passed as the `iss` attribute of the JWT payload.

## DID methods

All DID methods that can be resolved using the [`did-resolver`](https://github.com/decentralized-identity/did-resolver)
interface are supported for verification.

If your DID method requires a different signing algorithm than what is already supported, please create an issue.

## Installation

```bash
npm install did-jwt
```

or if you use `yarn`

```bash
yarn add did-jwt
```

## Example

### 1. Create a did-JWT

In practice, you must secure the key passed to `ES256KSigner`. The key provided in code below is for informational
purposes only.

```ts
import didJWT from 'did-jwt';

const signer = didJWT.ES256KSigner(didJWT.hexToBytes('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))

let jwt = await didJWT.createJWT(
  { aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', iat: undefined, name: 'uPort Developer' },
  { issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', signer },
  { alg: 'ES256K' }
)
console.log(jwt)
```

### 2. Decode a did-JWT

Try decoding the JWT. You can also do this using [jwt.io](https://jwt.io)

```js
//pass the jwt from step 1
let decoded = didJWT.decodeJWT(jwt)
console.log(decoded)
```

Once decoded a did-JWT will resemble:

```ts
expect(decoded).toEqual({
  header: { alg: 'ES256K', typ: 'JWT' },
  payload: {
    aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    name: 'uPort Developer',
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  signature: 'mAhpAnw-9u57hyAaDufj2GPMbmuZyPDlU7aYSUMKk7P_9_cF3iLk-hFjFhb5xaUQB5nXYrciw6ZJ2RSAZI-IDQ',
  data: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQiLCJuYW1lIjoidVBvcnQgRGV2ZWxvcGVyIiwiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0'
})
```

### 3. Verify a did-JWT

You need to provide a did-resolver for the verify function. For this example we will use `did:ethr`, but there are other
methods available. For more information on configuring the Resolver object please
see [did-resolver](https://github.com/decentralized-identity/did-resolver#configure-resolver-object)

```bash
npm install ethr-did-resolver
```

```js
import {Resolver} from 'did-resolver';
import {getResolver} from 'ethr-did-resolver'

let resolver = new Resolver({...getResolver({infuraProjectId: '<get a free ID from infura.io>'})});

// use the JWT from step 1
let verificationResponse = await didJWT.verifyJWT(jwt, {
  resolver,
  audience: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
})
console.log(verificationResponse)
```

A verification response is an object resembling:

```typescript
expect(verificationResponse).toEqual({
  payload: {
    aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    name: 'uPort Developer',
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  didResolutionResult: {
    didDocumentMetadata: {},
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocument: {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/secp256k1recovery-2020/v2'
      ],
      id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
      verificationMethod: [
        {
          id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#controller',
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
          blockchainAccountId: 'eip155:1:0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74'
        }
      ],
      authentication: [
        'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#controller'
      ],
      assertionMethod: [
        'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#controller'
      ]
    }
  },
  issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
  signer: {
    id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#controller',
    type: 'EcdsaSecp256k1RecoveryMethod2020',
    controller: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    blockchainAccountId: 'eip155:1:0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74'
  },
  jwt: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQiLCJuYW1lIjoidVBvcnQgRGV2ZWxvcGVyIiwiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.mAhpAnw-9u57hyAaDufj2GPMbmuZyPDlU7aYSUMKk7P_9_cF3iLk-hFjFhb5xaUQB5nXYrciw6ZJ2RSAZI-IDQ',
  policies: {}
})
```
