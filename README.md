[![npm](https://img.shields.io/npm/dt/did-jwt.svg)](https://www.npmjs.com/package/did-jwt)
[![npm](https://img.shields.io/npm/v/did-jwt.svg)](https://www.npmjs.com/package/did-jwt)
[![Twitter Follow](https://img.shields.io/twitter/follow/uport_me.svg?style=social&label=Follow)](https://twitter.com/uport_me)
[![codecov](https://codecov.io/gh/decentralized-identity/did-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/decentralized-identity/did-jwt)

# did-jwt

The did-JWT library allows you to sign and verify [JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519)
using `ES256K` and `EdDSA` algorithms. The non-standard `ES256K-R` is also supported for backward compatibility
reasons, as well as the `Ed25519` legacy name for `EdDSA`.

Public keys are resolved using the [Decentralized ID (DID)](https://w3c.github.io/did-core/#identifier) of the signing
identity of the token, which is passed as the `iss` attribute of the JWT payload.

## DID methods

All DID methods that can be resolved using the [`did-resolver'](https://github.com/decentralized-identity/did-resolver)
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

In practice, you must secure the key passed to ES256KSigner. The key provided in code below is for informational
purposes only.

```js
const didJWT = require('did-jwt')
const signer = didJWT.ES256KSigner(didJWT.hexToBytes('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))

let jwt = await didJWT.createJWT(
  { aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', exp: 1957463421, name: 'uPort Developer' },
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

```js
{
  header: { typ: 'JWT', alg: 'ES256K' },
  payload: {
    iat: 1571692233,
    exp: 1957463421,
    aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    name: 'uPort Developer',
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  signature: 'kkSmdNE9Xbiql_KCg3IptuJotm08pSEeCOICBCN_4YcgyzFc4wIfBdDQcz76eE-z7xUR3IBb6-r-lRfSJcHMiAA',
  data: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NzE2OTIyMzMsImV4cCI6MTk1NzQ2MzQyMSwiYXVkIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0IiwibmFtZSI6InVQb3J0IERldmVsb3BlciIsImlzcyI6ImRpZDpldGhyOjB4ZjNiZWFjMzBjNDk4ZDllMjY4NjVmMzRmY2FhNTdkYmI5MzViMGQ3NCJ9'
}
```

### 3. Verify a did-JWT

You need to provide a did-resolver for the verify function. For this example we will use `did:ethr`, but there are other
methods available. For more information on configuring the Resolver object please
see [did-resolver](https://github.com/decentralized-identity/did-resolver#configure-resolver-object)

```bash
npm install ethr-did-resolver
```

```js
const Resolver = require('did-resolver')
const ethrDid = require('ethr-did-resolver').getResolver({ rpcUrl: 'https://mainnet.infura.io/v3/...' })

let resolver = new Resolver.Resolver(ethrDid)

// pass the JWT from step 1
let verificationResponse = await didJWT.verifyJWT(jwt, {
  resolver: resolver,
  audience: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
})
console.log(verificationResponse)
```

A verification response is an object resembling:

```typescript
{
  payload: {
    iat: 1571692448,
    exp: 1957463421,
    aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    name: 'uPort Developer',
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  didResolutionResult: {
    didDocumentMetadata: {},
    didResolutionMetadata: {},
    didDocument: {
      '@context': 'https://w3id.org/did/v1',
      id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
      publicKey: [ [Object] ],
      authentication: [ [Object] ]
    }
  },
  issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
  signer: {
    id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#owner',
    type: 'Secp256k1VerificationKey2018',
    owner: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    ethereumAddress: '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1NzE2OTI0NDgsImV4cCI6MTk1NzQ2MzQyMSwiYXVkIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0IiwibmFtZSI6InVQb3J0IERldmVsb3BlciIsImlzcyI6ImRpZDpldGhyOjB4ZjNiZWFjMzBjNDk4ZDllMjY4NjVmMzRmY2FhNTdkYmI5MzViMGQ3NCJ9.xd_CSWukS6rK8y7GVvyH_c5yRsDXojM6BuKaf1ZMg0fsgpSBioS7jBfyk4ZZvS0iuFu4u4_771_PNWvmsvaZQQE'
}
```
