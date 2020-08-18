# did-jwt
[![npm](https://img.shields.io/npm/dt/did-jwt.svg)](https://www.npmjs.com/package/did-jwt)
[![npm](https://img.shields.io/npm/v/did-jwt.svg)](https://www.npmjs.com/package/did-jwt)
[![Twitter Follow](https://img.shields.io/twitter/follow/uport_me.svg?style=social&label=Follow)](https://twitter.com/uport_me)

[Algorithms supported](docs/guides/index.md#algorithms-supported) | [DID Public Key Types](docs/guides/index.md#did-publickey-types) | [Claim Specification](docs/guides/index.md#claims)

The did-JWT library allows you to sign and verify [JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519) using ES256K, ES256K-R and Ed25519 algorithms.

Public keys are resolved using the [Decentralized ID (DID)](https://w3c-ccg.github.io/did-spec/#decentralized-identifiers-dids) of the signing identity of the claim, which is passed as the `iss` attribute of the encoded JWT.

## DID methods
We currently support the following DID methods:

- [`ethr`](https://github.com/uport-project/ethr-did-resolver)
- [`uport`](https://github.com/uport-project/uport-did-resolver)
- [`https`](https://github.com/uport-project/https-did-resolver)
- [`nacl`](https://github.com/uport-project/nacl-did)
- [`muport`](https://github.com/3box/muport-did-resolver)

You will need to install each one you need to support. See each method for how to configure it.

Support for other DID methods should be simple. Write a DID resolver supporting the [`did-resolver'](https://github.com/uport-project/did-resolver) interface. Once you've verified that it works, please add a PR adding it to the above list so people can find it.

If your DID method requires a different signing algorithm than what is already supported, please create a PR.

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

[createJWT](docs/reference/index.md#did-jwtjwtcreatejwtpayload-config--promiseobject-error)

In practice you should secure the key passed to SimpleSigner.  The key provided in code below is for informational purposes; you will need to create an application identity at [My Apps](http://developer.uport.me/myapps) or use our uport-credentials library to [generate an ethereum key pair](https://github.com/uport-project/uport-credentials/blob/develop/docs/guides/index.md#generate-an-ethereum-keypair).

```js
const didJWT = require('did-jwt')
const signer = didJWT.SimpleSigner('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f');

let jwt = await didJWT.createJWT({aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', exp: 1957463421, name: 'uPort Developer'},
                 {alg: 'ES256K', issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', signer})
console.log(jwt);
```


### 2. Decode a did-JWT

Try decoding the JWT.  You can also do this using [jwt.io](jwt.io)

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
[verifyJWT](/docs/reference/index.md#did-jwtjwtverifyjwtjwt-config--promiseobject-error)

You need to provide a did-resolver for the verify function. For this example we will use ethr-did, but there are other methods available above. For more information on configuring the Resolver object please see [did-resolver](https://github.com/decentralized-identity/did-resolver#configure-resolver-object)

``` bash
npm install ethr-did-resolver
```

```js
const Resolver = require('did-resolver')
const ethrDid =  require('ethr-did-resolver').getResolver({rpcUrl: 'https://mainnet.infura.io/v3/...'})

let resolver = new Resolver.Resolver(ethrDid)

// pass the JWT from step 1 & 2
let verifiedRespone = await didJWT.verifyJWT(jwt, {resolver: resolver, audience: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'})
console.log(verifiedRespone);
```

A verified did-JWT returns an object resembling:

```js
{
  payload: {
    iat: 1571692448,
    exp: 1957463421,
    aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    name: 'uPort Developer',
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  doc: {
    '@context': 'https://w3id.org/did/v1',
    id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    publicKey: [ [Object] ],
    authentication: [ [Object] ]
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
