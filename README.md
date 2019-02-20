# did-jwt
[![Join the chat at](https://img.shields.io/badge/Riot-Join%20chat-green.svg)](https://chat.uport.me/#/login)
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
const signer = didJWT.SimpleSigner('fa09a3ff0d486be2eb69545c393e2cf47cb53feb44a3550199346bdfa6f53245');

let jwt = '';
didJWT.createJWT({aud: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts', exp: 1957463421, name: 'uPort Developer'},
                 {issuer: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts', signer}).then( response =>
                 { jwt = response });

console.log(jwt);
```


### 2. Decode a did-JWT

Try decoding the JWT.  You can also do this using [jwt.io](jwt.io)

```js
didJWT.decodeJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1MjU5Mjc1MTcsImF1ZCI6ImRpZDp1cG9> didJWT.decodeJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1MjU5Mjc1MTcsImF1ZCI6ImRpZDp1cG9y dDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyIsImV4cCI6MTU1NzQ2MzQyMSwibmFtZSI6InVQb3J0IERldmVsb3> didJWT.decodeJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1MjU5Mjc1MTcsImF1ZCI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyIsImV4cCI6MTU1NzQ2MzQyMSwibmFtZSI6InVQb3J0IERldmVsb3B lciIsImlzcyI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyJ9.R7owbvNZoL4ti5ec-Kpktb0d> didJWT.decodeJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1MjU5Mjc1MTcsImF1ZCI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyIsImV4cCI6MTU1NzQ2MzQyMSwibmFtZSI6InVQb3J0IERldmVsb3BlciIsImlzcyI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyJ9.R7owbvNZoL4ti5ec-Kpktb0da tw9Y-FshHsF5R7cXuKaiGlQz1dcOOXbXTOb-wg7-30CDfchFERR6Yc8F61ymw')

```

Once decoded a did-JWT will resemble:

```js
{ header: { typ: 'JWT', alg: 'ES256K' },
  payload:
   { iat: 1525927517,
     aud: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts',
     exp: 1557463421,
     name: 'uPort Developer',
     iss: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts' },
  signature: 'R7owbvNZoL4ti5ec-Kpktb0datw9Y-FshHsF5R7cXuKaiGlQz1dcOOXbXTOb-wg7-30CDfchFERR6Yc8F61ymw',
  data: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1MjU5Mjc1MTcsImF1ZCI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyIsImV4cCI6MTU1NzQ2MzQyMSwibmFtZSI6InVQb3J0IERldmVsb3BlciIsImlzcyI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyJ9' }
```

### 2. Verify a did-JWT

[verifyJWT](/docs/reference/index.md#did-jwtjwtverifyjwtjwt-config--promiseobject-error)

```js
// pass the JWT from step 1 & 2
let verifiedRespone = {};
didJWT.verifyJWT(jwt, {audience: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts'}).then((response) =>
{ verifiedRespone = response });

console.log(verifiedRespone);
```

A verified did-JWT returns an object resembling:

```js
{ payload:
   { iat: 1525927517,
     aud: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts',
     exp: 1557463421,
     name: 'uPort Developer',
     iss: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts' },
  doc:
   { '@context': 'https://w3id.org/did/v1',
     id: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts',
     publicKey: [ [Object] ],
     uportProfile:
      { '@context': 'http://schema.org',
        '@type': 'App',
        name: 'Uport Developer Splash Demo',
        description: 'This app demonstrates basic login functionality',
        url: 'https://developer.uport.me' } },
  issuer: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts',
  signer:
   { id: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts#keys-1',
     type: 'EcdsaPublicKeySecp256k1',
     owner: 'did:uport:2osnfJ4Wy7LBAm2nPBXire1WfQn75RrV6Ts',
     publicKeyHex: '04c74d8a9154bbf48ce4b259b703c420e10aba42d03fa592ccf9dea60c83cd9ca81d3e08b859d4dc5a6dee30da2600e50ace688201b6f5a1e0938d135ec4b442ad' },
  jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1MjU5Mjc1MTcsImF1ZCI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyIsImV4cCI6MTU1NzQ2MzQyMSwibmFtZSI6InVQb3J0IERldmVsb3BlciIsImlzcyI6ImRpZDp1cG9ydDoyb3NuZko0V3k3TEJBbTJuUEJYaXJlMVdmUW43NVJyVjZUcyJ9.R7owbvNZoL4ti5ec-Kpktb0datw9Y-FshHsF5R7cXuKaiGlQz1dcOOXbXTOb-wg7-30CDfchFERR6Yc8F61ymw' }
```
