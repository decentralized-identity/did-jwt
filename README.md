# did-jwt

The did-JWT library allows you to sign and verify [JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519). Public keys are resolved using the [Decentralized ID (DID)](https://w3c-ccg.github.io/did-spec/#decentralized-identifiers-dids) of the `iss` claim of the JWT.

## JWT Details

### Algorithms supported

- `ES256K` the [secp256k1 ECDSA curve](https://en.bitcoin.it/wiki/Secp256k1)
- `ES256K-R` the [secp256k1 ECDSA curve](https://en.bitcoin.it/wiki/Secp256k1) with recovery parameter

### DID PublicKey Types

The `PublicKey` section of a DID document contains one or more Public Keys. We support the following types:

Name | Encoding | Algorithm's
---- | -------- | -----------
`Secp256k1SignatureVerificationKey2018` | `publicKeyHex` | `ES256K`, `ES256K-R`
`Secp256k1VerificationKey2018` | `publicKeyHex` | `ES256K`, `ES256K-R`
`Secp256k1VerificationKey2018` | `ethereumAddress` | `ES256K-R`

### Claims

Name | Description | Required
---- | ----------- | --------
[`iss`](https://tools.ietf.org/html/rfc7519#section-4.1.1) | The [DID](https://w3c-ccg.github.io/did-spec/) of the signing identity| yes
[`sub`](https://tools.ietf.org/html/rfc7519#section-4.1.2) | The [DID](https://w3c-ccg.github.io/did-spec/) of the subject of the JWT| no
[`aud`](https://tools.ietf.org/html/rfc7519#section-4.1.3) | The [DID](https://w3c-ccg.github.io/did-spec/) or URL of the audience of the JWT. Our libraries or app will not accept any JWT that has someone else as the audience| no
[`iat`](https://tools.ietf.org/html/rfc7519#section-4.1.6) | The time of issuance | yes
[`exp`](https://tools.ietf.org/html/rfc7519#section-4.1.4) | Expiration time of JWT | no

## Installation

```bash
npm install did-jwt
```

or if you use `yarn`

```bash
yarn add did-jwt
```

## API

### Creating a JWT

Use the `createJWT()` function

```js
import { createJWT, SimpleSigner } from 'did-jwt'

const signer = SimpleSigner('PRIVATEKEY')

createJWT(
    {aud: 'did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqY', exp: 1485321133, name: 'Bob Smith'},
    {issuer: 'did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX', signer}).then(jwt => {
    console.log(jwt)
})
```

#### Parameters

```js
createJWT(payload, settings)
```

Name | Description | Required
---- | ----------- | --------
`payload` | an object containing any claims you want to encode in the JWT including optional standard claims such as `sub`, `aud` and `exp` | yes
`settings.issuer` | The [DID](https://w3c-ccg.github.io/did-spec/#decentralized-identifiers-dids) of the audience of the JWT | yes
`settings.signer` | A signing function (see SimpleSigner) | yes
`settings.expiresIn` | How many seconds after signing should the JWT be valid (sets the `exp` claim) | no

#### Promise Return Value

The `createJWT()` function returns a Promise.

A successfull call returns an object containing the following attributes:

Name | Description
---- | -----------
`jwt` | String containing a [JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519)

If there are any errors found during the signing process the promise is rejected with a clear error message.

### Verifying a JWT

Use the `verifyJWT()` function

```js
import { verifyJWT } from 'did-jwt'

verifyJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6dXBvcn....', {audience: 'Your DID'}).then({payload, doc, did, signer, jwt} => {
    console.log(payload)
})
```

#### Parameters

```js
verifyJWT(jwt, options)
```

Name | Description | Required
---- | ----------- | --------
`jwt` | String containing a [JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519) | yes
`options.auth` | Require signer to be listed in the authentication section of the DID document (for Authentication of a user with DID-AUTH)
`options.audience` | The [DID](https://w3c-ccg.github.io/did-spec/#decentralized-identifiers-dids) of the audience of the JWT | no
`options.callbackUrl` | The the URL receiving the JWT | no

#### Promise Return Value

The `verifyJWT()` function returns a Promise.

A successfull call returns an object containing the following attributes:

Name | Description
---- | -----------
`payload` | An object containing the JSON parsed contents of the payload section of the JWT
`issuer` | The [DID](https://w3c-ccg.github.io/did-spec/#decentralized-identifiers-dids) of the issuer of the JWT
`signer` | An object containing information about which key signed the JWT. This is useful if a DID document has multiple keys listed
`doc` | The [DID Document](https://w3c-ccg.github.io/did-spec/#did-documents) of the issuer of the JWT
`jwt` | The original JWT passed in to the function

If there are any errors found during the verification process the promise is rejected with a clear error message.

## Signer Functions

We provide a simple signing abstraction that makes it easy to add support for your own Key Management infrastructure.

### SimpleSigner

For most people you can use our `SimpleSigner()` function to creaate a signer function using a hex encoded private key.

```js
import { SimpleSigner } from 'did-jwt'
const signer = SimpleSigner('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f')
```

#### Parameters

```js
SimpleSigner(privateKey)
```

Name | Description | Required
---- | ----------- | --------
`privateKey` | hex encoded [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) privatekey | yes

Note this is NOT a constructor, but a higher order function that returns a signing function.

### Creating Custom Signers for integrating with HSM

You can easily create custom signers that integrates into your existing signing infrastructure. A signer function takes the raw data to be signed and returns a Promise containing the signature parameters.

```js
function mySigner (data) {
    return new Promise((resolve, reject) => {
        const signature = /// sign it
        resolve(signature)
    })
}
```

#### Parameters

Name | Description | Required
---- | ----------- | --------
`data` | String or [Buffer](https://nodejs.org/api/buffer.html) containing data to be signed | yes

#### Promise Return Value

Your function must returns a Promise.

A successfull call returns an object containing the following attributes:

Name | Description | Required
---- | ----------- | --------
`r` | Hex encoded `r` value of [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) signature | yes
`s` | Hex encoded `s` value of [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) signature | yes
`recoveryParam` | Recovery parameter of signature (can be used to calculate signing public key) | only required for (`ES256K-R`)
