---
title: "did-jwt"
index: 3
category: "reference"
type: "content"
---

## Algorithms supported

- `ES256K` the [secp256k1 ECDSA curve](https://en.bitcoin.it/wiki/Secp256k1)
- `ES256K-R` the [secp256k1 ECDSA curve](https://en.bitcoin.it/wiki/Secp256k1) with recovery parameter

## DID PublicKey Types

The `PublicKey` section of a DID document contains one or more Public Keys. We support the following types:

Name | Encoding | Algorithm's
---- | -------- | -----------
`Secp256k1SignatureVerificationKey2018` | `publicKeyHex` | `ES256K`, `ES256K-R`
`Secp256k1VerificationKey2018` | `publicKeyHex` | `ES256K`, `ES256K-R`
`Secp256k1VerificationKey2018` | `ethereumAddress` | `ES256K-R`

## Claims

Name | Description | Required
---- | ----------- | --------
[`iss`](https://tools.ietf.org/html/rfc7519#section-4.1.1) | The [DID](https://w3c-ccg.github.io/did-spec/) of the signing identity| yes
[`sub`](https://tools.ietf.org/html/rfc7519#section-4.1.2) | The [DID](https://w3c-ccg.github.io/did-spec/) of the subject of the JWT| no
[`aud`](https://tools.ietf.org/html/rfc7519#section-4.1.3) | The [DID](https://w3c-ccg.github.io/did-spec/) or URL of the audience of the JWT. Our libraries or app will not accept any JWT that has someone else as the audience| no
[`iat`](https://tools.ietf.org/html/rfc7519#section-4.1.6) | The time of issuance | yes
[`exp`](https://tools.ietf.org/html/rfc7519#section-4.1.4) | Expiration time of JWT | no

## Modules

<dl>
<dt><a href="#module_did-jwt/JWT">did-jwt/JWT</a></dt>
<dd></dd>
</dl>

## Functions

<dl>
<dt><a href="#SimpleSigner">SimpleSigner(hexPrivateKey)</a> ⇒ <code>function</code></dt>
<dd><p>The SimpleSigner returns a configured function for signing data. It also defines
 an interface that you can also implement yourself and use in our other modules.</p>
</dd>
</dl>

<a name="module_did-jwt/JWT"></a>

## did-jwt/JWT

* [did-jwt/JWT](#module_did-jwt/JWT)
    * [.createJWT(payload, [config])](#module_did-jwt/JWT.createJWT) ⇒ <code>Promise.&lt;Object, Error&gt;</code>
    * [.verifyJWT(jwt, [config])](#module_did-jwt/JWT.verifyJWT) ⇒ <code>Promise.&lt;Object, Error&gt;</code>
    * [.resolveAuthenticator(alg, did, auth)](#module_did-jwt/JWT.resolveAuthenticator) ⇒ <code>Promise.&lt;Object, Error&gt;</code>

<a name="module_did-jwt/JWT.createJWT"></a>

### did-jwt/JWT.createJWT(payload, [config]) ⇒ <code>Promise.&lt;Object, Error&gt;</code>
Creates a signed JWT given an address which becomes the issuer, a signer, and a payload for which the signature is over.

**Kind**: static method of [<code>did-jwt/JWT</code>](#module_did-jwt/JWT)  
**Returns**: <code>Promise.&lt;Object, Error&gt;</code> - a promise which resolves with a signed JSON Web Token or rejects with an error  

| Param | Type | Description |
| --- | --- | --- |
| payload | <code>Object</code> | payload object |
| [config] | <code>Object</code> | an unsigned credential object |
| config.issuer | <code>String</code> | The DID of the issuer (signer) of JWT |
| config.alg | <code>String</code> | The JWT signing algorithm to use. Supports: [ES256K, ES256K-R], Defaults to: ES256K |
| config.signer | [<code>SimpleSigner</code>](#SimpleSigner) | a signer, reference our SimpleSigner.js |

**Example**  
```js
const signer = SimpleSigner(process.env.PRIVATE_KEY)
 createJWT({address: '5A8bRWU3F7j3REx3vkJ...', signer}, {key1: 'value', key2: ..., ... }).then(jwt => {
     ...
 })

 
```
<a name="module_did-jwt/JWT.verifyJWT"></a>

### did-jwt/JWT.verifyJWT(jwt, [config]) ⇒ <code>Promise.&lt;Object, Error&gt;</code>
Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 and the did doc of the issuer of the JWT.

**Kind**: static method of [<code>did-jwt/JWT</code>](#module_did-jwt/JWT)  
**Returns**: <code>Promise.&lt;Object, Error&gt;</code> - a promise which resolves with a response object or rejects with an error  

| Param | Type | Description |
| --- | --- | --- |
| jwt | <code>String</code> | a JSON Web Token to verify |
| [config] | <code>Object</code> | an unsigned credential object |
| config.auth | <code>Boolean</code> | Require signer to be listed in the authentication section of the DID document (for Authentication purposes) |
| config.audience | <code>String</code> | DID of the recipient of the JWT |
| config.callbackUrl | <code>String</code> | callback url in JWT |

**Example**  
```js
verifyJWT('did:uport:eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJyZXF1Z....', {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...}).then(obj => {
       const did = obj.did // DID of signer
     const payload = obj.payload
     const doc = obj.doc // DID Document of signer
     const jwt = obj.jwt
     const signerKeyId = obj.signerKeyId // ID of key in DID document that signed JWT
     ...
 })

 
```
<a name="module_did-jwt/JWT.resolveAuthenticator"></a>

### did-jwt/JWT.resolveAuthenticator(alg, did, auth) ⇒ <code>Promise.&lt;Object, Error&gt;</code>
Resolves relevant public keys or other authenticating material used to verify signature from the DID document of provided DID

**Kind**: static method of [<code>did-jwt/JWT</code>](#module_did-jwt/JWT)  
**Returns**: <code>Promise.&lt;Object, Error&gt;</code> - a promise which resolves with a response object containing an array of authenticators or if non exist rejects with an error  

| Param | Type | Description |
| --- | --- | --- |
| alg | <code>String</code> | a JWT algorithm |
| did | <code>String</code> | a Decentralized IDentifier (DID) to lookup |
| auth | <code>Boolean</code> | Restrict public keys to ones specifically listed in the 'authentication' section of DID document |

**Example**  
```js
resolveAuthenticator('ES256K', 'did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX').then(obj => {
     const payload = obj.payload
     const profile = obj.profile
     const jwt = obj.jwt
     ...
 })

 
```
<a name="SimpleSigner"></a>

## SimpleSigner(hexPrivateKey) ⇒ <code>function</code>
The SimpleSigner returns a configured function for signing data. It also defines
 an interface that you can also implement yourself and use in our other modules.

**Kind**: global function  
**Returns**: <code>function</code> - a configured signer function  

| Param | Type | Description |
| --- | --- | --- |
| hexPrivateKey | <code>String</code> | a hex encoded private key |

**Example**  
```js
const signer = SimpleSigner(process.env.PRIVATE_KEY)
 signer(data, (err, signature) => {
   ...
 })

 
```
