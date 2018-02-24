## Modules

<dl>
<dt><a href="#module_uport-js/JWT">uport-js/JWT</a></dt>
<dd></dd>
</dl>

## uport-js/JWT

* [uport-js/JWT](#module_uport-js/JWT)
    * [.createJWT([config], payload)](#module_uport-js/JWT.createJWT) ⇒ <code>Promise.&lt;Object, Error&gt;</code>
    * [.verifyJWT([config], jwt, callbackUrl)](#module_uport-js/JWT.verifyJWT) ⇒ <code>Promise.&lt;Object, Error&gt;</code>

<a name="module_uport-js/JWT.createJWT"></a>

### uport-js/JWT.createJWT([config], payload) ⇒ <code>Promise.&lt;Object, Error&gt;</code>
Creates a signed JWT given an address which becomes the issuer, a signer, and a payload for which the signature is over.

**Kind**: static method of <code>[uport-js/JWT](#module_uport-js/JWT)</code>  
**Returns**: <code>Promise.&lt;Object, Error&gt;</code> - a promise which resolves with a signed JSON Web Token or rejects with an error  

| Param | Type | Description |
| --- | --- | --- |
| [config] | <code>Object</code> | an unsigned credential object |
| config.address | <code>String</code> | address, typically the uPort address of the signer which becomes the issuer |
| config.signer | <code>SimpleSigner</code> | a signer, reference our SimpleSigner.js |
| payload | <code>Object</code> | payload object |

**Example**  
```js
const signer = SimpleSigner(process.env.PRIVATE_KEY)
 createJWT({address: '5A8bRWU3F7j3REx3vkJ...', signer}, {key1: 'value', key2: ..., ... }).then(jwt => {
     ...
 })

 
```
<a name="module_uport-js/JWT.verifyJWT"></a>

### uport-js/JWT.verifyJWT([config], jwt, callbackUrl) ⇒ <code>Promise.&lt;Object, Error&gt;</code>
Verifies given JWT. Registry is used to resolve uPort address to public key for verification.
 If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 and the profile of the issuer of the JWT.

**Kind**: static method of <code>[uport-js/JWT](#module_uport-js/JWT)</code>  
**Returns**: <code>Promise.&lt;Object, Error&gt;</code> - a promise which resolves with a response object or rejects with an error  

| Param | Type | Description |
| --- | --- | --- |
| [config] | <code>Object</code> | an unsigned credential object |
| config.address | <code>String</code> | address, typically the uPort address of the signer which becomes the issuer |
| config.registry | <code>UportLite</code> | a uPort registry, reference our uport-lite library |
| jwt | <code>String</code> | a JSON Web Token to verify |
| callbackUrl | <code>String</code> | callback url in JWT |

**Example**  
```js
const registry =  new UportLite()
 verifyJWT({registry, address: '5A8bRWU3F7j3REx3vkJ...'}, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJyZXF1Z....').then(obj => {
     const payload = obj.payload
     const profile = obj.profile
     const jwt = obj.jwt
     ...
 })
```
