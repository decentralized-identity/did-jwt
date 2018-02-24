# uport-jwt

TODO write docs

## JWT

## Creating Custom Signers for integrating with HSM

You can easily create custom signers that integrates into your existing signing infrastructure.

```javascript
function sign(data, callback) {
    const signature = '' // send your data to your back end signer and return DER signed data
    callback(null, signature)
}
```
