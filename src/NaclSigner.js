import nacl from 'tweetnacl'
import naclutil from 'tweetnacl-util'

/**
*  The NaclSigner returns a configured function for signing data using the Ed25519 algorithm. It also defines
*  an interface that you can also implement yourself and use in our other modules.
*
*  The signing function itself takes the data as a string parameter and returls a base64Url encoded signature
*
*  @example
*  const signer = NaclSigner(process.env.PRIVATE_KEY)
*  signer(data, (err, signature) => {
*    ...
*  })
*
*  @param    {String}         base64PrivateKey    a 64 byte base64 encoded private key
*  @return   {Function}                     a configured signer function
*/

function pad (base64url) {
  switch (base64url.length % 4) {
    case 0: return base64url
    case 2: return base64url + '=='
    case 3: return base64url + '='
    default: throw new Error('Invalid base64url encoded string')
  }
}

export function encodeBase64Url (data) {
  return naclutil.encodeBase64(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

export function decodeBase64Url (base64url) {
  return naclutil.decodeBase64(pad(base64url).replace(/-/g, '+').replace(/_/g, '/'))
}

export function NaclSigner (base64PrivateKey) {
  const privateKey = naclutil.decodeBase64(base64PrivateKey)
  return async (data) => {
    return encodeBase64Url(nacl.sign.detached(naclutil.decodeUTF8(data), privateKey))
  }
}

module.exports = { NaclSigner, encodeBase64Url, decodeBase64Url }
