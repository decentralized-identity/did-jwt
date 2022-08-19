/**
 * Error prefixes used for known verification failure cases.
 *
 * For compatibility, these error prefixes match the existing error messages, but will be adjusted in a future major
 * version update to match the scenarios better.
 *
 * @beta
 */
export const JWT_ERROR = {
  /**
   * Thrown when a JWT payload schema is unexpected or when validity period does not match
   */
  INVALID_JWT: 'invalid_jwt',
  /**
   * Thrown when the verifier audience does not match the one set in the JWT payload
   */
  INVALID_AUDIENCE: 'invalid_config',
  /**
   * Thrown when none of the public keys of the issuer match the signature of the JWT.
   *
   * This is equivalent to `NO_SUITABLE_KEYS` when the `proofPurpose` is NOT specified.
   */
  INVALID_SIGNATURE: 'invalid_signature',
  /**
   * Thrown when the DID document of the issuer does not have any keys that match the signature for the given
   * `proofPurpose`.
   *
   * This is equivalent to `invalid_signature`, when a `proofPurpose` is specified.
   */
  NO_SUITABLE_KEYS: 'no_suitable_keys',
  /**
   * Thrown when the `alg` of the JWT or the encoding of the key is not supported
   */
  NOT_SUPPORTED: 'not_supported',
  /**
   * Thrown when the DID resolver is unable to resolve the issuer DID.
   */
  RESOLVER_ERROR: 'resolver_error',
}
