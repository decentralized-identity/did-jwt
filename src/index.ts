import SimpleSigner from './SimpleSigner'
import NaclSigner from './NaclSigner'
import { verifyJWT, createJWT, decodeJWT } from './JWT'

export default {
  SimpleSigner,
  NaclSigner,
  verifyJWT,
  createJWT,
  decodeJWT
}
