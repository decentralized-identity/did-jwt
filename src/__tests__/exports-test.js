import SimpleSigner from '../SimpleSigner'
import NaclSigner from '../NaclSigner'
import { toEthereumAddress } from '../Digest'
import { verifyJWT, createJWT, decodeJWT } from '../JWT'
import * as exported from '../index'

describe('has correct exports', () => {
  it('exports SimpleSigner', () => {
    expect(exported.SimpleSigner).toEqual(SimpleSigner)
  })
  it('exports NaclSigner', () => {
    expect(exported.NaclSigner).toEqual(NaclSigner)
  })
  it('exports verifyJWT', () => {
    expect(exported.verifyJWT).toEqual(verifyJWT)
  })
  it('exports createJWT', () => {
    expect(exported.createJWT).toEqual(createJWT)
  })
  it('exports decodeJWT', () => {
    expect(exported.decodeJWT).toEqual(decodeJWT)
  })
  it('exports toEthereumAddress', () => {
    expect(exported.toEthereumAddress).toEqual(toEthereumAddress)
  })
})
