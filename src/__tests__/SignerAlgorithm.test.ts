import SignerAlgorithm from '../SignerAlgorithm'

describe('SignerAlgorithm', () => {

  it('supports EdDSA', () => {
    expect(typeof SignerAlgorithm('EdDSA')).toEqual('function')
  })

  it('fails on unsupported algorithm', () => {
    expect(() => SignerAlgorithm('BADALGO')).toThrowError('Unsupported algorithm BADALGO')
  })
})

