import VerifierAlgorithm from '../VerifierAlgorithm'

describe('VerifierAlgorithm', () => {
  it('fails on unsupported algorithm', () => {
    expect(() => VerifierAlgorithm('BADALGO')).toThrowError('Unsupported algorithm BADALGO')
  })

  it('supports EdDSA', () => {
    expect(typeof VerifierAlgorithm('EdDSA')).toEqual('function')
  })
})
