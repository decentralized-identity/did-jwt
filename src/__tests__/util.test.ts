import { parseKey } from '../util'

describe('parseKey', () => {
  const privateKeyBase58 = '2sxRbZxrkTR1tmUH88aWcosMRf8zianLjV3vZcVewCDzgimGt5gLeHx1cm4bqfeEuVmDaCREgUNZbKHJAB8HHf9e'
  const privateKeyHex =
    '5DF58BB06C22FEBAC638296C0F629703E2B9E4A1D9D68298DDEC13D1757D73E056D299B8CF2FC5AB12EDEF6C0B28A7D57ED0649A188B6C5B88E74F208792E62D'
  const privateKeyHexPrefix =
    '0x5df58bb06c22febac638296c0f629703e2b9e4a1d9d68298ddec13d1757d73e056d299b8cf2fc5ab12edef6c0b28a7d57ed0649a188b6c5b88e74f208792e62d'
  const privateKeyBase64 = 'XfWLsGwi/rrGOClsD2KXA+K55KHZ1oKY3ewT0XV9c+BW0pm4zy/FqxLt72wLKKfVftBkmhiLbFuI508gh5LmLQ'
  const privateKeyBase64Url = 'XfWLsGwi_rrGOClsD2KXA-K55KHZ1oKY3ewT0XV9c-BW0pm4zy_FqxLt72wLKKfVftBkmhiLbFuI508gh5LmLQ'

  const privateKeyBytes = Uint8Array.from(
    Buffer.from('XfWLsGwi/rrGOClsD2KXA+K55KHZ1oKY3ewT0XV9c+BW0pm4zy/FqxLt72wLKKfVftBkmhiLbFuI508gh5LmLQ', 'base64')
  )

  it('parses hex', () => {
    expect(parseKey(privateKeyHex)).toMatchObject(privateKeyBytes)
  })

  it('parses prefixed hex', () => {
    expect(parseKey(privateKeyHexPrefix)).toMatchObject(privateKeyBytes)
  })

  it('parses base64', () => {
    expect(parseKey(privateKeyBase64)).toMatchObject(privateKeyBytes)
  })

  it('parses base64url', () => {
    expect(parseKey(privateKeyBase64Url)).toMatchObject(privateKeyBytes)
  })

  it('parses base58btc', () => {
    expect(parseKey(privateKeyBase58)).toMatchObject(privateKeyBytes)
  })
})
