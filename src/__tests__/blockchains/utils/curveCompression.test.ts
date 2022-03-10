import { compressionAlgorithm } from '../../../blockchains/utils/curveCompression'

describe('Cryptographic curve compression multi-selection algorithm', () => {
  it('compresses a P-256 Public Key', async () => {
     expect.assertions(1)
     const publicKey = '04f9c36f8964623378bdc068d4bce07ed17c8fa486f9ac0c2613ca3c8c306d7bb61cd36717b8ac5e4fea8ad23dc8d0783c2318ee4ad7a80db6e0026ad0b072a24f'
     const compressor = compressionAlgorithm('p256-pub')
     return expect(compressor(publicKey)).toEqual("03f9c36f8964623378bdc068d4bce07ed17c8fa486f9ac0c2613ca3c8c306d7bb6")
  })

  it('compresses a secp256k1 Public Key', () => {
     expect.assertions(1)
     const publicKey = '049dbed6380de46f520f885c6292e4524c7d39fc4b6a68af81cf9db74cde95c3629595e15bf4bf02e1b12375f7f0f332d159572370a28f47ed5a110dd1a35b96d3'
     const compressor = compressionAlgorithm('secp256k1-pub')
     return expect(compressor(publicKey)).toEqual("039dbed6380de46f520f885c6292e4524c7d39fc4b6a68af81cf9db74cde95c362")

  })

  it('defaults to secp256k1 compression algorithm', () => {
     expect.assertions(1)
     const publicKey = '049dbed6380de46f520f885c6292e4524c7d39fc4b6a68af81cf9db74cde95c3629595e15bf4bf02e1b12375f7f0f332d159572370a28f47ed5a110dd1a35b96d3'
     const compressor = compressionAlgorithm()
     return expect(compressor(publicKey)).toEqual("039dbed6380de46f520f885c6292e4524c7d39fc4b6a68af81cf9db74cde95c362")
  })
  
  it('expects no public key to throw an error', () => {
     const publicKey = '049dbed6380de46f520f885c6292e4524c7d39fc4b6a68af81cf9db74cde95c3629595e15bf4bf02e1b12375f7f0f332d159572370a28f47ed5a110dd1a35b96d3'
     const compressor = compressionAlgorithm()
      expect(() => {
       compressor();
      }).toThrowError('input cannot be null or undefined.');   
  })
  
  it('expects an unsupported algorithm to throw an error', async () => {
     expect(() => {
       compressionAlgorithm('bla')
     }).toThrowError('not_supported: Unsupported algorithm bla');
  })
  
})
