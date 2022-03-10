import { ec as EC } from 'elliptic'
import { publicKeyToAddress as toCosmosAddressWithoutPrefix } from '../../blockchains/cosmos'

describe('Keep the output consistent for toCosmosAddressWithoutPrefix', () => {
    it('creates cosmos address with secp256k1 Public Key', () => {
       expect.assertions(1)
       const secp256k1 = new EC('secp256k1')
       const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
       const kp = secp256k1.keyFromPrivate(privateKey)
       const publicKey = String(kp.getPublic('hex'))
       const cosmosPrefix = 'example'
       return expect(toCosmosAddressWithoutPrefix(publicKey, cosmosPrefix)).toEqual("1px23rnt8hsweg9s3lsdfvdsarh4fa9dwxhedt7")
     })
})
