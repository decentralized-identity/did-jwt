import { publicKeyToAddress as bip122 } from './bip122'
import { publicKeyToAddress as cosmos } from './cosmos'
import { toEthereumAddress } from '../Digest'

export const verifyBlockchainAccountId = (publicKey: string, blockchainAccountId: string | undefined): boolean => {
  if (blockchainAccountId) {
    const chain = blockchainAccountId.split(':')
    switch (chain[0]) {
      case 'bip122':
        chain[chain.length - 1] = bip122(publicKey, chain[chain.length - 1])
        break
      case 'cosmos':
        chain[chain.length - 1] = cosmos(publicKey, chain[1])
        break
      case 'eip155':
        chain[chain.length - 1] = toEthereumAddress(publicKey)
        break
      default:
        return false
    }
    return chain.join(':') === blockchainAccountId
  }
  return false
}
