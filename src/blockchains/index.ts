import { publicKeyToAddress as bip122 } from './bip122'
import { publicKeyToAddress as cosmos } from './cosmos'
import { toEthereumAddress } from '../Digest'

export const verifyBlockchainAccountId = (
  publicKeyBuffer: string,
  blockchainAccountId: string | undefined
): boolean => {
  if (blockchainAccountId) {
    const chain = blockchainAccountId.split(':')
    switch (chain[0]) {
      case 'bip122':
        chain[chain.length - 1] = bip122(publicKeyBuffer)
        break
      case 'cosmos':
        chain[chain.length - 1] = cosmos(publicKeyBuffer, chain[1])
        break
      case 'eip155':
        chain[chain.length - 1] = toEthereumAddress(publicKeyBuffer)
        break
      default:
        return false
    }
    return chain.join(':') === blockchainAccountId
  }
  return false
}
