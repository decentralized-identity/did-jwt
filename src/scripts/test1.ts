import { hexToBytes, base58ToBytes, base64ToBytes } from '../util.js'
import { ES256Signer } from '../signers/ES256Signer.js'


const privateKey = '040f1dbf0a2ca86875447a7c010b0fc6d39d76859c458fbe8f2bf775a40ad74a'
const signer = ES256Signer(hexToBytes(privateKey))
const plaintext = 'thequickbrownfoxjumpedoverthelazyprogrammer'

async function main() {
    const whatever = signer(plaintext)
    console.log("whatever: ", whatever)
}
    

main().catch(console.log)