// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function instanceOfEcdsaSignature(object: any): object is EcdsaSignature {
  return typeof object === 'object' && 'r' in object && 's' in object
}
