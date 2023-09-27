import VerifierAlgorithm from '../VerifierAlgorithm.js'
import { verifyJWT } from '../JWT.js'

const edKey58 = {
  id: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
  type: 'Ed25519VerificationKey2018',
  controller: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
  publicKeyBase58: 'A12q688RGRdqshXhL9TW8QXQaX9H82ejU9DnqztLaAgy',
}

describe('Ed25519', () => {
  const verifier = VerifierAlgorithm('Ed25519')

  it('validates hardcoded jwt', async () => {
    expect.assertions(1)
    const jwt =
      'eyJhbGciOiJFZERTQSJ9.eyJleHAiOjE3NjQ4Nzg5MDgsImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNTA4LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNS0xMi0wNFQxNDowODoyOC0wNjowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMTItMDRUMTQ6MDg6MjgtMDY6MDAiLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdfX0.6ovgQ-T_rmYueviySqXhzMzgqJMAizOGUKAObQr2iikoRNsb8DHfna4rh1puwWqYwgT3QJVpzdO_xZARAYM9Dw'
    const parts = jwt.match(/^([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
    return expect(verifier(parts!![1], parts!![2], [edKey58])).toEqual(edKey58)
  })

  it('handles EdDSA algorithm with did:key', async () => {
    expect.assertions(1)
    const resolver = {
      resolve: async () => ({
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: {
          '@context': 'https://w3id.org/did/v1',
          id: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
          publicKey: [
            {
              id: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
              type: 'Ed25519VerificationKey2018',
              controller: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
              publicKeyBase58: 'A12q688RGRdqshXhL9TW8QXQaX9H82ejU9DnqztLaAgy',
            },
          ],
        },
      }),
    }
    const jwt =
      'eyJhbGciOiJFZERTQSJ9.eyJleHAiOjE3NjQ4Nzg5MDgsImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNTA4LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNS0xMi0wNFQxNDowODoyOC0wNjowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMTItMDRUMTQ6MDg6MjgtMDY6MDAiLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdfX0.6ovgQ-T_rmYueviySqXhzMzgqJMAizOGUKAObQr2iikoRNsb8DHfna4rh1puwWqYwgT3QJVpzdO_xZARAYM9Dw'
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toMatchObject({
      exp: 1764878908,
      iss: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
      nbf: 1607112508,
      sub: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
      vc: {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://identity.foundation/.well-known/did-configuration/v1',
        ],
        credentialSubject: {
          id: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
          origin: 'identity.foundation',
        },
        expirationDate: '2025-12-04T14:08:28-06:00',
        issuanceDate: '2020-12-04T14:08:28-06:00',
        issuer: 'did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM',
        type: ['VerifiableCredential', 'DomainLinkageCredential'],
      },
    })
  })

  it('handles EdDSA algorithm with did:peer', async () => {
    expect.assertions(1)

    const resolver = {
      resolve: async () => ({
        didDocumentMetadata: {},
        didResolutionMetadata: {
          contentType: 'application/did+ld+json',
        },
        didDocument: {
          '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
          id: 'did:peer:0z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
          verificationMethod: [
            {
              id: 'did:peer:0z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw#6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
              type: 'Ed25519VerificationKey2020',
              controller: 'did:peer:0z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
              publicKeyMultibase: 'z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
            },
          ],
          authentication: [
            'did:peer:0z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw#6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
          ],
          assertionMethod: [
            'did:peer:0z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw#6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
          ],
          capabilityInvocation: [
            'did:peer:0z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw#6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
          ],
          capabilityDelegation: [
            'did:peer:0z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw#6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
          ],
        },
      }),
    }
    const jwt =
      'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5vdGhpbmciOiJlbHNlIG1hdHRlcnMifX0sIm5iZiI6MTY5NTA1MjE4MSwiaXNzIjoiZGlkOnBlZXI6MHo2TWtuTlc1bXZyVXBzc1NKd1pSUVNpbkxXWHpjRUNQdGp6ZUtVc1RSMU12dW1mdyJ9.mvgdqscXYjIXRuut83e8AfcBVdQJJOppQ9flohALoke_qRL9rR0FBOuBjWbf6uHftKv8lqUcqZuPnmsAJ0sbAA'
    const { payload } = await verifyJWT(jwt, { resolver })
    return expect(payload).toMatchObject({
      iss: 'did:peer:0z6MknNW5mvrUpssSJwZRQSinLWXzcECPtjzeKUsTR1Mvumfw',
      nbf: 1695052181,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        credentialSubject: {
          nothing: 'else matters',
        },
        type: ['VerifiableCredential'],
      },
    })
  })
})
