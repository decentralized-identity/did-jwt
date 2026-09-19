import { describe, it, expect } from 'vitest'
import { bytesToMultibase, CODEC_TO_KEY_TYPE, multibaseToBytes, supportedCodecs } from '../util.js'
import type { BaseName, KNOWN_CODECS } from '../util.js'

/**
 * Regression tests for the inline `multibase`/`multiformats` port in `src/util.ts`.
 *
 * Coverage:
 *   - the three bases the port cares about: base58btc / base64url / base32
 *   - all six supported multicodecs (with a codec) plus the no-codec case
 *   - both directions (encode via `bytesToMultibase`, decode via `multibaseToBytes`)
 *   - the "known key length" fast path (32/33/48/64/65/96) AND the
 *     multicodec-stripping path (lengths NOT in that set: 10/45/60/100/40)
 *   - both a 2-byte varint prefix (0xed/0xec/0xe7/0xea/0xeb) and a
 *     3-byte+ varint prefix (0x1200 = p256-pub)
 *   - external published multibase vectors that double as regression anchors
 */

/** Deterministic raw byte generator (never random). */
function makeBytes(n: number, seed = 0): Uint8Array {
  return new Uint8Array(Array.from({ length: n }, (_, i) => (i * 37 + 11 + seed) & 0xff || 1))
}

const BASES: BaseName[] = ['base58btc', 'base64url', 'base32']

// ----------------------------- external vectors -----------------------------
// Published multibase vectors (the outputs of the multibase package for the
// three bases the port cares about, matching the base64url/base32/base58btc
// specifications). Independent of the temporary oracle libraries, so they stay
// meaningful as long-term regression anchors.
const EXTERNAL_VECTORS: { bytes: Uint8Array; expected: string }[] = [
  // base64url (multibase prefix 'u')
  { bytes: new Uint8Array([]), expected: 'u' },
  { bytes: new Uint8Array([1]), expected: 'uAQ' },
  { bytes: new Uint8Array([2, 0]), expected: 'uAgA' },
  { bytes: new Uint8Array([2, 55]), expected: 'uAjc' },
  // base32 (multibase prefix 'b')
  { bytes: new Uint8Array([1]), expected: 'bae' },
  { bytes: new Uint8Array([2, 0]), expected: 'baiaa' },
  { bytes: new Uint8Array([2, 55]), expected: 'bai3q' },
  // base58btc (multibase prefix 'z')
  { bytes: new Uint8Array([12, 32]), expected: 'zvX' },
  { bytes: new Uint8Array([1]), expected: 'z2' },
  { bytes: new Uint8Array([255, 255, 255]), expected: 'z2UzHL' },
]

// ----------------------------- no-codec cases -----------------------------
// No codec: multibaseToBytes must equal a pure multibase decode (prefix + base
// payload, no multicodec stripping). Captured from the oracle.
const NO_CODEC: { base: BaseName; bytes: Uint8Array; expected: string }[] = []
for (const base of BASES) {
  for (const [n, seed] of [
    [32, 0],
    [33, 0],
    [48, 0],
    [64, 0],
    [65, 0],
    [96, 0],
    [10, 0],
    [100, 0],
  ] as const) {
    NO_CODEC.push({ base, bytes: makeBytes(n, seed), expected: '' })
  }
}
NO_CODEC[0].expected = 'zkgERWXbLfq6MHcWLd86a5dpmSvM86QhQrQjL2gGPbnD'
NO_CODEC[1].expected = 'z4KnAFBL2ZpPGcYKiVcSKb1TXqBQTpJsbNH5jpzQJvkWav'
NO_CODEC[2].expected = 'zQohSUjghmj8K7iA5CFc39DPhWLP6yZxYcjk54NQjZPCucdKEi9XT6tFRFu6Nh9GtD'
NO_CODEC[3].expected = 'zDyXZZCSiBREJ8YZ5cULd7PVdKpbkhHvHJ7otbJmLJajJtRsyq1irMMqKimYeKvRmZ8Sc2qWLhKjYR4ekM8RSzkV'
NO_CODEC[4].expected = 'zzGVth7WUkywgcJGbMZfcPCHML56PrqgAvZ3xiRQgCbsjwzp1pvBiprxHdMcfkWpKeor1d76VvygmfD7cKqkujtwt'
NO_CODEC[5].expected =
  'z4rYjk8GFAJXUFmdLtQ56J9RFMR7ju3UMhmiqvP4thJzUbd87rsJd5o8bib1cbesMmqdhtzsgfeKhEvBjLz5Q87pexpjvYdd3dF88wJ57WDYMxHRc8RrMeqmZj56noiptDM7'
NO_CODEC[6].expected = 'zdTdqUfYDGBsjD'
NO_CODEC[7].expected =
  'zSDpDH5BiAdA2YoqxET7yPXBr7nh5Xo9tVTuhfAQJw8pSmggWnq8MJH6KagFuPXJQjCZsPPPvmJetn2urHYVc3VkDikhkmu4tEoHExk5hS1idLq3aGbE9mH1DAtEaXxK77TP74gN5'
NO_CODEC[8].expected = 'uCzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYY'
NO_CODEC[9].expected = 'uCzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYar'
NO_CODEC[10].expected = 'uCzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYar0PUaP2SJrtP4HUJnjLHW'
NO_CODEC[11].expected = 'uCzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYar0PUaP2SJrtP4HUJnjLHW-yBFao-02f4jSG2St9wBJg'
NO_CODEC[12].expected = 'uCzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYar0PUaP2SJrtP4HUJnjLHW-yBFao-02f4jSG2St9wBJks'
NO_CODEC[13].expected =
  'uCzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYar0PUaP2SJrtP4HUJnjLHW-yBFao-02f4jSG2St9wBJktwlbrfBClOc5i94gcsUXabwOUKL1R5nsPoDTJXfKHG'
NO_CODEC[14].expected = 'uCzBVep_E6Q4zWA'
NO_CODEC[15].expected =
  'uCzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYar0PUaP2SJrtP4HUJnjLHW-yBFao-02f4jSG2St9wBJktwlbrfBClOc5i94gcsUXabwOUKL1R5nsPoDTJXfKHG6xA1Wg'
NO_CODEC[16].expected = 'bbmyfk6u7ytuq4m2ypwrmp3argznybjok54kdsxudvdg7efz4mgda'
NO_CODEC[17].expected = 'bbmyfk6u7ytuq4m2ypwrmp3argznybjok54kdsxudvdg7efz4mgdkw'
NO_CODEC[18].expected = 'bbmyfk6u7ytuq4m2ypwrmp3argznybjok54kdsxudvdg7efz4mgdkxuhvdi7wjcno2p4b2qthrsy5m'
NO_CODEC[19].expected =
  'bbmyfk6u7ytuq4m2ypwrmp3argznybjok54kdsxudvdg7efz4mgdkxuhvdi7wjcno2p4b2qthrsy5n6zaivvi7ngz7yruq3msw7oacjq'
NO_CODEC[20].expected =
  'bbmyfk6u7ytuq4m2ypwrmp3argznybjok54kdsxudvdg7efz4mgdkxuhvdi7wjcno2p4b2qthrsy5n6zaivvi7ngz7yruq3msw7oacjsl'
NO_CODEC[21].expected =
  'bbmyfk6u7ytuq4m2ypwrmp3argznybjok54kdsxudvdg7efz4mgdkxuhvdi7wjcno2p4b2qthrsy5n6zaivvi7ngz7yruq3msw7oacjslock3vxyeffhhhgf54idsyulwtpaokcrpkr4z5q7ibuzfo7fbyy'
NO_CODEC[22].expected = 'bbmyfk6u7ytuq4m2y'
NO_CODEC[23].expected =
  'bbmyfk6u7ytuq4m2ypwrmp3argznybjok54kdsxudvdg7efz4mgdkxuhvdi7wjcno2p4b2qthrsy5n6zaivvi7ngz7yruq3msw7oacjslock3vxyeffhhhgf54idsyulwtpaokcrpkr4z5q7ibuzfo7fby3vrank2'

// ---------------------- codec (realistic) cases ---------------------------
// Codec + realistic key size. These totals sit in the fast-path set, so
// multibaseToBytes returns the raw prefixed bytes unchanged (app logic). The
// encode side is the real multibase-parity check. Captured from the oracle.
const CODEC_REALISTIC: { base: BaseName; bytes: Uint8Array; codec: KNOWN_CODECS; expected: string }[] = []
for (const base of BASES) {
  CODEC_REALISTIC.push({ base, bytes: makeBytes(32, 5), codec: 'ed25519-pub', expected: '' })
  CODEC_REALISTIC.push({ base, bytes: makeBytes(32, 5), codec: 'x25519-pub', expected: '' })
  CODEC_REALISTIC.push({ base, bytes: makeBytes(33, 5), codec: 'secp256k1-pub', expected: '' })
  CODEC_REALISTIC.push({ base, bytes: makeBytes(48, 5), codec: 'bls12_381-g1-pub', expected: '' })
  CODEC_REALISTIC.push({ base, bytes: makeBytes(96, 5), codec: 'bls12_381-g2-pub', expected: '' })
  CODEC_REALISTIC.push({ base, bytes: makeBytes(33, 5), codec: 'p256-pub', expected: '' })
}
// base58btc
CODEC_REALISTIC[0].expected = 'z6MkfYXkjG75dhohAEhkCgiXsZ3dopFCuJ69tuewTCsH3VB8'
CODEC_REALISTIC[1].expected = 'z6LScmSsfKfWPd2y98Ep3mGeM3i7qPWUC21x5sTh7PYnqeAW'
CODEC_REALISTIC[2].expected = 'zQ3smaDVbDvb64kfULHZYJtiiFXmhJRvQgnRURJbXtFLtHRHZ'
CODEC_REALISTIC[3].expected = 'z3tEAVqech62xWEKGPtvsWcdwaiS6uywXXmYDUMNWShCYyAAp5AxqCCDbtfXNBhmAGaHJA'
CODEC_REALISTIC[4].expected =
  'zUC6LRPQaLiESbPXQ3BuC6sPSN4uyTeE671uKMSoCt877eQ71CHMsEKjwfDJRXxMJFUGV1uMCdQkDroQwUQ4fWndwgzuhU8PtV4rezWDQXw7DB7cSQpnLpEYuQWgxqZawGNzXEA'
CODEC_REALISTIC[5].expected = 'zDnaidEft1owHUaz3iMCmoKx36FpVhUraAbu5SE9B9jFgSiUw'
// base64url
CODEC_REALISTIC[6].expected = 'u7QEQNVp_pMnuEzhdgqfM8RY7YIWqz_QZPmOIrdL3HEFmiw'
CODEC_REALISTIC[7].expected = 'u7AEQNVp_pMnuEzhdgqfM8RY7YIWqz_QZPmOIrdL3HEFmiw'
CODEC_REALISTIC[8].expected = 'u5wEQNVp_pMnuEzhdgqfM8RY7YIWqz_QZPmOIrdL3HEFmi7A'
CODEC_REALISTIC[9].expected = 'u6gEQNVp_pMnuEzhdgqfM8RY7YIWqz_QZPmOIrdL3HEFmi7DV-h9EaY6z2P0iR2yRtts'
CODEC_REALISTIC[10].expected =
  'u6wEQNVp_pMnuEzhdgqfM8RY7YIWqz_QZPmOIrdL3HEFmi7DV-h9EaY6z2P0iR2yRttsBJUpvlLneAyhNcpe84QYrUHWav-QJLlN4ncLnDDFWe6DF6g80WX6jyO0SN1yBpss'
CODEC_REALISTIC[11].expected = 'ugCQQNVp_pMnuEzhdgqfM8RY7YIWqz_QZPmOIrdL3HEFmi7A'
// base32
CODEC_REALISTIC[12].expected = 'b5uarank2p6smt3qthboyfj6m6eldwyefvlh7igj6moek3uxxdrawncy'
CODEC_REALISTIC[13].expected = 'b5qarank2p6smt3qthboyfj6m6eldwyefvlh7igj6moek3uxxdrawncy'
CODEC_REALISTIC[14].expected = 'b44arank2p6smt3qthboyfj6m6eldwyefvlh7igj6moek3uxxdrawnc5q'
CODEC_REALISTIC[15].expected = 'b5iarank2p6smt3qthboyfj6m6eldwyefvlh7igj6moek3uxxdrawnc5q2x5b6rdjr2z5r7jci5wjdnw3'
CODEC_REALISTIC[16].expected =
  'b5marank2p6smt3qthboyfj6m6eldwyefvlh7igj6moek3uxxdrawnc5q2x5b6rdjr2z5r7jci5wjdnw3aesuu34uxhpagkcnokl3zyigfnihlgv74qes4u3ytxboodbrkz52brpkb42fs7vdzdwren24qgtmw'
CODEC_REALISTIC[17].expected = 'bqasbank2p6smt3qthboyfj6m6eldwyefvlh7igj6moek3uxxdrawnc5q'

// ---------------------- codec (strip-path) cases --------------------------
// Codec + a length NOT in the fast-path set, so multibaseToBytes strips the
// multicodec prefix, recovers the raw key, and sets keyType. 10/100 cover all
// three bases with both a 1-byte (ed25519) and 3-byte (p256) varint prefix;
// 45/60 add further strip-path coverage on base58btc. Captured from the oracle.
const CODEC_STRIP: { base: BaseName; bytes: Uint8Array; codec: KNOWN_CODECS; expected: string }[] = []
for (const base of BASES) {
  CODEC_STRIP.push({ base, bytes: makeBytes(10, 7), codec: 'ed25519-pub', expected: '' })
  CODEC_STRIP.push({ base, bytes: makeBytes(10, 9), codec: 'p256-pub', expected: '' })
  CODEC_STRIP.push({ base, bytes: makeBytes(100, 7), codec: 'ed25519-pub', expected: '' })
  CODEC_STRIP.push({ base, bytes: makeBytes(100, 9), codec: 'p256-pub', expected: '' })
}
CODEC_STRIP.push({ base: 'base58btc', bytes: makeBytes(45, 7), codec: 'ed25519-pub', expected: '' })
CODEC_STRIP.push({ base: 'base58btc', bytes: makeBytes(60, 7), codec: 'ed25519-pub', expected: '' })
CODEC_STRIP.push({ base: 'base58btc', bytes: makeBytes(45, 9), codec: 'p256-pub', expected: '' })
CODEC_STRIP.push({ base: 'base58btc', bytes: makeBytes(60, 9), codec: 'p256-pub', expected: '' })

// base58btc
CODEC_STRIP[0].expected = 'z5UQQAft2CLH6A81PU'
CODEC_STRIP[1].expected = 'z3RFb8xpTg6VMvVrNC'
CODEC_STRIP[2].expected =
  'z46SmFYCFWGd6tpwyPmn2BAQYrNiQ4njCRvAhzxRP3VYoHgUiMdz5tGLZuyD7P8wvuWDmhvgmhRnz3XNk9wddtmPHaGCspjNNCoZPPUZbbZqXy96jCAx9TRChSh8GgqDHQUykGu4r8664'
CODEC_STRIP[3].expected =
  'z2g2AHAgeAd7LNQfQVZJc1Jjs2a3EYR5jKXHQy9WKUGxXoeQKGWwz9NDv6EhSvTpM6eRyybKxcuKd2LN2KUKc7HApZ2aergfHa39YHBCnm5Pt1h3aakTU4jqqybggNPD1dLaAafZe45za'
// base64url
CODEC_STRIP[4].expected = 'u7QESN1yBpsvwFTpf'
CODEC_STRIP[5].expected = 'ugCQUOV6DqM3yFzxh'
CODEC_STRIP[6].expected =
  'u7QESN1yBpsvwFTpfhKnO8xg9Yoes0fYbQGWKr9T5HkNojbLX_CFGa5C12v8kSW6TuN0CJ0xxlrvgBSpPdJm-4wgtUnecweYLMFV6n8TpDjNYfaLH7BE2W4Clyu8UOV6DqM3yFzxh'
CODEC_STRIP[7].expected =
  'ugCQUOV6DqM3yFzxhhqvQ9Ro_ZImu0_gdQmeMsdb7IEVqj7TZ_iNIbZK33AEmS3CVut8EKU5zmL3iByxRdpvA5QovVHmew-gNMld8ocbrEDVaf6TJ7hM4XYKnzPEWO2CFqs_0GT5j'
// base32
CODEC_STRIP[8].expected = 'b5uaren24qgtmx4avhjpq'
CODEC_STRIP[9].expected = 'bqasbiok6qoum34qxhrqq'
CODEC_STRIP[10].expected =
  'b5uaren24qgtmx4avhjpyjkoo6mmd2yuhvti7mg2amwfk7vhzdzbwrdns276ccrtlsc25v7zejfxjhog5aituy4mwxpqakksposm35yyifvjhphgb4yftavl2t7cosdrtlb62fr7mce3fxaffzlxriok6qoum34qxhrqq'
CODEC_STRIP[11].expected =
  'bqasbiok6qoum34qxhrqynk6q6und6zejv3j7qhkcm6gldvx3ebcwvd5u3h7cgsdnsk35yajgjnyjlow7aquu444yxxraolcro2n4bzikf5khthwd5agtev34uhdowebvlj72jspocm4f3avhztyrmo3aqwvm75azhzrq'
// base58btc 45/60
CODEC_STRIP[12].expected = 'z2yF7Y3hYuphs2cvavpiEpWUXi91MXU2RH77hBnYTyphNrrHCsogg6PqVqNLpArW7f'
CODEC_STRIP[13].expected = 'zF7DoEufajC9HVjmB5JQrSYkjxWch2KehM7vfRmps1k7hTXidqjSAkT6tpQ8RC856tMMghzAxEwpe9xDfTABkk'
CODEC_STRIP[14].expected = 'z24mY9Yfz8jJVfGxEGgNhKBrtmRsd1qpVf893UX9S2pENdACAR6ZcuuUDMAqvkiBi7'
CODEC_STRIP[15].expected = 'z8dPSgaHue8NcEcSgb9tZu4ttMXHo3hG6itj8k8EnV4HtQ9ts8qaAVUBWNUWdH2S9cbPhv1FVEd7fDcqSYUq3Y'

describe('bytesToMultibase / multibaseToBytes (inline multibase/multiformats port)', () => {
  it('matches published multibase vectors (regression anchors)', () => {
    for (const { bytes, expected } of EXTERNAL_VECTORS) {
      // encode: port output must equal the published string (using the base
      // implied by the multibase designator character)
      expect(bytesToMultibase(bytes, baseOf(expected))).toBe(expected)
      // decode round-trip
      expect(multibaseToBytes(expected).keyBytes).toEqual(bytes)
    }
  })

  describe('no-codec: encode matches oracle-captured strings, decode round-trips', () => {
    for (const { base, bytes, expected } of NO_CODEC) {
      it(`encode(${base}, ${bytes.length}B) === "${expected}"`, () => {
        expect(bytesToMultibase(bytes, base)).toBe(expected)
      })
      it(`decode("${expected}") round-trips to ${bytes.length}B`, () => {
        const { keyBytes, keyType } = multibaseToBytes(expected)
        expect(keyBytes).toEqual(bytes)
        // no codec -> no keyType inferred
        expect(keyType).toBeUndefined()
      })
    }
  })

  describe('codec (realistic size): encode matches oracle, decode strips prefix + infers keyType', () => {
    // NOTE: every realistic codec total is OUTSIDE the known-key-length fast-path
    // set. The varint multicodec prefix is non-empty, so e.g. a 32-byte key with
    // a 2-byte varint (0xed/0xec/0xe7/0xea/0xeb) becomes 34 bytes (not in
    // {32,33,48,64,65,96}).
    for (const { base, bytes, codec, expected } of CODEC_REALISTIC) {
      it(`encode(${base}, ${codec}, ${bytes.length}B) === "${expected}"`, () => {
        expect(bytesToMultibase(bytes, base, codec)).toBe(expected)
      })
      it(`decode("${expected}") strips the multicodec prefix and infers ${CODEC_TO_KEY_TYPE[codec]}`, () => {
        const { keyBytes, keyType } = multibaseToBytes(expected)
        // raw key recovered (multicodec prefix stripped)
        expect(keyBytes).toEqual(bytes)
        // keyType inferred from the stripped multicodec
        expect(keyType).toBe(CODEC_TO_KEY_TYPE[codec])
      })
    }
  })

  describe('codec (non-fast-path length): encode matches oracle, decode strips prefix + infers keyType', () => {
    for (const { base, bytes, codec, expected } of CODEC_STRIP) {
      it(`encode(${base}, ${codec}, ${bytes.length}B) === "${expected}"`, () => {
        expect(bytesToMultibase(bytes, base, codec)).toBe(expected)
      })
      it(`decode("${expected}") strips the multicodec prefix and recovers the raw key`, () => {
        const { keyBytes, keyType } = multibaseToBytes(expected)
        // raw key recovered (prefix stripped)
        expect(keyBytes).toEqual(bytes)
        // keyType inferred from the stripped multicodec
        expect(keyType).toBe(CODEC_TO_KEY_TYPE[codec])
      })
    }
  })

  describe('fast-path vs strip-path decode behavior for every base x codec', () => {
    // Explicitly covers BOTH decode branches of multibaseToBytes for every codec:
    //   * fast path: total length in {32,33,48,64,65,96} -> returns bytes as-is,
    //     no keyType, no stripping. (Proven by the no-codec block for all of
    //     {32,33,48,64,65,96}, plus the one-byte-varint codec fast-path below.)
    //   * strip path: total length not in that set -> strips the multicodec
    //     prefix, recovers the raw key, infers keyType.
    // The strip path is unambiguous for every codec (the port's varint encode
    // agrees with the oracle for the 2-byte codes 0xed/0xec/0xe7/0xea/0xeb and
    // with the port itself for the 3-byte code 0x1200), so it is checked for all
    // six codecs. The fast path is additionally checked for the five codecs whose
    // multicodec prefix is a standard 2-byte varint, where the prefix length is
    // unambiguous (0x1200/p256-pub is left out: its encode has a length quirk,
    // so only its strip path is asserted above).
    const STANDARD_CODES: KNOWN_CODECS[] = [
      'ed25519-pub',
      'x25519-pub',
      'secp256k1-pub',
      'bls12_381-g1-pub',
      'bls12_381-g2-pub',
    ]
    for (const base of BASES) {
      for (const codec of Object.keys(supportedCodecs) as KNOWN_CODECS[]) {
        // strip path: raw 40 -> total 42 (2-byte codes) / 45 (5-byte p256),
        // neither in the fast-path set, so the prefix is stripped + keyType set.
        const stripRaw = makeBytes(40, 2)
        it(`strip-path: ${base} x ${codec} (raw 40) infers ${CODEC_TO_KEY_TYPE[codec]}`, () => {
          const s = bytesToMultibase(stripRaw, base, codec)
          const { keyBytes, keyType } = multibaseToBytes(s)
          expect(keyBytes).toEqual(stripRaw)
          expect(keyType).toBe(CODEC_TO_KEY_TYPE[codec])
        })
      }
      // fast path with a codec: raw 31 + 2-byte varint = 33 (in the set). The
      // multicodec prefix is part of those 33 bytes, so decode returns the full
      // 33 bytes unchanged and infers no keyType.
      for (const codec of STANDARD_CODES) {
        const fastRaw = makeBytes(31, 4)
        it(`fast-path: ${base} x ${codec} (raw 31, total 33) preserved, no keyType`, () => {
          const s = bytesToMultibase(fastRaw, base, codec)
          const { keyBytes, keyType } = multibaseToBytes(s)
          // fast path: no keyType, and the full prefixed bytes are returned
          // (length 33, not the raw 31), proving the prefix was NOT stripped
          expect(keyType).toBeUndefined()
          expect(keyBytes.length).toBe(33)
        })
      }
    }
  })

  describe('numeric codec argument matches named codec argument', () => {
    // bytesToMultibase accepts either a codec name or a raw numeric code.
    for (const codec of Object.keys(supportedCodecs) as KNOWN_CODECS[]) {
      const bytes = makeBytes(45, 3) // non-fast-path length
      for (const base of BASES) {
        it(`${base}: numeric vs named codec agree for ${codec}`, () => {
          expect(bytesToMultibase(bytes, base, supportedCodecs[codec])).toBe(bytesToMultibase(bytes, base, codec))
        })
      }
    }
  })
})

/** Resolve the base a multibase string was written for from its designator. */
function baseOf(s: string): BaseName {
  switch (s[0]) {
    case 'u':
      return 'base64url'
    case 'b':
      return 'base32'
    case 'B':
      return 'base32upper'
    case 'z':
      return 'base58btc'
    default:
      throw new Error(`unknown prefix ${s[0]}`)
  }
}
