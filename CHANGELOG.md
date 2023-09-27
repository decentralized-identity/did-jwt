## [7.4.1](https://github.com/decentralized-identity/did-jwt/compare/7.4.0...7.4.1) (2023-09-27)


### Bug Fixes

* accept 32 or 64 bytes as keys for EdDSASigner ([#299](https://github.com/decentralized-identity/did-jwt/issues/299)) ([546f31c](https://github.com/decentralized-identity/did-jwt/commit/546f31cd0f6baa5112c70da87a6111168fb6d57e)), closes [#289](https://github.com/decentralized-identity/did-jwt/issues/289)

# [7.4.0](https://github.com/decentralized-identity/did-jwt/compare/7.3.0...7.4.0) (2023-09-27)


### Features

* interpret publicKeyMultibase as multicodec ([#298](https://github.com/decentralized-identity/did-jwt/issues/298)) ([bf76cea](https://github.com/decentralized-identity/did-jwt/commit/bf76ceab6b6b84b22919ccefeaeebbd973220d1b)), closes [#297](https://github.com/decentralized-identity/did-jwt/issues/297)

# [7.3.0](https://github.com/decentralized-identity/did-jwt/compare/7.2.8...7.3.0) (2023-09-23)


### Features

* **deps:** replace bech32 and old chacha with noble and scure packages ([#294](https://github.com/decentralized-identity/did-jwt/issues/294)) ([853c799](https://github.com/decentralized-identity/did-jwt/commit/853c79993925ff65777d07800594a11d29687bfc))

## [7.2.8](https://github.com/decentralized-identity/did-jwt/compare/7.2.7...7.2.8) (2023-09-18)


### Bug Fixes

* **deps:** update dependency multiformats to v12.1.1 ([#290](https://github.com/decentralized-identity/did-jwt/issues/290)) ([4fe1ef1](https://github.com/decentralized-identity/did-jwt/commit/4fe1ef1af95f738662427046ff1719355771edf1))

## [7.2.7](https://github.com/decentralized-identity/did-jwt/compare/7.2.6...7.2.7) (2023-09-04)


### Bug Fixes

* **deps:** update dependency multiformats to v12.1.0 ([b8bafb0](https://github.com/decentralized-identity/did-jwt/commit/b8bafb0a85eaff3153a012b70a6d9f5fe24e27db))

## [7.2.6](https://github.com/decentralized-identity/did-jwt/compare/7.2.5...7.2.6) (2023-08-23)


### Bug Fixes

* **deps:** update all non-major dependencies ([9fe266d](https://github.com/decentralized-identity/did-jwt/commit/9fe266d5fdbcbb350d71d8977aace860dfae31e4))

## [7.2.5](https://github.com/decentralized-identity/did-jwt/compare/7.2.4...7.2.5) (2023-08-04)


### Bug Fixes

* **deps:** update dependency uint8arrays to v4.0.6 ([cf111bc](https://github.com/decentralized-identity/did-jwt/commit/cf111bcd760e5f68ac94863aa2a6cd5c1ae5dd42))

## [7.2.4](https://github.com/decentralized-identity/did-jwt/compare/7.2.3...7.2.4) (2023-06-26)


### Bug Fixes

* **deps:** update dependency multiformats to v12 ([#285](https://github.com/decentralized-identity/did-jwt/issues/285)) ([90b2d68](https://github.com/decentralized-identity/did-jwt/commit/90b2d68e321dda12f04e796b7c2e4fb0e7fddd80))

## [7.2.3](https://github.com/decentralized-identity/did-jwt/compare/7.2.2...7.2.3) (2023-06-26)


### Bug Fixes

* add padding to bigints whose byte-length is expected ([#288](https://github.com/decentralized-identity/did-jwt/issues/288)) ([bfa8e71](https://github.com/decentralized-identity/did-jwt/commit/bfa8e714cbb104d7761e4e23f481c39675bbef31)), closes [#283](https://github.com/decentralized-identity/did-jwt/issues/283)

## [7.2.2](https://github.com/decentralized-identity/did-jwt/compare/7.2.1...7.2.2) (2023-06-07)


### Bug Fixes

* **deps:** update dependency uint8arrays to v4.0.4 ([d481064](https://github.com/decentralized-identity/did-jwt/commit/d4810647900310fc05bed0a06277d34a7b5a04cf))

## [7.2.1](https://github.com/decentralized-identity/did-jwt/compare/7.2.0...7.2.1) (2023-06-03)


### Bug Fixes

* **deps:** update all non-major dependencies ([ce185d5](https://github.com/decentralized-identity/did-jwt/commit/ce185d5c0b3df781394326313dc39a68ad0eff61))

# [7.2.0](https://github.com/decentralized-identity/did-jwt/compare/7.1.0...7.2.0) (2023-05-17)


### Features

* refactor JWE code to allow external algorithm implementations ([#284](https://github.com/decentralized-identity/did-jwt/issues/284)) ([e5d570d](https://github.com/decentralized-identity/did-jwt/commit/e5d570da745b89bba9195536210b188e970f1e68))

# [7.1.0](https://github.com/decentralized-identity/did-jwt/compare/7.0.0...7.1.0) (2023-05-03)


### Features

* add support for ConditionalProof2022 verificationMethods ([#272](https://github.com/decentralized-identity/did-jwt/issues/272)) ([9bebe3f](https://github.com/decentralized-identity/did-jwt/commit/9bebe3fc7393db0a9b1d06655337a6e8b4a9eaf9))

# [7.0.0](https://github.com/decentralized-identity/did-jwt/compare/6.11.6...7.0.0) (2023-04-19)


### Features

* **deps:** replace @stablelib/ with noble-crypto ([#280](https://github.com/decentralized-identity/did-jwt/issues/280)) ([0f6221a](https://github.com/decentralized-identity/did-jwt/commit/0f6221ab7b96383de2f4cdee7d05dd31a5c03c76)), closes [#270](https://github.com/decentralized-identity/did-jwt/issues/270)


### BREAKING CHANGES

* **deps:** `ES256*` signers are now enforcing canonical signatures (s-value less than or equal to half the curve order). This will likely break some expectations for dependents that were using the previous versions.

## [6.11.6](https://github.com/decentralized-identity/did-jwt/compare/6.11.5...6.11.6) (2023-04-03)


### Bug Fixes

* **deps:** update dependency canonicalize to v2 ([a916e62](https://github.com/decentralized-identity/did-jwt/commit/a916e6216c82db98cf5023cd66fbacb7515681c7))

## [6.11.5](https://github.com/decentralized-identity/did-jwt/compare/6.11.4...6.11.5) (2023-03-16)


### Bug Fixes

* **deps:** Update dependency did-resolver to v4.1.0 ([85de440](https://github.com/decentralized-identity/did-jwt/commit/85de44043021e6bd7217aa3cb5c2af72cc4f69f3))

## [6.11.4](https://github.com/decentralized-identity/did-jwt/compare/6.11.3...6.11.4) (2023-03-15)


### Bug Fixes

* **deps:** update all non-major dependencies ([c637b84](https://github.com/decentralized-identity/did-jwt/commit/c637b84493ee7c3591a7ddcf9ca90fd7baa9287a))

## [6.11.3](https://github.com/decentralized-identity/did-jwt/compare/6.11.2...6.11.3) (2023-03-15)


### Bug Fixes

* **deps:** remove dev dependency did-key-creator ([#274](https://github.com/decentralized-identity/did-jwt/issues/274)) ([fbe09e1](https://github.com/decentralized-identity/did-jwt/commit/fbe09e1639a323fc39b31c3578ba8b7889f1f9f1))

## [6.11.2](https://github.com/decentralized-identity/did-jwt/compare/6.11.1...6.11.2) (2023-03-08)


### Bug Fixes

* provide hash algorithms as exported functions ([#271](https://github.com/decentralized-identity/did-jwt/issues/271)) ([71cc19b](https://github.com/decentralized-identity/did-jwt/commit/71cc19b9a88a76d3fb754d77a4773678460020c5))

## [6.11.1](https://github.com/decentralized-identity/did-jwt/compare/6.11.0...6.11.1) (2023-02-13)


### Bug Fixes

* add ESM types exports resolution ([#269](https://github.com/decentralized-identity/did-jwt/issues/269)) ([dea4e6b](https://github.com/decentralized-identity/did-jwt/commit/dea4e6b86cdda39170f69d7e8c4b2b7e237a4bfb))

# [6.11.0](https://github.com/decentralized-identity/did-jwt/compare/6.10.1...6.11.0) (2022-12-13)


### Features

* add support for SIOP request JWT ([#262](https://github.com/decentralized-identity/did-jwt/issues/262)) ([3259ffd](https://github.com/decentralized-identity/did-jwt/commit/3259ffd25840e9baf8046494fdafe3f0697e13b9))

## [6.10.1](https://github.com/decentralized-identity/did-jwt/compare/6.10.0...6.10.1) (2022-11-29)


### Bug Fixes

* support jwts generated for JWT VC Presentation Profile ([#260](https://github.com/decentralized-identity/did-jwt/issues/260)) ([8b36550](https://github.com/decentralized-identity/did-jwt/commit/8b3655097a1382934cabdf774d580e6731a636b1))

# [6.10.0](https://github.com/decentralized-identity/did-jwt/compare/6.9.0...6.10.0) (2022-11-28)


### Features

* support JsonWebKey for ES256K(-R)([#259](https://github.com/decentralized-identity/did-jwt/issues/259)) ([f9f1aeb](https://github.com/decentralized-identity/did-jwt/commit/f9f1aebb33ef8adfe2200a5d0e365a0c12042098))

# [6.9.0](https://github.com/decentralized-identity/did-jwt/compare/6.8.0...6.9.0) (2022-10-15)


### Features

* add ES256 to JWT verifier ([#254](https://github.com/decentralized-identity/did-jwt/issues/254)) ([86a4d23](https://github.com/decentralized-identity/did-jwt/commit/86a4d2328a33c1b38ffa7cc31374c5a3f1461a44))

# [6.8.0](https://github.com/decentralized-identity/did-jwt/compare/6.7.0...6.8.0) (2022-09-06)


### Features

* add VerifierAlgorithm for ES256 ([#249](https://github.com/decentralized-identity/did-jwt/issues/249)) ([05283ac](https://github.com/decentralized-identity/did-jwt/commit/05283aca631f06a4c5db971bd71c46b9e185595f))

# [6.7.0](https://github.com/decentralized-identity/did-jwt/compare/6.6.1...6.7.0) (2022-09-02)


### Features

* add ES256 signer alg for jwt ([#248](https://github.com/decentralized-identity/did-jwt/issues/248)) ([3789c9d](https://github.com/decentralized-identity/did-jwt/commit/3789c9d0b88dca9b9ed49e54175545381c8b339a))

## [6.6.1](https://github.com/decentralized-identity/did-jwt/compare/6.6.0...6.6.1) (2022-09-02)


### Bug Fixes

* remove `recoverable` parameter from ES256Signer ([#247](https://github.com/decentralized-identity/did-jwt/issues/247)) ([a68ac47](https://github.com/decentralized-identity/did-jwt/commit/a68ac47d97f73615e32f39dbd263a2acdd1ee1ec))

# [6.6.0](https://github.com/decentralized-identity/did-jwt/compare/6.5.0...6.6.0) (2022-08-19)


### Features

* export error prefixes as object instead of enum ([#244](https://github.com/decentralized-identity/did-jwt/issues/244)) ([e5b070d](https://github.com/decentralized-identity/did-jwt/commit/e5b070d369acdaabeb7ea4e540e7cc0d6f945cb9)), closes [#243](https://github.com/decentralized-identity/did-jwt/issues/243)

# [6.5.0](https://github.com/decentralized-identity/did-jwt/compare/6.4.0...6.5.0) (2022-08-18)


### Features

* add `aud` override policy for verification ([#242](https://github.com/decentralized-identity/did-jwt/issues/242)) ([87cbfd0](https://github.com/decentralized-identity/did-jwt/commit/87cbfd0f719fc2fdb0ac83ed9ca964b3c1b1b1a9)), closes [#239](https://github.com/decentralized-identity/did-jwt/issues/239)

# [6.4.0](https://github.com/decentralized-identity/did-jwt/compare/6.3.0...6.4.0) (2022-08-12)


### Features

* add JWT verification policies to override timestamp checking ([#241](https://github.com/decentralized-identity/did-jwt/issues/241)) ([2934f4c](https://github.com/decentralized-identity/did-jwt/commit/2934f4ce6cf9209757839ac1130601fd5872f39b))

# [6.3.0](https://github.com/decentralized-identity/did-jwt/compare/6.2.2...6.3.0) (2022-08-07)


### Features

* add ES256Signer ([#240](https://github.com/decentralized-identity/did-jwt/issues/240)) ([08b2761](https://github.com/decentralized-identity/did-jwt/commit/08b2761e97d7de47a9ed7456e29fda82121cee72))

## [6.2.2](https://github.com/decentralized-identity/did-jwt/compare/6.2.1...6.2.2) (2022-08-02)


### Bug Fixes

* **deps:** Update dependency did-resolver to v4 ([f4276b5](https://github.com/decentralized-identity/did-jwt/commit/f4276b5e7539668e513bfc8d60879b36ea8ac860))

## [6.2.1](https://github.com/decentralized-identity/did-jwt/compare/6.2.0...6.2.1) (2022-07-21)


### Bug Fixes

* remove nullish coalescing operator ([#237](https://github.com/decentralized-identity/did-jwt/issues/237)) ([8cf01de](https://github.com/decentralized-identity/did-jwt/commit/8cf01de0a7c47cba4a9bdf2b1a13396febdee7e3)), closes [#236](https://github.com/decentralized-identity/did-jwt/issues/236)

# [6.2.0](https://github.com/decentralized-identity/did-jwt/compare/6.1.2...6.2.0) (2022-06-24)


### Features

* add Ed25519VerificationKey2020 & JsonWebKey2020 as accepted methods ([#235](https://github.com/decentralized-identity/did-jwt/issues/235)) ([60987e0](https://github.com/decentralized-identity/did-jwt/commit/60987e0025b1fd45e4a8e583a8c1e28df403fa0b))

## [6.1.2](https://github.com/decentralized-identity/did-jwt/compare/6.1.1...6.1.2) (2022-06-06)


### Bug Fixes

* ES256K-R verification with checksumAddress in eip155 blockchainAccountId ([#232](https://github.com/decentralized-identity/did-jwt/issues/232)) ([dcbd0b9](https://github.com/decentralized-identity/did-jwt/commit/dcbd0b95c338182452b4df26fde8a4ba6563116a)), closes [#231](https://github.com/decentralized-identity/did-jwt/issues/231)

## [6.1.1](https://github.com/decentralized-identity/did-jwt/compare/6.1.0...6.1.1) (2022-06-06)


### Bug Fixes

* **ci:** groom the build scripts and dependencies ([#230](https://github.com/decentralized-identity/did-jwt/issues/230)) ([34e943d](https://github.com/decentralized-identity/did-jwt/commit/34e943dc9e244564f3f40a0f086f29dddb67a64a))

# [6.1.0](https://github.com/decentralized-identity/did-jwt/compare/6.0.0...6.1.0) (2022-05-17)


### Features

* support Ed25519 publicKeyJwk ([#227](https://github.com/decentralized-identity/did-jwt/issues/227)) ([fd81edb](https://github.com/decentralized-identity/did-jwt/commit/fd81edb0aa3f9aafcd8ea9eff7f7b6f8c50ffac5))

# [6.0.0](https://github.com/decentralized-identity/did-jwt/compare/5.12.4...6.0.0) (2022-04-04)


### Bug Fixes

* remove parseKey, change ES256K and Ed25519 signers to Uint8Array only ([#224](https://github.com/decentralized-identity/did-jwt/issues/224)) ([9132caf](https://github.com/decentralized-identity/did-jwt/commit/9132caf50d58a79ccf42e43664cca048db885c78)), closes [#222](https://github.com/decentralized-identity/did-jwt/issues/222)


### BREAKING CHANGES

* The Signer classes exported by this library no longer accept private keys with string encodings, only `Uint8Array`. This reduces the potential ambiguity between different formats. Some utility methods are exported that allow users to convert some popular encodings to raw `Uint8Array`.

## [5.12.4](https://github.com/decentralized-identity/did-jwt/compare/5.12.3...5.12.4) (2022-01-27)


### Bug Fixes

* use uint8arrays instead of Buffer ([#217](https://github.com/decentralized-identity/did-jwt/issues/217)) ([d9de4fc](https://github.com/decentralized-identity/did-jwt/commit/d9de4fc30d65569545c1f5d62ee6d1850714232f)), closes [#216](https://github.com/decentralized-identity/did-jwt/issues/216)

## [5.12.3](https://github.com/decentralized-identity/did-jwt/compare/5.12.2...5.12.3) (2022-01-13)


### Bug Fixes

* **deps:** bump did-resolver to 3.1.5 ([6f6eca0](https://github.com/decentralized-identity/did-jwt/commit/6f6eca08ee8edfd95e8445816c6d1866410642ad))

## [5.12.2](https://github.com/decentralized-identity/did-jwt/compare/5.12.1...5.12.2) (2022-01-10)


### Bug Fixes

* finalize transition to ES modules ([#211](https://github.com/decentralized-identity/did-jwt/issues/211)) ([2de6ac9](https://github.com/decentralized-identity/did-jwt/commit/2de6ac932fb7dd3b8bfda7666f0a1dc5d6db4da5))

## [5.12.1](https://github.com/decentralized-identity/did-jwt/compare/5.12.0...5.12.1) (2021-12-03)


### Bug Fixes

* add missing quotes around undefined ([#207](https://github.com/decentralized-identity/did-jwt/issues/207)) ([4abd521](https://github.com/decentralized-identity/did-jwt/commit/4abd52125542f4f89998c2d70ee3221b3f41a432))

# [5.12.0](https://github.com/decentralized-identity/did-jwt/compare/5.11.1...5.12.0) (2021-11-19)


### Features

* allow alternative Bitcoin address prefixes ([#206](https://github.com/decentralized-identity/did-jwt/issues/206)) ([2087995](https://github.com/decentralized-identity/did-jwt/commit/208799509b1b6f180ce6408b1108df312f158769))

## [5.11.1](https://github.com/decentralized-identity/did-jwt/compare/5.11.0...5.11.1) (2021-11-10)


### Bug Fixes

* **deps:** bump did-resolver to 3.1.3 ([e15ba89](https://github.com/decentralized-identity/did-jwt/commit/e15ba8982b28ef85be66aca1c60dbe27fe0c36dc))

# [5.11.0](https://github.com/decentralized-identity/did-jwt/compare/5.10.0...5.11.0) (2021-11-10)


### Features

* CAIP 10 support for bip122 & cosmos ([#205](https://github.com/decentralized-identity/did-jwt/issues/205)) ([73cba89](https://github.com/decentralized-identity/did-jwt/commit/73cba89d6a0cbbff277ad0d5f4c5dd258de1d773))

# [5.10.0](https://github.com/decentralized-identity/did-jwt/compare/5.9.0...5.10.0) (2021-11-08)


### Features

* add recursive lookup for key exchange keys when encrypting data ([#203](https://github.com/decentralized-identity/did-jwt/issues/203)) ([63999a5](https://github.com/decentralized-identity/did-jwt/commit/63999a52741e65a83de0ea8621570cc12e4b0c91)), closes [#202](https://github.com/decentralized-identity/did-jwt/issues/202)

# [5.9.0](https://github.com/decentralized-identity/did-jwt/compare/5.8.0...5.9.0) (2021-10-21)


### Features

* support verification of OIDC SIOPv0.1 & SIOPv2 JWT ([#201](https://github.com/decentralized-identity/did-jwt/issues/201)) ([cebf2e6](https://github.com/decentralized-identity/did-jwt/commit/cebf2e6f255e559a1275bb97b35146ce72ce27f5))

# [5.8.0](https://github.com/decentralized-identity/did-jwt/compare/5.7.0...5.8.0) (2021-09-29)


### Features

* support publicKeyMultibase ([#200](https://github.com/decentralized-identity/did-jwt/issues/200)) ([0f4a81c](https://github.com/decentralized-identity/did-jwt/commit/0f4a81c36764ef06401282bbbaea6b6e704994ac))

# [5.7.0](https://github.com/decentralized-identity/did-jwt/compare/5.6.3...5.7.0) (2021-08-31)


### Features

* export JWTOptions and JWTVerifyOptions parameter types ([#198](https://github.com/decentralized-identity/did-jwt/issues/198)) ([8ba42e7](https://github.com/decentralized-identity/did-jwt/commit/8ba42e7d05f85c79784ae1c9afc5b557b9352dee)), closes [#197](https://github.com/decentralized-identity/did-jwt/issues/197)

## [5.6.3](https://github.com/decentralized-identity/did-jwt/compare/5.6.2...5.6.3) (2021-08-18)


### Bug Fixes

* **deps:** update dependency uint8arrays to v3 ([#193](https://github.com/decentralized-identity/did-jwt/issues/193)) ([ae4afec](https://github.com/decentralized-identity/did-jwt/commit/ae4afec562519f5903bbbad3596848fa5670466b))

## [5.6.2](https://github.com/decentralized-identity/did-jwt/compare/5.6.1...5.6.2) (2021-06-25)


### Bug Fixes

* add better error messages ([#189](https://github.com/decentralized-identity/did-jwt/issues/189)) ([db8f93a](https://github.com/decentralized-identity/did-jwt/commit/db8f93a2d3e0457ad00f8c32a3925da1a8265f93))

## [5.6.1](https://github.com/decentralized-identity/did-jwt/compare/5.6.0...5.6.1) (2021-06-11)


### Bug Fixes

* remove skid from the recipient header ([#188](https://github.com/decentralized-identity/did-jwt/issues/188)) ([0682cd1](https://github.com/decentralized-identity/did-jwt/commit/0682cd1336013a2afe95b650fb8ce4ccc2089ffa))

# [5.6.0](https://github.com/decentralized-identity/did-jwt/compare/5.5.3...5.6.0) (2021-06-09)


### Features

* enable remote ECDH for JWE [de]encrypters ([#186](https://github.com/decentralized-identity/did-jwt/issues/186)) ([ff26440](https://github.com/decentralized-identity/did-jwt/commit/ff264405658f54a6f0f1a236284a03cb47027225)), closes [#183](https://github.com/decentralized-identity/did-jwt/issues/183)

## [5.5.3](https://github.com/decentralized-identity/did-jwt/compare/5.5.2...5.5.3) (2021-06-07)


### Bug Fixes

* remove `type` from `JWTPayload` ([#185](https://github.com/decentralized-identity/did-jwt/issues/185)) ([1b63949](https://github.com/decentralized-identity/did-jwt/commit/1b63949c70ff48998dd89e57f2f99d5d6bc381cf))

## [5.5.2](https://github.com/decentralized-identity/did-jwt/compare/5.5.1...5.5.2) (2021-06-02)


### Bug Fixes

* remove `exports` statement from package.json ([#182](https://github.com/decentralized-identity/did-jwt/issues/182)) ([5dbd6df](https://github.com/decentralized-identity/did-jwt/commit/5dbd6df2308065c1abc03c89438589a4af274467)), closes [#181](https://github.com/decentralized-identity/did-jwt/issues/181)

## [5.5.1](https://github.com/decentralized-identity/did-jwt/compare/5.5.0...5.5.1) (2021-06-02)


### Bug Fixes

* **build:** non-minified outputs and better handling of strict mode ([#175](https://github.com/decentralized-identity/did-jwt/issues/175)) ([029b429](https://github.com/decentralized-identity/did-jwt/commit/029b429aa5fd9e1bc57ad6013c71a644f7b885ff)), closes [#173](https://github.com/decentralized-identity/did-jwt/issues/173) [#174](https://github.com/decentralized-identity/did-jwt/issues/174)
* **ci:** add GH push ability to build bot ([e50edf6](https://github.com/decentralized-identity/did-jwt/commit/e50edf6715272d10ca2accae2a73014d696f9c52))

# [5.5.0](https://github.com/decentralized-identity/did-jwt/compare/5.4.1...5.5.0) (2021-05-31)


### Features

* Add support for authenticated encryption ([#177](https://github.com/decentralized-identity/did-jwt/issues/177)) ([9a71b07](https://github.com/decentralized-identity/did-jwt/commit/9a71b077b2f0f6ad548e60e3e0222a3bfaa6a404))

## [5.4.1](https://github.com/decentralized-identity/did-jwt/compare/5.4.0...5.4.1) (2021-05-19)


### Bug Fixes

* don't run JSON.stringify on canonicalized data ([#172](https://github.com/decentralized-identity/did-jwt/issues/172)) ([5480bfc](https://github.com/decentralized-identity/did-jwt/commit/5480bfc55989620ff248540921563679bd204635)), closes [#171](https://github.com/decentralized-identity/did-jwt/issues/171)

# [5.4.0](https://github.com/decentralized-identity/did-jwt/compare/5.3.1...5.4.0) (2021-05-18)


### Features

* add option to canonicalize JSON payloads ([#161](https://github.com/decentralized-identity/did-jwt/issues/161)) ([4cfd3ee](https://github.com/decentralized-identity/did-jwt/commit/4cfd3eef41d93cd0829b50c9a9bde9be3a0512d0))

## [5.3.1](https://github.com/decentralized-identity/did-jwt/compare/5.3.0...5.3.1) (2021-05-15)


### Bug Fixes

* add repository to package.json ([#167](https://github.com/decentralized-identity/did-jwt/issues/167)) ([5ecbb32](https://github.com/decentralized-identity/did-jwt/commit/5ecbb322375e5eb998d6a8f2116b0980a997915e))

# [5.3.0](https://github.com/decentralized-identity/did-jwt/compare/5.2.0...5.3.0) (2021-05-11)


### Features

* use multiple keyAgreementKeys when creating JWE ([#166](https://github.com/decentralized-identity/did-jwt/issues/166)) ([e327ef2](https://github.com/decentralized-identity/did-jwt/commit/e327ef2a2af6f351079374c75fd473e3d9f38c74))

# [5.2.0](https://github.com/decentralized-identity/did-jwt/compare/5.1.2...5.2.0) (2021-04-22)


### Features

* add support for secp256k1 publicKeyJwk ([#160](https://github.com/decentralized-identity/did-jwt/issues/160)) ([1d578ba](https://github.com/decentralized-identity/did-jwt/commit/1d578ba9ab6afc48c9b7449ce3e495cd7a4d8449))

## [5.1.2](https://github.com/decentralized-identity/did-jwt/compare/5.1.1...5.1.2) (2021-03-26)


### Bug Fixes

* **deps:** use Resolvable type from did-resolver ([4641e56](https://github.com/decentralized-identity/did-jwt/commit/4641e56ba58c362ad63a68846d152c0dbf708682))

## [5.1.1](https://github.com/decentralized-identity/did-jwt/compare/5.1.0...5.1.1) (2021-03-25)


### Bug Fixes

* simplify expected Resolver type in verify methods ([#159](https://github.com/decentralized-identity/did-jwt/issues/159)) ([969de89](https://github.com/decentralized-identity/did-jwt/commit/969de8942c95ed8e82d092685ac3586c18c19d25)), closes [#158](https://github.com/decentralized-identity/did-jwt/issues/158)

# [5.1.0](https://github.com/decentralized-identity/did-jwt/compare/5.0.2...5.1.0) (2021-03-24)


### Features

* adapt to did core spec ([#156](https://github.com/decentralized-identity/did-jwt/issues/156)) ([4283ab3](https://github.com/decentralized-identity/did-jwt/commit/4283ab39ce33fddfb13be09df99db0f0cd0cd988)), closes [#155](https://github.com/decentralized-identity/did-jwt/issues/155)

## [5.0.2](https://github.com/decentralized-identity/did-jwt/compare/5.0.1...5.0.2) (2021-03-23)


### Bug Fixes

* **deps:** update dependencies ([#157](https://github.com/decentralized-identity/did-jwt/issues/157)) ([82da9e2](https://github.com/decentralized-identity/did-jwt/commit/82da9e2248f3861097e72edf519db5337d2aa3ad)), closes [#135](https://github.com/decentralized-identity/did-jwt/issues/135)

## [5.0.1](https://github.com/decentralized-identity/did-jwt/compare/5.0.0...5.0.1) (2021-03-11)


### Bug Fixes

* add explicit support for EcdsaSecp256k1RecoveryMethod2020 ([#153](https://github.com/decentralized-identity/did-jwt/issues/153)) ([2b04c34](https://github.com/decentralized-identity/did-jwt/commit/2b04c347b1115e2de22c604093521a04d44c2629))

# [5.0.0](https://github.com/decentralized-identity/did-jwt/compare/4.9.0...5.0.0) (2021-03-09)


### Features

* upgrade did-resolver to v3 ([#151](https://github.com/decentralized-identity/did-jwt/issues/151)) ([e02f56b](https://github.com/decentralized-identity/did-jwt/commit/e02f56b45a8af7031473888f8bff265268f73717))


### BREAKING CHANGES

* The `Resolver` used during verification is expected to conform to the latest spec.

# [4.9.0](https://github.com/decentralized-identity/did-jwt/compare/4.8.1...4.9.0) (2021-02-10)


### Features

* add `ES256KSigner` and `EdDSASigner` with uniform APIs ([#149](https://github.com/decentralized-identity/did-jwt/issues/149))([#78](https://github.com/decentralized-identity/did-jwt/issues/78)) ([cdd3c0f](https://github.com/decentralized-identity/did-jwt/commit/cdd3c0f75915b4ff161f2813eae22a9d254fb90f))

## [4.8.1](https://github.com/decentralized-identity/did-jwt/compare/4.8.0...4.8.1) (2020-12-18)


### Bug Fixes

* **deps:** update dependency uint8arrays to v2 ([#145](https://github.com/decentralized-identity/did-jwt/issues/145)) ([fef0308](https://github.com/decentralized-identity/did-jwt/commit/fef03086faebe5f3b0d419bd0562359bab351faa))

# [4.8.0](https://github.com/decentralized-identity/did-jwt/compare/4.7.1...4.8.0) (2020-12-09)


### Features

* **did auth:** update resolution of authentication entries in DIDDocument ([#143](https://github.com/decentralized-identity/did-jwt/issues/143)) ([a10ca34](https://github.com/decentralized-identity/did-jwt/commit/a10ca34ddea10019b09f71e81e83ad5e6696ac8d))

## [4.7.1](https://github.com/decentralized-identity/did-jwt/compare/4.7.0...4.7.1) (2020-12-08)


### Bug Fixes

* **verifyJWT:** fix verification of JWT using EdDSA alg ([#142](https://github.com/decentralized-identity/did-jwt/issues/142)) ([12e2b88](https://github.com/decentralized-identity/did-jwt/commit/12e2b887f74312b0735b8790182b7a220191ad8c)), closes [#141](https://github.com/decentralized-identity/did-jwt/issues/141)

# [4.7.0](https://github.com/decentralized-identity/did-jwt/compare/4.6.3...4.7.0) (2020-11-20)


### Features

* **jwt:** add skewTime option that replaces NBF_SKEW if present ([#140](https://github.com/decentralized-identity/did-jwt/issues/140)) ([8a8cb0f](https://github.com/decentralized-identity/did-jwt/commit/8a8cb0f62ba384d39438d8550bdba019cb8a6205))

## [4.6.3](https://github.com/decentralized-identity/did-jwt/compare/4.6.2...4.6.3) (2020-11-10)


### Bug Fixes

* support multiple pubkey encodings ([#139](https://github.com/decentralized-identity/did-jwt/issues/139)) ([c4ae63a](https://github.com/decentralized-identity/did-jwt/commit/c4ae63a689fef7b15f3ca8c19eb74e3557a010e8)), closes [#128](https://github.com/decentralized-identity/did-jwt/issues/128) [#127](https://github.com/decentralized-identity/did-jwt/issues/127)

## [4.6.2](https://github.com/decentralized-identity/did-jwt/compare/4.6.1...4.6.2) (2020-10-02)


### Bug Fixes

* export resolveX25519Encrypters function ([#134](https://github.com/decentralized-identity/did-jwt/issues/134)) ([0c80711](https://github.com/decentralized-identity/did-jwt/commit/0c80711a58ad6e1a3a23bdb864b5fab58202a3f8))

## [4.6.1](https://github.com/decentralized-identity/did-jwt/compare/4.6.0...4.6.1) (2020-10-01)


### Bug Fixes

* use EdDSA as the 'alg' header for Ed25519 signatures ([#131](https://github.com/decentralized-identity/did-jwt/issues/131)) ([2736ee7](https://github.com/decentralized-identity/did-jwt/commit/2736ee733546bd6cefc9765279ee3d258a5c3d43))

# [4.6.0](https://github.com/decentralized-identity/did-jwt/compare/4.5.1...4.6.0) (2020-10-01)


### Features

* add support for low level JWE functions ([#132](https://github.com/decentralized-identity/did-jwt/issues/132)) ([dc4e78b](https://github.com/decentralized-identity/did-jwt/commit/dc4e78b371a30b27587de25e9dacf56b825cd22b))

## [4.5.1](https://github.com/decentralized-identity/did-jwt/compare/4.5.0...4.5.1) (2020-08-31)


### Bug Fixes

* **deps:** reduce package size by replacing tweetnacl with stablelib([#129](https://github.com/decentralized-identity/did-jwt/issues/129)) ([fe81585](https://github.com/decentralized-identity/did-jwt/commit/fe81585dd5e7686cc3cc58c0763da61a8c8d08a6))

# [4.5.0](https://github.com/decentralized-identity/did-jwt/compare/4.4.2...4.5.0) (2020-08-19)


### Features

* enable arbitrary payloads for JWS ([#126](https://github.com/decentralized-identity/did-jwt/issues/126)) ([5573e63](https://github.com/decentralized-identity/did-jwt/commit/5573e6390a30f088d5b6d298cf348b1ec58c3b92))

## [4.4.2](https://github.com/decentralized-identity/did-jwt/compare/4.4.1...4.4.2) (2020-08-18)


### Bug Fixes

* **deps:** upgrade direct dependencies ([#125](https://github.com/decentralized-identity/did-jwt/issues/125)) ([fec222f](https://github.com/decentralized-identity/did-jwt/commit/fec222ff353c5349f8e3f67ce9e6b52d9bf8dc72))

## [4.4.1](https://github.com/decentralized-identity/did-jwt/compare/4.4.0...4.4.1) (2020-08-18)


### Bug Fixes

* export interfaces used for JWT verification ([#123](https://github.com/decentralized-identity/did-jwt/issues/123)) ([76229c5](https://github.com/decentralized-identity/did-jwt/commit/76229c5e7d567db95d842e44649c3f58fa7f1b1a))
* export more JWT interfaces ([#121](https://github.com/decentralized-identity/did-jwt/issues/121)) ([2fd049c](https://github.com/decentralized-identity/did-jwt/commit/2fd049ca38d39c33941bad7ae4383776618bbdbd))

# [4.4.0](https://github.com/decentralized-identity/did-jwt/compare/4.3.4...4.4.0) (2020-06-18)


### Features

* add EllipticSigner that returns string ([#114](https://github.com/decentralized-identity/did-jwt/issues/114)) ([7c93513](https://github.com/decentralized-identity/did-jwt/commit/7c9351309cc7016f682eb93f271ebda465ae8e6a))

## [4.3.4](https://github.com/decentralized-identity/did-jwt/compare/4.3.3...4.3.4) (2020-06-08)


### Bug Fixes

* avoid decoding jws twice in verification ([#95](https://github.com/decentralized-identity/did-jwt/issues/95)) ([bc95cb1](https://github.com/decentralized-identity/did-jwt/commit/bc95cb11c554f4e4022c1d1cabaa7383edcac845))

## [4.3.3](https://github.com/decentralized-identity/did-jwt/compare/4.3.2...4.3.3) (2020-05-29)


### Bug Fixes

* handle SimpleSigner privateKey 0x hex prefix by stripping it ([#93](https://github.com/decentralized-identity/did-jwt/issues/93)) ([47595d3](https://github.com/decentralized-identity/did-jwt/commit/47595d354d167625e243a491fbab237c827991a6))

## [4.3.2](https://github.com/decentralized-identity/did-jwt/compare/4.3.1...4.3.2) (2020-04-27)


### Bug Fixes

* export JWS functions ([897b2a5](https://github.com/decentralized-identity/did-jwt/commit/897b2a5d501ec9d5cf047a947cd5f66a56ec3339))

## [4.3.1](https://github.com/decentralized-identity/did-jwt/compare/v4.3.0...4.3.1) (2020-04-26)


### Bug Fixes

* **build:** generate changelog during release ([5d659d9](https://github.com/decentralized-identity/did-jwt/commit/5d659d93caa738b745f606635ae3c6c69b3a22cb))
* **test:** catch rejected promises in tests ([d3b2e9e](https://github.com/decentralized-identity/did-jwt/commit/d3b2e9ee36c6ce21b880c46724ee2b165647c41e))
