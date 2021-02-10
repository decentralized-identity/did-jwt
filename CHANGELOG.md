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
