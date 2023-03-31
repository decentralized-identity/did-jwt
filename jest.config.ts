import type { Config } from 'jest';
import { defaults } from 'jest-config';

const config: Config = {
  moduleFileExtensions: [...defaults.moduleFileExtensions, 'mts'],
  "transform": {
    "^.+\\.m?tsx?$": [
      "ts-jest",
      {
        "useESM": true,
        "tsconfig": "./tsconfig.json"
      }
    ]
  },
  // // typescript 5 removes the need to specify relative imports as .js, so we should no longer need this workaround
  // "moduleNameMapper": {
  //   "^(\\.{1,2}/.*)\\.js$": "$1"
  // },
  "extensionsToTreatAsEsm": [
    ".ts"
  ],
  "testMatch": [
    "**/__tests__/**/*.test.ts"
  ],
  "testEnvironment": "node",
};

export default config;
