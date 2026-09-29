import typescriptEslint from '@typescript-eslint/eslint-plugin'
import vitest from '@vitest/eslint-plugin'
import tsParser from '@typescript-eslint/parser'
import prettierConfig from 'eslint-config-prettier'
import prettierPlugin from 'eslint-plugin-prettier'

export default [
  { ignores: ['src/**/*.test.[jt]s', 'canary/**/*'] },
  ...typescriptEslint.configs['flat/recommended'],
  prettierConfig,
  {
    files: ['src/**/*.{js,ts}'],
    plugins: {
      vitest,
      prettier: prettierPlugin,
    },
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2024,
      sourceType: 'module',
    },
    rules: {
      'prettier/prettier': 'error',
    },
  },
]
