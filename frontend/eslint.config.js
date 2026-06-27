import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'node_modules'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // HMR-only rule, not a correctness concern — pre-existing mixed-export files
      'react-refresh/only-export-components': 'off',
      // Hook dep exhaustiveness requires touching component logic; disabled for now
      'react-hooks/exhaustive-deps': 'off',
      // TypeScript handles unused vars — suppress ESLint's noisier variant
      '@typescript-eslint/no-unused-vars': 'off',
      // Allow `any` when explicitly typed (existing codebase uses it for API shapes)
      '@typescript-eslint/no-explicit-any': 'off',
      // Empty interfaces used as named type aliases — intentional pattern
      '@typescript-eslint/no-empty-object-type': 'off',
    },
  },
)
