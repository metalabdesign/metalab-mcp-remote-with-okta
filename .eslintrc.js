module.exports = {
  env: {
    node: true,
    es2021: true,
    jest: true,
  },
  extends: [
    'eslint:recommended',
  ],
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  rules: {
    'no-console': 'warn',
    'indent': ['error', 2],
    'linebreak-style': ['error', 'unix'],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
    'max-len': ['error', { code: 100 }],
    'no-trailing-spaces': 'error',
    'object-shorthand': 'error',
    'prefer-const': 'error',
  },
  overrides: [
    {
      files: ['*.test.js', '**/__tests__/**/*.js'],
      env: {
        jest: true,
      },
      rules: {
        'no-console': 'off', // Allow console in tests
      },
    },
  ],
}; 