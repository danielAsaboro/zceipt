module.exports = {
  preset: '@metamask/snaps-jest',
  transform: { '^.+\\.(t|j)sx?$': ['ts-jest', { diagnostics: false }] },
  testTimeout: 900000,
};
