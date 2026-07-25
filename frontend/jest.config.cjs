module.exports = {
  testEnvironment: "jsdom",
  moduleNameMapper: {
    // Component modules import their own stylesheet; see test-stubs/styleStub.cjs
    "\\.(css|less|sass|scss)$": "<rootDir>/test-stubs/styleStub.cjs",
    // Static assets imported by components resolve to the same stub.
    "\\.(jpg|jpeg|png|gif|svg|webp)$": "<rootDir>/test-stubs/styleStub.cjs",
  },
};
