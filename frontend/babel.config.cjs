// Jest needs this to transform the app's ES modules.
//
// babel-jest and @babel/preset-react were already devDependencies, but with
// no Babel config present babel-jest transformed nothing — so any test that
// imported application code died with "Cannot use import statement outside
// a module". That is why the only frontend test was
// `expect(true).toBe(true)`: it was the only thing that could run.
//
// Vite never reads this file; it handles ESM and import.meta natively. This
// exists purely so Jest can load application code.

// api/client.js reads import.meta.env.VITE_API_URL (Vite's env mechanism),
// which Babel cannot lower to CommonJS on its own — Jest fails with
// "Cannot use 'import.meta' outside a module".
//
// Written inline rather than pulling in babel-plugin-transform-import-meta:
// that package (and @babel/preset-env@8) both conflict with the Babel 7
// toolchain @vitejs/plugin-react already pins here, and a ten-line visitor
// is a smaller liability than forcing peer resolutions with --legacy-peer-deps.
//
// Substituting an empty env is correct for tests: client.js falls back to
// "/api" when VITE_API_URL is unset, which is what a unit test should see.
// Tests needing a specific value should mock the module.
function transformImportMeta() {
  return {
    visitor: {
      MetaProperty(path) {
        if (path.node.meta && path.node.meta.name === "import") {
          path.replaceWithSourceString("({ env: {} })");
        }
      },
    },
  };
}

module.exports = {
  plugins: [transformImportMeta],
  presets: [
    ["@babel/preset-env", { targets: { node: "current" } }],
    ["@babel/preset-react", { runtime: "automatic" }],
  ],
};
