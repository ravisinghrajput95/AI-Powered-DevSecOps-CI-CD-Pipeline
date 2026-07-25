// Jest cannot parse CSS. Vite handles `import './X.css'` natively; under
// Jest those imports are mapped here and resolve to an empty object.
// A local two-line stub avoids adding identity-obj-proxy, which would mean
// another dependency in a tree that already had peer conflicts with
// @babel/preset-env@8 and babel-plugin-transform-import-meta.
module.exports = {}
