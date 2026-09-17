// TypeScript 7 diagnoses a side-effect import it cannot resolve. Stylesheets
// are resolved by the bundler, not the compiler.
declare module '*.css'
declare module '@hanzo/font/css'
