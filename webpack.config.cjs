const path = require('path')

// @type {import('webpack').Configuration}
module.exports = {
  // entry: './lib/index.js',
  entry: './lib/index.module.js',
  mode: 'production',
  resolve: {
    fallback: {
      crypto: false,
      // crypto: require.resolve('crypto-browserify'),
      util: false
      // util: require.resolve('util/'),
    }
  },
  output: {
    filename: 'did-jwt.js',
    path: path.resolve(__dirname, 'dist'),
    libraryTarget: 'module',
    umdNamedDefine: true,
    // library: 'DID-JWT',
  },
  experiments: {
    outputModule: true
  }
}
