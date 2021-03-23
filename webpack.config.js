const path = require('path')

module.exports = {
  entry: './lib/index.js',
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
    libraryTarget: 'umd',
    umdNamedDefine: true,
    library: 'DID-JWT'
  }
}
