var path = require('path')

module.exports = {
  entry: './lib/index.js',
  output: {
    filename: 'did-jwt.js',
    path: path.resolve(__dirname, 'dist'),
    libraryTarget: 'umd',
    umdNamedDefine: true,
    library: 'DID-JWT'
  }
}
