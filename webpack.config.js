const path = require('path');

module.exports = {
  entry: './install.js',
  target: 'node',
  mode: 'production',
  devtool: false,
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'install.js',
  },
  externals: {
    'fs': 'commonjs fs',
    'path': 'commonjs path',
    'os': 'commonjs os'
  },
  resolve: {
    extensions: ['.js', '.json']
  },
  optimization: {
    minimize: true,
  },
  plugins: [
    {
      apply: (compiler) => {
        compiler.hooks.afterEmit.tap('AddShebang', () => {
          const fs = require('fs');
          const outputPath = path.resolve(__dirname, 'dist', 'install.js');
          const content = fs.readFileSync(outputPath, 'utf8');
          fs.writeFileSync(outputPath, '#!/usr/bin/env node\n' + content);
        });
      }
    }
  ]
};
