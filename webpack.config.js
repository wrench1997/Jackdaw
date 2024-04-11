const path = require('path');
const NodePolyfillPlugin = require('node-polyfill-webpack-plugin')
const nodeExternals = require('webpack-node-externals');
const webpack = require('webpack');

module.exports = [
    // 未压缩版
    {
        entry: {
            'sdk': './index.js'
        },
        target: 'node',
        output: {
            path: path.resolve(__dirname, 'dist'),
            filename: '[name].js',
            library: 'SDK',
            libraryTarget: "umd"
        },
        plugins: [
            new NodePolyfillPlugin(),
            new webpack.ContextReplacementPlugin(
                "lib",
                /\.js$/
            )
        ],
        externals: [nodeExternals()],
    },
]
