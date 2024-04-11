


var PROTO_PATH = __dirname + '/../mesonrpc/mesonrpc.proto';

// var fs = require('fs');
// var parseArgs = require('minimist');
// var path = require('path');
// var _ = require('lodash');
var grpc = require('@grpc/grpc-js');
var protoLoader = require('@grpc/proto-loader');

var packageDefinition = protoLoader.loadSync(
    PROTO_PATH,
    {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true
    });
var mesonrpc = grpc.loadPackageDefinition(packageDefinition).mesonrpc;


module.exports = mesonrpc;