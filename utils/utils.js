const crypto = require('crypto');


exports.ObjToUrlencoded = function (obj) {
    let s = new URLSearchParams(obj.entries(o)).toString();
    return s;
}

exports.strConvUsp = function (str) {
    let searchParams = new URLSearchParams(str);
    return searchParams;
}

exports.objToHeadersEntry = function (obj) {
    let HeadersEntry = [];
    for (let key in obj) { HeadersEntry.push({ name: key, value: obj[key] }) }
    return HeadersEntry;
}


exports.plain2sha1 = function (str) {
    const hash = crypto.createHash('sha1');
    hash.update(str);
    return hash.digest('hex');
}


exports.randomString = function (length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}
