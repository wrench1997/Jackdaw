const url = require('url');
const path = require('path');

function extractBaseUrl(fullUrl) {
    const parsedUrl = url.parse(fullUrl);
    const baseUrl = parsedUrl.protocol + '//' + parsedUrl.host + path.dirname(parsedUrl.pathname);
    return baseUrl;
}


function getFilenameFromUrl(websiteUrl) {
    // 解析url
    const parsedUrl = url.parse(websiteUrl);

    // 获取文件名
    const filename = parsedUrl.pathname.split('/').pop();

    return filename;
}



module.exports = { extractBaseUrl, getFilenameFromUrl };