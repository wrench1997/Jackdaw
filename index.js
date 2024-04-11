//SDK封装打包目录

const { CoreLayer, createReport, urlencodedParams, urlGetParams, browerHttpJob } = require('./core/core.js');
const HeadlessChrome = require('./lib/Browser.js');

var index = {
    CoreLayer, urlencodedParams,
    HeadlessChrome,
    createReport, urlGetParams,
    browerHttpJob
};


export default index;