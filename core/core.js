
const { objToHeadersEntry } = require('../utils/utils.js')
const querystring = require('querystring');
const path = require('path');
//const md5 = require('md5');
//import axios from 'axios';


class urlencodedParams {
    constructor(search) {
        this.qs = (search);
        this.params = [];
        this.parseQuerstring();
        this.length = this.params.length;
    }
    /**
     * Parses the query string and populates the "params" array with key-value pairs.
     *
     * @return {void} This function does not return a value.
     */
    parseQuerstring() {
        this.qs.split('&').reduce((a, b) => {
            let [key, val] = b.split('=');
            if (key && val) { // 判断参数名称和值是否存在
                val = decodeURIComponent(val);
                this.params.push({ name: key, value: val });
            }
            return a;
        }, this.params);
    }
    /**
     * Retrieves the value at the specified index from the params array.
     *
     * @param {number} index - The index of the value to retrieve.
     * @return {any} The value at the specified index in the params array, or undefined if the index is out of bounds.
     */
    getValue(index) {
        if (this.params[index]) {
            return this.params[index].value;
        }
        return undefined;
    }
    /**
     * Retrieves the key at the specified index.
     *
     * @param {number} index - The index of the key to retrieve.
     * @return {string|undefined} The key at the specified index, or undefined if no key exists.
     */
    getKey(index) {
        if (this.params[index]) {
            return this.params[index].name;
        }
        return undefined;
    }
    /**
     * Retrieves the value associated with the specified key.
     *
     * @param {string} key - The key to search for in the params array.
     * @return {unknown} The value associated with the key, or undefined if the key is not found.
     */
    getValueFromKey(key) {
        let index = this.params.findIndex(obj => obj.name === key);
        if (index >= 0) {
            return this.params[index].value;
        }
        return undefined;
    }
    /**
     * Set the value of a parameter based on its key.
     *
     * @param {string} key - The key of the parameter.
     * @param {any} value - The value to set for the parameter.
     */
    setValueFromKey(key, value) {
        let index = this.params.findIndex(obj => obj.name === key);
        if (index >= 0) { // 判断参数值是否合法
            this.params[index].value = value;
        }
    }
    /**
     * Set the value of a parameter at the specified index.
     *
     * @param {number} index - The index of the parameter to set the value for.
     * @param {any} value - The value to set for the parameter.
     */
    setValue(index, value) {
        if (this.params[index]) { // 判断参数值是否合法
            this.params[index].value = value;
        }
    }
    /**
     * Converts the object to a string representation of query parameters.
     *
     * @return {string} The string representation of the query parameters.
     */
    toString() {
        var str = [];
        for (var i = 0; i < this.params.length; i++) {
            str.push(this.getKey(i) + "=" + this.getValue(i))
        }
        return str.join("&");
    }

    /**
     * Checks if the given key exists in the params array.
     *
     * @param {string} key - The key to check.
     * @return {boolean} Returns true if the key exists, false otherwise.
     */
    hasOwnProperty(key) {
        let index = this.params.findIndex(obj => obj.name === key);
        return index >= 0;
    }
}
class emtryParams {
    constructor() {
        this.length = 0;
    }
}



class urlGetParams {
    constructor(url) {
        const searchParams = new URL(url).searchParams.toString();
        const queryParams = querystring.parse(searchParams);
        this.params = [];
        for (const [key, value] of Object.entries(queryParams)) {
            this.params.push({ name: key, value: value });
        }
        this.length = this.params.length;
    }
    /**
     * Retrieves the value associated with a given key.
     *
     * @param {string} key - The key to search for in the params array.
     * @return {any} The value associated with the given key, or undefined if the key is not found.
     */
    getValueFromKey(key) {
        let index = this.params.findIndex(obj => obj.name === key);
        if (index >= 0) {
            return this.params[index].value;
        }
        return undefined;
    }
    /**
     * A function to set the value of a parameter based on its key.
     *
     * @param {string} key - The key of the parameter.
     * @param {any} value - The value to set for the parameter.
     */
    setValueFromKey(key, value) {
        let index = this.params.findIndex(obj => obj.name === key);
        if (index >= 0) { // 判断参数值是否合法
            this.params[index].value = value;
        }
    }
    /**
     * A description of the entire function.
     *
     * @param {number} index - the index of the value to set
     * @param {any} value - the new value to set
     * @return {undefined} 
     */
    setValue(index, value) {
        if (this.params[index]) { // 判断参数值是否合法
            this.params[index].value = value;
        }
    }
    /**
     * Retrieves the value at the specified index from the params array.
     *
     * @param {number} index - The index of the value to retrieve.
     * @return {any} The value at the specified index in the params array, or undefined if it does not exist.
     */
    getValue(index) {
        if (this.params[index]) {
            return this.params[index].value;
        }
        return undefined;
    }
    /**
     * Retrieves the key at the specified index from the parameters array.
     *
     * @param {number} index - The index of the parameter to retrieve the key from.
     * @return {string|null} The key at the specified index, or null if the index is out of range.
     */
    getKey(index) {
        if (index >= 0 && index < this.params.length) {
            return this.params[index].name;
        } else {
            return null;
        }
    }
    /**
     * Retrieves the value associated with the given key from the list of parameters.
     *
     * @param {string} key - The key to search for in the list of parameters.
     * @return {any} The value associated with the given key, or null if the key is not found.
     */
    getValueFromKey(key) {
        const param = this.params.find((p) => p.name === key);
        if (param) {
            return param.value;
        } else {
            return null;
        }
    }
    /**
     * Update the value of a parameter based on a given key.
     *
     * @param {string} key - The key used to identify the parameter.
     * @param {any} value - The new value to assign to the parameter.
     */
    setValueFromKey(key, value) {
        const param = this.params.find((p) => p.name === key);
        if (param) {
            param.value = value;
        }
    }
    /**
     * Converts the object to a string representation.
     *
     * @return {string} The string representation of the object.
     */
    toString() {
        const str = [];
        for (let i = 0; i < this.params.length; i++) {
            str.push(`${this.getKey(i)}=${this.getValue(i)}`);
        }
        return str.join('&');
    }


}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}



class CoreLayer {
    constructor(Core) {
        this.scheme = Core.scheme;
        this.url = Core.url;
        this.foundVulnOnVariation = false;
        this.browser = Core.browser;
        this.headers = objToHeadersEntry(Core.headers);
        this.method = Core.method;
        this.__call = Core.__call;
        this.debug = false;
        this.taskid = Core.taskid;
        this.hostid = Core.hostid;
        this.postData = Core.postData;
        this.variations = Core.variations;
        this.isFile = Core.isFile;
        this.filename = Core.filename;
        this.fileContent = Core.fileContent;
        // // 創建一個互斥鎖
        // this.mutex = new Mutex();
    }

    /**
     * Returns the vulnerability ID from a given file path.
     *
     * @param {string} file - The file path.
     * @return {string} The vulnerability ID extracted from the file path.
     */
    getVulnId(file) {
        const parsed = path.parse(file);
        return parsed.name.replace('.js', '');
    }

    debug(msg) {
        if (this.debug) {
            console.log(`[DEBUG] ${msg}`);
        }
    }

    /**
     * Copies the Report object and updates the fields.hostid property with the value of this.hostid.
     * Sends a message containing the updated Report object using this.__call.send().
     *
     * @param {Object} Report - The Report object to be copied and updated.
     */
    alert(Report) {
        // 複製 Report 對象
        const updatedReport = JSON.parse(JSON.stringify(Report));
        updatedReport.fields.hostid = {
            numberValue: this.hostid
        };
        var message = {
            Report: updatedReport
        };
        this.__call.send(message);
    }

}


/**
 * Creates a report based on the given queue.
 *
 * @param {Object} queue - The queue object containing key-value pairs.
 * @return {Object} - The report object with fields.
 */
function createReport(queue) {
    var fields = {};
    var keys = Object.keys(queue); // 獲取所有的鍵
    for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        var value = queue[key];
        fields[key] = { stringValue: value };
    }
    return {
        fields: fields
    };
}

class browerHttpJob {
    constructor(browser) {
        this.url = null;
        this.uri = null;
        this.headers = [];
        this.cookies = [];  // 修改属性名为小写，遵循 JavaScript 命名规范
        this.method = null;
        this.postData = null;
        this.response = null;
        this.browser = browser;
        this.NetMode = 'browser';
    }
    /**
     * Adds a header to the headers array.
     *
     * @param {any} name - The name of the header.
     * @param {any} value - The value of the header.
     */
    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }
    /**
     * Adds a cookie to the list of cookies and updates the headers.
     *
     * @param {string} name - The name of the cookie.
     * @param {string} value - The value of the cookie.
     */
    addCookie(name, value) {
        this.cookies.push({ name: name, value: value });
        const cookieIndex = this.headers.findIndex(h => h.name.toLowerCase() === 'cookie');
        if (cookieIndex >= 0) {
            this.headers[cookieIndex].value += `; ${cookieHeader}`;
        } else {
            this.headers.push({ name: 'Cookie', value: cookieHeader });
        }
    }
    /**
     * Executes the function.
     *
     * @return {Promise} The promise that resolves to the result of the function execution.
     */
    async execute() {
        this.tab = await this.browser.newTab();
        const domain = this.url.hostname;
        const url = this.uri ? domain + this.uri : this.url.urlStr;
        if (this.method == "POST") {
            const httprqueset = {
                url: url,
                method: this.method,
                headers: this.headers,
                postData: Buffer.from(this.postData).toString("base64"),
                isEncodeUrl: false,
            }
            var ret = await this.tab.postEx(httprqueset);
            this.response = { body: ret.body, headers: ret.headers, responseStatus: ret.status }
            this.responseStatus = ret.status
            await this.tab.close()
            return ret
        } else {
            const httprqueset = {
                url: this.url,
                method: this.method,
                headers: this.headers,
                // postData: Buffer.from(this.postData).toString("base64"),
                isEncodeUrl: false,
            }
            var ret = await this.tab.getEx(httprqueset);
            this.response = { body: ret.body, headers: ret.headers, responseStatus: ret.status }
            this.responseStatus = ret.status
            await this.tab.close()
            return ret
        }
    }
}



class THTTPJob {
    constructor() {
        this.url = null;
        this.uri = null;
        this.headers = [];
        this.cookies = [];  // 修改属性名为小写，遵循 JavaScript 命名规范
        this.method = null;
        this.postData = null;
        this.response = null;
        this.NetMode = 'normal';
        this.wasError = false;

    }
    /**
     * Adds a header to the list of headers.
     *
     * @param {string} name - The name of the header.
     * @param {string} value - The value of the header.
     */
    addHeader(name, value) {
        this.headers.push({ name: name, value: value });
    }
    /**
     * Adds a cookie to the cookies array and updates the headers with the cookie information.
     *
     * @param {string} name - The name of the cookie.
     * @param {string} value - The value of the cookie.
     * @return {undefined} This function does not return a value.
     */
    addCookie(name, value) {
        this.cookies.push({ name: name, value: value });
        const cookieIndex = this.headers.findIndex(h => h.name.toLowerCase() === 'cookie');
        if (cookieIndex >= 0) {
            this.headers[cookieIndex].value += `; ${cookieHeader}`;
        } else {
            this.headers.push({ name: 'Cookie', value: cookieHeader });
        }
    }

    /**
     * Executes the function and sends an HTTP request using axios.
     *
     * @return {Promise<void>} - A promise that resolves when the request is complete.
     */
    async execute() {
        const domain = this.url.hostname;
        const url = this.uri ? domain + this.uri : this.url.urlStr;
        let axiosConfig = {
            url,
            method: this.method,
            headers: this.headers
        };
        if (this.method === 'POST') {
            axiosConfig.data = this.postData;
        }
        const res = await axios(axiosConfig);
        this.response = {
            body: res.data,
            headers: res.headers,
            status: res.status
        };
    }
}


class urlHelper {
    constructor(urlStr) {
        this.urlStr = urlStr;
        this.parse();
    }

    parse() {
        let url = new URL(this.urlStr);
        this.protocol = url.protocol;
        this.host = url.host;
        this.hostname = url.hostname;
        this.port = url.port;
        this.pathname = url.pathname;
        this.search = url.search;
    }

    getPort() {
        if (this.port) {
            return this.port;
        }
        if (this.protocol === 'http:') {
            return 80;
        } else if (this.protocol === 'https:') {
            return 443;
        }
    }





    

}




function classMatches() {
    this.plainArray = [];
    this.regexArray = [];
}

classMatches.prototype.searchOnText = function (text) {
    let _in = "body";

    if (text.startsWith("HTTP/1.") || text.startsWith("HTTP/0."))
        _in = "response";

    for (var i = 0; i < this.plainArray.length; i++) {
        if (text.indexOf(this.plainArray[i]) != -1) {
            return this.plainArray[i];
        }
    }

    for (var i = 0; i < this.regexArray.length; i++) {
        var m = this.regexArray[i].exec(text);
        if (m) {
            return m;
        }
    }

    return false;
};



/**
 * Convert a plain text string to base64 encoding.
 *
 * @param {string} plain - The plain text string to be encoded.
 * @return {string} The base64 encoded string.
 */
function plain2b64(plain) {
    const buff = Buffer.from(plain);
    return buff.toString('base64');
}




module.exports = {
    //plain2md5,
    urlHelper,
    classMatches,
    THTTPJob,
    CoreLayer,
    createReport,
    urlencodedParams,
    urlGetParams,
    emtryParams,
    plain2b64,
    browerHttpJob
};