
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
        if (this.__call)
            this.__call.send(message);
        else {
            console.log(`Sending message: ${JSON.stringify(message)}`);
        }
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
            this.headers.push({ name: 'Cookie', value: value });
        }
    }
    /**
     * Executes the function.
     *
     * @param {boolean} [closeTab=true] - 是否在执行完成后关闭标签页
     * @param {number} [timeout=5000] - 请求超时时间(毫秒)
     * @return {Promise} The promise that resolves to the result of the function execution.
     */
    async execute(closeTab = true, timeout = 500) {
        // browserIsInitialized.call(this);
        this.tab = await this.browser.newTab();

        // const domain = this.url.hostname;
        const url = this.url //this.uri ? domain + this.uri : this.url.urlStr;
        if (this.method == "POST") {
            const httprqueset = {
                url: url,
                method: this.method,
                headers: this.headers,
                postData: Buffer.from(this.postData).toString("base64"),
                isEncodeUrl: false,
            }
            var ret = await this.tab.postEx(httprqueset, timeout);
            this.response = { body: ret.body, headers: ret.headers, responseStatus: ret.status }
            this.responseStatus = ret.status
            
            // 根据参数决定是否关闭标签页
            if (closeTab) {
                await this.tab.close()
            }
            return ret
        } else {
            const httprqueset = {
                url: url,
                method: this.method,
                headers: this.headers,
                // postData: Buffer.from(this.postData).toString("base64"),
                isEncodeUrl: false,
            }
            var ret = await this.tab.getEx(httprqueset, timeout);
            if (ret != null) {
                this.response = { body: ret.body, headers: ret.headers, responseStatus: ret.status }
                this.responseStatus = ret.status   
            }
            
            // 根据参数决定是否关闭标签页
            if (closeTab) {
                await this.tab.close()
            }
            return ret
        }
    }

    /**
     * 在当前标签页中执行JavaScript脚本
     * 
     * @param {string|function} script - 要执行的JavaScript脚本或函数
     * @param {...any} args - 传递给脚本的参数
     * @return {Promise<any>} - 脚本执行的结果
     */
    async evaluate(script, ...args) {
        if (!this.tab) {
            throw new Error('Tab is not initialized. Call execute() first with closeTab=false');
        }
        
        return await this.tab.evaluate(script, ...args);
    }

    /**
     * 触发页面中的所有 DOM 事件
     * 这个方法会尝试触发页面中所有元素的各种事件，帮助发现潜在的 DOM XSS 漏洞
     * 
     * @param {number} [timeout=3000] - 触发事件的超时时间(毫秒)
     * @return {Promise<Object>} - 返回触发事件的结果统计
     */
    async triggerAllDomEvents(timeout = 3000) {
        if (!this.tab) {
            throw new Error('Tab is not initialized. Call execute() first with closeTab=false');
        }
        
        console.log('开始触发所有 DOM 事件...');
        
        try {
            // 设置超时
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('触发事件超时')), timeout);
            });
            
            // 执行事件触发
            const triggerPromise = this.tab.evaluate(() => {
                // 创建结果统计对象
                const stats = {
                    elementsProcessed: 0,
                    eventsFired: 0,
                    eventsByType: {}
                };
                
                // 定义要触发的事件类型
                const eventTypes = [
                    // 鼠标事件
                    'click', 'dblclick', 'mousedown', 'mouseup', 'mouseover', 'mouseout', 'mousemove',
                    // 键盘事件
                    'keydown', 'keyup', 'keypress',
                    // 表单事件
                    'focus', 'blur', 'change', 'submit', 'reset', 'select', 'input',
                    // 拖拽事件
                    'drag', 'dragstart', 'dragend', 'dragover', 'dragenter', 'dragleave', 'drop',
                    // 其他常见事件
                    'load', 'unload', 'resize', 'scroll', 'contextmenu'
                ];
                
                // 触发指定元素的所有事件
                function triggerEventsOnElement(element) {
                    stats.elementsProcessed++;
                    
                    // 遍历所有事件类型
                    for (const eventType of eventTypes) {
                        try {
                            // 创建事件对象
                            let event;
                            
                            // 根据事件类型创建不同的事件对象
                            if (['click', 'dblclick', 'mousedown', 'mouseup', 'mouseover', 'mouseout', 'mousemove', 'contextmenu'].includes(eventType)) {
                                // 鼠标事件
                                event = new MouseEvent(eventType, {
                                    bubbles: true,
                                    cancelable: true,
                                    view: window
                                });
                            } else if (['keydown', 'keyup', 'keypress'].includes(eventType)) {
                                // 键盘事件
                                event = new KeyboardEvent(eventType, {
                                    bubbles: true,
                                    cancelable: true,
                                    key: 'a',
                                    code: 'KeyA'
                                });
                            } else {
                                // 其他事件
                                event = new Event(eventType, {
                                    bubbles: true,
                                    cancelable: true
                                });
                            }
                            
                            // 触发事件
                            const dispatched = element.dispatchEvent(event);
                            
                            // 更新统计信息
                            stats.eventsFired++;
                            stats.eventsByType[eventType] = (stats.eventsByType[eventType] || 0) + 1;
                            
                            // 特殊处理表单元素
                            if (eventType === 'focus' && (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA')) {
                                // 尝试设置值并触发 input 和 change 事件
                                const originalValue = element.value;
                                element.value = 'test_input';
                                
                                // 触发 input 事件
                                const inputEvent = new Event('input', { bubbles: true, cancelable: true });
                                element.dispatchEvent(inputEvent);
                                
                                // 触发 change 事件
                                const changeEvent = new Event('change', { bubbles: true, cancelable: true });
                                element.dispatchEvent(changeEvent);
                                
                                // 恢复原始值
                                element.value = originalValue;
                                
                                // 更新统计信息
                                stats.eventsFired += 2;
                                stats.eventsByType['input'] = (stats.eventsByType['input'] || 0) + 1;
                                stats.eventsByType['change'] = (stats.eventsByType['change'] || 0) + 1;
                            }
                            
                            // 特殊处理表单提交
                            if (eventType === 'submit' && element.tagName === 'FORM') {
                                // 阻止实际提交
                                element.onsubmit = function(e) {
                                    e.preventDefault();
                                    return false;
                                };
                            }
                        } catch (e) {
                            // 忽略错误，继续处理下一个事件
                            console.warn(`触发 ${eventType} 事件时出错:`, e.message);
                        }
                    }
                    
                    // 检查元素是否有自定义事件处理器属性
                    const attributes = element.attributes;
                    for (let i = 0; i < attributes.length; i++) {
                        const attr = attributes[i];
                        if (attr.name.startsWith('on') && attr.value) {
                            const eventType = attr.name.substring(2); // 去掉 'on' 前缀
                            try {
                                // 创建并触发自定义事件
                                const customEvent = new Event(eventType, {
                                    bubbles: true,
                                    cancelable: true
                                });
                                element.dispatchEvent(customEvent);
                                
                                // 更新统计信息
                                stats.eventsFired++;
                                stats.eventsByType[eventType] = (stats.eventsByType[eventType] || 0) + 1;
                            } catch (e) {
                                // 忽略错误
                            }
                        }
                    }
                }
                
                // 获取所有可交互元素
                const interactiveElements = document.querySelectorAll(
                    'a, button, input, select, textarea, form, [onclick], [onmouseover], ' +
                    '[onmousedown], [onmouseup], [onkeydown], [onkeypress], [onkeyup], ' +
                    '[onfocus], [onblur], [onchange], [onsubmit], [onreset], [onselect], ' +
                    '[oninput], [ondrag], [ondragstart], [ondragend], [ondragover], ' +
                    '[ondragenter], [ondragleave], [ondrop], [onload], [onunload], ' +
                    '[onresize], [onscroll], [oncontextmenu], [role="button"], [tabindex]'
                );
                
                // 触发所有可交互元素的事件
                interactiveElements.forEach(triggerEventsOnElement);
                
                // 特殊处理 window 和 document 事件
                ['load', 'unload', 'resize', 'scroll'].forEach(eventType => {
                    try {
                        const event = new Event(eventType, {
                            bubbles: true,
                            cancelable: true
                        });
                        window.dispatchEvent(event);
                        document.dispatchEvent(event);
                        
                        // 更新统计信息
                        stats.eventsFired += 2;
                        stats.eventsByType[eventType] = (stats.eventsByType[eventType] || 0) + 2;
                    } catch (e) {
                        // 忽略错误
                    }
                });
                
                return stats;
            });
            
            // 使用 Promise.race 实现超时
            const result = await Promise.race([triggerPromise, timeoutPromise]);
            
            console.log('DOM事件触发成功:', result.result.value);
            return result.result.value;
        } catch (error) {
            console.error('触发DOM事件时出错:', error.message);
            return {
                error: error.message,
                elementsProcessed: 0,
                eventsFired: 0
            };
        }
    }
    /**
     * 关闭当前标签页
     * 
     * @return {Promise<void>}
     */
    async closeTab() {
        if (this.tab) {
            await this.tab.close();
            this.tab = null;
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
            this.headers.push({ name: 'Cookie', value: value });
        }
    }

    /**
     * Executes the function and sends an HTTP request using axios.
     *
     * @return {Promise<void>} - A promise that resolves when the request is complete.
     */
    async execute() {
        // const domain = this.url.hostname;
        const url = this.url //this.uri ? domain + this.uri : this.url.urlStr;
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




class ScriptArg {
    constructor(options = {}) {
      this.http = {
        request: {
          method: options.method || 'GET',
          uri: options.uri || '/',
          headers: options.headers || {},
        },
        response: {
          isType: (contentType) => {
            return this.headers['content-type'].includes(contentType);
          },
          statusCode: options.statusCode || 0,
          body: options.body || '',
        },
        hostname: options.hostname || '',
      };
      this.location = {
        url: {
          path: options.path || '/',
        },
      };
      this.target = {
        url: options.targetUrl || '',
      };
    }
}


class ScriptCore {
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

        this.scriptArg = ScriptArg()

        
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
    browerHttpJob,
    ScriptArg,
    ScriptCore,

};