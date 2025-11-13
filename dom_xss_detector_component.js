const { CoreLayer, createReport, browerHttpJob } = require('./core/core.js');
const fs = require('fs');
const path = require('path');


/**
 * 检查网站是否可访问
 * @param {string} url - 要检查的URL
 * @param {number} timeout - 超时时间(毫秒)
 * @return {Promise<boolean>} - 网站是否可访问
 */
async function isWebsiteAccessible(url, timeout = 5000) {
    try {
      const job = new browerHttpJob(this.browser);
      job.url = url;
      job.method = "HEAD"; // 使用HEAD请求减少数据传输
      
      // 设置超时
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      
      const response = await job.execute();
      clearTimeout(timeoutId);
      
      return response && response.status >= 200 && response.status < 400;
    } catch (error) {
      console.error(`网站访问检查失败: ${url}`, error.message);
      return false;
    }
  }


  /**
 * 带有限流和重试机制的请求函数
 * @param {string} url - 请求URL
 * @param {Object} options - 请求选项
 * @param {number} maxRetries - 最大重试次数
 * @param {number} retryDelay - 重试延迟(毫秒)
 * @return {Promise<Object>} - 响应结果
 */
async function requestWithRetry(url, options = {}, maxRetries = 3, retryDelay = 1000) {
    // 首先检查网站是否可访问
    const isAccessible = await isWebsiteAccessible(url);
    if (!isAccessible) {
      console.log(`网站 ${url} 不可访问，跳过请求`);
      return null;
    }
    
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
      try {
        const job = new browerHttpJob(this.browser);
        job.url = url;
        job.method = options.method || "GET";
        
        // 添加请求头
        if (options.headers) {
          for (const [name, value] of Object.entries(options.headers)) {
            job.addHeader(name, value);
          }
        }
        
        // 设置POST数据
        if (options.method === "POST" && options.postData) {
          job.postData = options.postData;
        }
        
        const response = await job.execute();
        return response;
      } catch (error) {
        lastError = error;
        console.warn(`请求失败(${i+1}/${maxRetries}): ${url}`, error.message);
        
        if (i < maxRetries - 1) {
          // 等待一段时间后重试
          await sleep(retryDelay);
        }
      }
    }
    
    throw lastError;
  }



class DOMXSSDetector extends CoreLayer {
    constructor(Core) {
        super(Core);
        this.name = "DOM XSS Detector";
        this.vulnid = this.getVulnId(__filename);
        
        // 定义DOM XSS的源列表
        this.sources = [
            { label: "location", property: "location" },
            { label: "location.href", property: "location.href" },
            { label: "location.hash", property: "location.hash" },
            { label: "location.search", property: "location.search" },
            { label: "location.pathname", property: "location.pathname" },
            { label: "document.URL", property: "document.URL" },
            { label: "window.name", property: "window.name" },
            { label: "document.referrer", property: "document.referrer" },
            { label: "document.documentURI", property: "document.documentURI" },
            { label: "document.baseURI", property: "document.baseURI" },
            { label: "document.cookie", property: "document.cookie" },
            { label: "localStorage", property: "localStorage" },
            { label: "sessionStorage", property: "sessionStorage" },
            { label: "URLSearchParams", property: "URLSearchParams" }
        ];

        // 定义DOM XSS的接收点列表
        this.sinks = [
            // JavaScript 执行接收点 - 高危险性
            { label: "eval", property: "eval", priority: 2, category: "js" },
            { label: "Function", property: "Function", priority: 3, category: "js" },
            { label: "setTimeout", property: "setTimeout", priority: 5, category: "js" },
            { label: "setInterval", property: "setInterval", priority: 6, category: "js" },
            { label: "script.src", property: "script.src", priority: 8, category: "js" },
            { label: "script.textContent", property: "script.textContent", priority: 9, category: "js" },
            { label: "script.innerHTML", property: "script.innerHTML", priority: 12, category: "js" },
            
            // HTML 注入接收点 - 中危险性
            { label: "document.write", property: "document.write", priority: 15, category: "html" },
            { label: "document.writeln", property: "document.writeln", priority: 16, category: "html" },
            { label: "element.innerHTML", property: "innerHTML", priority: 21, category: "html" },
            { label: "element.outerHTML", property: "outerHTML", priority: 22, category: "html" },
            { label: "element.insertAdjacentHTML", property: "insertAdjacentHTML", priority: 23, category: "html" },
            { label: "iframe.srcdoc", property: "iframe.srcdoc", priority: 24, category: "html" },
            
            // URL 相关接收点 - 低危险性
            { label: "location.href", property: "location.href", priority: 25, category: "url" },
            { label: "location.replace", property: "location.replace", priority: 26, category: "url" },
            { label: "location.assign", property: "location.assign", priority: 27, category: "url" },
            { label: "window.open", property: "window.open", priority: 29, category: "url" },
            { label: "iframe.src", property: "iframe.src", priority: 30, category: "url" },
            
            // 事件处理接收点
            { label: "javascriptURL", property: "javascriptURL", priority: 31, category: "event" },
            { label: "element.setAttribute.onclick", property: "element.setAttribute.onclick", priority: 33, category: "event" }
        ];
        
        // 自定义标识符，用于验证DOM XSS漏洞
        this.identifier = "DOMXSS_" + Math.random().toString(36).substring(2, 10);
        
        // 构造不同类型的payload
        this.payloads = this.generatePayloads();
        
        // 添加一个标志，用于跟踪是否已经发现漏洞
        this.vulnerabilityFound = false;
    }

    /**
     * 生成不同类型的DOM XSS payload
     * @returns {Object} 包含不同类型payload的对象
     */
    generatePayloads() {
        return {
            // HTML注入类payload
            html: [
                `<img src=x onerror=this.setAttribute('data-xss-found','${this.identifier}')>`,
                `<div data-xss-found="${this.identifier}"></div>`,
                `<svg onload="document.documentElement.setAttribute('data-xss-found','${this.identifier}')">`,
                `<iframe srcdoc="<script>parent.document.documentElement.setAttribute('data-xss-found','${this.identifier}')</script>"></iframe>`
            ],
            
            // JavaScript执行类payload
            js: [
                `document.documentElement.setAttribute('data-xss-found','${this.identifier}')`,
                `(function(){document.documentElement.setAttribute('data-xss-found','${this.identifier}')})()`,
                `setTimeout(function(){document.documentElement.setAttribute('data-xss-found','${this.identifier}')},0)`
            ],
            
            // URL类payload
            url: [
                `javascript:document.documentElement.setAttribute('data-xss-found','${this.identifier}');void(0)`,
                `data:text/html,<script>document.documentElement.setAttribute('data-xss-found','${this.identifier}')</script>`
            ],
            
            // 事件处理类payload
            event: [
                `x" onload="document.documentElement.setAttribute('data-xss-found','${this.identifier}')" "`,
                `x" onclick="document.documentElement.setAttribute('data-xss-found','${this.identifier}')" "`
            ]
        };
    }

    /**
     * 获取适合特定接收点的payload
     * @param {Object} sink - 接收点对象
     * @returns {string} 适合该接收点的payload
     */
    getPayloadForSink(sink) {
        if (!sink || !sink.category) {
            return this.payloads.html[0]; // 默认使用HTML注入payload
        }
        
        switch (sink.category) {
            case 'js':
                return this.payloads.js[Math.floor(Math.random() * this.payloads.js.length)];
            case 'html':
                return this.payloads.html[Math.floor(Math.random() * this.payloads.html.length)];
            case 'url':
                return this.payloads.url[Math.floor(Math.random() * this.payloads.url.length)];
            case 'event':
                return this.payloads.event[Math.floor(Math.random() * this.payloads.event.length)];
            default:
                return this.payloads.html[0];
        }
    }

    /**
     * 检查DOM XSS漏洞
     * @param {string} url - 要检测的URL
     * @param {Object} params - 请求参数
     * @returns {Promise<Object>} 检测结果
     */
    async checkDOMXSS(url, params) {
        const results = [];
        
        // 如果已经发现漏洞，直接返回空结果
        if (this.vulnerabilityFound) {
            return results;
        }
        
        // 为每个参数尝试不同的payload
        for (let i = 0; i < params.length; i++) {
            const param = params[i];
            const originalValue = param.value;
            
            // 为每个接收点类型尝试不同的payload
            for (const sinkCategory of ['js', 'html', 'url', 'event']) {
                // 如果已经发现漏洞，跳出循环
                if (this.vulnerabilityFound) {
                    break;
                }
                
                const payloads = this.payloads[sinkCategory];
                
                for (const payload of payloads) {
                    // 如果已经发现漏洞，跳出循环
                    if (this.vulnerabilityFound) {
                        break;
                    }
                    
                    // 设置payload
                    param.value = payload;
                    
                    // 发送请求并检查响应
                    const result = await this.sendRequest(url, params);
                    
                    if (result.vulnerable) {
                        results.push({
                            param: param.name,
                            payload: payload,
                            sink: result.sink,
                            category: sinkCategory
                        });
                        
                        // 设置标志，表示已经发现漏洞
                        this.vulnerabilityFound = true;
                        break; // 找到漏洞后立即跳出循环
                    }
                    
                    // 恢复原始值
                    param.value = originalValue;
                }
            }
        }
        
        return results;
    }

    /**
     * 发送请求并检查响应中是否存在DOM XSS漏洞
     * @param {string} url - 要检测的URL
     * @param {Array} params - 请求参数
     * @returns {Promise<Object>} 检测结果
     */
    async sendRequest(url, params) {
    // 检查网站是否存在
    const isAccessible = await isWebsiteAccessible(url);
    if (!isAccessible) {
        console.log(`网站 ${url} 不可访问，跳过请求`);
        return { vulnerable: false };
    }
    
    // 创建浏览器HTTP请求
    const job = new browerHttpJob(this.browser);
    job.url = url;
    job.method = "GET";
    
    // 添加请求头
    for (const header of this.headers) {
        job.addHeader(header.name, header.value);
    }
    
    // 执行请求
    const response = await job.execute();
    
    if (!response || !response.body) {
        return { vulnerable: false };
    }
    
    // 检查响应中是否存在我们的标识符
    const hasIdentifier = await this.checkResponseForIdentifier(response.body);
    
    // 确保只有在真正验证到标识符时才报告漏洞
    if (hasIdentifier && hasIdentifier.found === true) {
        return {
        vulnerable: true,
        sink: hasIdentifier.sink
        };
    }

    return { vulnerable: false };
    }

    /**
     * 检查响应中是否存在我们的标识符
     * @param {string} responseBody - 响应体
     * @returns {Promise<Object>} 检测结果
     */
    async checkResponseForIdentifier(responseBody) {
        // 创建一个新的浏览器标签页
        const tab = await this.browser.newTab();
        
        // 设置HTML内容
        await tab.setContent(responseBody);
        
        // 检查是否存在我们的标识符
        const result = await tab.evaluate((identifier) => {
            // 检查是否有元素包含我们的标识符
            const elements = document.querySelectorAll(`[data-xss-found="${identifier}"]`);
            if (elements.length > 0) {
                return { found: true, sink: 'element.attribute' };
            }
            
            // 检查document.documentElement是否有我们的标识符
            if (document.documentElement.getAttribute('data-xss-found') === identifier) {
                return { found: true, sink: 'document.documentElement' };
            }
            
            // 检查HTML中是否包含我们的标识符 - 这一步可能导致误报，应该移除或修改
            // if (document.documentElement.innerHTML.includes(identifier)) {
            //     return { found: true, sink: 'document.innerHTML' };
            // }
            
            return { found: false };
        }, this.identifier);
        
        // 关闭标签页
        await tab.close();
        
        return result;
    }

    /**
     * 检测URL中的DOM XSS漏洞
     * @param {string} url - 要检测的URL
     * @returns {Promise<void>}
     */
    async detect() {
        try {
            // 如果已经发现漏洞，直接返回
            if (this.vulnerabilityFound) {
                return;
            }
            
            // 解析URL
            const urlObj = new URL(this.url);
            
            // 获取URL参数
            const searchParams = new URLSearchParams(urlObj.search);
            const params = [];
            
            // 将URL参数转换为数组
            for (const [name, value] of searchParams.entries()) {
                params.push({ name, value });
            }
            
            // 如果没有参数，添加一些常见参数进行测试
            if (params.length === 0) {
                params.push({ name: 'q', value: 'test' });
                params.push({ name: 'search', value: 'test' });
                params.push({ name: 'id', value: '1' });
                params.push({ name: 'name', value: 'test' });
            }
            
            // 检查DOM XSS漏洞
            const results = await this.checkDOMXSS(this.url, params);
            
            // 报告结果
            if (results.length > 0) {
                for (const result of results) {
                    const report = createReport({
                        vulnid: this.vulnid,
                        taskid: this.taskid,
                        url: this.url,
                        param: result.param,
                        payload: result.payload,
                        sink: result.sink,
                        category: result.category,
                        severity: this.getSeverity(result.category),
                        details: `DOM XSS vulnerability found in parameter '${result.param}' with payload '${result.payload}'. The payload was executed in the '${result.sink}' sink.`
                    });
                    
                    this.alert(report);
                }
            }
        } catch (error) {
            console.error(`[${this.name}] Error:`, error);
        }
    }

    /**
     * 根据接收点类别获取漏洞严重性
     * @param {string} category - 接收点类别
     * @returns {string} 严重性级别
     */
    getSeverity(category) {
        switch (category) {
            case 'js':
                return 'High';
            case 'html':
                return 'Medium';
            case 'url':
            case 'event':
                return 'Low';
            default:
                return 'Medium';
        }
    }

    /**
     * 注入DOM XSS检测脚本
     * @param {Object} tab - 浏览器标签页
     * @returns {Promise<void>}
     */
    async injectDetectorScript(tab) {
        // 读取DOM XSS检测器脚本
        const detectorScript = fs.readFileSync(path.join(__dirname, './dom_xss_detector.js'), 'utf8');
        
        // 注入脚本
        await tab.evaluate((script, identifier) => {
            // 创建一个自定义回调函数，用于接收检测结果
            window.xssReportCallback = function(results) {
                // 将结果存储在window对象上，以便后续检索
                window.domXssResults = results;
                
                // 添加自定义标识符
                document.documentElement.setAttribute('data-xss-detector', identifier);
            };
            
            // 创建脚本元素并添加到页面
            const scriptElement = document.createElement('script');
            scriptElement.textContent = script;
            document.head.appendChild(scriptElement);
        }, detectorScript, this.identifier);
    }

    /**
     * 获取检测结果
     * @param {Object} tab - 浏览器标签页
     * @returns {Promise<Array>} 检测结果
     */
    async getDetectionResults(tab) {
        return await tab.evaluate(() => {
            return window.domXssResults || [];
        });
    }

    /**
     * 高级DOM XSS检测
     * @returns {Promise<void>}
     */
    async advancedDetect() {
        try {
            // 如果已经发现漏洞，直接返回
            if (this.vulnerabilityFound) {
                return;
            }
            
            // 创建一个新的浏览器标签页
            const tab = await this.browser.newTab();
            
            // 导航到目标URL
            await tab.goTo(this.url);
            
            // 注入DOM XSS检测器脚本
            await this.injectDetectorScript(tab);
   
            
            // 获取检测结果
            const results = await this.getDetectionResults(tab);
            
            // 关闭标签页
            await tab.close();
            
            // 报告结果
            if (results.length > 0) {
                for (const result of results) {
                    if (hasIdentifier && hasIdentifier.result && hasIdentifier.result.value && hasIdentifier.result.value.found) {
                        const report = createReport({
                            vulnid: this.vulnid,
                            taskid: this.taskid,
                            url: this.url,
                            source: result.source.label,
                            sink: result.sink.label,
                            value: result.value,
                            severity: result.severity,
                            details: `DOM XSS vulnerability found. Source: '${result.source.label}', Sink: '${result.sink.label}', Value: '${result.value}'`
                        });
                        
                        this.alert(report);
                        
                        // 设置标志，表示已经发现漏洞
                        this.vulnerabilityFound = true;
                        return; // 找到漏洞后立即返回
                    }
                }
            }
            
            // 如果没有发现漏洞，进行主动测试
            if (!this.vulnerabilityFound) {
                await this.activeDetection();
            }
        } catch (error) {
            console.error(`[${this.name}] Error:`, error);
        }
    }

    // 触发DOM事件
    async triggerEvents(tab, timeout = 5000) {
        try {
            // 设置超时
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('触发事件超时')), timeout);
            });
            
            // 执行事件触发
            const triggerPromise = tab.evaluate(() => {
                // 获取所有可点击元素
                const clickableElements = document.querySelectorAll('a, button, input[type="button"], input[type="submit"], [onclick]');
                
                // 触发点击事件
                clickableElements.forEach(element => {
                    try {
                        const event = new MouseEvent('click', {
                            bubbles: true,
                            cancelable: true,
                            view: window
                        });
                        element.dispatchEvent(event);
                    } catch (e) {
                        // 忽略错误
                    }
                });
                
                // 获取所有表单元素
                const formElements = document.querySelectorAll('input[type="text"], textarea');
                
                // 触发输入事件
                formElements.forEach(element => {
                    try {
                        element.value = 'test';
                        const event = new Event('input', {
                            bubbles: true,
                            cancelable: true
                        });
                        element.dispatchEvent(event);
                        
                        const changeEvent = new Event('change', {
                            bubbles: true,
                            cancelable: true
                        });
                        element.dispatchEvent(changeEvent);
                    } catch (e) {
                        // 忽略错误
                    }
                });
                
                // 触发鼠标移动事件
                const mouseoverElements = document.querySelectorAll('[onmouseover]');
                mouseoverElements.forEach(element => {
                    try {
                        const event = new MouseEvent('mouseover', {
                            bubbles: true,
                            cancelable: true,
                            view: window
                        });
                        element.dispatchEvent(event);
                    } catch (e) {
                        // 忽略错误
                    }
                });
                
                return '事件触发完成';
            });
            
            // 使用 Promise.race 实现超时
            await Promise.race([triggerPromise, timeoutPromise]);
            
            console.log('DOM事件触发成功');
        } catch (error) {
            console.error('触发DOM事件时出错:', error.message);
        }
    }

    async setupDialogHandler(tab) {
        // 启用Page域以接收JavaScript对话框事件
        await tab.client.Page.enable();
        
        // 监听JavaScript对话框事件
        tab.client.Page.javascriptDialogOpening(async ({ type, message, url }) => {
            // console.log(`对话框被拦截: ${type} - ${message}`);
            
            // 自动关闭对话框
            await tab.client.Page.handleJavaScriptDialog({
                accept: true  // 接受对话框
            });
        });
    }

    /**
     * 主动DOM XSS检测
     * @returns {Promise<void>}
     */
    async activeDetection() {
        try {
            // 如果已经发现漏洞，直接返回
            if (this.vulnerabilityFound) {
                return;
            }
            
            // 解析URL
            const urlObj = new URL(this.url);
            
            // 获取URL参数
            const searchParams = new URLSearchParams(urlObj.search);
            const params = [];
            
            // 将URL参数转换为数组
            for (const [name, value] of searchParams.entries()) {
                params.push({ name, value });
            }
            
            // 如果没有参数，添加一些常见参数进行测试
            if (params.length === 0) {
                const commonParams = ['q', 'search', 'id', 'name', 'input', 'query', 'keyword', 'redirect', 'url', 'callback'];
                for (const param of commonParams) {
                    params.push({ name: param, value: 'test' });
                }
            }
            
            // 为每个参数尝试不同的payload
            for (const param of params) {
                // 如果已经发现漏洞，跳出循环
                if (this.vulnerabilityFound) {
                    break;
                }
                
                const originalValue = param.value;
                
                // 为每个接收点类型尝试不同的payload
                for (const sink of this.sinks) {
                    // 如果已经发现漏洞，跳出循环
                    if (this.vulnerabilityFound) {
                        break;
                    }

                    const payload = this.getPayloadForSink(sink);
                    
                    // 构建测试URL
                    const testParams = new URLSearchParams(searchParams);
                    testParams.set(param.name, payload);
                    
                    const testUrl = `${urlObj.origin}${urlObj.pathname}?${testParams.toString()}`;
                    
                    // 创建一个新的浏览器标签页
                    const tab = await this.browser.newTab();
                    // 设置对话框处理器
                    await this.setupDialogHandler(tab);

                    try {
                        // 导航到测试URL
                        await tab.goTo(testUrl);
                    
                        // 触发DOM事件，设置1.5秒超时
                        await this.triggerEvents(tab, 1500);

                        // 检查是否存在我们的标识符
                        const hasIdentifier = await tab.evaluate((identifier) => {
                            // 检查是否有元素包含我们的标识符
                            const elements = document.querySelectorAll(`[data-xss-found="${identifier}"]`);
                            if (elements.length > 0) {
                                return { found: true, sink: 'element.attribute' };
                            }
                            
                            // // 检查HTML中是否包含我们的标识符
                            // if (document.documentElement.innerHTML.includes(identifier)) {
                            //     return { found: true, sink: 'document.innerHTML' };
                            // }a
                            
                            // 检查document.documentElement是否有我们的标识符
                            if (document.documentElement.getAttribute('data-xss-found') === identifier) {
                                return { found: true, sink: 'document.documentElement' };
                            }
                            
                            return { found: false };
                        }, this.identifier);
                    
                        // 如果找到漏洞，报告结果
                        if (hasIdentifier.result.value.found) {
                            const report = createReport({
                                vulnid: this.vulnid,
                                taskid: this.taskid,
                                url: testUrl,
                                param: param.name,
                                payload: payload,
                                sink: hasIdentifier.sink,
                                category: sink.category,
                                severity: this.getSeverity(sink.category),
                                details: `DOM XSS vulnerability found in parameter '${param.name}' with payload '${payload}'. The payload was executed in the '${hasIdentifier.sink}' sink.`
                            });
                            
                            this.alert(report);
                            
                            // 设置标志，表示已经发现漏洞
                            this.vulnerabilityFound = true;
                        }
                        

                    } catch (error) {
                        console.error(`[${this.name}] Error:`, error);
                    } finally {
                        // 确保标签页被关闭
                        await tab.close();
                        
                        // 如果已经发现漏洞，跳出循环
                        if (this.vulnerabilityFound) {
                            break;
                        }
                    }
                }
                // 如果已经发现漏洞，跳出循环
                if (this.vulnerabilityFound) {
                    break;
                }
            }
        } catch (error) {
            console.error(`[${this.name}] Error in activeDetection:`, error);
        }
    }

    /**
     * 主入口函数
     * @returns {Promise<void>}
     */
    async run() {
        console.log(`[${this.name}] Starting detection...`);
        
        // 执行高级检测
        await this.advancedDetect();
        
        console.log(`[${this.name}] Detection completed.`);
    }
}

module.exports = DOMXSSDetector;