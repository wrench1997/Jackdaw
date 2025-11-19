
// plugins/dom_xss_scanner.js
const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js');
const fs = require('fs');
const path = require('path');

async function loadDetectorScript() {
    return new Promise((resolve, reject) => {
      const filePath = path.join(__dirname, '../dom_xss_detector.js');
      const stream = fs.createReadStream(filePath, { encoding: 'utf8' });
      
      let content = '';  // 用于累加文件内容
      
      stream.on('data', (chunk) => {
        content += chunk;  // 逐块累加
      });
      
      stream.on('end', () => {
        console.log('文件读取完成，内容长度:', content.length);
        resolve(content);  // 返回完整内容
      });
      
      stream.on('error', (error) => {
        console.error('读取文件出错:', error);
        reject(error);  // 抛出错误
      });
    });
}

class DOMXSSScanner extends CoreLayer {
    constructor(Core) {
        super(Core);
        this.name = "DOM XSS Scanner";
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
        
        // 存储被动扫描发现的可疑点
        this.suspiciousPoints = [];
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
     * 注入DOM XSS检测脚本
     * @param {Object} tab - 浏览器标签页
     * @returns {Promise<void>}
     */
    async injectDetectorScript(tab) {
        // 读取DOM XSS检测器脚本
        const detectorScript = await loadDetectorScript();
        // 注入脚本
        await tab.evaluate((script) => {
            try {
                
                // 创建一个自定义回调函数，用于接收检测结果
                window.xssReportCallback = function(results) {
                    window.domXssResults = results;
                    document.documentElement.setAttribute('data-xss-detector-loaded', 'true');
                };
                
                // 创建脚本元素并添加到页面
                const scriptElement = document.createElement('script');
                scriptElement.textContent  = script;
                document.head.appendChild(scriptElement);
                console.log("DOM XSS 检测器已成功加载");

                return true;
            } catch (e) {
                console.error("DOM XSS 检测器加载失败:", e.message);
                return false;
            }
        }, detectorScript);
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
     * 触发DOM事件
     * @param {Object} tab - 浏览器标签页
     * @param {number} timeout - 超时时间(毫秒)
     * @returns {Promise<void>}
     */
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

    /**
     * 设置对话框处理器
     * @param {Object} tab - 浏览器标签页
     * @returns {Promise<void>}
     */
    async setupDialogHandler(tab) {
        // 启用Page域以接收JavaScript对话框事件
        await tab.client.Page.enable();
        
        // 监听JavaScript对话框事件
        tab.client.Page.javascriptDialogOpening(async ({ type, message, url }) => {
            console.log(`对话框被拦截: ${type} - ${message}`);
            
            // 自动关闭对话框
            await tab.client.Page.handleJavaScriptDialog({
                accept: true  // 接受对话框
            });
        });
    }

    /**
     * 被动扫描 - 检测页面中可能存在的DOM XSS漏洞
     * @returns {Promise<Array>} 可疑的DOM XSS点
     */
    async passiveScan() {
        console.log(`[${this.name}] 开始被动扫描...`);
        
        try {
            // 创建一个新的浏览器标签页
            const tab = await this.browser.newTab();
            
            // 设置对话框处理器
            await this.setupDialogHandler(tab);
            
            try {

                // 导航到目标URL
                await tab.goTo(this.url);
                // 注入DOM XSS检测脚本
                await this.injectDetectorScript(tab);         
                
                // 触发DOM事件
                await this.triggerEvents(tab, 5000);
                
                // 获取检测结果
                const detectionResults = await this.getDetectionResults(tab);
                
                console.log(`[${this.name}] 被动扫描发现 ${detectionResults ? detectionResults.result.value.length : 0} 个可疑点`);
                
                // 存储可疑点
                this.suspiciousPoints = detectionResults || [];
                
                return this.suspiciousPoints;
            } catch (error) {
                console.error(`[${this.name}] 被动扫描出错:`, error);
                return [];
            } finally {
                // 确保标签页被关闭
                await tab.close();
            }
        } catch (error) {
            console.error(`[${this.name}] 被动扫描出错:`, error);
            return [];
        }
    }

    /**
     * 主动验证 - 验证被动扫描发现的可疑点
     * @returns {Promise<void>}
     */
    async activeVerification() {
        console.log(`[${this.name}] 开始主动验证...`);
        
        // 如果没有可疑点或者已经发现漏洞，直接进行全面主动扫描
        if (!this.suspiciousPoints || this.suspiciousPoints.result.value.length === 0 || this.vulnerabilityFound) {
            console.log(`[${this.name}] 没有可疑点需要验证或已发现漏洞，开始全面主动扫描...`);
            await this.activeDetection();
            return;
        }
        
        try {
            // 为每个可疑点进行验证
            for (const point of this.suspiciousPoints.result.value) {
                // 如果已经发现漏洞，跳出循环
                if (this.vulnerabilityFound) {
                    break;
                }
                
                // 确保点有源和接收点
                if (!point.source || !point.sink) {
                    continue;
                }
                
                console.log(`[${this.name}] 验证可疑点: 源=${point.source.label}, 接收点=${point.sink.label}`);
                
                // 根据源类型确定测试方法
                if (this.method === "GET") {
                    await this.verifyGetParameter(point);
                } else if (this.method === "POST") {
                    await this.verifyPostParameter(point);
                }
            }
            
            // 如果验证后仍未发现漏洞，进行全面主动扫描
            // if (!this.vulnerabilityFound) {
            //     await this.activeDetection();
            // }
        } catch (error) {
            console.error(`[${this.name}] 主动验证出错:`, error);
        }
    }
    
    /**
     * 验证GET参数
     * @param {Object} point - 可疑点
     * @returns {Promise<void>}
     */
    async verifyGetParameter(point) {
        try {
            // 解析URL参数
            const url = new URL(this.url);
            const urlParams = new URLSearchParams(url.search);
            
            // 确定源参数
            let sourceParam = null;
            
            // 尝试从URL参数中找到可能的源参数
            for (const [name, value] of urlParams.entries()) {
                if (point.value && point.value.includes(value)) {
                    sourceParam = name;
                    break;
                }
            }
            
            // 如果没有找到源参数，使用一个默认参数或第一个参数
            if (!sourceParam) {
                if (urlParams.keys().next().value) {
                    sourceParam = urlParams.keys().next().value;
                } else {
                    sourceParam = 'xss';
                    // 如果没有参数，添加一个测试参数
                    urlParams.append(sourceParam, 'test');
                }
            }

            // 构建验证payload
            const payload = this.getPayloadForSink({
                category: this.getSinkCategory(point.sink.label)
            });

            // 使用引擎的请求连接方式发送请求
            const lastJob = new browerHttpJob(this.browser);

            lastJob.method = this.method
            lastJob.headers = this.headers
            lastJob.isEncodeUrl = false;
            for (var i = 0; i < this.variations.length; i++) {
                this.variations.setValue(i, payload)
                let payload11 = this.variations.toString()
                let url = new URL(this.url);
                let newurl = url.origin + url.pathname + '?' + payload11
                lastJob.url = newurl
                const response = await lastJob.execute(false);
                await lastJob.triggerAllDomEvents(800)
                if (!response || !response.body) {
                    console.log(`[${this.name}] 验证请求失败或响应为空`);
                    return;
                }

                try {
                    // 检查是否存在我们的标识符
                    const hasIdentifier = await lastJob.evaluate((identifier) => {
                        // 检查是否有元素包含我们的标识符
                        const elements = document.querySelectorAll(`[data-xss-found="${identifier}"]`);
                        if (elements.length > 0) {
                            return { found: true, sink: 'element.attribute' };
                        }
                        
                        // 检查document.documentElement是否有我们的标识符
                        if (document.documentElement.getAttribute('data-xss-found') === identifier) {
                            return { found: true, sink: 'document.documentElement' };
                        }
                        
                        return { found: false };
                    }, this.identifier);
                    
                    // 如果找到漏洞，报告结果
                    if (hasIdentifier && hasIdentifier.result.value.found) {
                        const report = createReport({
                            vulnid: this.vulnid,
                            taskid: this.taskid,
                            url: this.url,
                            param: sourceParam,
                            payload: payload,
                            source: point.source.label,
                            sink: point.sink.label,
                            category: this.getSinkCategory(point.sink.label),
                            severity: point.severity || this.getSeverity(this.getSinkCategory(point.sink.label)),
                            details: `DOM XSS vulnerability found in GET parameter '${sourceParam}'. Source: ${point.source.label}, Sink: ${point.sink.label}`
                        });
                        
                        this.alert(report);
                        
                        // 设置标志，表示已经发现漏洞
                        this.vulnerabilityFound = true;
                        return
                    }
                } catch (error) {
                    console.error(`[${this.name}] 验证出错:`, error);
                } finally {
                    // 确保标签页被关闭
                    await lastJob.closeTab();
                }
            }
        } catch (error) {
            console.error(`[${this.name}] 验证GET参数出错:`, error);
        }
    }
    
    /**
     * 验证POST参数
     * @param {Object} point - 可疑点
     * @returns {Promise<void>}
     */
    async verifyPostParameter(point) {
        try {
            // 解析POST数据
            const postParams = new URLSearchParams(this.postData);
            
            // 确定源参数
            let sourceParam = null;
            
            // 尝试从POST参数中找到可能的源参数
            for (const [name, value] of postParams.entries()) {
                if (point.value && point.value.includes(value)) {
                    sourceParam = name;
                    break;
                }
            }
            
            // 如果没有找到源参数，使用一个默认参数或第一个参数
            if (!sourceParam) {
                if (postParams.keys().next().value) {
                    sourceParam = postParams.keys().next().value;
                } else {
                    sourceParam = 'xss';
                    postParams.append(sourceParam, 'test');
                }
            }
            
            // 构建验证payload
            const payload = this.getPayloadForSink({
                category: this.getSinkCategory(point.sink.label)
            });
            
            // 设置payload到参数中
            postParams.set(sourceParam, payload);
            
            // 使用引擎的请求连接方式发送请求
            const lastJob = new browerHttpJob(this.browser);
            lastJob.url = this.url;
            lastJob.method = "POST";
            lastJob.headers = this.headers;
            lastJob.postData = postParams.toString();
            lastJob.isEncodeUrl = false;
            
            const response = await lastJob.execute();
            
            if (!response || !response.body) {
                console.log(`[${this.name}] 验证请求失败或响应为空`);
                return;
            }
            
      
            try {
                // 检查是否存在我们的标识符
                const hasIdentifier = await lastJob.evaluate((identifier) => {
                    // 检查是否有元素包含我们的标识符
                    const elements = document.querySelectorAll(`[data-xss-found="${identifier}"]`);
                    if (elements.length > 0) {
                        return { found: true, sink: 'element.attribute' };
                    }
                    // 检查document.documentElement是否有我们的标识符
                    if (document.documentElement.getAttribute('data-xss-found') === identifier) {
                        return { found: true, sink: 'document.documentElement' };
                    }
                    return { found: false };
                }, this.identifier);
                
                // 如果找到漏洞，报告结果
                if (hasIdentifier && hasIdentifier.result.value.found) {
                    const report = createReport({
                        vulnid: this.vulnid,
                        taskid: this.taskid,
                        url: this.url,
                        param: sourceParam,
                        payload: payload,
                        source: point.source.label,
                        sink: point.sink.label,
                        category: this.getSinkCategory(point.sink.label),
                        severity: point.severity || this.getSeverity(this.getSinkCategory(point.sink.label)),
                        details: `DOM XSS vulnerability found in POST parameter '${sourceParam}'. Source: ${point.source.label}, Sink: ${point.sink.label}`
                    });
                    
                    this.alert(report);
                    
                    // 设置标志，表示已经发现漏洞
                    this.vulnerabilityFound = true;
                }
            } catch (error) {
                console.error(`[${this.name}] 验证出错:`, error);
            }
            // 不需要关闭标签页，因为我们使用的是已有的标签页
        } catch (error) {
            console.error(`[${this.name}] 验证POST参数出错:`, error);
        }
    }

    /**
     * 获取接收点类别
     * @param {string} sinkLabel - 接收点标签
     * @returns {string} 接收点类别
     */
    getSinkCategory(sinkLabel) {
        // 查找接收点
        const sink = this.sinks.find(s => s.label === sinkLabel);
        
        if (sink) {
            return sink.category;
        }
        
        // 根据接收点名称推断类别
        if (sinkLabel.includes('eval') || sinkLabel.includes('Function') || 
            sinkLabel.includes('setTimeout') || sinkLabel.includes('setInterval') || 
            sinkLabel.includes('script')) {
            return 'js';
        } else if (sinkLabel.includes('innerHTML') || sinkLabel.includes('outerHTML') || 
                  sinkLabel.includes('write') || sinkLabel.includes('HTML')) {
            return 'html';
        } else if (sinkLabel.includes('href') || sinkLabel.includes('location') || 
                  sinkLabel.includes('src') || sinkLabel.includes('open')) {
            return 'url';
        } else if (sinkLabel.includes('on') || sinkLabel.includes('event') || 
                  sinkLabel.includes('click') || sinkLabel.includes('mouse')) {
            return 'event';
        }
        
        return 'html'; // 默认类别
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
     * 主入口函数
     * @returns {Promise<void>}
     */
    async startTesting() {
        console.log(`[${this.name}] 开始DOM XSS检测...`);
        
        try {
            // 1. 首先进行被动扫描
            await this.passiveScan();
            
            // 2. 然后进行主动验证
            await this.activeVerification();
            
            console.log(`[${this.name}] DOM XSS检测完成. 发现漏洞: ${this.vulnerabilityFound}`);
        } catch (error) {
            console.error(`[${this.name}] 检测过程出错:`, error);
        }
    }
}

module.exports = DOMXSSScanner;
