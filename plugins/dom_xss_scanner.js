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
        // 修改：不使用alert，改用document.documentElement.setAttribute
        // 并添加额外的payload变体
        const extraPayloads = [
            `"><div data-custom="${this.identifier}"></div>`,
            `"><script>document.documentElement.setAttribute('data-xss-${Math.random().toString(36).substring(2)}','${this.identifier}')</script>`,
            `javascript:document.documentElement.setAttribute('data-xss-${Math.random().toString(36).substring(2)}','${this.identifier}')`
        ];

        return {
            // HTML注入类payload
            html: [
                `"><svg/onload=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
                `"><img/src/onerror=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
                `<img src=x onerror=this.setAttribute('data-xss-found','${this.identifier}')>`,
                `<div data-xss-found="${this.identifier}"></div>`,
                `<svg onload="document.documentElement.setAttribute('data-xss-found','${this.identifier}')">`,
                `<iframe srcdoc="<script>parent.document.documentElement.setAttribute('data-xss-found','${this.identifier}')</script>"></iframe>`,
                ...extraPayloads
            ],
            
            // JavaScript执行类payload
            js: [
                `"><svg/onload=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
                `"><img/src/onerror=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
                `document.documentElement.setAttribute('data-xss-found','${this.identifier}')`,
                `(function(){document.documentElement.setAttribute('data-xss-found','${this.identifier}')}())`,
                `setTimeout(function(){document.documentElement.setAttribute('data-xss-found','${this.identifier}')},0)`,
                ...extraPayloads
            ],
            
            // URL类payload
            url: [
                `"><svg/onload=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
                `"><img/src/onerror=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
                `javascript:document.documentElement.setAttribute('data-xss-found','${this.identifier}');void(0)`,
                `data:text/html,<script>document.documentElement.setAttribute('data-xss-found','${this.identifier}')</script>`,
                ...extraPayloads
            ],
            
            // 事件处理类payload
            event: [
                `"><svg/onload=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
                `"><img/src/onerror=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
                `x" onload="document.documentElement.setAttribute('data-xss-found','${this.identifier}')" "`,
                `x" onclick="document.documentElement.setAttribute('data-xss-found','${this.identifier}')" "`,
                ...extraPayloads
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
                scriptElement.textContent = script;
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
            console.log('当前检测结果:', window.domXssResults);
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
                const clickableElements = document.querySelectorAll('button, input[type="button"], input[type="submit"], [onclick]');
                
                // 新增: 模拟 onerror 和 onload 事件
                const errorElements = document.querySelectorAll('img, script, iframe');
                errorElements.forEach(element => {
                    try {
                        element.dispatchEvent(new Event('error', { bubbles: true }));
                        element.dispatchEvent(new Event('load', { bubbles: true }));
                    } catch (e) {}
                });
                    
                // 新增: 模拟自定义事件（如果页面有监听）
                document.dispatchEvent(new CustomEvent('customXssTrigger', { detail: { test: 'xss' } }));
                    
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
                        const event = new MouseEvent('mouseover', { bubbles: true, cancelable: true, view: window });
                        element.dispatchEvent(event);
                
                        // 新增：若存在内联事件属性则主动 eval 执行
                        const handler = element.getAttribute('onmouseover');
                        if (handler) {
                            eval(handler);
                        }
                    } catch (e) {
                        console.warn("事件触发出错:", e);
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
                // 注入DOM XSS检测脚本
                await this.injectDetectorScript(tab);     
                // 导航到目标URL
                await tab.goTo(this.url);
    
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
        // 执行不发包表单填充检测
        const tab = await this.browser.newTab();
        await this.setupDialogHandler(tab);
        await tab.goTo(this.url);
        await this.injectDetectorScript(tab);
        await this.formFillingDetection(tab);
        await tab.close();
    
        if (this.vulnerabilityFound) {
            console.log(`[${this.name}] 已通过不发包检测发现漏洞，跳过主动验证`);
            return;
        }
        console.log(`[${this.name}] 开始主动验证...`);
        
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

            lastJob.method = this.method;
            lastJob.headers = this.headers;
            lastJob.isEncodeUrl = false;
            
            for (var i = 0; i < this.variations.length; i++) {
                this.variations.setValue(i, payload);
                let payload11 = this.variations.toString();
                let url = new URL(this.url);
                let newurl = url.origin + url.pathname + '?' + payload11;
                lastJob.url = newurl;
                const response = await lastJob.execute(false);
                await lastJob.triggerAllDomEvents(800);
                
                if (!response || !response.body) {
                    console.log(`[${this.name}] 验证请求失败或响应为空`);
                    return;
                }

                try {
                    // 修改：检查任何属性是否包含我们的标识符，而不仅仅是data-xss-found
                    const hasIdentifier = await lastJob.evaluate((identifier) => {
                        // 检查是否有元素的任何属性包含我们的标识符
                        const allElements = document.querySelectorAll('*');
                        for (const element of allElements) {
                            const attributes = element.attributes;
                            for (let i = 0; i < attributes.length; i++) {
                                if (attributes[i].value.includes(identifier)) {
                                    return { 
                                        found: true, 
                                        sink: 'element.attribute', 
                                        attribute: attributes[i].name,
                                        value: attributes[i].value
                                    };
                                }
                            }
                        }
                        
                        // 检查document.documentElement的所有属性
                        const docAttributes = document.documentElement.attributes;
                        for (let i = 0; i < docAttributes.length; i++) {
                            if (docAttributes[i].value.includes(identifier)) {
                                return { 
                                    found: true, 
                                    sink: 'document.documentElement', 
                                    attribute: docAttributes[i].name,
                                    value: docAttributes[i].value
                                };
                            }
                        }
                        
                        return { found: false };
                    }, this.identifier);
                    
                    // 如果找到漏洞，报告结果
                    if (hasIdentifier.result.value.found) {
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
                            details: `DOM XSS vulnerability found in GET parameter '${sourceParam}'. Source: ${point.source.label}, Sink: ${point.sink.label}, Attribute: ${hasIdentifier.result.value.attribute}, Value: ${hasIdentifier.result.value.value}`
                        });
                        
                        this.alert(report);
                        
                        // 设置标志，表示已经发现漏洞
                        this.vulnerabilityFound = true;
                        return;
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
            // 使用引擎的请求连接方式发送请求
            const lastJob = new browerHttpJob(this.browser);
            lastJob.url = this.url;
            lastJob.method = "POST";
            lastJob.headers = this.headers;
            lastJob.isEncodeUrl = false;

            // 构建验证payload
            const payload = this.getPayloadForSink({
                category: this.getSinkCategory(point.sink.label)
            });

            // 遍历所有变量参数
            for (var i = 0; i < this.variations.length; i++) {
                // 设置当前参数的值为payload
                this.variations.setValue(i, payload);
                // 获取完整的POST数据字符串
                let postData = this.variations.toString();
                // 设置POST数据
                lastJob.postData = postData;
                
                // 执行请求，不关闭标签页
                const response = await lastJob.execute(false);
                
                // 触发DOM事件
                await lastJob.triggerAllDomEvents(800);
                
                if (!response || !response.body) {
                    console.log(`[${this.name}] 验证请求失败或响应为空`);
                    continue; // 继续测试下一个参数
                }

                try {
                    // 修改：检查任何属性是否包含我们的标识符
                    const hasIdentifier = await lastJob.evaluate((identifier) => {
                        // 检查是否有元素的任何属性包含我们的标识符
                        const allElements = document.querySelectorAll('*');
                        for (const element of allElements) {
                            const attributes = element.attributes;
                            for (let i = 0; i < attributes.length; i++) {
                                if (attributes[i].value.includes(identifier)) {
                                    return { 
                                        found: true, 
                                        sink: 'element.attribute', 
                                        attribute: attributes[i].name,
                                        value: attributes[i].value
                                    };
                                }
                            }
                        }
                        
                        // 检查document.documentElement的所有属性
                        const docAttributes = document.documentElement.attributes;
                        for (let i = 0; i < docAttributes.length; i++) {
                            if (docAttributes[i].value.includes(identifier)) {
                                return { 
                                    found: true, 
                                    sink: 'document.documentElement', 
                                    attribute: docAttributes[i].name,
                                    value: docAttributes[i].value
                                };
                            }
                        }
                        
                        return { found: false };
                    }, this.identifier);
                    
                    // 如果找到漏洞，报告结果
                    if (hasIdentifier.result.value.found) {
                        const report = createReport({
                            vulnid: this.vulnid,
                            taskid: this.taskid,
                            url: this.url,
                            param: this.variations.getKey(i), // 使用当前参数名
                            payload: payload,
                            source: point.source.label,
                            sink: point.sink.label,
                            category: this.getSinkCategory(point.sink.label),
                            severity: point.severity || this.getSeverity(this.getSinkCategory(point.sink.label)),
                            details: `DOM XSS vulnerability found in POST parameter '${this.variations.getKey(i)}'. Source: ${point.source.label}, Sink: ${point.sink.label}, Attribute: ${hasIdentifier.result.value.attribute}, Value: ${hasIdentifier.result.value.value}`
                        });
                        
                        this.alert(report);
                        
                        // 设置标志，表示已经发现漏洞
                        this.vulnerabilityFound = true;
                        await lastJob.closeTab(); // 关闭标签页
                        return; // 找到漏洞后立即返回
                    }
                } catch (error) {
                    console.error(`[${this.name}] 验证出错:`, error);
                }
                
                // 恢复原始值
                this.variations.setValue(i, this.variations.getValue(i));
            }
            
            // 完成所有测试后关闭标签页
            await lastJob.closeTab();
        } catch (error) {
            console.error(`[${this.name}] 验证POST参数出错:`, error);
        }
    }

    /**
     * 新增：不发包的表单填充检测
     * @param {Object} tab - 浏览器标签页
     * @returns {Promise<void>}
     */
    async formFillingDetection(tab) {
        try {
            // 如果已经发现漏洞，直接返回
            if (this.vulnerabilityFound) {
                return;
            }

            console.log('开始不发包的表单填充检测...');
            
            // 获取页面中的输入字段
            const formElements = await tab.evaluate(() => {
                const inputs = Array.from(document.querySelectorAll('input[type="text"], input[type="search"], input[type="email"], input[type="url"], textarea, select'));
                return inputs.map(el => ({
                    tag: el.tagName,
                    type: el.type || 'text',
                    id: el.id,
                    name: el.name
                }));
            });

            // 如果没有输入字段，跳过
            if (!formElements.result.value.length) {
                console.log('未找到输入字段，跳过表单填充检测');
                return;
            }

            // 为每个接收点类型尝试payload
            for (const sink of this.sinks) {
                if (this.vulnerabilityFound) break;

                const payload = this.getPayloadForSink(sink);

                // 在注入payload后的 tab.evaluate 内部加入触发按钮点击
                await tab.evaluate((payload) => {
                    const inputs = document.querySelectorAll('input[type="text"], input[type="search"], input[type="email"], input[type="url"], textarea, select');
                    inputs.forEach(input => {
                        if (input.tagName === 'SELECT') {
                            input.options[0].value = payload;
                            input.options[0].text = payload;
                        } else {
                            input.value = payload;
                        }
                        // 模拟输入事件
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                        input.dispatchEvent(new Event('blur', { bubbles: true }));
                    });

                    // 模拟点击按钮
                    const buttons = document.querySelectorAll('button, input[type="submit"], input[type="button"]');
                    buttons.forEach(btn => {
                        try {
                            btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
                        } catch (e) {}
                    });
                }, payload);

                // 额外触发页面事件（例如，表单的onchange或自定义事件）
                await this.triggerEvents(tab, 1500); // 复用现有方法，超时1.5秒

                // 修改：检查任何属性是否包含我们的标识符
                const hasIdentifier = await tab.evaluate((identifier) => {
                    // 检查是否有元素的任何属性包含我们的标识符
                    const allElements = document.querySelectorAll('*');
                    for (const element of allElements) {
                        const attributes = element.attributes;
                        for (let i = 0; i < attributes.length; i++) {
                            if (attributes[i].value.includes(identifier)) {
                                return { 
                                    found: true, 
                                    sink: 'element.attribute', 
                                    attribute: attributes[i].name,
                                    value: attributes[i].value
                                };
                            }
                        }
                    }
                    
                    // 检查document.documentElement的所有属性
                    const docAttributes = document.documentElement.attributes;
                    for (let i = 0; i < docAttributes.length; i++) {
                        if (docAttributes[i].value.includes(identifier)) {
                            return { 
                                found: true, 
                                sink: 'document.documentElement', 
                                attribute: docAttributes[i].name,
                                value: docAttributes[i].value
                            };
                        }
                    }
                    
                    return { found: false };
                }, this.identifier);
                
                // 如果找到漏洞，报告结果
                if (hasIdentifier.result.value.found) {
                    const report = createReport({
                        vulnid: this.vulnid,
                        taskid: this.taskid,
                        url: this.url,
                        param: 'form_input',
                        payload: payload,
                        source: 'form_filling',
                        sink: hasIdentifier.result.value.sink,
                        category: sink.category,
                        severity: this.getSeverity(sink.category),
                        details: `DOM XSS found via form filling with payload '${payload}'. Executed in '${hasIdentifier.result.value.sink}' sink. Attribute: ${hasIdentifier.result.value.attribute}, Value: ${hasIdentifier.result.value.value}`
                    });
                    this.alert(report);
                    this.vulnerabilityFound = true;
                    break;
                }
                
                // 新增: 更多 payload 变体以覆盖过滤
                const extraPayloads = [
                    `"><div data-test="${this.identifier}"></div>`,
                    `"><script>document.documentElement.setAttribute('data-${Math.random().toString(36).substring(2)}','${this.identifier}')</script>`,
                    `javascript:document.documentElement.setAttribute('data-${Math.random().toString(36).substring(2)}','${this.identifier}')`
                ];
                
                for (const extraPayload of extraPayloads) {
                    if (this.vulnerabilityFound) break;
                    
                    await tab.evaluate((payload) => {
                        const inputs = document.querySelectorAll('input[type="text"], input[type="search"], input[type="email"], input[type="url"], textarea, select');
                        inputs.forEach(input => {
                            if (input.tagName === 'SELECT') {
                                input.options[0].value = payload;
                                input.options[0].text = payload;
                            } else {
                                input.value = payload;
                            }
                            input.dispatchEvent(new Event('input', { bubbles: true }));
                            input.dispatchEvent(new Event('change', { bubbles: true }));
                            input.dispatchEvent(new Event('blur', { bubbles: true }));
                        });
                        
                        const buttons = document.querySelectorAll('button, input[type="submit"], input[type="button"]');
                        buttons.forEach(btn => {
                            try {
                                btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
                            } catch (e) {}
                        });
                    }, extraPayload);
                    
                    await this.triggerEvents(tab, 1500);
                    
                    // 修改：检查任何属性是否包含我们的标识符
                    const checkResult = await tab.evaluate((identifier) => {
                        // 检查是否有元素的任何属性包含我们的标识符
                        const allElements = document.querySelectorAll('*');
                        for (const element of allElements) {
                            const attributes = element.attributes;
                            for (let i = 0; i < attributes.length; i++) {
                                if (attributes[i].value.includes(identifier)) {
                                    return { 
                                        found: true, 
                                        sink: 'element.attribute', 
                                        attribute: attributes[i].name,
                                        value: attributes[i].value
                                    };
                                }
                            }
                        }
                        
                        // 检查document.documentElement的所有属性
                        const docAttributes = document.documentElement.attributes;
                        for (let i = 0; i < docAttributes.length; i++) {
                            if (docAttributes[i].value.includes(identifier)) {
                                return { 
                                    found: true, 
                                    sink: 'document.documentElement', 
                                    attribute: docAttributes[i].name,
                                    value: docAttributes[i].value
                                };
                            }
                        }
                        
                        return { found: false };
                    }, this.identifier);
                    
                    if (checkResult.result.value.found) {
                        const report = createReport({
                            vulnid: this.vulnid,
                            taskid: this.taskid,
                            url: this.url,
                            param: 'form_input',
                            payload: extraPayload,
                            source: 'form_filling',
                            sink: checkResult.result.value.sink,
                            category: sink.category,
                            severity: this.getSeverity(sink.category),
                            details: `DOM XSS found via form filling with extra payload '${extraPayload}'. Executed in '${checkResult.result.value.sink}' sink. Attribute: ${checkResult.result.value.attribute}, Value: ${checkResult.result.value.value}`
                        });
                        this.alert(report);
                        this.vulnerabilityFound = true;
                        break;
                    }
                }
                
                // 新增: 延迟检查 DOM 变化以避免异步误报
                await new Promise(resolve => setTimeout(resolve, 1000));
                const finalCheck = await tab.evaluate((identifier) => {
                    // 检查是否有元素的任何属性包含我们的标识符
                    const allElements = document.querySelectorAll('*');
                    for (const element of allElements) {
                        const attributes = element.attributes;
                        for (let i = 0; i < attributes.length; i++) {
                            if (attributes[i].value.includes(identifier)) {
                                return { 
                                    found: true, 
                                    sink: 'element.attribute', 
                                    attribute: attributes[i].name,
                                    value: attributes[i].value
                                };
                            }
                        }
                    }
                    
                    // 检查document.documentElement的所有属性
                    const docAttributes = document.documentElement.attributes;
                    for (let i = 0; i < docAttributes.length; i++) {
                        if (docAttributes[i].value.includes(identifier)) {
                            return { 
                                found: true, 
                                sink: 'document.documentElement', 
                                attribute: docAttributes[i].name,
                                value: docAttributes[i].value
                            };
                        }
                    }
                    
                    return { found: false };
                }, this.identifier);
                
                if (finalCheck.result.value.found && !this.vulnerabilityFound) {
                    const report = createReport({
                        vulnid: this.vulnid,
                        taskid: this.taskid,
                        url: this.url,
                        param: 'form_input',
                        payload: payload,
                        source: 'form_filling_delayed',
                        sink: finalCheck.result.value.sink,
                        category: sink.category,
                        severity: this.getSeverity(sink.category),
                        details: `DOM XSS found via form filling (delayed execution) with payload '${payload}'. Executed in '${finalCheck.result.value.sink}' sink. Attribute: ${finalCheck.result.value.attribute}, Value: ${finalCheck.result.value.value}`
                    });
                    this.alert(report);
                    this.vulnerabilityFound = true;
                    break;
                }
            }

            console.log('表单填充检测完成');
        } catch (error) {
            console.error('表单填充检测出错:', error);
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