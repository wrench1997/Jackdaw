// plugins/dom_xss_scanner.js
const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js');
const fs = require('fs');
const path = require('path');


// 工具函数：加载检测器脚本
const loadDetectorScript = async () => {
  return new Promise((resolve, reject) => {
    const filePath = path.join(__dirname, '../dom_xss_detector.js');
    const stream = fs.createReadStream(filePath, { encoding: 'utf8' });
    let content = '';
    
    stream.on('data', chunk => content += chunk);
    stream.on('end', () => resolve(content));
    stream.on('error', error => reject(error));
  });
};

class DOMXSSScanner extends CoreLayer {
  constructor(Core) {
    super(Core);
    this.name = "DOM XSS Scanner";
    this.vulnid = this.getVulnId(__filename);
    
    // 初始化配置
    this.initConfig();
    
    // 生成测试 payloads
    this.payloads = this.generatePayloads();
    
    // 状态标志
    this.vulnerabilityFound = false;
    this.suspiciousPoints = [];
  }

  // 初始化配置
  initConfig() {
    // DOM XSS 源列表
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

    // DOM XSS 接收点列表
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
  }

  // 生成不同类型的DOM XSS payload
  generatePayloads() {
    const extraPayloads = [
      `"><div data-custom="${this.identifier}"></div>`,
      `"><script>document.documentElement.setAttribute('data-xss-${Math.random().toString(36).substring(2)}','${this.identifier}')</script>`,
      `javascript:document.documentElement.setAttribute('data-xss-${Math.random().toString(36).substring(2)}','${this.identifier}')`
    ];

    return {
      html: [
        `"><svg/onload=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
        `"><img/src/onerror=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
        `<img src=x onerror=this.setAttribute('data-xss-found','${this.identifier}')>`,
        `<div data-xss-found="${this.identifier}"></div>`,
        `<svg onload="document.documentElement.setAttribute('data-xss-found','${this.identifier}')">`,
        `<iframe srcdoc="<script>parent.document.documentElement.setAttribute('data-xss-found','${this.identifier}')</script>"></iframe>`,
        ...extraPayloads
      ],
      
      js: [
        `"><svg/onload=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
        `"><img/src/onerror=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
        `document.documentElement.setAttribute('data-xss-found','${this.identifier}')`,
        `(function(){document.documentElement.setAttribute('data-xss-found','${this.identifier}')}())`,
        `setTimeout(function(){document.documentElement.setAttribute('data-xss-found','${this.identifier}')},0)`,
        ...extraPayloads
      ],
      
      url: [
        `"><svg/onload=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
        `"><img/src/onerror=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
        `javascript:document.documentElement.setAttribute('data-xss-found','${this.identifier}');void(0)`,
        `data:text/html,<script>document.documentElement.setAttribute('data-xss-found','${this.identifier}')</script>`,
        ...extraPayloads
      ],
      
      event: [
        `"><svg/onload=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
        `"><img/src/onerror=document.documentElement.setAttribute('data-xss-found','${this.identifier}')>`,
        `x" onload="document.documentElement.setAttribute('data-xss-found','${this.identifier}')" "`,
        `x" onclick="document.documentElement.setAttribute('data-xss-found','${this.identifier}')" "`,
        ...extraPayloads
      ]
    };
  }

  // 获取适合特定接收点的payload
  getPayloadForSink(sink) {
    if (!sink || !sink.category) {
      return this.payloads.html[0]; // 默认使用HTML注入payload
    }
    
    const payloadList = this.payloads[sink.category];
    return payloadList[Math.floor(Math.random() * payloadList.length)];
  }

  // 浏览器操作相关方法
  async injectDetectorScript(tab) {
    const detectorScript = await loadDetectorScript();
    await tab.evaluate((script) => {
      try {
        window.xssReportCallback = function(results) {
          window.domXssResults = results;
          document.documentElement.setAttribute('data-xss-detector-loaded', 'true');
        };
        
        const scriptElement = document.createElement('script');
        scriptElement.textContent = script;
        document.head.appendChild(scriptElement);
        return true;
      } catch (e) {
        console.error("DOM XSS 检测器加载失败:", e.message);
        return false;
      }
    }, detectorScript);
  }

  async getDetectionResults(tab) {
    return await tab.evaluate(() => {
      return window.domXssResults || [];
    });
  }

  async setupDialogHandler(tab) {
    await tab.client.Page.enable();
    
    tab.client.Page.javascriptDialogOpening(async ({ type, message }) => {
      console.log(`对话框被拦截: ${type} - ${message}`);
      await tab.client.Page.handleJavaScriptDialog({ accept: true });
    });
  }

  async triggerEvents(tab, timeout = 5000) {
    try {
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('触发事件超时')), timeout);
      });
      
      const triggerPromise = tab.evaluate(() => {
        // 获取并触发可点击元素
        const clickableElements = document.querySelectorAll('button, input[type="button"], input[type="submit"], [onclick]');
        clickableElements.forEach(element => {
          try {
            element.dispatchEvent(new MouseEvent('click', {
              bubbles: true,
              cancelable: true,
              view: window
            }));
          } catch (e) {}
        });
        
        // 触发错误和加载事件
        const errorElements = document.querySelectorAll('img, script, iframe');
        errorElements.forEach(element => {
          try {
            element.dispatchEvent(new Event('error', { bubbles: true }));
            element.dispatchEvent(new Event('load', { bubbles: true }));
          } catch (e) {}
        });
        
        // 触发自定义事件
        document.dispatchEvent(new CustomEvent('customXssTrigger', { detail: { test: 'xss' } }));
        
        // 触发表单元素事件
        const formElements = document.querySelectorAll('input[type="text"], textarea');
        formElements.forEach(element => {
          try {
            element.value = 'test';
            element.dispatchEvent(new Event('input', { bubbles: true }));
            element.dispatchEvent(new Event('change', { bubbles: true }));
          } catch (e) {}
        });
        
        // 触发鼠标移动事件
        const mouseoverElements = document.querySelectorAll('[onmouseover]');
        mouseoverElements.forEach(element => {
          try {
            element.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
            const handler = element.getAttribute('onmouseover');
            if (handler) {
              eval(handler);
            }
          } catch (e) {}
        });
        
        return '事件触发完成';
      });
      
      await Promise.race([triggerPromise, timeoutPromise]);
    } catch (error) {
      console.error('触发DOM事件时出错:', error.message);
    }
  }

  // 检测方法
  async passiveScan() {
    console.log(`[${this.name}] 开始被动扫描...`);
    
    try {
      const tab = await this.browser.newTab();
      await this.setupDialogHandler(tab);
      
      try {
        await this.injectDetectorScript(tab);
        await tab.goTo(this.url);
        await this.triggerEvents(tab, 5000);
        
        const detectionResults = await this.getDetectionResults(tab);
        
        console.log(`[${this.name}] 被动扫描发现 ${detectionResults ? detectionResults.result.value.length : 0} 个可疑点`);
        
        this.suspiciousPoints = detectionResults || [];
        
        return this.suspiciousPoints;
      } finally {
        await tab.close();
      }
    } catch (error) {
      console.error(`[${this.name}] 被动扫描出错:`, error);
      return [];
    }
  }

  async formFillingDetection(tab) {
    if (this.vulnerabilityFound) return;

    try {
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

      if (!formElements.result.value.length) {
        console.log('未找到输入字段，跳过表单填充检测');
        return;
      }

      // 为每个接收点类型尝试payload
      for (const sink of this.sinks) {
        if (this.vulnerabilityFound) break;

        const payload = this.getPayloadForSink(sink);
        await this.testFormPayload(tab, payload, sink);
        
        // 测试额外的payload变体
        const extraPayloads = [
          `"><div data-test="${this.identifier}"></div>`,
          `"><script>document.documentElement.setAttribute('data-${Math.random().toString(36).substring(2)}','${this.identifier}')</script>`,
          `javascript:document.documentElement.setAttribute('data-${Math.random().toString(36).substring(2)}','${this.identifier}')`
        ];
        
        for (const extraPayload of extraPayloads) {
          if (this.vulnerabilityFound) break;
          await this.testFormPayload(tab, extraPayload, sink);
        }
        
        // 延迟检查DOM变化
        if (!this.vulnerabilityFound) {
          await new Promise(resolve => setTimeout(resolve, 1000));
          await this.checkForIdentifier(tab, payload, sink, 'form_filling_delayed');
        }
      }

      console.log('表单填充检测完成');
    } catch (error) {
      console.error('表单填充检测出错:', error);
    }
  }
  
  async testFormPayload(tab, payload, sink) {
    // 注入payload到表单
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

      // 模拟点击按钮
      const buttons = document.querySelectorAll('button, input[type="submit"], input[type="button"]');
      buttons.forEach(btn => {
        try {
          btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
        } catch (e) {}
      });
    }, payload);

    // 触发DOM事件
    await this.triggerEvents(tab, 1500);
    
    // 检查是否存在标识符
    await this.checkForIdentifier(tab, payload, sink, 'form_filling');
  }
  
  async checkForIdentifier(tab, payload, sink, source = 'form_filling') {
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
    
    if (hasIdentifier.result.value.found) {
      const report = createReport({
        vulnid: this.vulnid,
        taskid: this.taskid,
        url: this.url,
        param: 'form_input',
        payload: payload,
        source: source,
        sink: hasIdentifier.result.value.sink,
        category: sink.category,
        severity: this.getSeverity(sink.category),
        details: `DOM XSS found via ${source} with payload '${payload}'. Executed in '${hasIdentifier.result.value.sink}' sink. Attribute: ${hasIdentifier.result.value.attribute}, Value: ${hasIdentifier.result.value.value}`,
        vulnname: "DOM_XSS"  // 新增这一行！设置 vulnType 的值，例如 "DOM_XSS" 或 this.name ("DOM XSS Scanner")
      });
      this.alert(report);
      this.vulnerabilityFound = true;
      return true;
    }
    return false;
  }

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
      for (const point of this.suspiciousPoints.result.value) {
        if (this.vulnerabilityFound) break;
        
        if (!point.source || !point.sink) continue;
        
        console.log(`[${this.name}] 验证可疑点: 源=${point.source.label}, 接收点=${point.sink.label}`);
        
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
  
  async verifyGetParameter(point) {
    try {
      const url = new URL(this.url);
      const urlParams = new URLSearchParams(url.search);
      
      // 确定源参数
      let sourceParam = null;
      
      for (const [name, value] of urlParams.entries()) {
        if (point.value && point.value.includes(value)) {
          sourceParam = name;
          break;
        }
      }
      
      if (!sourceParam) {
        if (urlParams.keys().next().value) {
          sourceParam = urlParams.keys().next().value;
        } else {
          sourceParam = 'xss';
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
        
        try {
          const response = await lastJob.execute(false);
          await lastJob.triggerAllDomEvents(800);
          
          if (!response || !response.body) {
            console.log(`[${this.name}] 验证请求失败或响应为空`);
            continue;
          }

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
              details: `DOM XSS vulnerability found in GET parameter '${sourceParam}'. Source: ${point.source.label}, Sink: ${point.sink.label}, Attribute: ${hasIdentifier.result.value.attribute}, Value: ${hasIdentifier.result.value.value}`,
              vulnname: "DOM_XSS" 
            });
            
            this.alert(report);
            this.vulnerabilityFound = true;
            await lastJob.closeTab();
            return;
          }
        } finally {
          await lastJob.closeTab();
        }
      }
    } catch (error) {
      console.error(`[${this.name}] 验证GET参数出错:`, error);
    }
  }
  
  async verifyPostParameter(point) {
    try {
      const lastJob = new browerHttpJob(this.browser);
      lastJob.url = this.url;
      lastJob.method = "POST";
      lastJob.headers = this.headers;
      lastJob.isEncodeUrl = false;

      const payload = this.getPayloadForSink({
        category: this.getSinkCategory(point.sink.label)
      });

      for (var i = 0; i < this.variations.length; i++) {
        this.variations.setValue(i, payload);
        let postData = this.variations.toString();
        lastJob.postData = postData;
        
        try {
          const response = await lastJob.execute(false);
          await lastJob.triggerAllDomEvents(800);
          
          if (!response || !response.body) {
            console.log(`[${this.name}] 验证请求失败或响应为空`);
            continue;
          }

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
          
          if (hasIdentifier.result.value.found) {
            const report = createReport({
              vulnid: this.vulnid,
              taskid: this.taskid,
              url: this.url,
              param: this.variations.getKey(i),
              payload: payload,
              source: point.source.label,
              sink: point.sink.label,
              category: this.getSinkCategory(point.sink.label),
              severity: point.severity || this.getSeverity(this.getSinkCategory(point.sink.label)),
              details: `DOM XSS vulnerability found in POST parameter '${this.variations.getKey(i)}'. Source: ${point.source.label}, Sink: ${point.sink.label}, Attribute: ${hasIdentifier.result.value.attribute}, Value: ${hasIdentifier.result.value.value}`,
              vulnname: "DOM_XSS" 
            });
            
            this.alert(report);
            this.vulnerabilityFound = true;
            await lastJob.closeTab();
            return;
          }
        } finally {
          await lastJob.closeTab();
        }
        
        // 恢复原始值
        this.variations.setValue(i, this.variations.getValue(i));
      }
    } catch (error) {
      console.error(`[${this.name}] 验证POST参数出错:`, error);
    }
  }

  // 辅助方法
  getSinkCategory(sinkLabel) {
    const sink = this.sinks.find(s => s.label === sinkLabel);
    
    if (sink) {
      return sink.category;
    }
    
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

  getSeverity(category) {
    switch (category) {
      case 'js': return 'High';
      case 'html': return 'Medium';
      case 'url':
      case 'event': return 'Low';
      default: return 'Medium';
    }
  }

  // 主入口函数
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
module.exports.requiresFileSupport = false;//对于不需要的插件，如dom_xss_scanner
