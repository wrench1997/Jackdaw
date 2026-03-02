#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const HeadlessChrome = require('./lib/Browser.js');
const { emtryParams, urlencodedParams, urlGetParams } = require('./core/core.js');

// 命令行参数处理
const args = require('minimist')(process.argv.slice(2), {
  string: ['url', 'plugin', 'method', 'data', 'headers', 'file', 'content', 'output'],
  default: {
    method: 'GET',
    headers: '{}',
    timeout: '30000'
  },
  alias: {
    u: 'url',
    p: 'plugin',
    m: 'method',
    d: 'data',
    H: 'headers',
    f: 'file',
    c: 'content',
    o: 'output',
    t: 'timeout'
  }
});

// 帮助信息
if (args.help || args.h) {
  console.log(`
使用方法: node test_plugin.js [选项]

选项:
  -u, --url <url>           要测试的URL (必须)
  -p, --plugin <plugin>     要测试的插件名或路径 (必须)
  -m, --method <method>     HTTP方法 (默认: GET)
  -d, --data <data>         POST数据
  -H, --headers <headers>   HTTP请求头 (JSON格式)
  -f, --file <file>         测试文件名
  -c, --content <content>   测试文件内容
  -o, --output <file>       输出结果到文件
  -t, --timeout <ms>        超时时间(毫秒) (默认: 30000)
  -h, --help                显示帮助信息
  `);
  process.exit(0);
}

// 验证必要参数
if (!args.url) {
  console.error('错误: 必须提供目标URL (-u, --url)');
  process.exit(1);
}

if (!args.plugin) {
  console.error('错误: 必须提供插件名或路径 (-p, --plugin)');
  process.exit(1);
}

async function runTest() {
  try {
    console.log('正在初始化测试环境...');
    
    // 验证插件
    const pluginPath = path.isAbsolute(args.plugin) ? 
      args.plugin : 
      path.join(__dirname, 'plugins', args.plugin);
    
    // 如果没有.js后缀，自动添加
    const fullPluginPath = pluginPath.endsWith('.js') ? 
      pluginPath : 
      `${pluginPath}.js`;
    
    if (!fs.existsSync(fullPluginPath)) {
      console.error(`找不到插件: ${fullPluginPath}`);
      process.exit(1);
    }
    
    console.log(`使用插件: ${fullPluginPath}`);
    
    // 初始化浏览器
    const browser = new HeadlessChrome({
      headless: true, // 隐藏浏览器窗口
      chrome: {
        flags: [
          '--disable-web-security',
          '--no-sandbox=true',
          "--disable-xss-auditor=true",
          "--disable-gpu",
          '--disable-dev-shm-usage'
        ]
      }
    });
    
    await browser.init();
    console.log('浏览器初始化完成');
    
    // 解析请求头
    let headers = {};
    try {
      headers = JSON.parse(args.headers);
    } catch (e) {
      console.error('解析请求头失败，使用空请求头');
    }
    
    // 确定是否使用文件模式
    const isSiteFile = !!args.file;
    
    // 创建变量容器
    let variations = null;
    if (isSiteFile) {
      variations = new emtryParams();
    }
    else if (args.data && args.method === "POST") {
      variations = new urlencodedParams(args.data);
    }
    else {
      variations = new urlGetParams(args.url);
    }
    
    // 创建漏洞报告记录器
    const vulnerabilities = [];
    
    // 构建核心对象
    const core = {
      browser: browser,
      scheme: args.url.startsWith("https") ? "https" : "http",
      url: args.url,
      headers: headers,
      method: args.method,
      postData: args.data || "",
      __call: {
        send: function(message) {
          if (message && message.Report) {
            const report = message.Report;
            const vulnType = report.fields.vulnname ? report.fields.vulnname.stringValue : "Unknown";
            const url = report.fields.url ? report.fields.url.stringValue : "Unknown";
            const payload = report.fields.payload ? report.fields.payload.stringValue : "";
            const severity = report.fields.severity ? report.fields.severity.stringValue : "Unknown";
            const details = report.fields.details ? report.fields.details.stringValue : "";
            
            console.log('\n发现漏洞:');
            console.log(`类型: ${vulnType}`);
            console.log(`URL: ${url}`);
            console.log(`载荷: ${payload}`);
            console.log(`严重性: ${severity}`);
            if (details) console.log(`详情: ${details}`);
            
            // 记录漏洞信息
            vulnerabilities.push({
              vulnType,
              url,
              payload,
              severity,
              details,
              timestamp: new Date().toISOString()
            });
          }
        }
      },
      taskid: Math.floor(Math.random() * 10000),
      targetid: Math.floor(Math.random() * 10000).toString(),
      hostid: args.hostid || "1",
      variations: variations,
      isFile: isSiteFile,
      filename: args.file || "",
      fileContent: args.content || "",
    };
    
    // 加载插件
    const PluginClass = require(fullPluginPath);
    
    // 检查插件是否需要文件支持
    if (PluginClass.requiresFileSupport === true && !isSiteFile) {
      console.warn('警告: 此插件需要文件支持，但未提供文件参数，可能会影响测试结果');
    }
    
    console.log(`创建插件实例: ${PluginClass.name || '未命名插件'}`);
    const pluginInstance = new PluginClass(core);
    
    // 设置超时
    const timeoutMs = parseInt(args.timeout);
    const timeout = setTimeout(() => {
      console.error(`测试超时(${timeoutMs}ms)，强制退出`);
      browser.close(true).then(() => process.exit(1));
    }, timeoutMs);
    
    console.log(`开始执行插件测试，超时设置为${timeoutMs}ms`);
    console.log('-------------------------------------------');
    
    // 执行测试
    const startTime = Date.now();
    await pluginInstance.startTesting();
    const endTime = Date.now();
    
    // 清除超时
    clearTimeout(timeout);
    
    console.log('-------------------------------------------');
    console.log(`测试完成，耗时: ${endTime - startTime}ms`);
    console.log(`发现的漏洞数量: ${vulnerabilities.length}`);
    
    // 保存结果到文件
    if (args.output && vulnerabilities.length > 0) {
      try {
        const resultData = {
          target: args.url,
          plugin: path.basename(fullPluginPath),
          timestamp: new Date().toISOString(),
          duration: endTime - startTime,
          vulnerabilities
        };
        
        fs.writeFileSync(args.output, JSON.stringify(resultData, null, 2));
        console.log(`结果已保存到 ${args.output}`);
      } catch (e) {
        console.error('保存结果失败:', e.message);
      }
    }
    
    // 关闭浏览器
    await browser.close(true);
    
    if (vulnerabilities.length > 0) {
      process.exit(0); // 发现漏洞，但测试成功
    } else {
      console.log('未发现漏洞');
      process.exit(0);
    }
    
  } catch (error) {
    console.error('测试过程中出错:', error);
    process.exit(1);
  }
}

// 执行测试
runTest();