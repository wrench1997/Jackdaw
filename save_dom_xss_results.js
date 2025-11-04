// save_dom_xss_results.js
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');

// 配置选项
const config = {
    targetUrl: 'http://localhost:5500/dom_xss_test.html', // 目标URL，根据实际情况修改
    outputFile: path.join(__dirname, 'dom_xss_results.json'),
    waitTime: 5000, // 等待时间，确保检测器有足够时间运行
    runAllTests: true // 是否运行页面上的所有测试
};

async function saveDOMXSSResults() {
    console.log('启动浏览器...');
    const browser = await puppeteer.launch({
        headless: false, // 设为 true 可以在后台运行
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    try {
        console.log(`正在访问 ${config.targetUrl}`);
        const page = await browser.newPage();
        
        // 捕获控制台输出
        const vulnerabilities = [];
        page.on('console', msg => {
            if (msg.type() === 'warning' && msg.text().includes('[DOM XSS Detector]')) {
                console.log(`检测到警告: ${msg.text()}`);
            }
        });
        
        // 导航到目标页面
        await page.goto(config.targetUrl, { waitUntil: 'networkidle2' });
        console.log('页面加载完成');
        
        // 如果需要运行所有测试
        if (config.runAllTests) {
            console.log('运行所有测试...');
            const testButtons = await page.$$('button[onclick^="runTest"]');
            for (const button of testButtons) {
                await button.click();
                await new Promise(r => setTimeout(r, 1000))

            }
        }
        
        // 等待检测器完成
        await new Promise(r => setTimeout(r, config.waitTime))

        
        // 获取检测到的漏洞
        const detectedVulnerabilities = await page.evaluate(() => {
            if (window.DOMXSSDetector) {
                return window.DOMXSSDetector.getDetectedVulnerabilities();
            }
            return [];
        });
        
        console.log(`检测到 ${detectedVulnerabilities.length} 个潜在的 DOM XSS 漏洞`);
        
        // 保存结果到 JSON 文件
        fs.writeFileSync(
            config.outputFile, 
            JSON.stringify(detectedVulnerabilities, null, 2)
        );
        
        console.log(`结果已保存到 ${config.outputFile}`);
        
    } catch (error) {
        console.error('发生错误:', error);
    } finally {
        await browser.close();
        console.log('浏览器已关闭');
    }
}

saveDOMXSSResults().catch(console.error);