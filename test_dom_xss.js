const HeadlessChrome = require('./lib/Browser.js');
const DOMXSSDetector = require('./dom_xss_detector_component.js');

async function runTest() {
    // 初始化浏览器
    const browser = new HeadlessChrome({
        headless: false,  // 设置为 true 可以在后台运行
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
    
    // 配置测试参数
    const testUrl = "http://127.0.0.1:5500/dom_xss_test.html?name=<script>alert(1)</script>&code=alert(2)&script=alert(3)&redirect=javascript:alert(4)&store=<img src=x onerror=alert(5)>";
    
    const core = {
        browser: browser,
        scheme: "http",
        url: testUrl,
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        },
        method: "GET",
        postData: "",
        taskid: 0,
        hostid: "test",
        variations: null,
        isFile: false,
        filename: "",
        fileContent: "",
        __call: {
            send: function(message) {
                console.log("检测到漏洞:", JSON.stringify(message, null, 2));
            }
        }
    };
    
    // 创建 DOM XSS 检测器实例
    const detector = new DOMXSSDetector(core);
    
    // 运行检测
    await detector.run();
    
    // 关闭浏览器
    await browser.close();
    
    console.log("测试完成");
}

runTest().catch(error => {
    console.error("测试出错:", error);
});