const HeadlessChrome = require('./lib/Browser.js'); 
const DOMXSSScanner = require('./plugins/dom_xss_scanner.js');

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
    const testUrl = "http://192.168.166.2/pikachu/vul/xss/xss_dom.php";

    const core = {
        browser: browser,
        scheme: "http",
        url: testUrl,
        headers: [{ name: "User-Agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36" }],
        method: "GET",
        postData: "",
        taskid: 0,
        hostid: "test",
        variations: { length: 0, setValue() {}, toString() {} }, // 简化，无需真实变体
    
        __call: {
            send: function (message) {
                console.log("检测到漏洞:", JSON.stringify(message, null, 2));
            }
        }
    };
    

    // 创建 DOM XSS 检测器实例
    const scanner = new DOMXSSScanner(core);

    // 整个检测流程会包含：被动扫描 + 不发包表单检测 + 主动验证
    await scanner.startTesting();


    await browser.close();
    console.log("测试完成");
    
}

runTest().catch(err => console.error("测试出错:", err));


