<center>

# 快速开始

</center>

下载SDK包：

```bash
wget http://example.com/sdk.zip
```

下载完SDK压缩包后，使用mkdir命令创建一个新的文件夹，并使用unzip命令将SDK解压到该文件夹中

```bash
# 创建一个名为sdk的文件夹
mkdir client

# 将sdk.zip解压到sdk文件夹中
unzip sdk.zip -d client/

# 进入client目录中
cd client/

# 使用npm下载剩下的依赖包
npm install .
```

新建一个测试文件exec.js

```bash
touch exec.js

# 使用相关文档编辑器编写代码
vim exec.js
```

导入sdk包:
```JavaScript
// 导入SDK模块中的HeadlessChrome对象
const SDK = require('./dist/sdk.js').default;
const HeadlessChrome = SDK.HeadlessChrome;

// 定义异步函数，返回一个带有browser和tab属性的对象
async function startBrowser() {
    // 创建一个HeadlessChrome对象
    const browser = new HeadlessChrome({
        headless: false, // 设置是否启用无头模式
        chrome: {
            flags: [
                '--disable-web-security', // 禁用浏览器的同源策略
                '--no-sandbox=true', // 在Docker容器中运行时需要的一个标志
                "--disable-xss-auditor=true", // 禁用XSS审计
                "--disable-gpu", // 禁用GPU
                '--disable-dev-shm-usage', // 禁用/dev/shm使用
            ]
        }
    });
    // 初始化浏览器
    await browser.init();
    // 创建一个新标签页
    const tab = await browser.newTab();
    // 返回包含browser和tab属性的对象
    return { browser, tab };
}

// 定义异步函数，调用startBrowser函数并获取返回的browser和tab对象
async function main() {
    const { browser, tab } = await startBrowser();
}

// 调用main函数
main();
```