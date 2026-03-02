
安装环境
下载node 22.x 版本
npm install 





使用示例
列出所有可用插件:

node list_plugins.js


测试单个插件:

node test_plugin.js --plugin dom_xss_scanner --url https://example.com --output results.json


使用简化脚本测试:
./quick_test.sh dom_xss_scanner https://example.com --output results.json


4.批量测试:


# 创建配置文件 tests.json:
{
  "tests": [
    {
      "name": "DOM XSS测试",
      "url": "https://example.com",
      "plugin": "dom_xss_scanner",
      "output": "results/dom_xss_result.json"
    },
    {
      "name": "XXE测试",
      "url": "https://example.com/api",
      "plugin": "xxe_scanner",
      "method": "POST",
      "data": "<xml>test</xml>",
      "headers": {
        "Content-Type": "application/xml"
      },
      "output": "results/xxe_result.json"
    }
  ]
}

# 执行批量测试
node batch_test.js tests.json

