#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// 命令行参数处理
const args = process.argv.slice(2);
const configFile = args[0];

if (!configFile || args.includes('--help') || args.includes('-h')) {
  console.log(`
使用方法: node batch_test.js <配置文件路径>

配置文件格式 (JSON):
{
  "tests": [
    {
      "name": "测试名称",
      "url": "目标URL",
      "plugin": "插件名称",
      "method": "HTTP方法",
      "data": "POST数据",
      "headers": { "请求头名称": "值" },
      "file": "测试文件名",
      "content": "测试文件内容",
      "output": "结果输出文件",
      "timeout": "超时时间(毫秒)"
    }
  ]
}
  `);
  process.exit(0);
}

async function runBatchTests() {
  try {
    // 读取配置文件
    if (!fs.existsSync(configFile)) {
      console.error(`配置文件不存在: ${configFile}`);
      process.exit(1);
    }
    
    const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    
    if (!config.tests || !Array.isArray(config.tests) || config.tests.length === 0) {
      console.error('配置文件中缺少有效的tests数组');
      process.exit(1);
    }
    
    console.log(`加载了 ${config.tests.length} 个测试配置`);
    
    // 按顺序依次执行测试
    for (let i = 0; i < config.tests.length; i++) {
      const test = config.tests[i];
      console.log(`\n[${i+1}/${config.tests.length}] 执行测试: ${test.name || '未命名测试'}`);
      
      // 构建test_plugin.js的参数
      const args = ['test_plugin.js'];
      
      if (!test.url) {
        console.error('测试配置缺少URL，跳过');
        continue;
      }
      
      if (!test.plugin) {
        console.error('测试配置缺少插件名称，跳过');
        continue;
      }
      
      args.push('--url', test.url);
      args.push('--plugin', test.plugin);
      
      if (test.method) args.push('--method', test.method);
      if (test.data) args.push('--data', test.data);
      if (test.headers) args.push('--headers', JSON.stringify(test.headers));
      if (test.file) args.push('--file', test.file);
      if (test.content) args.push('--content', test.content);
      if (test.output) args.push('--output', test.output);
      if (test.timeout) args.push('--timeout', test.timeout);
      
      // 执行test_plugin.js
      const testProcess = spawn('node', args, { stdio: 'inherit' });
      
      await new Promise((resolve) => {
        testProcess.on('close', (code) => {
          if (code === 0) {
            console.log(`测试 ${test.name || '未命名测试'} 完成`);
          } else {
            console.error(`测试 ${test.name || '未命名测试'} 失败，错误码: ${code}`);
          }
          resolve();
        });
      });
    }
    
    console.log('\n所有测试完成');
    
  } catch (error) {
    console.error('批量测试过程中出错:', error);
    process.exit(1);
  }
}

runBatchTests();