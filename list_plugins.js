#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

// 获取插件目录
const pluginsDir = path.join(__dirname, 'plugins');

// 检查目录是否存在
if (!fs.existsSync(pluginsDir)) {
  console.error(`插件目录不存在: ${pluginsDir}`);
  process.exit(1);
}

console.log('可用插件列表:');
console.log('-------------------------------------------');

// 读取所有JS文件
const plugins = fs.readdirSync(pluginsDir)
  .filter(file => file.endsWith('.js'))
  .sort();

if (plugins.length === 0) {
  console.log('未找到插件');
  process.exit(0);
}

// 遍历并打印信息
plugins.forEach(plugin => {
  const pluginPath = path.join(pluginsDir, plugin);
  try {
    const PluginClass = require(pluginPath);
    const requiresFile = PluginClass.requiresFileSupport === true ? '是' : '否';
    
    let pluginName = plugin.replace('.js', '');
    console.log(`- ${pluginName}`);
    console.log(`  文件: ${plugin}`);
    console.log(`  需要文件支持: ${requiresFile}`);
    console.log('-------------------------------------------');
  } catch (error) {
    console.log(`- ${plugin} (加载失败: ${error.message})`);
    console.log('-------------------------------------------');
  }
});

console.log(`共找到 ${plugins.length} 个插件`);