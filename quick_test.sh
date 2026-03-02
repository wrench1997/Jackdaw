#!/bin/bash
# 快速测试脚本

if [ "$#" -lt 2 ]; then
  echo "使用方法: $0 <插件名> <目标URL> [其他参数]"
  echo "例如: $0 dom_xss_scanner https://example.com"
  exit 1
fi

PLUGIN=$1
URL=$2
shift 2

# 执行测试
node test_plugin.js --plugin "$PLUGIN" --url "$URL" "$@"