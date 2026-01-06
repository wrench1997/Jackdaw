const express = require('express');
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

app.post('/api/login-proxy', async (req, res) => {
  try {
      const { targetUrl, options } = req.body;
      
      // 发送实际请求
      const response = await fetch(targetUrl, options);
      
      // 获取响应数据
      const responseData = {
          status: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body: await response.text(),
          cookies: response.headers.get('set-cookie')
      };
      
      res.json(responseData);
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});

app.listen(6060, () => {
  console.log('代理服务器运行在 http://localhost:6060');
});