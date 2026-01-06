document.addEventListener('DOMContentLoaded', function() {
  // 标签页切换
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach(tab => {
      tab.addEventListener('click', function() {
          const tabId = this.getAttribute('data-tab');
          
          // 激活当前标签
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          this.classList.add('active');
          
          // 显示对应内容
          document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
          document.getElementById(`${tabId}-tab`).classList.add('active');
      });
  });
  
  // 认证类型切换
  const authTypeSelect = document.getElementById('auth-type');
  authTypeSelect.addEventListener('change', function() {
      const authSections = document.querySelectorAll('.auth-section');
      authSections.forEach(section => section.style.display = 'none');
      
      const selectedAuth = this.value;
      if (selectedAuth !== 'none') {
          document.getElementById(`${selectedAuth}-auth`).style.display = 'block';
      }
  });
  
  // 验证码设置
  const hasCaptchaSelect = document.getElementById('has-captcha');
  hasCaptchaSelect.addEventListener('change', function() {
      document.getElementById('captcha-settings').style.display = 
          this.value === 'yes' ? 'block' : 'none';
  });
  
  // 加载验证码
  const loadCaptchaBtn = document.getElementById('load-captcha');
  loadCaptchaBtn.addEventListener('click', function() {
      const captchaUrl = document.getElementById('captcha-url').value;
      if (captchaUrl) {
          // 添加时间戳防止缓存
          const timestamp = new Date().getTime();
          const urlWithTimestamp = captchaUrl.includes('?') 
              ? `${captchaUrl}&t=${timestamp}` 
              : `${captchaUrl}?t=${timestamp}`;
              
          document.getElementById('captcha-image').src = urlWithTimestamp;
      } else {
          alert('请先输入验证码URL');
      }
  });
  
  // 测试登录
  const testLoginBtn = document.getElementById('test-login');
  testLoginBtn.addEventListener('click', async function() {
      const resultDiv = document.getElementById('result');
      const resultContent = document.getElementById('result-content');
      
      resultDiv.style.display = 'block';
      resultContent.textContent = '正在测试登录...';
      
      try {
          const loginData = collectFormData();
          const response = await performLogin(loginData);
          displayResult(response);
      } catch (error) {
          resultContent.textContent = `错误: ${error.message}`;
      }
  });
  
  // 保存配置
  const saveConfigBtn = document.getElementById('save-config');
  saveConfigBtn.addEventListener('click', function() {
      const config = collectFormData();
      const configJson = JSON.stringify(config, null, 2);
      
      // 创建下载链接
      const blob = new Blob([configJson], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'login-config.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
  });
  
  // 加载配置
  const loadConfigBtn = document.getElementById('load-config');
  loadConfigBtn.addEventListener('click', function() {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = 'application/json';
      
      input.onchange = function(event) {
          const file = event.target.files[0];
          if (file) {
              const reader = new FileReader();
              reader.onload = function(e) {
                  try {
                      const config = JSON.parse(e.target.result);
                      loadFormData(config);
                  } catch (error) {
                      alert('配置文件格式错误: ' + error.message);
                  }
              };
              reader.readAsText(file);
          }
      };
      
      input.click();
  });
  
  // 收集表单数据
  function collectFormData() {
      const data = {
          basic: {
              targetUrl: document.getElementById('target-url').value,
              method: document.getElementById('method').value,
              contentType: document.getElementById('content-type').value,
              usernameField: document.getElementById('username-field').value,
              passwordField: document.getElementById('password-field').value,
              username: document.getElementById('username-value').value,
              password: document.getElementById('password-value').value,
              additionalParams: {}
          },
          auth: {
              type: document.getElementById('auth-type').value,
              details: {}
          },
          captcha: {
              enabled: document.getElementById('has-captcha').value === 'yes',
              url: '',
              field: '',
              value: ''
          },
          headers: {},
          response: {
              successIndicator: document.getElementById('success-indicator').value,
              failureIndicator: document.getElementById('failure-indicator').value,
              redirectUrl: document.getElementById('redirect-url').value,
              extractCookies: document.getElementById('extract-cookies').value === 'yes'
          }
      };
      
      // 解析额外参数
      try {
          const additionalParamsText = document.getElementById('additional-params').value;
          if (additionalParamsText.trim()) {
              data.basic.additionalParams = JSON.parse(additionalParamsText);
          }
      } catch (e) {
          throw new Error('额外参数JSON格式错误: ' + e.message);
      }
      
      // 解析自定义请求头
      try {
          const headersText = document.getElementById('custom-headers').value;
          if (headersText.trim()) {
              data.headers = JSON.parse(headersText);
          }
      } catch (e) {
          throw new Error('自定义请求头JSON格式错误: ' + e.message);
      }
      
      // 根据认证类型收集详细信息
      switch (data.auth.type) {
          case 'cookie':
              data.auth.details = {
                  name: document.getElementById('cookie-name').value,
                  value: document.getElementById('cookie-value').value,
                  domain: document.getElementById('cookie-domain').value
              };
              break;
          case 'session':
              data.auth.details = {
                  name: document.getElementById('session-name').value,
                  value: document.getElementById('session-value').value
              };
              break;
          case 'digest':
              data.auth.details = {
                  username: document.getElementById('digest-username').value,
                  password: document.getElementById('digest-password').value,
                  realm: document.getElementById('digest-realm').value,
                  nonce: document.getElementById('digest-nonce').value
              };
              break;
          case 'basic':
              data.auth.details = {
                  username: document.getElementById('basic-username').value,
                  password: document.getElementById('basic-password').value
              };
              break;
          case 'token':
              data.auth.details = {
                  type: document.getElementById('token-type').value,
                  value: document.getElementById('token-value').value,
                  header: document.getElementById('token-header').value
              };
              break;
      }
      
      // 验证码信息
      if (data.captcha.enabled) {
          data.captcha.url = document.getElementById('captcha-url').value;
          data.captcha.field = document.getElementById('captcha-field').value;
          data.captcha.value = document.getElementById('captcha-value').value;
      }
      
      return data;
  }
  
  // 加载表单数据
  function loadFormData(config) {
      // 基本设置
      document.getElementById('target-url').value = config.basic.targetUrl || '';
      document.getElementById('method').value = config.basic.method || 'POST';
      document.getElementById('content-type').value = config.basic.contentType || 'application/x-www-form-urlencoded';
      document.getElementById('username-field').value = config.basic.usernameField || 'username';
      document.getElementById('password-field').value = config.basic.passwordField || 'password';
      document.getElementById('username-value').value = config.basic.username || '';
      document.getElementById('password-value').value = config.basic.password || '';
      
      if (config.basic.additionalParams) {
          document.getElementById('additional-params').value = JSON.stringify(config.basic.additionalParams, null, 2);
      }
      
      // 认证设置
      document.getElementById('auth-type').value = config.auth.type || 'none';
      
      // 触发认证类型变更事件
      const event = new Event('change');
      document.getElementById('auth-type').dispatchEvent(event);
      
      // 根据认证类型设置详细信息
      if (config.auth.details) {
          switch (config.auth.type) {
              case 'cookie':
                  document.getElementById('cookie-name').value = config.auth.details.name || '';
                  document.getElementById('cookie-value').value = config.auth.details.value || '';
                  document.getElementById('cookie-domain').value = config.auth.details.domain || '';
                  break;
              case 'session':
                  document.getElementById('session-name').value = config.auth.details.name || '';
                  document.getElementById('session-value').value = config.auth.details.value || '';
                  break;
              case 'digest':
                  document.getElementById('digest-username').value = config.auth.details.username || '';
                  document.getElementById('digest-password').value = config.auth.details.password || '';
                  document.getElementById('digest-realm').value = config.auth.details.realm || '';
                  document.getElementById('digest-nonce').value = config.auth.details.nonce || '';
                  break;
              case 'basic':
                  document.getElementById('basic-username').value = config.auth.details.username || '';
                  document.getElementById('basic-password').value = config.auth.details.password || '';
                  break;
              case 'token':
                  document.getElementById('token-type').value = config.auth.details.type || 'Bearer';
                  document.getElementById('token-value').value = config.auth.details.value || '';
                  document.getElementById('token-header').value = config.auth.details.header || 'Authorization';
                  break;
          }
      }
      
      // 验证码设置
      document.getElementById('has-captcha').value = config.captcha.enabled ? 'yes' : 'no';
      document.getElementById('has-captcha').dispatchEvent(new Event('change'));
      
      if (config.captcha.enabled) {
          document.getElementById('captcha-url').value = config.captcha.url || '';
          document.getElementById('captcha-field').value = config.captcha.field || 'captcha';
          document.getElementById('captcha-value').value = config.captcha.value || '';
      }
      
      // 请求头设置
      if (config.headers) {
          document.getElementById('custom-headers').value = JSON.stringify(config.headers, null, 2);
      }
      
      // 响应处理
      document.getElementById('success-indicator').value = config.response.successIndicator || '';
      document.getElementById('failure-indicator').value = config.response.failureIndicator || '';
      document.getElementById('redirect-url').value = config.response.redirectUrl || '';
      document.getElementById('extract-cookies').value = config.response.extractCookies ? 'yes' : 'no';
  }
  
  // 执行登录请求
  async function performLogin(loginData) {
      const resultContent = document.getElementById('result-content');
      resultContent.textContent = '准备登录请求...\n';
      
      // 构建请求参数
      const requestOptions = {
          method: loginData.basic.method,
          headers: new Headers({
              'Content-Type': loginData.basic.contentType
          }),
          credentials: 'include',
          mode: 'cors'
      };
      
      // 添加自定义请求头
      for (const [key, value] of Object.entries(loginData.headers)) {
          requestOptions.headers.append(key, value);
      }
      
      // 处理认证
      switch (loginData.auth.type) {
          case 'basic':
              const credentials = btoa(`${loginData.auth.details.username}:${loginData.auth.details.password}`);
              requestOptions.headers.append('Authorization', `Basic ${credentials}`);
              break;
          case 'token':
              const tokenPrefix = loginData.auth.details.type === 'Custom' ? '' : `${loginData.auth.details.type} `;
              requestOptions.headers.append(
                  loginData.auth.details.header, 
                  `${tokenPrefix}${loginData.auth.details.value}`
              );
              break;
          case 'cookie':
              if (loginData.auth.details.name && loginData.auth.details.value) {
                  document.cookie = `${loginData.auth.details.name}=${loginData.auth.details.value}; domain=${loginData.auth.details.domain || window.location.hostname}; path=/`;
              }
              break;
      }
      
      // 构建请求体
      let body = {};
      body[loginData.basic.usernameField] = loginData.basic.username;
      body[loginData.basic.passwordField] = loginData.basic.password;
      
      // 添加额外参数
      Object.assign(body, loginData.basic.additionalParams);
      
      // 添加验证码
      if (loginData.captcha.enabled && loginData.captcha.field && loginData.captcha.value) {
          body[loginData.captcha.field] = loginData.captcha.value;
      }
      
      // 根据内容类型格式化请求体
      if (loginData.basic.method !== 'GET') {
          if (loginData.basic.contentType === 'application/json') {
              requestOptions.body = JSON.stringify(body);
          } else if (loginData.basic.contentType === 'application/x-www-form-urlencoded') {
              const formData = new URLSearchParams();
              for (const [key, value] of Object.entries(body)) {
                  formData.append(key, value);
              }
              requestOptions.body = formData.toString();
          } else if (loginData.basic.contentType === 'multipart/form-data') {
              const formData = new FormData();
              for (const [key, value] of Object.entries(body)) {
                  formData.append(key, value);
              }
              requestOptions.body = formData;
              // 删除Content-Type头，让浏览器自动设置带边界的Content-Type
              requestOptions.headers.delete('Content-Type');
          }
      } else {
          // 对于GET请求，将参数添加到URL
          const url = new URL(loginData.basic.targetUrl);
          for (const [key, value] of Object.entries(body)) {
              url.searchParams.append(key, value);
          }
          loginData.basic.targetUrl = url.toString();
      }
      
      resultContent.textContent += `请求URL: ${loginData.basic.targetUrl}\n`;
      resultContent.textContent += `请求方法: ${loginData.basic.method}\n`;
      resultContent.textContent += `请求头: ${JSON.stringify(Object.fromEntries(requestOptions.headers.entries()), null, 2)}\n`;
      
      if (requestOptions.body) {
          resultContent.textContent += `请求体: ${requestOptions.body}\n`;
      }
      
      resultContent.textContent += '\n发送请求中...\n';
      
      try {
          // 使用代理服务器发送请求，避免跨域问题
          // 注意：在实际使用中，你需要设置一个代理服务器来处理这些请求
          const proxyUrl = 'http:/localhost:6060/api/login-proxy';
          const response = await fetch(proxyUrl, {
              method: 'POST',
              headers: {
                  'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                  targetUrl: loginData.basic.targetUrl,
                  options: requestOptions
              })
          });
          
          const responseData = await response.json();
          
          return {
              success: true,
              status: responseData.status,
              headers: responseData.headers,
              body: responseData.body,
              cookies: responseData.cookies
          };
      } catch (error) {
          return {
              success: false,
              error: error.message
          };
      }
  }
  
  // 显示结果
  function displayResult(response) {
      const resultContent = document.getElementById('result-content');
      
      if (!response.success) {
          resultContent.textContent = `请求失败: ${response.error}`;
          return;
      }
      
      let resultText = `状态码: ${response.status}\n\n`;
      resultText += `响应头:\n${JSON.stringify(response.headers, null, 2)}\n\n`;
      
      if (response.cookies && response.cookies.length > 0) {
          resultText += `Cookies:\n${JSON.stringify(response.cookies, null, 2)}\n\n`;
      }
      
      resultText += `响应体:\n${response.body}\n\n`;
      
      // 检查登录是否成功
      const successIndicator = document.getElementById('success-indicator').value;
      const failureIndicator = document.getElementById('failure-indicator').value;
      
      if (successIndicator && response.body.includes(successIndicator)) {
          resultText += `登录结果: 成功 (匹配成功指示器: "${successIndicator}")\n`;
      } else if (failureIndicator && response.body.includes(failureIndicator)) {
          resultText += `登录结果: 失败 (匹配失败指示器: "${failureIndicator}")\n`;
      } else {
          resultText += "登录结果: 未知 (未匹配任何指示器)\n";
      }
      
      resultContent.textContent = resultText;
  }
});

// 代理服务器实现示例 (需要在服务器端实现)
/*
// Node.js Express 示例
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

app.listen(3000, () => {
  console.log('代理服务器运行在 http://localhost:3000');
});
*/