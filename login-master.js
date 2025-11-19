// login-master.js  —— Node.js 万能登录脚本（漏洞扫描专用）
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');
const tough = require('tough-cookie');
const axiosCookieJarSupport = require('axios-cookiejar-support').default;
const OCR = require('node-ocr-hk'); // 轻量级中文验证码识别（或改用 tesseract.js）

// 初始化带 CookieJar 的 axios 实例（自动保持所有 Cookie）
const cookieJar = new tough.CookieJar();
const client = axios.default.create({
  jar: cookieJar,
  withCredentials: true,
  timeout: 15000,
  maxRedirects: 5,
  validateStatus: () => true, // 永远不抛错，自己判断
});
axiosCookieJarSupport(client);

// 配置 User-Agent
client.defaults.headers.common['User-Agent'] =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

class UltimateLogin {
  constructor(baseUrl = '') {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.sessionId = null;
    this.token = null;
  }

  // 1. 普通表单登录（最常用）
  async formLogin({
    loginUrl,
    username,
    password,
    usernameField = 'username',
    passwordField = 'password',
    extraData = {},
    captchaSelector = null, // 验证码图片 selector，如 '#captcha'
    successKeyword = '欢迎',
    failKeyword = '错误|失败|invalid'
  }) {
    loginUrl = this._fullUrl(loginUrl);

    // 如果需要验证码，先识别
    if (captchaSelector) {
      extraData['captcha'] = await this._ocrCaptcha(loginUrl, captchaSelector);
    }

    // 自动抓 CSRF Token（常见 name: csrf_token, __RequestVerificationToken 等）
    await this._extractCsrfToken(loginUrl);

    const data = {
      [usernameField]: username,
      [passwordField]: password,
      ...extraData,
      ...this.token ? { [Object.keys(this.token)[0]]: Object.values(this.token)[0] } : {}
    };

    const res = await client.post(loginUrl, new URLSearchParams(data), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    // 判断登录成功
    if (
      res.status === 200 &&
      res.request?.path !== '/login' &&
      (!failKeyword || !new RegExp(failKeyword, 'i').test(res.data)) &&
      (successKeyword ? res.data.includes(successKeyword) : true)
    ) {
      console.log('[+] 表单登录成功');
      await this._captureSessionFromResponse(res);
      return true;
    }

    console.log('[-] 表单登录失败');
    return false;
  }

  // 2. Basic Auth
  async basicAuth(username, password, testUrl = '/admin') {
    const auth = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');
    const res = await client.get(this._fullUrl(testUrl), {
      headers: { Authorization: auth }
    });

    if (res.status < 400) {
      console.log('[+] Basic Auth 登录成功');
      return true;
    }
    console.log('[-] Basic Auth 失败');
    return false;
  }

  // 3. Digest Auth（少见但必须支持）
  async digestAuth(username, password, testUrl = '/') {
    try {
      const res = await client.get(this._fullUrl(testUrl), {
        auth: { username, password }
      });
      if (res.status === 200) {
        console.log('[+] Digest Auth 登录成功');
        return true;
      }
    } catch (e) {}
    console.log('[-] Digest Auth 失败');
    return false;
  }

  // 4. 自动抓取并注入 CSRF Token
  async _extractCsrfToken(url) {
    try {
      const res = await client.get(url);
      const dom = new JSDOM(res.data);
      const doc = dom.window.document;

      // 常见 token 位置
      const patterns = [
        'input[name*="csrf" i], input[name*="token" i], input[name*="verification" i]',
        'meta[name="csrf-token" i], meta[name="token" i]'
      ];

      for (const pattern of patterns) {
        const el = doc.querySelector(pattern);
        if (el) {
          const name = el.name || el.getAttribute('content') ? 'csrf-token' : null;
          const value = el.value || el.getAttribute('content');
          if (name && value) {
            this.token = { [name]: value };
            console.log(`[+] 提取到 CSRF Token: ${name}=${value.substr(0, 20)}...`);
            return;
          }
        }
      }
    } catch (e) {}
  }

  // 5. 简单图片验证码识别（支持常见4-6位数字字母）
  async _ocrCaptcha(pageUrl, selector) {
    const res = await client.get(pageUrl);
    const dom = new JSDOM(res.data);
    const imgSrc = dom.window.document.querySelector(selector)?.src;
    if (!imgSrc) return '';

    const imgUrl = imgSrc.startsWith('http') ? imgSrc : this.baseUrl + (imgSrc.startsWith('/') ? '' : '/') + imgSrc;
    const imgRes = await client.get(imgUrl, { responseType: 'arraybuffer' });
    const code = await OCR.recognize(imgRes.data); // 返回纯文本，如 "A1B2"
    console.log(`[+] OCR 识别验证码 => ${code}`);
    return code;
  }

  // 6. 从响应中暴力捕获 Session（支持所有变种）
  async _captureSessionFromResponse(res) {
    const text = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
    const patterns = [
      /"session[_-]?id"\s*:\s*"([^"]+)"/i,
      /"sid"\s*:\s*"([^"]+)"/i,
      /"token"\s*:\s*"([^"]+)"/i,
      /JSESSIONID=([^;\s]+)/i,
      /PHPSESSID=([^;\s]+)/i,
      /session=([a-f0-9]{32,})/i,
      /([A-Z_]{3,20})=([a-f0-9]{20,})/i
    ];

    for (const pattern of patterns) {
      const m = text.match(pattern);
      if (m) {
        const name = m[1] ? m[1].toUpperCase() : 'sessionid';
        const value = m[2] || m[1];
        await cookieJar.setCookie(`${name}=${value}; Path=/; HttpOnly`, this.baseUrl);
        console.log(`[+] 捕获并注入 Session: ${name}=${value.substr(0, 40)}...`);
        this.sessionId = value;
        return;
      }
    }

    // JSON 深层提取
    try {
      const json = typeof res.data === 'object' ? res.data : JSON.parse(text);
      const candidates = ['session_id', 'sid', 'token', 'jsessionid', 'data.session_id', 'data.token'];
      for (const key of candidates) {
        const keys = key.split('.');
        let val = json;
        for (const k of keys) val = val?.[k];
        if (val) {
          await cookieJar.setCookie(`sessionid=${val}; Path=/`, this.baseUrl);
          console.log(`[+] JSON 提取 Session: ${val.substr(0, 40)}...`);
          this.sessionId = val;
          return;
        }
      }
    } catch (e) {}
  }

  // 7. 保存 Cookie（给 sqlmap / nuclei / burp 用）
  async saveCookies(filename = 'cookies.txt') {
    const cookies = await cookieJar.getCookies(this.baseUrl);
    const netscape = cookies.map(c => 
      `${c.domain}\tTRUE\t${c.path}\t${c.secure ? 'TRUE' : 'FALSE'}\t${c.expires ? Math.floor(c.expires.getTime()/1000) : 0}\t${c.key}\t${c.value}`
    ).join('\n');

    fs.writeFileSync(filename, netscape);
    console.log(`[+] Cookie 已保存到 ${path.resolve(filename)}（Netscape 格式，可直接喂给 sqlmap/nuclei）`);
  }

  // 8. 加载已有 Cookie（滑块后手动导出使用）
  async loadCookies(filename = 'cookies.txt') {
    if (!fs.existsSync(filename)) return false;
    const data = fs.readFileSync(filename, 'utf-8');
    for (const line of data.split('\n')) {
      if (!line.trim() || line.startsWith('#')) continue;
      const parts = line.split('\t');
      if (parts.length >= 7) {
        const cookie = new tough.Cookie({
          key: parts[5],
          value: parts[6],
          domain: parts[0],
          path: parts[2],
          secure: parts[3] === 'TRUE',
          httpOnly: false
        });
        await cookieJar.setCookie(cookie, this.baseUrl);
      }
    }
    console.log('[+] 已加载本地 Cookie，可直接扫描');
    return true;
  }

  _fullUrl(url) {
    if (url.startsWith('http')) return url;
    return this.baseUrl + (url.startsWith('/') ? '' : '/') + url;
  }

  // 暴露 axios 实例，方便后续扫描
  getClient() {
    return client;
  }
}

// ==================== 快速使用示例 ====================
(async () => {
  const target = 'http://192.168.1.100:8080';
  const login = new UltimateLogin(target);

  // 示例1：普通表单登录（支持自动抓 token + 验证码）
  await login.formLogin({
    loginUrl: '/login.php',
    username: 'admin',
    password: 'admin123',
    captchaSelector: '#captcha',        // 有验证码就填 selector
    successKeyword: '欢迎'
  });

  // 示例2：Basic Auth
  // await login.basicAuth('admin', '123456');

  // 示例3：加载已有 Cookie（滑块后用这个）
  // await login.loadCookies('hikvision_cookies.txt');

  // 保存 Cookie 给扫描器用
  await login.saveCookies('cookies.txt');

  // 现在可以用这个 client 继续发请求或喂给其他工具
  const res = await login.getClient().get(target + '/admin/index.php');
  console.log('测试访问后台:', res.status);
})();