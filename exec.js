


// const SDK = require('./dist/sdk.js').default;
// const HeadlessChrome = SDK.HeadlessChrome;
// b站cookie ，无用，主要测试ai分析。
//const Cookies = "buvid3=9E048463-B429-9F4A-37A9-F7DB0D40F8DA33316infoc; b_nut=1710232733; CURRENT_FNVAL=4048; _uuid=3681889A-A7210-1A3F-111E-1C9A7C15BE9134351infoc; buvid4=890775BD-EC94-2D7C-0941-1217131C0D4B34243-024031208-jYd35e8Y2o77vj2LPQy6RA%3D%3D; rpdid=|(u))YJkYu~m0J'u~u|kJk~Jl; buvid_fp_plain=undefined; DedeUserID=471883909; DedeUserID__ckMd5=098334bb5a005111; enable_web_push=DISABLE; FEED_LIVE_VERSION=V8; header_theme_version=CLOSE; home_feed_column=5; CURRENT_QUALITY=0; LIVE_BUVID=AUTO1017131473924062; _ga=GA1.1.1575720864.1710739021; _ga_34B604LFFQ=GS1.1.1715060463.15.0.1715060463.60.0.0; fingerprint=89488ba47a9a3bd86d134442f257a364; SESSDATA=9d7900c5%2C1731820711%2C441f4%2A51CjDO_rHukcnmf3ljL8Oxt2akCm8FAVBIOYNRKRTEofl-Hc-mULIUfqOyK11Or2wLtoASVkowNEFyMlpLenJrMVF4Q2NHNGRCTFFOR3VENl8yZWtjSjJSUlk5WGlYaUJsNEowZGJZZ1lUZmdXc3ZKN2NMQVJaaXZvUFBYZFdoV3NtZEEtYjdfTGV3IIEC; bili_jct=851ff1124262370c8a4fcacc9c6df593; perf_dv6Tr4n=1; bili_ticket=eyJhbGciOiJIUzI1NiIsImtpZCI6InMwMyIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTY1Mjc5NTQsImlhdCI6MTcxNjI2ODY5NCwicGx0IjotMX0.1pLU8xMlTrXatv77nv_Hn0ECVBRcvEQm9-iDI-WcPM0; bili_ticket_expires=1716527894; buvid_fp=89488ba47a9a3bd86d134442f257a364; PVID=3; bp_t_offset_471883909=934228899573792790; bmg_af_switch=1; bmg_src_def_domain=i1.hdslb.com; sid=5xnuke63; bsource=search_google; b_lsid=74A1E7E9_18FA38706C9; browser_resolution=1538-751"

const {emtryParams, urlencodedParams, urlGetParams,urlHelper } = require('./core/core.js')
const HeadlessChrome = require('./lib/Browser.js');
//插入脚本
const Moudle = require('./plugins_dev/phpdeserialization.js')
const { setGlobalDispatcher, ProxyAgent } = require("undici");
const dispatcher = new ProxyAgent({ uri: new URL(process.env.https_proxy).toString() });
setGlobalDispatcher(dispatcher);



// node --version # Should be >= 18
// npm install @google/generative-ai

const {
    GoogleGenerativeAI,
    HarmCategory,
    HarmBlockThreshold,
  } = require("@google/generative-ai");
  
  const MODEL_NAME = "gemini-1.5-pro-latest";
  const API_KEY = "AIzaSyChODhI-dYAJ0xNBznE7OvFWzK2pCnKQJg";
  
//使用 Google AI进行分析标签
async function runChat(mychat) {
    const genAI = new GoogleGenerativeAI(API_KEY);
    const model = genAI.getGenerativeModel({ model: MODEL_NAME });
  
    const generationConfig = {
      temperature: 1,
      topK: 64,
      topP: 0.95,
      maxOutputTokens: 8192,
      response_mime_type: "application/json",
    };
  
    const safetySettings = [
      {
        category: HarmCategory.HARM_CATEGORY_HARASSMENT,
        threshold: HarmBlockThreshold.BLOCK_NONE,
      },
      {
        category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        threshold: HarmBlockThreshold.BLOCK_NONE,
      },
      {
        category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        threshold: HarmBlockThreshold.BLOCK_NONE,
      },
      {
        category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold: HarmBlockThreshold.BLOCK_NONE,
      },
    ];
  
    const chat = model.startChat({
      generationConfig,
      safetySettings,
      history: [
      ],
    });
  
    const result = await chat.sendMessage(mychat);
    const response = result.response;
    console.log(response.text());
    return response;
  }
  
 
/**
 * Initializes and starts a new browser instance.
 *
 * @return {Object} An object containing the browser and tab instances.
 */
async function startBrowser() {
    const browser = new HeadlessChrome({
        headless: false,
        chrome: {
            flags: [
                '--disable-web-security',
                '--no-sandbox=true',
                "--disable-xss-auditor=true",
                "--disable-gpu",
                '--disable-dev-shm-usage', // <-- add this one
                // "--proxy-server=http://127.0.0.1:7777"
            ]
        }
    });
    await browser.init()
    return { browser}
}


// ```
//      "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
// 			"Cookie":                    "PHPSESSID=ofl9dchd22r5s46qa8cs0bcanp",
// 			"Referer":                   "http://192.168.166.2/pikachu/",
// 			"Content-Type":              "application/x-www-form-urlencoded",
// 			"Upgrade-Insecure-Requests": "1",
// 			"User-Agent":                "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
// ```


async function main() {
    // 获取所有的入口参数
    const args = process.argv
    console.log("所有入口参数：", args)
    // 获取除了前两个元素之外的参数（即自定义参数）
    const customArgs = args.slice(2)
    const { browser} = await startBrowser()
    const Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
    const Cookies = "PHPSESSID=ofl9dchd22r5s46qa8cs0bcanp"
    const Referrer = "http://192.168.166.2/pikachu"
    const ContentType = "application/x-www-form-urlencoded"
    const UpgradeInsecureRequests = "1"
    const UserAgent = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"
    // const lastJob = new browerHttpJob(browser);
    // lastJob.url = "http://192.168.166.2/pikachu/vul/unserilization/unser.php"
    // lastJob.method = "POST"
    // lastJob.addHeader("UserAgent",UserAgent)
    // lastJob.isEncodeUrl = false
    // await lastJob.execute();
    //使用ai分析
    //await runChat("请列出具有下列dom渲染的标签: " + lastJob.response.body[0]);
    scheme= "http"
    url = "http://192.168.166.2/pikachu/vul/unserilization/unser.php"
    method = "POST"
    postData = "o=sss"
    headers = {
        "Accept": Accept,
        "Referer": Referrer,
        "Content-Type": ContentType,
        "Upgrade-Insecure-Requests": UpgradeInsecureRequests,
        "User-Agent": UserAgent
    }
    taskid = 0
    hostid = "1234"
    isSiteFile = false
    var variations = null

    if (isSiteFile) {
        variations = new emtryParams()
    } else if (postData != undefined && method == "POST") {
        variations = new urlencodedParams(postData)
    } else if (method == "GET") {
        variations = new urlGetParams(url)
    }



    // new urlHelper(
    const core = {
      browser: browser,
      scheme: scheme,
      url: url,
      headers: headers,
      method: method,
      postData: postData,
      // __call: process,
      taskid: taskid,
      hostid: hostid,
      variations: variations,
      isFile: isSiteFile,
      filename: "",
      fileContent: "",
    }

    const scriptobj = new Moudle(core)

    await scriptobj.startTesting()
    

    process.exit()
    return;
}




main();
