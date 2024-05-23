


// const SDK = require('./dist/sdk.js').default;
// const HeadlessChrome = SDK.HeadlessChrome;


const { CoreLayer, createReport, browerHttpJob } = require('./core/core.js')
const HeadlessChrome = require('./lib/Browser.js');

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
            ]
        }
    });
    await browser.init();



    return { browser};
}




async function main() {
    // 获取所有的入口参数
    const args = process.argv;
    console.log("所有入口参数：", args);
    // 获取除了前两个元素之外的参数（即自定义参数）
    const customArgs = args.slice(2);

    const { browser} = await startBrowser();

    const lastJob = new browerHttpJob(browser);

    lastJob.url = "http://192.168.166.2"
    lastJob.method = "GET"
    lastJob.headers = { "Accept": "application/json" }
    await lastJob.execute();

    await runChat("请列出下列内容的链接: " + lastJob.response.body[0]);


    return;
}

main();
