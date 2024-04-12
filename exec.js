


// const SDK = require('./dist/sdk.js').default;
// const HeadlessChrome = SDK.HeadlessChrome;

const { CoreLayer, createReport, browerHttpJob } = require('./core/core.js')
const HeadlessChrome = require('./lib/Browser.js');
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

    lastJob.url = "http://192.168.166.2/abc"
    lastJob.method = "GET"
    lastJob.headers = { "Accept": "application/json" }
    await lastJob.execute();

    lastJob.url = "http://192.168.166.2"
    lastJob.method = "GET"
    lastJob.headers = { "Accept": "application/json" }
    await lastJob.execute();

      

}

main();
