const HeadlessChrome = require('./lib/Browser.js');
const util = require('./utils/utils.js');
const rpc = require('./load/loadrpc.js');
var grpc = require('@grpc/grpc-js');
const { emtryParams, urlencodedParams, urlGetParams, urlHelper } = require('./core/core.js');
const { taskmanager } = require('./core/taskmanager.js');
const cluster = require('cluster');

const cpuNums = 4

var gWorker = [];
var workerRecord = [];
var isCommunicationEnded = false;
var taskManagers = new taskmanager();




function handleRequest(call, SendJsonRequest) {
    var url = null;
    var headers = {};
    var postData = null;
    var hostid = null;
    var method = null;
    var taskid = null;
    // serialize the struct to bytes
    const Details = SendJsonRequest.Details;
    var msg = "ok";
    var siteFiles = null;
    var isSiteFile = false;
    var targetLength = 0;


    if (Details.fields.url == undefined) { msg = "error rpc数据包中没有url成员" } else { url = Details.fields.url.stringValue; }

    if (Details.fields.headers == undefined) { msg = "error rpc数据包中没有headers成员" } else {
        tmpheaders = Details.fields.headers.structValue.fields
        for (var attr in Details.fields.headers.structValue.fields) {
            headers[attr] = tmpheaders[attr].stringValue
        }
    }

    Details.fields.data == undefined ? (msg = "error rpc数据包中没有data成员") : (postData = Details.fields.data.stringValue);

    Details.fields.targetLength == undefined ? (msg = "error rpc数据包中没有data成员") : (targetLength = Details.fields.targetLength.numberValue);

    if (Details.fields.method == undefined) { msg = "error rpc数据包中没有method成员" } else { method = Details.fields.method.stringValue; }

    if (Details.fields.hostid == undefined) { msg = "error rpc数据包中没有hostid成员" } else { hostid = Details.fields.hostid.numberValue; }

    if (Details.fields.taskid == undefined) { msg = "error rpc数据包中没有taskid成员" } else { taskid = Details.fields.taskid.numberValue; }

    if (Details.fields.isFile == undefined) { msg = "error rpc数据包中没有isFile成员" } else {
        isSiteFile = Details.fields.isFile.boolValue;
        if (isSiteFile) {
            fileName = Details.fields.FileName.stringValue;
            filenameContent = Details.fields.FileContent.stringValue;
        }
    }

    if (cluster.isPrimary) {

        const waitWorker = () => {
            return new Promise(resolve => {
                const checkWorker = setInterval(() => {
                    const idleWorker = gWorker.find(w => w.state === "idle");
                    if (idleWorker) {
                        clearInterval(checkWorker);
                        resolve(idleWorker);
                    }
                }, 500);
                // Timeout after 10 seconds
                setTimeout(() => {
                    clearInterval(checkWorker);
                    resolve(null);
                }, 10000);

            });
        };

        (async () => {
            var ii = 0;
            setInterval(() => {
                if (isCommunicationEnded) {
                    //console.log('isCommunicationEnded has close.');
                }
            }, 10000);

            for (; ;) {
                if (workerRecord.length < cpuNums) {
                    ii++
                    if (isCommunicationEnded) { return }
                    // await new Promise(resolve => setTimeout(resolve, 1000))
                    const worker = cluster.fork();
                    let requestInfo = {}
                    if (isSiteFile) {
                        requestInfo = {
                            url: url,
                            headers: headers,
                            postData: postData,
                            hostid: hostid,
                            method: method,
                            taskid: taskid,
                            details: SendJsonRequest.Details,
                            msg: "ok",
                            siteFile: fileName,
                            siteFilecontent: filenameContent,
                            isSiteFile: isSiteFile,
                            call: call,
                        };
                    } else {
                        requestInfo = {
                            url: url,
                            headers: headers,
                            postData: postData,
                            hostid: hostid,
                            method: method,
                            taskid: taskid,
                            details: SendJsonRequest.Details,
                            msg: "ok",
                            siteFile: "",
                            siteFilecontent: "",
                            isSiteFile: isSiteFile,
                            call: call,
                        };
                    }

                    //Add once with the same tashid
                    taskManagers.addTask(taskid, targetLength, call);
                    //console.log(`taskManagers ${worker.process.pid} push`);
                    taskManagers.addProcess(taskid, worker.process.pid);
                    gWorker.push({ worker: worker, state: "idle", Info: requestInfo });
                    workerRecord.push({ pid: worker.process.pid });
                    break;
                } else {
                    await waitWorker();
                }
            }
        })();
    }
    return
}


function routeChat(call) {

    call.on('data', function (JsonRequest) {
        // const { handleRequest, workerExitHandler } = HandleRequest(call, JsonRequest);
        // handlers.push({ handleRequest, workerExitHandler });

        isCommunicationEnded = false;
        handleRequest(call, JsonRequest);
        //console.log("exit")
        //HandleRequest(call, JsonRequest)
    });
    call.on('end', function (status) {
        console.log("结束本次通讯");
        setTimeout(() => {
            isCommunicationEnded = true;
        }, 1000);
        //taskManagers.clearTasks();
    });
}





// const HeadlessChrome = require('./lib/Browser.js')
function getServer() {
    var server = new grpc.Server();
    server.addService(rpc.RouteGuide.service, {
        RouteChat: routeChat
    });
    return server;
}


// 
async function main() {
    if (cluster.isPrimary) {
        cluster.schedulingPolicy = cluster.SCHED_RR; // 指定调度策略为轮询加权
        console.log(`Primary ${process.pid} is running`);
        var routeServer = getServer();
        routeServer.bindAsync('127.0.0.1:50051', grpc.ServerCredentials.createInsecure(), () => {
            routeServer.start();
        });

        // 注册 worker 的 exit 监听器
        cluster.on('exit', (worker, code, signal) => {
            //console.log(`worker ${worker.process.pid} died`);
            workerRecord = workerRecord.filter(function (w) {
                if (w)
                    return w.pid !== worker.process.pid;
            });
            taskid = taskManagers.getTaskId(worker.process.pid);
            taskManagers.processCompleted(worker.process.pid);
            if (taskid != null) {
                if (taskManagers.isTaskEnd(taskid)) {
                    //task has Complete, End the of call it.
                    taskManagers.removeTask(taskid);
                }
            }
        });

        // wait for available worker when gWorker is full
        const waitWorker = () => {
            return new Promise(resolve => {
                const checkWorker = setInterval(() => {
                    const idleWorker = gWorker.shift();
                    if (idleWorker) {
                        clearInterval(checkWorker);
                        resolve(idleWorker);
                    }
                }, 500);
            });
        };

        //等待队列有空位
        (async () => {
            for (; ;) {
                const availableWorker = await waitWorker();
                if (availableWorker) {
                    //console.log(availableWorker.worker.process.pid);

                    if (availableWorker.Info.isSiteFile) {
                        availableWorker.worker.send({
                            scheme: "http",
                            url: availableWorker.Info.url,
                            headers: availableWorker.Info.headers,
                            method: availableWorker.Info.method,
                            postData: availableWorker.Info.postData,
                            taskid: availableWorker.Info.taskid,
                            hostid: availableWorker.Info.hostid,
                            isSiteFile: availableWorker.Info.isSiteFile,
                            siteFile: availableWorker.Info.siteFile,
                            siteFilecontent: availableWorker.Info.siteFilecontent,
                        });
                    } else {
                        availableWorker.worker.send({
                            scheme: "http",
                            url: availableWorker.Info.url,
                            headers: availableWorker.Info.headers,
                            method: availableWorker.Info.method,
                            postData: availableWorker.Info.postData,
                            taskid: availableWorker.Info.taskid,
                            hostid: availableWorker.Info.hostid
                        });
                    }

                    availableWorker.state = "running";

                    availableWorker.worker.on('message', function (msg) {
                        //console.log('Master ' + process.pid + ' received message from worker ' + this.pid + '.', msg);
                        availableWorker.Info.call.write(msg);
                    });

                }

            }
        })();

    } else {
        //console.log(`Worker ${process.pid} started`);
        const path = require('node:path');
        const fs = require('fs');
        const directoryPath = path.join(__dirname, '/plugins');
        const files = fs.readdirSync(directoryPath);
        const HeadlessChrome = require('./lib/Browser.js')

        const browser = new HeadlessChrome({
            headless: true,
            chrome: {
                flags: [
                    '--disable-web-security',
                    '--no-sandbox=true',
                    "--disable-xss-auditor=true",
                    "--disable-gpu",
                    '--disable-dev-shm-usage', // <-- add this one
                    //"--proxy-server=http://127.0.0.1:7777"
                ]
            }
        })

        process.on('message', (msg) => {

            var variations = null;

            if (msg.isSiteFile) {
                variations = new emtryParams();
            } else if (msg.postData != undefined && msg.method == "POST") {
                variations = new urlencodedParams(msg.postData);
            } else if (msg.method == "GET") {
                variations = new urlGetParams(msg.url)
            }

            const CL = {
                browser: browser,
                scheme: msg.scheme,
                url: new urlHelper(msg.url),
                headers: msg.headers,
                method: msg.method,
                postData: msg.postData,
                __call: process,
                taskid: msg.taskid,
                hostid: msg.hostid,
                variations: variations,
                isFile: msg.isSiteFile,
                filename: msg.siteFile,
                fileContent: msg.siteFilecontent,
            }

            const runTesting = async function () {
                await CL.browser.init();
                try {
                    // 动态加载 JavaScript 文件
                    const testingPromises = [];
                    for (const file of files) {
                        const filePath = path.join(directoryPath, file);
                        const module = require(filePath);
                        // 检查文件是否是 .js 文件
                        if (path.extname(file) === '.js') {
                            const scriptobj = new module(CL);
                            const startTesting = async function () {
                                await scriptobj.startTesting();
                            };
                            testingPromises.push(startTesting());
                        }
                    }
                    await Promise.all(testingPromises);

                } catch (error) {
                    console.error('Testing failed with error:', error);
                } finally {
                    await CL.browser.close(true);
                }
            };


            runTesting().then(() => {
                process.exit(0);
            }).catch((err) => {
                console.error(err);
                process.exit(1);
            });

        });
    }

}




main();