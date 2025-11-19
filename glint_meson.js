const HeadlessChrome = require('./lib/Browser.js');
const util = require('./utils/utils.js');
const rpc = require('./load/loadrpc.js');
var grpc = require('@grpc/grpc-js');
const { emtryParams, urlencodedParams, urlGetParams, urlHelper } = require('./core/core.js');
const { taskmanager } = require('./core/taskmanager.js');
const cluster = require('cluster');
const { sleep } = require('./core/core.js');

const cpuNums = 4

var gWorker = [];
var workerRecord = [];
var isCommunicationEnded = false;
var taskManagers = new taskmanager();

function handleRequest(call, SendJsonRequest) {
    // 获取任务ID和目标ID
    const taskid = SendJsonRequest.taskid;
    const targetid = SendJsonRequest.targetid;
    
    // 处理所有Details数组中的请求
    const detailsArray = SendJsonRequest.Details;
    let targetLength = detailsArray.length;
    
    if (targetLength === 0) {
        console.log("警告: 没有要处理的目标");
        return;
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

            // 为每个目标创建一个工作进程
            for (let i = 0; i < detailsArray.length; i++) {
                const Details = detailsArray[i];
                
                // 提取每个目标的信息
                let url = null;
                let headers = {};
                let postData = null;
                let hostid = null;
                let method = null;
                let isSiteFile = false;
                let fileName = "";
                let filenameContent = "";
                
                // 解析目标详情
                if (Details.fields.url) url = Details.fields.url.stringValue;
                
                if (Details.fields.headers) {
                    const tmpheaders = Details.fields.headers.structValue.fields;
                    for (var attr in tmpheaders) {
                        headers[attr] = tmpheaders[attr].stringValue;
                    }
                }
                
                if (Details.fields.data) postData = Details.fields.data.stringValue;
                if (Details.fields.method) method = Details.fields.method.stringValue;
                if (Details.fields.hostid) hostid = Details.fields.hostid.numberValue;
                
                if (Details.fields.isFile && Details.fields.isFile.boolValue) {
                    isSiteFile = true;
                    if (Details.fields.FileName) fileName = Details.fields.FileName.stringValue;
                    if (Details.fields.FileContent) filenameContent = Details.fields.FileContent.stringValue;
                }
                
                // 等待有可用的工作进程
                if (workerRecord.length < cpuNums) {
                    ii++;
                    if (isCommunicationEnded) return;
                    
                    const worker = cluster.fork();
                    let requestInfo = {
                        url: url,
                        headers: headers,
                        postData: postData,
                        hostid: hostid,
                        method: method,
                        taskid: taskid,
                        targetid: targetid,
                        details: Details,
                        msg: "ok",
                        siteFile: fileName,
                        siteFilecontent: filenameContent,
                        isSiteFile: isSiteFile,
                        call: call,
                    };
                    
                    // 添加任务到管理器
                    taskManagers.addTask(taskid, targetLength, call);
                    taskManagers.addProcess(taskid, worker.process.pid);
                    gWorker.push({ worker: worker, state: "idle", Info: requestInfo });
                    workerRecord.push({ pid: worker.process.pid });
                } else {
                    // 等待有工作进程可用
                    await waitWorker();
                    i--; // 重试当前目标
                }
            }
        })();
    }
    return;
}

function routeChat(call) {
    call.on('data', function (JsonRequest) {
        isCommunicationEnded = false;
        handleRequest(call, JsonRequest);
    });
    
    call.on('end', function (status) {
        console.log("结束本次通讯");
        setTimeout(() => {
            isCommunicationEnded = true;
        }, 60000);
    });
}

function getServer() {
    var server = new grpc.Server();
    server.addService(rpc.RouteGuide.service, {
        RouteChat: routeChat
    });
    return server;
}

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
                    if (availableWorker.Info.isSiteFile) {
                        availableWorker.worker.send({
                            scheme: "http",
                            url: availableWorker.Info.url,
                            headers: availableWorker.Info.headers,
                            method: availableWorker.Info.method,
                            postData: availableWorker.Info.postData,
                            taskid: availableWorker.Info.taskid,
                            targetid: availableWorker.Info.targetid,
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
                            targetid: availableWorker.Info.targetid,
                            hostid: availableWorker.Info.hostid
                        });
                    }

                    availableWorker.state = "running";

                    availableWorker.worker.on('message', function (msg) {
                        // 确保响应包含targetid
                        if (!msg.targetid && availableWorker.Info.targetid) {
                            msg.targetid = availableWorker.Info.targetid;
                        }
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
            headless: false,
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
                url: msg.url,
                headers: msg.headers,
                method: msg.method,
                postData: msg.postData,
                __call: process,
                taskid: msg.taskid,
                targetid: msg.targetid, // 添加targetid
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
                        // 检查文件是否是 .js 文件
                        if (path.extname(file) === '.js') {
                            const module = require(filePath);
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