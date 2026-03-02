const HeadlessChrome = require('./lib/Browser.js');
const util = require('./utils/utils.js');
const rpc = require('./load/loadrpc.js');
var grpc = require('@grpc/grpc-js');
const { emtryParams, urlencodedParams, urlGetParams, urlHelper } = require('./core/core.js');
const { taskmanager } = require('./core/taskmanager.js');
const cluster = require('cluster');
const { sleep } = require('./core/core.js');
const fs = require('fs');
const path = require('path');
const os = require("os");

// 设置最大并发进程数，取CPU核心数和4之间的较小值
const cpuNums = Math.min(os.cpus().length, 4);

var gWorker = [];
var workerRecord = [];
var isCommunicationEnded = false;
var taskManagers = new taskmanager();

// 用于CLI模式的结果收集
let cliScanResults = [];
let cliTaskCompleted = 0;
let cliTotalTasks = 0;
let cliOutputFile = '';
let cliTaskId = 0;

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

async function server() {
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

            // 新增：加载插件并检查requiresFileSupport
            const pluginRequiresFile = {}; // 存储每个插件的requiresFileSupport
            for (const file of files) {
                const filePath = path.join(directoryPath, file);
                if (path.extname(file) === '.js') {
                    const module = require(filePath);
                    pluginRequiresFile[file] = module.requiresFileSupport || false; // 默认false
                }
            }

            // 修改：根据插件需求决定是否处理isSiteFile
            let effectiveIsSiteFile = msg.isSiteFile; // 默认使用消息中的值
            if (msg.isSiteFile) {
                // 检查是否有任何插件需要文件支持
                const anyPluginNeedsFile = Object.values(pluginRequiresFile).some(needs => needs === true);
                if (!anyPluginNeedsFile) {
                    effectiveIsSiteFile = false; // 如果所有插件都不需要，禁用文件处理
                    //console.log(`[Worker ${process.pid}] 所有插件都不需要文件支持，跳过isSiteFile处理`);
                }
            }

            if (effectiveIsSiteFile) {
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
                isFile: effectiveIsSiteFile, // 使用effective值
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

// CLI模式的多进程扫描实现
async function runCliScan(configFile) {
    if (!fs.existsSync(configFile)) {
        console.error(`配置文件 ${configFile} 不存在!`);
        process.exit(1);
    }
    
    console.log(`正在从配置文件 ${configFile} 加载扫描参数...`);
    
    try {
        // 读取JSON配置文件
        const configData = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        
        // 提取配置信息
        const taskId = configData.taskId || Math.floor(Math.random() * 10000);
        cliTaskId = taskId;
        const targets = configData.targets || [];
        const files = configData.files || [];
        cliOutputFile = configData.outputFile || `jackdaw_results_${taskId}.json`;
        const timeout = configData.timeout || 3600; // 默认超时时间1小时
        
        if (targets.length === 0 && files.length === 0) {
            console.error('配置文件中缺少必要的targets或files参数!');
            process.exit(1);
        }
        
        console.log("扫描配置信息:");
        console.log("任务ID:", taskId);
        console.log("目标数量:", targets.length);
        console.log("文件数量:", files.length);
        console.log("输出文件:", cliOutputFile);
        console.log("超时时间:", timeout, "秒");
        console.log(`将使用 ${cpuNums} 个进程并发扫描`);
        
        // 初始化结果数组
        cliScanResults = [];
        
        // 获取插件列表
        const directoryPath = path.join(__dirname, '/plugins');
        const pluginFiles = fs.readdirSync(directoryPath).filter(file => path.extname(file) === '.js');
        
        // 合并targets和files为一个任务列表
        const allTargets = [
            ...targets.map(target => ({
                ...target,
                isFile: false
            })),
            ...files.map(file => ({
                ...file,
                isFile: true
            }))
        ];
        
        // 设置总任务数
        cliTotalTasks = allTargets.length;
        cliTaskCompleted = 0;
        
        if (cluster.isPrimary) {
            // 主进程：创建工作进程并分配任务
            console.log(`主进程 ${process.pid} 启动`);
            
            // 设置超时处理
            const timeoutId = setTimeout(() => {
                console.log(`扫描超时(${timeout}秒)，正在终止...`);
                
                // 将当前结果写入文件
                fs.writeFileSync(cliOutputFile, JSON.stringify(cliScanResults, null, 2));
                
                console.log(`已保存部分结果到 ${cliOutputFile}`);
                process.exit(0);
            }, timeout * 1000);
            
            // 监听工作进程退出事件
            cluster.on('exit', (worker, code, signal) => {
                console.log(`工作进程 ${worker.process.pid} 已完成`);
                cliTaskCompleted++;
                
                // 检查是否所有任务都已完成
                if (cliTaskCompleted >= cliTotalTasks) {
                    clearTimeout(timeoutId);
                    console.log('所有扫描任务已完成，正在保存结果...');
                    
                    // 将结果写入输出文件
                    fs.writeFileSync(cliOutputFile, JSON.stringify(cliScanResults, null, 2));
                    
                    console.log(`扫描完成。结果已保存到 ${cliOutputFile}`);
                    process.exit(0);
                }
            });
            
            // 监听工作进程消息
            cluster.on('message', (worker, message) => {
                if (message && message.type === 'SCAN_RESULT') {
                    if (message.results && message.results.length > 0) {
                        console.log(`工作进程 ${worker.process.pid} 发现 ${message.results.length} 个漏洞`);
                        
                        // 将结果转换为指定格式
                        const formattedResults = message.results.map(result => ({
                            vuln: result.vulnType || "Unknown",
                            url: result.url || "Unknown",
                            payload: result.payload || "",
                            level: result.severity ? result.severity.toLowerCase() : "medium",
                            hostid: result.hostid || 1
                        }));
                        
                        cliScanResults = cliScanResults.concat(formattedResults);
                    }
                } else if (message && message.Report) {
                    // 处理标准格式的报告
                    try {
                        const report = message.Report;
                        const vulnType = report.fields.vulnname ? report.fields.vulnname.stringValue : "Unknown";
                        const url = report.fields.url ? report.fields.url.stringValue : "Unknown";
                        const payload = report.fields.payload ? report.fields.payload.stringValue : "";
                        const severity = report.fields.severity ? report.fields.severity.stringValue.toLowerCase() : "medium";
                        const hostid = report.fields.hostid ? parseInt(report.fields.hostid.stringValue) : 1;
                        
                        const formattedResult = {
                            vuln: vulnType,
                            url: url,
                            payload: payload,
                            level: severity,
                            hostid: hostid
                        };
                        
                        cliScanResults.push(formattedResult);
                        console.log(`发现漏洞: ${vulnType} - ${severity} - ${url}`);
                    } catch (error) {
                        console.error("处理漏洞报告时出错:", error);
                    }
                }
            });
            
            // 分配任务给工作进程
            const targetsPerWorker = Math.ceil(allTargets.length / cpuNums);
            
            for (let i = 0; i < cpuNums && i < allTargets.length; i++) {
                const startIndex = i * targetsPerWorker;
                const endIndex = Math.min(startIndex + targetsPerWorker, allTargets.length);
                
                if (startIndex < allTargets.length) {
                    const targetGroup = allTargets.slice(startIndex, endIndex);
                    const worker = cluster.fork();
                    
                    worker.send({
                        type: 'SCAN_TASK',
                        taskId: taskId,
                        targets: targetGroup,
                        plugins: pluginFiles
                    });
                    
                    console.log(`工作进程 ${worker.process.pid} 分配了 ${targetGroup.length} 个目标`);
                }
            }
            
        } else {
            // 工作进程：执行分配的扫描任务
            console.log(`工作进程 ${process.pid} 启动`);
            
            process.on('message', async (msg) => {
                if (msg.type === 'SCAN_TASK') {
                    const scanResults = [];
                    
                    // 创建自定义进程对象来捕获漏洞信息
                    const customProcess = {
                        send: function(message) {
                            if (message && message.Report) {
                                try {
                                    const report = message.Report;
                                    const vulnType = report.fields.vulnname ? report.fields.vulnname.stringValue : "Unknown";
                                    const url = report.fields.url ? report.fields.url.stringValue : "Unknown";
                                    const payload = report.fields.payload ? report.fields.payload.stringValue : "";
                                    const severity = report.fields.severity ? report.fields.severity.stringValue.toLowerCase() : "medium";
                                    const hostid = report.fields.hostid ? parseInt(report.fields.hostid.stringValue) : 1;
                                    
                                    const formattedResult = {
                                        vulnType: vulnType,
                                        url: url,
                                        payload: payload,
                                        severity: severity,
                                        hostid: hostid
                                    };
                                    
                                    console.log(`工作进程 ${process.pid} 发现漏洞: ${vulnType}`);
                                    scanResults.push(formattedResult);
                                    
                                    // 立即发送结果到主进程
                                    process.send({
                                        type: 'SCAN_RESULT',
                                        results: [formattedResult]
                                    });
                                } catch (error) {
                                    console.error("处理漏洞报告时出错:", error);
                                }
                            }
                        }
                    };
                    
                    // 初始化浏览器
                    const browser = new HeadlessChrome({
                        headless: true,
                        chrome: {
                            flags: [
                                "--disable-web-security",
                                "--no-sandbox=true",
                                "--disable-xss-auditor=true",
                                "--disable-gpu",
                                "--disable-dev-shm-usage"
                            ]
                        }
                    });
                    
                    await browser.init();
                    
                    try {
                        // 处理每个目标
                        for (const target of msg.targets) {
                            console.log(`工作进程 ${process.pid} 开始扫描目标: ${target.url || target.fileName}`);
                            
                            // 创建参数变量
                            let variations = null;
                            if (target.isFile) {
                                variations = new emtryParams();
                            } else if (target.data && target.method === "POST") {
                                variations = new urlencodedParams(target.data);
                            } else {
                                variations = new urlGetParams(target.url);
                            }
                            
                            // 创建核心对象
                            const CL = {
                                browser: browser,
                                scheme: target.url && target.url.startsWith("https") ? "https" : "http",
                                url: target.url || "",
                                headers: target.headers || {},
                                method: target.method || "GET",
                                postData: target.data || "",
                                __call: customProcess,
                                taskid: msg.taskId,
                                targetid: `${msg.taskId}-${process.pid}`,
                                hostid: target.hostid || 1,
                                variations: variations,
                                isFile: target.isFile,
                                filename: target.isFile ? target.fileName : "",
                                fileContent: target.isFile ? "" : "",
                            };
                            
                            // 执行所有插件
                            for (const pluginFile of msg.plugins) {
                                try {
                                    const pluginPath = path.join(__dirname, '/plugins', pluginFile);
                                    const module = require(pluginPath);
                                    const scriptObj = new module(CL);
                                    
                                    if (typeof scriptObj.startTesting === "function") {
                                        await scriptObj.startTesting();
                                    }
                                } catch (pluginError) {
                                    console.error(`执行插件 ${pluginFile} 失败:`, pluginError);
                                }
                            }
                        }
                    } catch (error) {
                        console.error(`工作进程 ${process.pid} 执行出错:`, error);
                    } finally {
                        // 关闭浏览器
                        await browser.close(true);
                        
                        // 发送所有结果到主进程
                        if (scanResults.length > 0) {
                            process.send({
                                type: 'SCAN_RESULT',
                                results: scanResults
                            });
                        }
                        
                        // 退出工作进程
                        process.exit(0);
                    }
                }
            });
        }
    } catch (error) {
        console.error("扫描过程中出错:", error);
        process.exit(1);
    }
}

// 主入口
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length > 0) {
        // CLI 模式：从JSON文件读取配置并使用多进程扫描
        runCliScan(args[0]);
    } else {
        server();
    }
}