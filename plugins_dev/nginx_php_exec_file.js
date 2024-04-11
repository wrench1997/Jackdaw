
const { CoreLayer, createReport, browerHttpJob, plain2md5 } = require('../core/core.js')

class nginx_php_exec_file extends CoreLayer {
    constructor(coreObj) {
        super(coreObj);
    }

    async startTesting() {
        testVuln();
    }

    async testVuln() {
        var fname = "/TestingNginxTest" + random(999999) + '.txt';
        var phpfname = fname + '/testing.php';

        const lastJob = new browerHttpJob(this.browser);
        lastJob.addCookies = false;
        lastJob.method = "GET";
        lastJob.url = scanURL;
        lastJob.uri = fname;
        lastJob.execute();

        if (!lastJob.wasError && lastJob.notFound) {
            var powered_by = lastJob.response.headerValue('X-Powered-By');
            if ((powered_by == '' || powered_by.match(/PHP\//) == null) && lastJob.response.bodyLength > 0) // no php
            {
                lastJob = new browerHttpJob(this.browser);
                lastJob.method = "GET";
                lastJob.url = scanURL;
                lastJob.uri = phpfname;
                lastJob.execute();

                if (!lastJob.wasError && lastJob.notFound) {
                    var powered_by = lastJob.response.headerValue('X-Powered-By'); // php
                    if (powered_by != "" && powered_by.match(/PHP\//) != null && lastJob.response.bodyLength == 0) {
                        if (this.url) {
                            const msg = { url: lastJob.url, body: "", payload: "", vuln: this.getVulnId(__filename), level: "h" }
                            this.alert(createReport(msg));
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }
}


module.exports = nginx_php_exec_file