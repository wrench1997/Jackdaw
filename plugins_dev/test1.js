const { CoreLayer, createReport } = require('../core/core.js')

class JBossTest extends CoreLayer {
    constructor(_coreobj_) {
        super(_coreobj_);
    }

    async request(uri) {
        var lastJob = new browerHttpJob(this.browser);

        lastJob.url = this.url;
        lastJob.addCookies = false;
        lastJob.method = 'GET';
        lastJob.uri = uri;
        await lastJob.execute();

        if (!lastJob.wasError && lastJob.response.msg2 == 200) {
            return true;
        }

        return false;
    }

    async TestJBossWebServiceConsole(_index_) {
        if (await this.request('/jbossws/services')) {
            matches.plainArray = ['>JBossWS/Services<'];
            matches.regexArray = [];
            var matchedText = matches.searchOnText(lastJob.response.body);
            if (matchedText) {
                const msg = {
                    url: this.url,
                    body: element.body,
                    payload: lastJob.uri,
                    vuln: this.getVulnId(__filename),
                    level: "m"
                }
                this.alert(createReport(msg));
            }
        }
    }

    async startTesting() {
        await this.TestJBossWebServiceConsole();
    }
}

module.exports = JBossTest;