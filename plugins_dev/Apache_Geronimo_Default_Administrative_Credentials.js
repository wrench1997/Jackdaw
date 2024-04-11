
const { CoreLayer, createReport, browerHttpJob, classMatches } = require('../core/core.js')

class ApacheGeronimoDefaultCreds extends CoreLayer {
    constructor(coreObj) {
        super(coreObj);
    }

    async request(uri) {
        const lastJob = new browerHttpJob(this.browser)
        lastJob.url = this.url
        lastJob.method = 'POST'
        lastJob.uri = uri
        lastJob.headers = this.headers
        lastJob.postData = 'j_username=system&j_password=manager&submit=Login';
        lastJob.isEncodeUrl = false
        lastJob.addHeader("Content-Type", "application/x-www-form-urlencoded");
        //return { body: bodys, status: status, statusText: statusText, err: err }
        ret = lastJob.execute();
        if (!ret.err && ret.status == 200) {
            return true;
        }
        return false;
    }


    async startTesting() {
        TestForDefaultCredentials();
    }

    async TestForDefaultCredentials() {
        var urls = [
            "/console/j_security_check"
        ];
        matches = new classMatches()

        matches.plainArray = [
            '<title>Geronimo Console</title>'
        ];

        matches.regexArray = [];

        for (var i = 0; i < urls.length; i++) {
            if (ret = await this.request(urls[i])) {
                const msg = { url: this.url, body: ret, payload: "", vuln: this.getVulnId(__filename), level: "m" }
                this.alert(createReport(msg));
            }
        }
    }


}


module.exports = ApacheGeronimoDefaultCreds