const { CoreLayer } = require('../core/core.js')
const { callIdOnce } = require('./flow')(scanState);

class ApacheSourceCodeDisclosure extends CoreLayer {
    constructor(coreObj) {
        super(coreObj);
    }

    async testVulnerability(path) {
        const httpAttack = await this.sendReq(path, [{ name: "Content-Length", value: "zzz" }]);
        if (httpAttack) {
            const httpRetest = await this.sendReq(path, []);
            if (!httpRetest) {
                this.alert(httpAttack);
            }
        }
    }

    async sendReq(path, headers) {
        const job = ax.http.job();
        job.setUrl(scriptArg.target.url);
        job.request.uri = path;
        for (let i = 0; i < headers.length; i++) {
            job.request.addHeader(headers[i]["name"], headers[i]["value"]);
        }
        const http = ax.http.execute(job).sync();
        if (http.response.body.includes("<?") && http.response.body.includes("?>")) {
            const sRegex = String.raw`<\?(?:php|=)??[\s]+`;
            if (http.response.body.match(sRegex))
                return http;
        }
        return false;
    }

    // alert(attackJob) {
    //     if (!scanState.hasVuln({ typeId: "Apache_Source_Code_Disclosure.xml", location: scriptArg.target.root })) {
    //         scanState.addVuln({
    //             typeId: "Apache_Source_Code_Disclosure.xml",
    //             location: scriptArg.target.root,
    //             http: attackJob,
    //         });
    //     }
    // }

    async startTesting() {
        if (scriptArg.location.url.path == "/") {
            await this.testVulnerability("/index.php");
        }
        if (!scriptArg.location.isFolder && scriptArg.location.name.toLowerCase().endsWith(".php")) {
            callIdOnce('apache_source_code_disclosure', this.testVulnerability, scriptArg.location.url.path);
        }
    }
}

module.exports = ApacheSourceCodeDisclosure;