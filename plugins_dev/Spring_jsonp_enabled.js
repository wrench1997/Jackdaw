const { ScriptCore, createReport, browerHttpJob } = require('../core/core.js');

class SpringJSONPEnabledByDefault extends ScriptCore {
    constructor(coreobj) {
        super(coreobj);
    }

    async startTesting() {
        const flow = ax.loadModule("/lib/utility/flow.js").flow(this.scanState);
        const rnd = ax.loadModule("/lib/utility/random.js");

        // Only GET endpoints and JSON content type
        if (this.scriptArg.http.request.method === "GET" &&
            this.scriptArg.http.response.isType('application/json') &&
            this.scriptArg.http.response.status === 200) {
            // Only test one time per each root folder, don't test each subfolder/file
            const parts = this.scriptArg.location.url.path.split("/");
            if (parts.length <= 2) {
                const rootFolder = parts[1];
                await flow.callIdOnce(
                    `spring-jsonp-${this.scriptArg.http.hostname}-${rootFolder}`,
                    this.testVulnerability.bind(this)
                );
            }
        }
    }

    async testVulnerability() {
        console.log(`Testing on URI: ${this.scriptArg.http.request.uri}`);

        // Prepare job from the current request scriptArg.http.request
        const job = new browerHttpJob();
        job.setUrl(this.scriptArg.target.url);
        //检测请求代码
        job.request.assign(this.scriptArg.http.request);

        // List of jsonp potential params
        const jsonp_params = ["callback", "jsonp", "cb", "json"];
        const rndStr = rnd.randStringLowerCase(10);
        let jsonp_string = jsonp_params.map(param => `${param}=${rndStr}`).join('&');

        // Add jsonp parameters to the URI
        if (job.request.uri.indexOf("?") === -1) {
            job.request.uri += `?${jsonp_string}`;
        } else {
            job.request.uri += `&${jsonp_string}`;
        }

        // Make http request
        const http = await job.execute();

        if (!http.error && http.response.status === 200 &&
            (http.response.isType("application/javascript") || http.response.isType("text/javascript"))) {
            const bodyStartsWith = (prefix) => http.response.body.startsWith(prefix.replace("{randStr}", rndStr));
            if (bodyStartsWith("/**/{randStr}(") || bodyStartsWith("{randStr}(")) {
                console.log("Vulnerable, should alert here!");
                this.alert("Spring_JSONP_Enabled_by_Default.xml", http);
            }
        }
    }

    alert(vulnxml, http) {
        const msg = {
            url: this.url,
            body: "",
            payload: "",
            vuln: this.getVulnId(__filename),
            level: "h"
        };
        this.alert(createReport(msg));
    }
}

module.exports = SpringJSONPEnabledByDefault;