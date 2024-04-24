const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js')

class SpringBootTester extends CoreLayer {
    constructor(coreobj) {
        super(coreobj);
    }

    async request(uri, user, pass, port = 80) {
        const lastJob = await browerHttpJob()
        lastJob.url = this.scanURL
        lastJob.verb = "GET"
        lastJob.URI = "/" + uri
        lastJob.addCookies = false
        await lastJob.execute()
        if (!lastJob.wasError && lastJob.response.msg2 == 200) {
            return true
        }
        return false
    }

    async startTesting() {
        const contentTypeStr = "application/vnd.spring-boot.actuator"

        const urls = ["auditevents", "autoconfig", "dump", "metrics", "mappings", "beans", "caches", "conditions", "configprops", "env", "flyway", "httptrace", "integrationgraph", "loggers", "liquibase", "scheduledtasks", "sessions", "threaddump", "heapdump", "jolokia", "logfile", "prometheus"]

        if (await this.request("health") && lastJob.response.headerValue('content-type').startsWith(contentTypeStr)) {
            const r2 = await this.request("health")
            if (!r2 || (r2 && !lastJob.response.headerValue('content-type').startsWith(contentTypeStr))) {
                for (let url of urls) {
                    if (await this.request(url) && lastJob.response.headerValue('content-type').startsWith(contentTypeStr)) {
                        const msg = { url: lastJob.url, body: "", payload: "", vuln: this.getVulnId(__filename), level: "h" }
                        this.alert(createReport(msg))
                        break
                    }
                }
            }
        }
    }
}

module.exports = SpringBootTester
