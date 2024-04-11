const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js')

class JSPTester extends CoreLayer {

    async request(uri, user, pass, port = 80) {
        const lastJob = await browerHttpJob()
        lastJob.url = this.scanURL
        lastJob.addCookies = false
        lastJob.verb = 'GET'
        lastJob.URI = uri
        lastJob.execute()
        if (!lastJob.wasError && lastJob.responseStatus == 200 && !lastJob.notFound) {
            return lastJob.response
        }
        return false
    }

    async startTesting() {
        const variants = [
            "/snoop.jsp",
            "/examples/jsp/snp/snoop.jsp",
            "/examples/servlet/SnoopServlet",
            "/servlet/SnoopServlet",
            "/j2ee/servlet/SnoopServlet",
            "/jsp/viewer/snoop.jsp"
        ]
        const matches = [
            "<h1> Request Information </h1>",
            "JSP Snoop page"
        ]

        for (let url of variants) {
            const res = await this.request(url)
            if (res) {
                for (let match of matches) {
                    if (res.body.includes(match)) {
                        const msg = { url, body: "", payload: "", vuln: this.getVulnId(__filename), level: "h" }
                        this.alert(createReport(msg))
                        break
                    }
                }
            }
        }
    }
}

module.exports = JSPTester