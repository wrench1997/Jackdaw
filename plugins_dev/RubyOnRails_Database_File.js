const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js')

class Tester extends CoreLayer {
    async request(uri, user, pass, port = 80) {
        const lastJob = await browerHttpJob()
        lastJob.url = this.scanURL
        lastJob.addCookies = false
        lastJob.verb = 'GET'
        lastJob.URI = uri
        lastJob.execute()
        if (!lastJob.wasError && lastJob.response.msg2 == 200 && !lastJob.notFound) {
            return lastJob.response
        }
        return false
    }

    async startTesting() {
        let siteRoot = this.scanURL.path
        if (siteRoot !== '/' && siteRoot.endsWith('/')) siteRoot = siteRoot.substr(0, siteRoot.length - 1)
        siteRoot = getPathDirectory(siteRoot)

        const urls = [
            "database.yml",
            "database.yml_original",
            "database.yml~",
            "database.yml.pgsql",
            "database.yml.sqlite3",
            "config/database.yml",
            "config/database.yml_original",
            "config/database.yml~",
            "config/database.yml.pgsql",
            "config/database.yml.sqlite3",
            "app/config/database.yml",
            "app/config/database.yml_original",
            "app/config/database.yml~",
            "app/config/database.yml.pgsql",
            "app/config/database.yml.sqlite3"
        ]

        for (let url of urls) {
            const res = await this.request(siteRoot + url)
            if (res.body.includes('development:') && res.body.includes('production:') && (res.body.includes('adapter:') || res.body.includes('type:'))) {
                const msg = { url, body: "", payload: "", vuln: this.getVulnId(__filename), level: "h" }
                this.alert(createReport(msg))
            }
        }
    }
}

module.exports = Tester