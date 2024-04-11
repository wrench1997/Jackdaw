
const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js')


// 使用类组织逻辑
class VulnerabilityScanner extends CoreLayer {
    constructor(coreobj) {
        super(coreobj);
        this.baseHost = null;
        this.localHostDomain = null;
        this.localHostIP = null;
    }
    async startTesting() {  // 入口函数为startTesting
        // 获取baseHost
        this.baseHost = scanHost;
        let m = /^www\d?\.(.*)$/.exec(scanHost);
        if (m) { this.baseHost = m[1]; }

        // 获取localHostDomain和localHostIP
        this.localHostDomain = `localhost.${this.baseHost}`;
        this.localHostIP = await getHostByName(this.localHostDomain);

        if (this.localHostIP && this.localHostIP.startsWith('127.0.0.')) {
            this.reportVulnerability();
        }
    }

    reportVulnerability() {
        const msg = {
            url: this.url,
            body: "",
            payload: "",
            vuln: this.getVulnId(__filename),
            level: "h"
        };
        this.alert(createReport(msg));
    }

    async getHostByName(host) {
        // 使用await简化回调
        const res = await axios.get(`${API_URL}resolve?name=${host}`);
        return res.data.hostAddress;
    }
}

const scanner = new VulnerabilityScanner();
scanner.startTesting();