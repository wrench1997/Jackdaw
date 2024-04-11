
const { CoreLayer, createReport, plain2b64, THTTPJob } = require('../core/core.js')

class tomcatAudit extends CoreLayer {
    constructor(coreobj) {
        super(coreobj);
        this.credentials = [
            ['tomcat', ''],
            ['tomcat', 'tomcat'],
            ['manager', 'manager'],
            ['admin', ''],
            ['admin', 'admin'],
            ['admin', 'password'],
            ['password', 'password'],
            ['ADMIN', 'ADMIN'],
            ['root', ''],
            ['root', 'tomcat'],

            ['j2deployer', 'j2deployer'],
            ['ovwebusr', 'OvW*busr1'],
            ['cxsdk', 'kdsxc']
        ];
        const host = extractHostForCredentials();
        if (host) {
            this.credentials.push([host, host]);
            this.credentials.push([host, 'admin']);
            this.credentials.push([host, 'tomcat']);
            this.credentials.push([host, '']);
        }
    }

    async startTesting() {
        const tomcatPort = await this.tomcatDetected();
        if (tomcatPort > 0) {
            await this.testAuth(tomcatPort);
        }
    }

    async tomcatDetected() {
        let lastJob = new browerHttpJob(this.browser)

        lastJob.url = this.url;
        lastJob.addCookies = false;
        lastJob.method = 'GET';
        lastJob.uri = '/manager/html/';
        lastJob.autoAuthenticate = false;
        await lastJob.execute();

        if (!lastJob.wasError && (lastJob.response.status == 401 || lastJob.response.status == 403)) {
            return this.scanURL.port;
        }

        if (this.scanURL.port != 8080) {
            lastJob = new THTTPJob();
            lastJob.url = this.url;
            lastJob.url.port = 8080;
            lastJob.addCookies = false;
            lastJob.method = 'GET';
            lastJob.uri = '/manager/html/';
            lastJob.autoAuthenticate = false;
            await lastJob.execute();

            if (!lastJob.wasError && (lastJob.response.status == 401 || lastJob.response.status == 403)) {
                return lastJob.url.port;
            }
        }

        return false;
    }

    async request(uri, user, pass, port) {
        let lastJob = new browerHttpJob(this.browser);

        lastJob.url = this.url;
        if (port) lastJob.url.port = port;

        lastJob.method = 'GET';
        lastJob.uri = uri;
        lastJob.autoAuthenticate = false;
        lastJob.addHeader('Authorization', `Basic ${plain2b64(user + ":" + pass)}`);
        await lastJob.execute();

        if (!lastJob.wasError && lastJob.response.status == 200) {
            return true;
        }

        return false;
    }

    async testAuth(port) {
        const urls = [
            "/manager/html/",
            "/manager/status/"
        ];

        for (let i = 0; i < urls.length; i++) {
            for (let j = 0; j < this.credentials.length; j++) {
                const username = this.credentials[j][0];
                const password = this.credentials[j][1];

                if (await this.request(urls[i], username, password, port) &&
                    lastJob.response.body.indexOf('Tomcat Web Application Manager') != -1) {
                    await this.alert('Apache_Tomcat_insecure_default_administrative_password.xml', username, password);
                    break;
                }
            }
        }
    }
}

module.exports = tomcatAudit