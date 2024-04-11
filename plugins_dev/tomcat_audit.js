
const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js')


class tomcatAudit extends CoreLayer {
    constructor(coreobj) {
        super(coreobj);
        this.tomcatVersion = '';
    }

    async startTesting() {
        if (this.TomcatIsDetected() && this.tomcatVersion) {
            //this.tomcatVersion = '7.0.18';

            // Apache Tomcat 7.x

            /*-----------------------------------------------------------------------------------------------------------*/
            let m = /^7\.0\.(0\d|1\d|2\d|3[01])$/.exec(this.tomcatVersion);
            if (m) this.alert('Apache_Tomcat_7_0_32.xml', this.tomcatVersion);
            /*-----------------------------------------------------------------------------------------------------------*/
            m = /^7\.0\.(0\d|1\d|2[0-9])$/.exec(this.tomcatVersion);
            if (m) this.alert('Apache_Tomcat_7_0_30.xml', this.tomcatVersion);
            /*-----------------------------------------------------------------------------------------------------------*/
            m = /^7\.0\.(0\d|1\d|2[0-7])$/.exec(this.tomcatVersion);
            if (m) this.alert('Apache_Tomcat_7_0_28.xml', this.tomcatVersion);
            /*-----------------------------------------------------------------------------------------------------------*/
            m = /^7\.0\.(0\d|1\d|2[0-2])$/.exec(this.tomcatVersion);
            if (m) this.alert('Apache_Tomcat_7_0_23.xml', this.tomcatVersion);
            /*-----------------------------------------------------------------------------------------------------------*/
            m = /^7\.0\.(0\d|1\d|2[0])$/.exec(this.tomcatVersion);
            if (m) this.alert('Apache_Tomcat_7_0_21.xml', this.tomcatVersion);
            /*-----------------------------------------------------------------------------------------------------------*/

            // Apache Tomcat 6.x

            /*-----------------------------------------------------------------------------------------------------------*/
            m = /^6\.0\.(0\d|1\d|2\d|3[0-5])$/.exec(this.tomcatVersion);
            if (m) this.alert('Apache_Tomcat_6_0_36.xml', this.tomcatVersion);
            /*-----------------------------------------------------------------------------------------------------------*/
            m = /^6\.0\.(0\d|1\d|2\d|3[0-3])$/.exec(this.tomcatVersion);
            if (m) this.alert('Apache_Tomcat_6_0_35.xml', this.tomcatVersion);
            /*-----------------------------------------------------------------------------------------------------------*/
        }

        this.TestTomcatJKConnectorBypass();
    }

    async TomcatIsDetected() {
        const lastJob = new browerHttpJob(this.browser)

        lastJob.method = "GET";
        lastJob.addCookies = false;
        lastJob.url = this.scanURL;
        lastJob.uri = "/" + randStr(10) + ".jsp";

        lastJob.execute();
        if (!lastJob.wasError && lastJob.notFound) {
            let m = /<html><head><title>Apache Tomcat\/([\d\.]*) - Error report<\/title><style>/.exec(lastJob.response.body);
            if (m && m[1]) {
                this.tomcatVersion = m[1];
                KBase("Apache Tomcat version", "Apache Tomcat version: " + m[1] + ".");
                return true;
            }
        }

        return false;
    }

    async TestTomcatJKConnectorBypass() {
        const lastJob = new browerHttpJob(this.browser)

        lastJob.method = "GET";
        lastJob.addCookies = false;
        lastJob.url = this.url;
        lastJob.uri = "/examples/jsp/%252e%252e/%252e%252e/manager/html/";

        lastJob.execute();
        if (!lastJob.wasError && lastJob.response.msg2 == 401 && lastJob.response.body.indexOf("<tt>tomcat</tt> with a password of <tt>s3cret</tt>") != -1) {
            this.alert('Tomcat_JK_Connector_Bypass.xml');
        }
    }
}


module.exports = tomcatAudit
