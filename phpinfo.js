//phpdeserialization.js
const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js');

let oldTitle = '<title>phpinfo()</title>';
let newTitle = ' - phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>';



var variants = [
    "phpinfo.php",
    "phpinfo.php5",
    "pi.php",
    "pi.php5",
    "php.php",
    "i.php",
    "test.php",
    "temp.php",
    "info.php"
];

let flow = ax.loadModule("/lib/utility/flow.js").flow(scanState);
let textSearch = ax.loadModule("/lib/utility/text_search.js").textSearch(scriptArg, scanState, flow);
//--------------------------------------------------------------------------------------------------------

function auditPHPInfoPage(phpInfoURI, http) {
    checkForMySQLAuthBypass(phpInfoURI, http);
    // only run the following if Aspect is disabled.
    if (!http.hasAspectData) {
        checkForPHPConfigProblems(phpInfoURI, http);
    }
}

//--------------------------------------------------------------------------------------------------------
var dir = getCurrentDirectory(); // this is the sitefile

if (dir.response.msg2 == 200) {
    for (var i = 0; i < variants.length; i++) {

        var dirName = dir.fullPath;
        if (dirName.charAt(dirName.length - 1) != '/') dirName = dirName + '/';

        var testURI = dirName + variants[i];

        var http = new THTTPJob();
        http.url = dir.url;
        http.verb = 'GET';
        http.URI = testURI;
        http.execute();

        if (!http.wasError && !http.notFound) {
            let retval = textSearch.checkFor_PHPInfo(http.response.body, http);
            if (retval === true) {
                var auditedPHPInfo = getGlobalValue("auditedPHPInfo");
                if (!auditedPHPInfo) {
                    setGlobalValue("auditedPHPInfo", 1, true);
                    auditPHPInfoPage(testURI, http);
                }
            }
        }
    }
}





class classPhpDeserialization extends CoreLayer {
    constructor(coreobj) {
        super(coreobj);
    }

    async startTesting() {
        if (this.variations.length != 0 && this.method == "POST") {
            //console.log(`url: ${this.url} method: ${this.method} postdata:${this.postData}`);
            for (var i = 0; i < this.variations.length; i++) {
                let report = await this.attack(i);
            }
        }
    }

    async attack(dir) {

        for (var i = 0; i < variants.length; i++) {
            var dirName = dir.fullPath;
            if (dirName.charAt(dirName.length - 1) != '/') dirName = dirName + '/';

            var testURI = dirName + variants[i];


            const lastJob = new browerHttpJob(this.browser)
            this.variations.setValue(index, php_payload_list[i])
            const payload = this.variations.toString()
            lastJob.url = this.url
            lastJob.method = this.method
            lastJob.headers = this.headers
            lastJob.postData = payload
            lastJob.isEncodeUrl = false
            let response = await lastJob.execute();

        }
        // response.body.forEach(element => {
        //     if (element.indexOf("ab49bdd251591b16da541abad631329c") != -1) {
        //         console.log(`发现漏洞`);
        //         const msg = { url: this.url, body: element, payload: payload, vuln: this.getVulnId(__filename), level: "h" } //"rj-020-0001"
        //         this.alert(createReport(msg));
        //     }
        // });

    }
}










module.exports = classPhpDeserialization