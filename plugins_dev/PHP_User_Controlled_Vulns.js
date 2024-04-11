const { getSensorData } = require('./http.js');
const rnd = require('./random.js');


function InjectionResult(data, adItem) {
    this.data = data;
    this.adItem = adItem;
}


class PHPUserControlledVulns extends CoreLayer {
    constructor(scheme, inputIndex) {
        super(scheme, inputIndex);
        this.variations = scheme.selectVariationsForInput(inputIndex);
        this.currentVariation = 0;
        this.foundVulnOnVariation = false;
    }

    async request(value) {
        this.scheme.loadVariation(this.variations.item(this.currentVariation));
        this.scheme.setInputValue(this.inputIndex, value);

        const lastJob = new browerHttpJob();
        lastJob.url = targetUrl;
        if (this.env.AcuSensor.enabled) lastJob.addAspectHeaders();
        this.scheme.populateRequest(lastJob);

        await lastJob.execute();
        return !lastJob.wasError;
    }

    async lookForVuln(itemName, sensorData, value) {
        const items = sensorData.getItems(itemName);
        if (!items) return null;
        for (const item of items) {
            for (const entry of item.dataList) {
                if (entry && entry.indexOf(value) != -1) {
                    return new InjectionResult(entry, item);
                }
            }
        }
        return false;
    }

    async alert(testValue, sourceFile, sourceLine, additionalInfo, vulnxml, acuSensor) {
        this.foundVulnOnVariation = true;
        const flags = [];
        if (acuSensor) {
            flags.push("verified");
            flags.push("acusensor");
        }
        const inputName = this.scheme.getInputName(this.inputIndex);
        const inputType = this.scheme.getInputTypeStr(this.inputIndex);
        const detailsObject = {
            input_type: inputType,
            input_name: inputName,
            test_value: testValue
        };
        const msg = {
            url: this.url,
            body: "",
            payload: "",
            vuln: vulnxml,
            level: "h",
            flags,
            parameter: inputName,
            scheme: this.scheme,
            attackVector: testValue,
            details: detailsObject,
            http: lastJob.getNativeObject(),
            ssl: this.target.url.protocol == 'https'
        };
        this.alert(createReport(msg));
    }

    async testInjection(value) {
        if (!await this.request(value)) return false;
        let data = this.disableSensorBased ? null : await getSensorData(this.lastJob);
        if (data) {
            const injRes = await this.lookForVuln("CURL_Exec", data, value);
            if (injRes && injRes.adItem) {
                const additional = injRes.adItem.additional[0];
                await this.alert(value, injRes.adItem.fileName, injRes.adItem.fileNo, additional, "PHP_curl_exec()_url_is_controlled_by_user.xml", 1);
                return true;
            }
            // ...
        } else {
            this.disableSensorBased = true;
        }
        return false;
    }

    async startTesting() {
        for (let i = 0; i < this.variations.count; i++) {
            if (this.foundVulnOnVariation) break;
            this.currentVariation = i;
            if (await this.testInjection(rnd.randStrDigits(6))) continue;
        }
    }
}

async function main() {
    for (let i = 0; i < scheme.inputCount; i++) {
        const tester = new PHPUserControlledVulns(scheme, i);
        await tester.startTesting();
        ScriptProgress(ComputeProgress(i, scheme.inputCount));
    }
}

main();