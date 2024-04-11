//java_lib_audit.js

const { CoreLayer, createReport } = require('../core/core.js')


var regexBenchmark = false; // Displays expensive regular expressions. ===> default: FALSE!
var regexBenchmarkThresholdMs = 5; // Threshold (milliseconds) to display alerts
var regexBenchmarkTruncate = 1024 * 10 * 0; // Optional truncation of input (script/response bodies). Set to 0 to disable.
var forceRegex = false; // Don't check file names, hashes etc. ===> default: FALSE!
var breakAfterFirstMatch = true;

/*
Benchmark-HOWTO:
1) Set regexBenchmark to true
2) Increase regexBenchmarkTruncate until trace() messages appear; e.g start with 1024, increase to 1024*2, and so on.
*/

var bPrescreenFiles = false; //  ===> experimental/debugging ===> default: FALSE!

if (forceRegex || regexBenchmark || bPrescreenFiles || !breakAfterFirstMatch)
    console.error('bdbg jslib debug settings enabled.');

let jslibRepo = undefined;
let synhashModuleRef = undefined;
let utilsModule = undefined;

var matchedText = "";
var synHash = null;
var synHashVersion = null;
var outdatedVersion = false;


/*

last synhash update: 2020-06

jquery		    3.5.1		https://code.jquery.com/
jquery mobile	1.5.0-rc1	https://jquerymobile.com/download/
jquery ui	    1.12.1		https://jqueryui.com/download/

angularjs	    1.8.0		https://code.angularjs.org/

jplayer		    2.9.2		https://github.com/jplayer/jPlayer/releases
yui		        3.18.1

 */

/*
        https://src.invicti.com/netsparker/standard/source/-/blob/develop/SecuritySubmodules/Version%20Tables/repository.json
 */


function isDefined(o) {
    return typeof o !== 'undefined';
}

function determineVersion(data, extractor, repo) {
    var detected = [];

    // loop through all libraries in repo
    loopScan:
    for (var component in repo) {
        if (repo.hasOwnProperty(component)) {

            if (extractor === 'filecontent') {
                if (repo[component].extractors?.presignature) {
                    if (data.includes(repo[component].extractors.presignature) !== true) {
                        continue;
                    }
                }
            }

            // use only extractors applicable to current dataType: "filename", "uri", or "filecontent".
            // NB: an extractor defines how version info can be extracted.
            var extractors = repo[component].extractors[extractor];
            var localdata = data;
            if (!isDefined(extractors)) continue;

            //trace(component);

            // experimental; will not run
            if (extractor === 'filecontent' && bPrescreenFiles) {
                if (repo[component].extractors.hasOwnProperty('filecontent-require-string')) {
                    var bFound = false;

                    var vPlay = new Date().getTime();
                    for (var idx = 0; idx < repo[component].extractors['filecontent-require-string'].length; idx++) {
                        //trace(repo[component].extractors['filecontent-require-string'][idx]);
                        if (data.indexOf(repo[component].extractors['filecontent-require-string'][idx]) != -1)
                            bFound = true;
                    }

                    if (!bFound) {
                        //trace(component + ' check requires string ' + repo[component].extractors['filecontent-require-string']);
                        extractors = []; // Skips following loop
                    }
                }
                else if (repo[component].extractors.hasOwnProperty('filecontent-truncate-at')) {
                    localdata = localdata.substr(0, repo[component].extractors['filecontent-truncate-at']);
                    //trace(component + ' forced truncation at ' + repo[component].extractors['filecontent-truncate-at']);
                }
            }

            // loop through extractor definitions
            loopExtractors:
            for (var i in extractors) {
                if (extractors.hasOwnProperty(i)) {
                    var regexStr = replaceVersion(extractors[i]);
                    //trace("RE:" + regexStr);
                    //trace('bdbg component/extractor ---------------> ' + component + '/' + extractor);

                    if (regexBenchmark) {
                        if (regexBenchmarkTruncate > 0 && localdata.length > regexBenchmarkTruncate) {
                            //trace('regexBenchmark truncating to ' + regexBenchmarkTruncate);
                            localdata = localdata.substr(0, regexBenchmarkTruncate);
                        }
                        var regexBenchmarkTime = new Date().getTime();
                    }

                    var re = new RegExp(regexStr);
                    var match = re.exec(localdata);
                    //__dbgout('bdbg: ' + component + ' / ' + JSON.stringify(match));

                    if (regexBenchmark) {
                        regexBenchmarkTime = new Date().getTime() - regexBenchmarkTime;
                        if (regexBenchmarkTime > regexBenchmarkThresholdMs) {
                            //trace('bdbg regexBenchmark: ' + component + ' (' + i + '): ' + regexBenchmarkTime + ' ms');
                        }
                    }


                    // if regex matches:
                    if (match) {

                        // if we have a synhash for current file:
                        if (synHash) {

                            //trace('bdbg synHash ' + extractor);

                            // if we are currently processing a filename or uri,
                            // apply regex against ARTIFICIAL (synhash db provided) filename/uri,
                            // and store result in matchComparison.

                            // if processing anything else, and if synHashVersion already determined,
                            // set matchComparison to previously determined synHashVersion


                            // -> implication: important to start with filename/uri,
                            // as that will cover the ARTIFICIAL filename/uri returned by the synhash db,
                            // based on the synhash of the filecontents. By the time we're here for filecontents,
                            // synhash may already have determined the version.

                            if (extractor === 'filename')
                                var matchComparison = re.exec(synhashModule().getSynhash()[synHash].fileName);
                            else if (extractor === 'uri')
                                var matchComparison = re.exec(synhashModule().getSynhash()[synHash].dirName + synhashModule().getSynhash()[synHash].fileName);
                            else if (synHashVersion)
                                var matchComparison = synHashVersion;
                            else
                                //trace('bdbg ============== MISSING VERSION EXTRACTOR FILENAME/URI ============== ' + component);


                                if (matchComparison) {
                                    //__dbgout(JSON.stringify(matchComparison));
                                    //logInfo(`bdbg synhash matchcmp: standard=${match[1]}, synhash=${matchComparison[1]}     ${extractor}`);
                                    // set synHashVersion to determined version for later use (as explained above)
                                    synHashVersion = matchComparison;
                                }
                        }

                        var synHashConfirmed = false;
                        // if synhash based version extraction was successful AND
                        // synhash based version MATCHES the version found based on actual filename/uri/... ,
                        // THEN set synHashConfirmed, and indicate extraction method was "synhash".
                        if (matchComparison && match[1] === matchComparison[1]) {
                            // confirmed/verified
                            synHashConfirmed = true;
                            //extractor = 'synhash';
                        }
                        // if synhash based version extraction was successful BUT
                        // synhash based version DOES NOT MATCH the version found based on actual filename/uri/... ,
                        // THEN set synHashConfirmed, and indicate extraction method was "synhash"
                        // AND ALSO give precedence to synhash version.
                        else if (matchComparison && match[1] !== matchComparison[1]) {
                            // definitely wrong version; overwrite
                            match = matchComparison; // overwrite
                            synHashConfirmed = true;
                            extractor = 'synhash';
                        }
                        else {
                            // likely wrong version; either: ignore OR overwrite OR do nothing
                            ////match = matchComparison;    // overwrite
                            //match[1] = null;          // ignore
                            //trace('bdbg else ' + extractor);
                        }

                        var matchStr = match[1];

                        //trace('match[1] for '+component+': ' + match[1]);
                        if (matchStr) {
                            matchStr = matchStr.replace(".min", "");
                            matchStr = matchStr.replace(".pack", "");
                            matchStr = matchStr.replace(".slim", "");
                            //trace(matchStr);
                            //trace('bdbg synhash vuln confirmed? ' + synHashConfirmed);

                            detected.push({
                                component: component,
                                version: matchStr,
                                detection: extractor,  // how did we determine the version?
                                synHashConfirmed: synHashConfirmed
                            });
                            if (extractor === 'synhash') {
                                //trace('bdbg: marked as synHash verified: ' + extractor);
                                //trace('bdbg exiting loopScan');
                                //break loopScan;

                            }
                            if (breakAfterFirstMatch) {
                                //trace('bdbg exiting loopExtractors');
                                break loopExtractors;

                            }
                        }
                    }
                }
            }
        }
    }
    //traceObject(detected);
    return detected;
}

function scanhash(hash, repo) {
    for (var component in repo) {
        var hashes = repo[component].extractors.hashes;
        if (!isDefined(hashes)) continue;
        for (var i in hashes) {
            //trace(i);
            if (i === hash) return [{ version: hashes[i], component: component, detection: 'hash' }];
        }
    }
    return [];
}

function checkRepoForVulnerabilities(results, repo) {
    //__dbgout('exaresults:' + JSON.stringify(results));
    //__dbgout('exarepo:' + JSON.stringify(results));

    for (var r in results)
        if (results.hasOwnProperty(r)) {
            var result = results[r];
            var vulns = repo[result.component].vulnerabilities;

            /*
            result properties:
                component           (library name)
                version             (version)
                outdated            false/true
                vulnerabilities     if outdated:    library website
                                    if vulnerable:  vuln detail string; usually links
                detection           how? string: synhash, filename, uri, filecontent, ...
                synHashConfirmed    false/true
             */

            result.outdated = false;
            result.vulnerabilities = [];

            for (var i in vulns) {
                if (vulns.hasOwnProperty(i)) {

                    if (!isAtOrAbove(result.version, vulns[i].below)) {
                        //traceObject(vulns[i]);

                        if (isDefined(vulns[i].atOrAbove) && !isAtOrAbove(result.version, vulns[i].atOrAbove)) {
                            //trace('continue');
                            continue;
                        }

                        for (let c of vulns[i].info) {
                            if (!result.vulnerabilities.includes(c))
                                result.vulnerabilities.push(c);
                        }
                        //result.vulnerabilities = vulns[i].info; // = merge, don't overwrite.

                        //__dbgout('--> ' + JSON.stringify(vulns[i].identifiers));
                        if (vulns[i].identifiers) {
                            if (vulns[i].identifiers.CVE) {
                                if (!result.identifiers)
                                    result.identifiers = {};
                                for (let thisCVE of vulns[i].identifiers.CVE) {
                                    //__dbgout('--> setting CVE: ' + thisCVE);
                                    if (result.identifiers.CVE && !result.identifiers.CVE.includes(thisCVE))
                                        result.identifiers.CVE.push(thisCVE);
                                    else
                                        result.identifiers.CVE = [thisCVE];
                                }
                            }

                            if (vulns[i].identifiers.summary) {
                                if (!result.identifiers)
                                    result.identifiers = {};

                                //__dbgout('--> setting SUMMARY: ' + vulns[i].identifiers.summary);
                                if (result.identifiers.summary && !result.identifiers.summary.includes(vulns[i].identifiers.summary))
                                    result.identifiers.summary = result.identifiers.summary + ' / ' + vulns[i].identifiers.summary;
                                else
                                    result.identifiers.summary = vulns[i].identifiers.summary;
                            }

                            //__dbgout('--> results33: ' + JSON.stringify(result));

                        }

                    }

                }
            }

            // if not vulnerable, then at least outdated?
            if (result.vulnerabilities.length === 0) {
                if (isDefined(repo[result.component].currentVersion) && repo[result.component].currentVersion !== '' && repo[result.component].website.length > 0) {

                    let curVers = repo[result.component].currentVersion;
                    if (typeof curVers === "string" && !isAtOrAbove(result.version, curVers)) {
                        // only single current version to check for
                        result.outdated = true;
                        result.vulnerabilities = repo[result.component].website;
                    }
                    else if (typeof curVers === "object" && curVers.highest && curVers.alternatives) {
                        if (!isAtOrAbove(result.version, curVers.highest) && !curVers.alternatives.includes(result.version)) {
                            // used library is not the highest available version,
                            //   nor the most recent version of an alternative branch
                            result.outdated = true;
                            result.vulnerabilities = repo[result.component].website;
                        }
                    }
                }
            }

        }

    return results;
}

function toComparable(n) {
    if (!isDefined(n)) return 0;
    if (n.match(/^[0-9]+$/)) {
        return parseInt(n, 10);
    }
    return n;
}

function isAtOrAbove(version1, version2) {
    //trace("isAtOrAbove()");
    //trace("version1:" + version1);
    //trace("version2:" + version2);
    var v1 = version1.split(/[\.\-]/g);
    var v2 = version2.split(/[\.\-]/g);
    var l = v1.length > v2.length ? v1.length : v2.length;
    for (var i = 0; i < l; i++) {
        var v1_c = toComparable(v1[i]);
        var v2_c = toComparable(v2[i]);
        if (typeof v1_c !== typeof v2_c) return typeof v1_c === 'number';

        if (v1_c > v2_c) {
            //trace('TRUE');
            return true;
        }
        if (v1_c < v2_c) {
            //trace('FALSE');
            return false;
        }
    }
    //trace('TRUE');
    return true;
}

replaceVersion = function (jsRepoJsonAsText) {
    return jsRepoJsonAsText.replace(/§§version§§/g, '[0-9]+[.][0-9.a-z\\\\-]+');
};

function extractVersionAndMapVulns(data, dataType, repo) {

    if (['filename', 'uri', 'filecontent'].includes(dataType) === false) {
        return false;
    }

    var result = determineVersion(data, dataType, repo);
    if (dataType === 'filecontent' && result.length === 0) {
        result = scanhash(utilsModules().plain2sha1(data), repo);
    }
    return checkRepoForVulnerabilities(result, repo);

}


// // **************************************************************************************
// function alert(comp, version, detection, refs, verifiedBySynHash, merelyOutdated, fileHash, identifiers = undefined) {

//     //    __dbgout('version: ' + version);

//     // WP-specific patch
//     if (version === '1.12.4-wp')
//         return false;

//     let friendlyText = "The library's name and version were determined based on the file's " + detection + ". ";


//     //trace('ALERT: ' + file.fullPath + '/ version: ' + version);

//     var myflags = [];

//     var compSupported = synhashModule().isComponentSupported(comp);
//     //trace('bdbg alerting: ' + file.fullPath + '/compSupported?:' + compSupported + '/' + comp + '/' + version + '/verif?:' + verifiedBySynHash + '/onlyOutdated?:' + merelyOutdated);
//     if (compSupported === true && verifiedBySynHash === true) {
//         // synhash support for component and matched
//         //trace('bdbg CONFIDENCE HIGH ' + file.fullPath + ' is version: ' + version);
//         myflags.push('confidence.100');
//         myflags.push('verified');
//         sTmp = '';
//         if (merelyOutdated !== true)
//             sTmp = 'and the associated vulnerabilities ';
//         friendlyText = friendlyText + "Acunetix verified the library version " + sTmp + "with the file's unique syntax fingerprint, which matched the syntax fingerprint expected by Acunetix.";
//     }
//     else if (compSupported === true && verifiedBySynHash !== true) {
//         // synhash support for component but NOT matched
//         trace('bdbg CONFIDENCE LOW ' + file.fullPath + ' is version: ' + version);
//         myflags.push('confidence.80');
//         sTmp = '';
//         if (merelyOutdated !== true)
//             sTmp = 'vulnerability ';
//         friendlyText = friendlyText + "Acunetix performed a syntax analysis of the file and detected functional differences between the file and the original library version. As the file was likely modified on purpose, the confidence level of the " + sTmp + "alert has been lowered.";
//     }
//     else if (compSupported === false) {
//         // NO synhash support for component
//         //trace('bdbg CONFIDENCE MEDIUM ' + file.fullPath + ' is version: ' + version);
//         myflags.push('confidence.95');
//     }

//     var vulntype = 'Vulnerable_Js_Library.xml';
//     if (merelyOutdated === true) {
//         __dbgout('bdbg not vulnerable, but outdated');
//         vulntype = 'Outdated_Js_Library.xml';
//     }

//     let sNameUI = comp;
//     if (jslibRepo[sNameUI].name && jslibRepo[sNameUI].name !== "")
//         sNameUI = jslibRepo[sNameUI].name;


//     let detailsObject = {
//         "url": scriptArg.location.url.toString(),
//         "name": sNameUI,
//         "version": version,
//         "refs": refs,
//         "detection": friendlyText,
//     };

//     //__dbgout('--> alert() identifiers: ' + JSON.stringify(identifiers));

//     detailsObject["CVE"] = 'N/A';
//     detailsObject["summary"] = 'N/A';

//     if (identifiers) {
//         if (identifiers.CVE)
//             detailsObject["CVE"] = identifiers.CVE.join(', ');

//         if (identifiers.summary)
//             detailsObject["summary"] = identifiers.summary;
//     }


//     //fileHash = fileHash;
//     // option 1: filehash-based merging:
//     // + entirely content-based (hash; either verbatim or reduced)
//     // - does not play well with dynamically modified per-page js files (no merging)

//     //fileHash = ax.util.sha1(comp + ':' + version);
//     //fileHash = ax.util.sha1(comp);
//     // option 2: aggressive merging:
//     // + files with different names, contents all merged into one alert as long as comp(/vers) identical
//     // - different files with same comp/vers result also merged, even if one is 100% synhash and the other 80% (= different file contents)
//     //   -> loses confidence level, which is not merged

//     fileHash = ax.util.sha1(comp + ':' + version + ':' + JSON.stringify(myflags));
//     // option 3: outcome-based merging:
//     // merges files leading to same comp/vers result IF detection mechanism is the same
//     // + merges dynamically modified js files
//     // + should otherwise behave the same as content-based, because identical content leads to identical comp+vers+detection
//     // + avoids losing confidence level by taking it into consideration for merging
//     // - but: identical comp+vers+detection can be result of different file contents.
//     // - ...?

//     scanState.addVuln({
//         location: scriptArg.target.root,
//         typeId: vulntype,
//         http: file.http(),
//         tags: myflags,
//         details: [detailsObject],
//         customId: fileHash,
//         merge: 'details'
//     });
// }

// **************************************************************************************
function fileShouldBeSearched() {
    /*
    trace(file.response.msg2);
    trace(file.response.body.length);
    trace(getFileExt(file.name));
    trace(file.response.headerValue('content-type'));
    */

    // only 200
    if (file.response.msg2 != 200) return false;

    // only files with some content
    if (file.response.body.length == 0) return false;

    // look for extension .js (if yes, search it)
    var fileExt = getFileExt(file.name);
    if (fileExt.toLowerCase() == 'js') return true;

    // or right content type
    var ct = file.response.headerValue('content-type');
    if (ct && ct.toLowerCase().indexOf("javascript") == -1 && ct.toLowerCase().indexOf("ecmascript") == -1) return false;

    return true;
}

// **************************************************************************************
function addDetectionStr(input, curStr) {
    let addStr = '';
    if (input === 'filename' && !curStr.includes('filename')) addStr = 'name';
    if (input === 'uri' && !curStr.includes('uri')) addStr = 'uri';
    if (input === 'hash' && !curStr.includes('file hash')) addStr = 'hash';
    if (input === 'filecontent' && !curStr.includes('file content')) addStr = 'contents';
    if (input === 'synhash' && !curStr.includes('syntax fingerprint')) addStr = 'syntax fingerprint';


    if (curStr !== '' && addStr !== '')
        addStr = ', and ' + addStr;
    return curStr + addStr;
}

function getRepo() {
    if (jslibRepo === undefined)
        jslibRepo = require("../utils/jslib-repo.js").getRepo();
    return jslibRepo;
}

function synhashModule() {
    if (synhashModuleRef === undefined)
        synhashModuleRef = require("../utils/jslib-synhash.js");
    return synhashModuleRef;
}

function utilsModules() {
    if (utilsModule === undefined)
        utilsModule = require("../utils/utils.js");
    return utilsModule;
}




function vulnCompIndex(sComponent, oVulns) {
    if (oVulns.length === 1 && oVulns[0].componentStr === "")
        return 0;

    for (let i = 0; i < oVulns.length; i++) {
        if (sComponent === oVulns[i].componentStr)
            return i;
    }
    return -1;
}

/*   FLOW:

- only process files that are likely to be scripts

- create SHA-1 hash for response body and synhash'ed response body
- if one of the hashes is found in synhash db, store hash in variable synHash
-> implication: if synhash !== null, we have a matching hash

- if hash found:
  - indicate detection mechanism "synhash"
  - retrieve artificial filename and uri from synhash db for the given hash. The purpose of the artificial filename/uri is to pass it to the version extractor that is usually applied to organic filenames/uris

- pass ACTUAL filename to extractVersionAndMapVulns()
- if nothing found, overwrite empty result with result of version extractor based on ARTIFICIAL filename
- implication: this gives precedence to real filename over synhash, but synhash will later still be used to *confirm* the result (or negate it, thereby lowering confidence)
- if result is not empty (ie. version either found through synhash or filename):
- store all vulns associated with version/lib in "references"
- repeat above for uri
- repeat above for filecontent

- if vulns found, alert()

*1) extractVersionAndMapVulns():
- pass data to determineVersion():
    - loop through all libraries in repo
    - for each component, loop through extractors
    - (an extractor defines how version info can be extracted)
    - for each extractor:
        - if regex match:
            - if we have a synhash for current file:
                - if currently processing filename/uri, apply regex against ARTIFICIAL filename/uri and store result in matchComparison
                - if processing anything else, and if synHashVersion already determined, set matchComparison to synHashVersion
                - if neither, synhash db is broken
                -> implication: important to first check fn/uri, as that will cover the ARTIFICIAL fn/uri returned by the synhash db, based on the synhash of the filecontents
                - set synHashVersion to determined version for later use (as seen above).
            - if synhash based version extraction was successful AND synhash based version matches that found by version extracted from actual filename/uri/... , set synHashConfirmed, indicate extraction method was "synhash"
            - if synhash based version extraction was successful BUT synhash based version DOES NOT MATCH that found by version extracted from actual filename/uri/... , give precedence to synhash version, then set synHashConfirmed, indicate extraction method was "synhash"
            - return result: version+library+howdidwefindit+synhashconfirmed?
- pass result to vulnerability extractor
.
 */




class classJavaAudits extends CoreLayer {
    constructor(coreobj) {
        super(coreobj);
    }


    async startTesting() {
        await this.attack(this.isFile, this.filename, this.url, this.fileContent)
    }

    async attack(isFile, filename, fullPath, filecontent) {
        var o = null;
        var file = {
            isFile: isFile,
            name: filename,
            fullPath: fullPath,
            response: { body: filecontent }
        }

        //var matches = new classMatches();


        //trace('CHECKING: ' + file.url.url);

        // only process files that are likely to be scripts
        // && fileShouldBeSearched()
        if (file.isFile && file.response) {
            var vulnsToReport = [{ componentStr: "", detectionStr: "", versionStr: "", verifiedBySynHash: null, references: [], outdatedVersion: false, identifiers: false }];

            //trace('bdbg ' + file.fullPath);

            // create SHA-1 hash for response body and search for it in synhash db (= jqSHA1 via synhashModule().getSynhash())
            var tempSynHash = utilsModules().plain2sha1(file.response.body);
            if (synhashModule().getSynhash()[tempSynHash] !== undefined) {

                // - if one of the hashes is found in synhash db, store hash in variable synHash
                // -> implication: if synhash !== null, we have a matching hash

                synHash = tempSynHash;
                //logInfo('bdbg synhash found (verbatim): ' + synhashModule().getSynhash()[synHash].dirName + synhashModule().getSynhash()[synHash].fileName);
            }
            else // if not found in synhash db, try with synhash'ed response body
            {
                var tempSynHash = utilsModules().plain2sha1(synhashModule().synHashPrep(file.response.body));
                if (synhashModule().getSynhash()[tempSynHash] !== undefined) {
                    synHash = tempSynHash;
                    //logInfo('bdbg synhash found (reduced): ' + synhashModule().getSynhash()[synHash].dirName + synhashModule().getSynhash()[synHash].fileName);
                }
            }




            //matchedText = TestForjQuery163XSS(matches, file.response.toString());
            //if (matchedText) alert(matchedText, "jQuery_163_XSS.xml");


            if (synHash) {

                // retrieve artificial filename and uri from synhash db for the given hash,
                // then pass it to the version extraction mechanism (extractVersionAndMapVulns)
                //   that was designed for real filenames/uris.
                // This allows for the existing filename/uri based code to be reused with hash-based detection.

                var resultsFilenameSynHash = extractVersionAndMapVulns(synhashModule().getSynhash()[synHash].fileName, 'filename', getRepo());
                var resultsUriSynHash = extractVersionAndMapVulns(synhashModule().getSynhash()[synHash].dirName + synhashModule().getSynhash()[synHash].fileName, 'uri', getRepo());

                // if vulns were found using synhash, indicate detection mechanism "synhash" for UI
                if (resultsFilenameSynHash && resultsFilenameSynHash.length > 0) {
                    resultsFilenameSynHash[0]['detection'] = 'synhash';
                    if (resultsFilenameSynHash[0]['outdated'] === true) vulnsToReport[0].outdatedVersion = true;
                }

                if (resultsUriSynHash && resultsUriSynHash.length > 0) {
                    resultsUriSynHash[0]['detection'] = 'synhash';
                    if (resultsUriSynHash[0]['outdated'] === true) vulnsToReport[0].outdatedVersion = true;
                }
            }

            if (!forceRegex) {

                // pass ACTUAL filename to extractVersionAndMapVulns()
                var resultsFilename = extractVersionAndMapVulns(file.name, 'filename', getRepo());

                // - if nothing found, overwrite empty result with result for synhash's ARTIFICIAL filename
                // - implication: this gives precedence to real filename over synhash,
                //   but synhash will later still be used to *confirm* the result (or negate it, thereby lowering confidence)
                if (resultsFilename.length <= 0 && synHash) {
                    resultsFilename = resultsFilenameSynHash;
                }

                // if result is NOT empty (ie. version either found through synhash or filename), and vulns found:
                if (resultsFilename.length > 0) {
                    o = resultsFilename[0];

                    //traceObject(resultsFilename);

                    if (vulnsToReport[0].detectionStr == "")
                        vulnsToReport[0].detectionStr = addDetectionStr(o['detection'], '');
                    else
                        vulnsToReport[0].detectionStr = addDetectionStr(o['detection'], vulnsToReport[0].detectionStr);

                    if (vulnsToReport[0].versionStr == "") vulnsToReport[0].versionStr = o["version"];
                    if (vulnsToReport[0].componentStr == "") vulnsToReport[0].componentStr = o["component"];
                    if (vulnsToReport[0].identifiers === false) vulnsToReport[0].identifiers = o["identifiers"];
                    if (o['synHashConfirmed'] && vulnsToReport[0].verifiedBySynHash === null)
                        vulnsToReport[0].verifiedBySynHash = o['synHashConfirmed'];
                    if (o['outdated'] === true) vulnsToReport[0].outdatedVersion = true;

                    var vulns = o["vulnerabilities"];



                    // Store all vulns associated with detected version of detected library in "references".
                    // "references" will later be used to issue alerts.
                    if (vulns) {
                        for (var i = 0; i < vulns.length; i++) {
                            if (vulnsToReport[0].references.indexOf(vulns[i]) == -1)
                                vulnsToReport[0].references.push(vulns[i]);
                        }
                    }
                }

                // -----> repeat the above (filename check) for uri and filecontent
                //        --> (important to do it in this exact order, do not change)
                // TODO: turn this into single function that is then called three times

                var resultsUri = extractVersionAndMapVulns(file.fullPath, 'uri', getRepo());

                if (resultsUri.length <= 0 && synHash)
                    resultsUri = resultsUriSynHash;

                if (resultsUri.length > 0) {
                    o = resultsUri[0];

                    if (vulnsToReport[0].detectionStr == "")
                        vulnsToReport[0].detectionStr = addDetectionStr(o['detection'], vulnsToReport[0].detectionStr);
                    else
                        vulnsToReport[0].detectionStr = addDetectionStr(o['detection'], vulnsToReport[0].detectionStr);

                    if (vulnsToReport[0].versionStr == "") vulnsToReport[0].versionStr = o["version"];
                    if (vulnsToReport[0].componentStr == "") vulnsToReport[0].componentStr = o["component"];
                    if (vulnsToReport[0].identifiers === false) vulnsToReport[0].identifiers = o["identifiers"];
                    if (o['synHashConfirmed'] && vulnsToReport[0].verifiedBySynHash === null)
                        vulnsToReport[0].verifiedBySynHash = o['synHashConfirmed'];
                    if (o['outdated'] === true) vulnsToReport[0].outdatedVersion = true;

                    if (typeof o.vulnerabilities !== 'undefined') {
                        vulns = o["vulnerabilities"];
                        for (var i = 0; i < vulns.length; i++) {
                            if (vulnsToReport[0].references.indexOf(vulns[i]) == -1)
                                vulnsToReport[0].references.push(vulns[i]);
                        }
                    }
                }
            }

            var resultsFileContent = extractVersionAndMapVulns(file.response.body, 'filecontent', getRepo());

            if (resultsFileContent.length <= 0 && synHash) {
                if (resultsUriSynHash && resultsUriSynHash.length > 0)
                    resultsFileContent = resultsUriSynHash;
                else if (resultsFilenameSynHash && resultsFilenameSynHash.length > 0)
                    resultsFileContent = resultsFilenameSynHash;
                else
                    resultsFileContent = resultsUriSynHash;
            }

            if (resultsFileContent.length > 0) {

                //__dbgout('vulnsToReport 1: ' + JSON.stringify(vulnsToReport, " ", 2));
                //__dbgout('resultsFileContent: ' + JSON.stringify(resultsFileContent, " ", 2));

                for (let curResult of resultsFileContent) {
                    o = curResult;

                    let vulnIndex = vulnCompIndex(o['component'], vulnsToReport);

                    if (vulnIndex === -1) {
                        vulnsToReport.push({
                            componentStr: o['component'],
                            detectionStr: "",
                            versionStr: "",
                            verifiedBySynHash: null,
                            references: [],
                            outdatedVersion: false,
                            identifiers: false
                        });
                        vulnIndex = vulnsToReport.length - 1;
                        //__dbgout('zzz' + vulnIndex + '===' + vulnCompIndex(o['component'], vulnsToReport));
                    }
                    else {
                        //__dbgout('potentially overwriting vulnIndex ' + vulnIndex + `: ${vulnsToReport[vulnIndex].componentStr}/${vulnsToReport[vulnIndex].versionStr} -> ${o["component"]}/${o["version"]}`);

                    }

                    vulnsToReport[vulnIndex].detectionStr = addDetectionStr(o['detection'], vulnsToReport[vulnIndex].detectionStr);

                    // overwrite previous result only if either incomplete or not confirmed with synhash
                    if (vulnsToReport[vulnIndex].versionStr === "" ||
                        (vulnsToReport[vulnIndex].componentStr !== "" &&
                            synhashModule().isComponentSupported(vulnsToReport[vulnIndex].componentStr) &&
                            vulnsToReport[vulnIndex].verifiedBySynHash !== true)) {
                        vulnsToReport[vulnIndex].versionStr = o["version"];
                    }

                    if (vulnsToReport[vulnIndex].componentStr === "" ||
                        (vulnsToReport[vulnIndex].componentStr !== "" &&
                            synhashModule().isComponentSupported(vulnsToReport[vulnIndex].componentStr) &&
                            vulnsToReport[vulnIndex].verifiedBySynHash !== true)) {
                        vulnsToReport[vulnIndex].componentStr = o["component"];
                    }

                    if (vulnsToReport[vulnIndex].identifiers === false ||
                        (vulnsToReport[vulnIndex].identifiers !== false &&
                            synhashModule().isComponentSupported(vulnsToReport[vulnIndex].componentStr) &&
                            vulnsToReport[vulnIndex].verifiedBySynHash !== true)) {
                        vulnsToReport[vulnIndex].identifiers = o["identifiers"];
                    }

                    if (o['synHashConfirmed'] && vulnsToReport[vulnIndex].verifiedBySynHash === null)
                        vulnsToReport[vulnIndex].verifiedBySynHash = o['synHashConfirmed'];
                    if (o['outdated'] === true) vulnsToReport[vulnIndex].outdatedVersion = true;

                    vulns = o["vulnerabilities"];

                    if (vulns) {
                        for (var i = 0; i < vulns.length; i++) {
                            if (vulnsToReport[vulnIndex].references.indexOf(vulns[i]) == -1)
                                vulnsToReport[vulnIndex].references.push(vulns[i]);
                        }
                    }
                }
                //__dbgout('vulnsToReport 2: ' + JSON.stringify(vulnsToReport, " ", 2));
            }



            // TODO loop through vulnsToReport

            for (let curVuln of vulnsToReport) {
                if (curVuln.componentStr && curVuln.versionStr) {
                    //scanState.setTags(scriptArg.location, ['jslib|'+componentStr.toLowerCase()+'|'+versionStr]);
                    //scanState.setTags(scriptArg.target.root, ['component|' + curVuln.componentStr.toLowerCase() + '|' + curVuln.versionStr]);
                }


                // if vulns found, alert()
                if (curVuln.componentStr && curVuln.versionStr && curVuln.detectionStr && curVuln.references && curVuln.references.length > 0) {
                    console.log(curVuln.componentStr)
                    console.log(curVuln.versionStr)
                    console.log(curVuln.detectionStr)
                    console.log(curVuln.references)
                    console.log(curVuln.verifiedBySynHash)
                    console.log(curVuln.outdatedVersion)
                    console.log(tempSynHash)
                    console.log(curVuln.identifiers)
                    console.log(`在${this.url}的网址检测易受攻击的脚本漏洞`);
                    if (this.url) {
                        const msg = { url: this.url, body: "22", payload: "11", vuln: "rj-022-0001", level: "m" } //"rj-020-0001"
                        this.alert(createReport(msg));
                    }

                    //alert(curVuln.componentStr, curVuln.versionStr, curVuln.detectionStr, curVuln.references, curVuln.verifiedBySynHash, curVuln.outdatedVersion, tempSynHash, curVuln.identifiers);
                }
            }

        }
    }

}






module.exports = classJavaAudits