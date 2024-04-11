
/*

Because this file will be processed in various places (not only by JavaScript_Library_Audit.script), please:

- Keep it valid json:
  - No comments
  - No calculations (instead of 1024*3 write 3072)
  - No trailing commas <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Trailing_commas>

- Do not change any root names without changing them in
  - synhash-jquery.inc->isComponentSupported()
  - httpdata/javascript_library_audit_external.js->translateLibNameCDNtoACX()
  - and possibly other places.
  - Also, ensure their names either match those used by CDNs or are translated.
  - IOW, do not change anything.

- For user-facing formatting changes, use the "name" property (not yet processed)

TODO:
- use name properties for UI

*/

module.exports.getRepo = function()
{
    return repo;
};

//TODO changed some names to lowercase

var repo = {
    "jquery": {
        "name": "jQuery",
        "currentVersion": "3.6.0",
        "website": ["https://code.jquery.com/"],
        "curvers_extractor": "/<li>jQuery Core ([0-9\\.]{3,}) - <a/",
        "vulnerabilities": [{
            "below": "1.6.3",
            "severity": "medium",
            "identifiers": { "CVE": ["CVE-2011-4969"], "summary": "Cross-site scripting (XSS) vulnerability in jQuery before 1.6.3, when using location.hash to select elements, allows remote attackers to inject arbitrary web script or HTML via a crafted tag." },
            "info": ["http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-4969", "http://research.insecurelabs.org/jquery/test/"]
        },

            {
                "below": "1.9.0b1",
                "identifiers": {
                    "bug": "11290",
                    "summary": "Selector interpreted as HTML"
                },

                "severity": "medium",
                "info": ["http://bugs.jquery.com/ticket/11290", "http://research.insecurelabs.org/jquery/test/"]
            },

            {
                "atOrAbove": "1.4.0",
                "below": "1.12.0",
                "identifiers": {
                    "bug": "2432",
                    "summary": "Possible Cross Site Scripting via third-party text/javascript responses"
                },

                "severity": "low",
                "info": ["https://github.com/jquery/jquery/issues/2432", "http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/"]
            },

            {
                "atOrAbove": "1.12.3",
                "below": "3.0.0-beta1",
                "identifiers": {
                    "bug": "2432",
                    "summary": "Possible Cross Site Scripting via third-party text/javascript responses"
                },

                "severity": "low",
                "info": ["https://github.com/jquery/jquery/issues/2432"]
            },

            {
                "atOrAbove": "2.2.0",
                "below": "3.5.0",
                "identifiers": {
                    "CVE": ["CVE-2020-11022", "CVE-2020-11023"],
                    "summary": "Possible Cross Site Scripting via jquery.htmlPrefilter()"
                },

                "severity": "low",
                "info": ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/", "https://mksben.l0.cm/2020/05/jquery3.5.0-xss.html", "https://jquery.com/upgrade-guide/3.5/", "https://api.jquery.com/jQuery.htmlPrefilter/"]
            }
        ],

        "extractors": {
            "func": ["/[0-9.]+/.test(jQuery.fn.jquery) ? jQuery.fn.jquery : undefined"],
            "uri": ["/(§§version§§)/jquery(\\.min)?\\.js"],
            "filename": ["jquery-(§§version§§?)(\\.min|\\.pack|\\.slim)?\\.js"],
            "filecontent": [
                "/\\*!? jQuery v(§§version§§)",
                "\\* jQuery JavaScript Library v(§§version§§)",
                "\\* jQuery (§§version§§) - New Wave Javascript",
                "// \\$Id: jquery.js,v (§§version§§)",
                "/\\*! jQuery v(§§version§§)",
                "[^a-z]f=\"(§§version§§)\",.*[^a-z]jquery:f,",
                "[^a-z]m=\"(§§version§§)\",.*[^a-z]jquery:m,",
                "[^a-z.]jquery:[ ]?\"(§§version§§)\""
            ],

            "filecontent-require-string": [" jQuery "],
            "hashes": {}
        }
    },

    "jquery-migrate": {
        "name": "jQuery Migrate",
        "currentVersion": "3.3.2",
        "website": ["https://github.com/jquery/jquery-migrate/releases"],
        "vulnerabilities": [{
            "below": "1.2.0",
            "severity": "medium",
            "identifiers": {
                "release": "jQuery Migrate 1.2.0 Released",
                "summary": "cross-site-scripting"
            },

            "info": ["http://blog.jquery.com/2013/05/01/jquery-migrate-1-2-0-released/"]
        },

            {
                "below": "1.2.2",
                "severity": "medium",
                "identifiers": {
                    "bug": "11290",
                    "summary": "HTML injection"
                },

                "info": ["http://bugs.jquery.com/ticket/11290", "http://research.insecurelabs.org/jquery/test/"]
            }
        ],

        "extractors": {
            "filename": ["jquery-migrate-(§§version§§)(.min)?\\.js"],
            "filecontent": ["/\\*!?(?:\n \\*)? jQuery Migrate(?: -)? v(§§version§§)"],
            "filecontent-require-string": [" jQuery Migrate"],
            "hashes": {}
        }
    },

    "jquery-mobile": {
        "name": "jQuery Mobile",
        "currentVersion": "1.4.5",
        "website": ["https://jquerymobile.com/download/"],
        "vulnerabilities": [{
            "below": "1.0RC2",
            "severity": "high",
            "identifiers": { "osvdb": ["94563", "93562", "94316", "94561", "94560"] },
            "info": ["http://osvdb.org/show/osvdb/94563", "http://osvdb.org/show/osvdb/94562", "http://osvdb.org/show/osvdb/94316", "http://osvdb.org/show/osvdb/94561", "http://osvdb.org/show/osvdb/94560"]
        },

            {
                "below": "1.0.1",
                "severity": "high",
                "identifiers": { "osvdb": "94317" },
                "info": ["http://osvdb.org/show/osvdb/94317"]
            },

            {
                "below": "1.1.2",
                "severity": "medium",
                "identifiers": {
                    "issue": "4787",
                    "release": "http://jquerymobile.com/changelog/1.1.2/",
                    "summary": "location.href cross-site scripting"
                },

                "info": ["http://jquerymobile.com/changelog/1.1.2/", "https://github.com/jquery/jquery-mobile/issues/4787"]
            },

            {
                "below": "1.2.0",
                "severity": "medium",
                "identifiers": {
                    "issue": "4787",
                    "release": "http://jquerymobile.com/changelog/1.2.0/",
                    "summary": "location.href cross-site scripting"
                },

                "info": ["http://jquerymobile.com/changelog/1.2.0/", "https://github.com/jquery/jquery-mobile/issues/4787"]
            },
            {
                "below" : "1.3.0",
                "severity": "high",
                "identifiers": {
                    "summary": "DOM XSS"
                },
                "info": [ "https://gist.github.com/jupenur/e5d0c6f9b58aa81860bf74e010cf1685" ]
            }
        ],

        "extractors": {
            "func": ["jQuery.mobile.version"],
            "filename": ["jquery.mobile-(§§version§§)(.min)?\\.js"],
            "uri": ["/(§§version§§)/jquery.mobile(\\.min)?\\.js"],
            "filecontent": ["/\\*!?(?:\n \\*)? jQuery Mobile(?: -)? v(§§version§§)"],
            "filecontent-require-string": [" jQuery Mobile"],
            "hashes": {}
        }
    },

    "jquery-ui": {
        "name": "jQuery UI",
        "currentVersion": "1.13.1",
        "website": ["https://jqueryui.com/"],
        "curvers_extractor": "/<h2>Download jQuery UI ([0-9a-z\\.]+)<\\/h2>/",
        "vulnerabilities": [
            {
                "atOrAbove": "1.0.0",
                "below": "1.13.0",
                "severity": "medium",
                "identifiers": {
                    "CVE": ["CVE-2021-41184"] ,
                    "summary": "XSS in the 'of' option of the '.position()' util"
                },
                "info": ["https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/", "https://github.com/jquery/jquery-ui/security/advisories/GHSA-gpqq-952q-5327"]
            }],
        "extractors": {
            "filename": ["jquery-ui-(§§version§§)(\\.min)?\\.js"],
            "uri": ["/jquery/ui/(§§version§§)/jquery-ui(\\.min)?\\.js", "/jquery-ui/(§§version§§)/jquery-ui(\\.min)?\\.js"],
            "filecontent": [
                "/\\*!? jQuery UI - v(§§version§§)",
                "/\\*!?[\n *]+jQuery UI (§§version§§)"
            ],

            "filecontent-require-string": ["jQuery UI "],
            "hashes": {}
        }
    },

    "jquery-ui-dialog": {
        "name": "jQuery UI Dialog",
        "currentVersion": "1.13.1",
        "website": ["https://jqueryui.com/download/"],
        "vulnerabilities": [{
            "atOrAbove": "1.8.9",
            "below": "1.10.0",
            "severity": "medium",
            "identifiers": {
                "bug": "6016",
                "CVE": ["CVE-2010-5312"],
                "summary": "Title cross-site scripting vulnerability"
            },

            "info": ["http://bugs.jqueryui.com/ticket/6016"]
        },

            {
                "atOrAbove": "1.0.0",
                "below": "1.12.0",
                "severity": "medium",
                "identifiers": {
                    "CVE": ["CVE-2016-7103"],
                    "summary": "XSS in dialog closeText"
                },

                "info": ["https://nodesecurity.io/advisories/127", "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7103", "https://www.cvedetails.com/cve/CVE-2016-7103/"]
            }
        ],

        "extractors": {
            "func": ["jQuery.ui.dialog.version"],
            "filename": ["jquery-ui-(§§version§§)(\\.min)?\\.js"],
            "uri": ["/jquery/ui/(§§version§§)/jquery-ui(\\.min)?\\.js", "/jquery-ui/(§§version§§)/jquery-ui(\\.min)?\\.js"],
            "filecontent": [
                "/\\*!? jQuery UI - v(§§version§§)(.*\n){1,}.*ui\\.dialog",
                "/\\*!?[\n *]+jQuery UI (§§version§§)(.*\n)*.*\\.ui\\.dialog",
                "/\\*!?[\n *]+jQuery UI Dialog (§§version§§)"
            ],

            "filecontent-require-string": ["jQuery UI "],
            "hashes": {}
        }
    },

    "jquery-ui-tooltip": {
        "name": "jQuery UI Tooltip",
        "currentVersion": "1.13.1",
        "website": ["https://jqueryui.com/download/"],
        "vulnerabilities": [{
            "atOrAbove": "1.9.2",
            "below": "1.10.0",
            "severity": "high",
            "identifiers": {
                "bug": "8859",
                "CVE": ["CVE-2012-6662"],
                "summary": "Autocomplete cross-site scripting vulnerability"
            },

            "info": ["http://bugs.jqueryui.com/ticket/8859"]
        }],

        "extractors": {
            "func": ["jQuery.ui.tooltip.version"],
            "uri": ["/jquery/ui/(§§version§§)/jquery-ui(\\.min)?\\.js", "/jquery-ui/(§§version§§)/jquery-ui(\\.min)?\\.js"],

            "filecontent": [
                "/\\*!? jQuery UI - v(§§version§§)(.*\n){1,3}.*ui\\.tooltip",
                "/\\*!?[\n *]+jQuery UI (§§version§§)(.*\n)*.*\\.ui\\.tooltip",
                "/\\*!?[\n *]+jQuery UI Tooltip (§§version§§)",
                "\\.widget\\(\"ui\\.tooltip\",\\{version:\"([0-9\\.]+)\","
            ],

            "filecontent-require-string": ["jQuery UI "],
            "hashes": {}
        }
    },

    "jquery-ui-datepicker": {
        "name": "jQuery UI Datepicker",
        "currentVersion": "1.13.1",
        "website": ["https://jqueryui.com/download/"],
        "vulnerabilities": [
            {
                "atOrAbove": "1.0.0",
                "below": "1.13.0",
                "severity": "medium",
                "identifiers": {
                    "CVE": ["CVE-2021-41182"],
                    "summary": "XSS in the 'altField' option of the Datepicker widget"
                },
                "info": ["https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/", "https://github.com/jquery/jquery-ui/security/advisories/GHSA-9gj3-hwp5-pmwc"]
            },
            {
                "atOrAbove": "1.0.0",
                "below": "1.13.0",
                "severity": "medium",
                "identifiers": {
                    "CVE": ["CVE-2021-41183"],
                    "summary": "XSS in '*Text' options of the Datepicker widget"
                },
                "info": ["https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/", "https://github.com/jquery/jquery-ui/security/advisories/GHSA-j7qv-pgf6-hvh4"]
            }],

        "extractors": {
            "func": ["jQuery.ui.datepicker.version"],
            "uri": ["/jquery/ui/(§§version§§)/jquery-ui(\\.min)?\\.js", "/jquery-ui/(§§version§§)/jquery-ui(\\.min)?\\.js"],

            "filecontent": [
                "/\\*!? jQuery UI - v(§§version§§)(.*\n){1,3}.*ui\\.datepicker",
                "/\\*!?[\n *]+jQuery UI (§§version§§)(.*\n)*.*\\.ui\\.datepicker",
                "/\\*!?[\n *]+jQuery UI Datepicker (§§version§§)",
                "\\.widget\\(\"ui\\.datepicker\",\\{version:\"([0-9\\.]+)\","
            ],

            "filecontent-require-string": ["jQuery UI "],
            "hashes": {}
        }
    },

    "jquery.prettyPhoto": {
        "name": "jQuery prettyPhoto",
        "currentVersion": "3.1.6",
        "website": ["http://www.no-margin-for-errors.com/projects/prettyphoto-jquery-lightbox-clone/"],
        "vulnerabilities": [{
            "below": "3.1.5",
            "severity": "high",
            "identifiers": { "CVE": ["CVE-2013-6837"], "summary": "Cross-site scripting (XSS) vulnerability in the setTimeout function in js/jquery.prettyPhoto.js in prettyPhoto 3.1.4 and earlier allows remote attackers to inject arbitrary web script or HTML via a crafted PATH_INTO to the default URI." },
            "info": ["http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-6837&cid=3"]
        },

            {
                "below": "3.1.6",
                "severity": "high",
                "identifiers": { "summary": "DOM XSS" },
                "info": ["https://github.com/scaron/prettyphoto/issues/149", "https://blog.anantshri.info/forgotten_disclosure_dom_xss_prettyphoto"]
            }
        ],

        "extractors": {
            "func": ["jQuery.prettyPhoto.version"],
            "filecontent": [
                "Class: prettyPhoto(?:\\s+[a-zA-Z0-9\\ ]+:.*)*(?:\\s+Version:[\\ ]?(§§version§§))",
                "\\.prettyPhoto[ ]?=[ ]?\\{version:[ ]?(?:'|\")(§§version§§)(?:'|\")\\}"
            ],

            "filecontent-require-string": ["prettyPhoto"],
            "filecontent-truncate-at": 3072,
            "hashes": {}
        }
    },

    "jplayer": {
        "name": "jPlayer",
        "currentVersion": "2.9.2",
        "website": ["https://github.com/jplayer/jPlayer/releases"],
        "vulnerabilities": [{
            "below": "2.4.0",
            "severity": "high",
            "identifiers": { "CVE": ["CVE-2013-2023"], "summary": "Cross-site scripting (XSS) vulnerability in actionscript/Jplayer.as in the Flash SWF component (jplayer.swf) in jPlayer allows remote attackers to inject arbitrary web script or HTML via unspecified vectors." },
            "info": ["http://jplayer.org/latest/release-notes/", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2023"]
        },

            {
                "below": "2.3.0",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2013-1942", "CVE-2013-2022"], "summary": "Multiple cross-site scripting (XSS) vulnerabilities in actionscript/Jplayer.as in the Flash SWF component (jplayer.swf) in jPlayer allow remote attackers to inject arbitrary web script or HTML via the (1) jQuery or (2) id parameters." },
                "info": ["http://jplayer.org/latest/release-notes/", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1942", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2022"]
            },

            {
                "below": "2.2.0",
                "severity": "high",
                "identifiers": {
                    "release": "2.2.0",
                    "summary": "Flash SWF vulnerability"
                },

                "info": ["http://jplayer.org/latest/release-notes/"]
            }
        ],

        "extractors": {
            "func": ["new jQuery.jPlayer().version.script"],
            "uri": ["/jplayer/jPlayer-(§§version§§)/.*jquery.jplayer(\\.min)?\\.js", "/jPlayer/jPlayer-(§§version§§)/.*jquery.jplayer(\\.min)?\\.js"],
            "filecontent": [
                "jPlayer Plugin[\\s\\S]+Version: (§§version§§)",
                "Version: ([0-9a-z\\.]+)[\\s]+Documentation: www\\.happyworm\\.com\\/jquery\\/jplayer\\s"
            ],

            "filecontent-require-string": ["jPlayer Plugin for jQuery"],
            "filecontent-truncate-at": 512,
            "hashes": {}
        }
    },

    "sessvars": {
        "name": "sessvars",
        "currentVersion": "",
        "website": ["http://www.thomasfrank.se/sessionvars.html"],
        "vulnerabilities": [{
            "below": "1.01",
            "severity": "low",
            "identifiers": { "summary": "Unsanitized data passed to eval()" },
            "info": ["https://web.archive.org/web/20131126051208/http://www.thomasfrank.se/sessionvars.html"]
        }],

        "extractors": {
            "filename": ["sessvars-(§§version§§)(.min)?\\.js"],
            "filecontent": ["sessvars ver (§§version§§)"],
            "hashes": {}
        }
    },

    "swfobject": {
        "name": "swfobject",
        "currentVersion": "",
        "website": ["https://code.google.com/p/swfobject/"],
        "vulnerabilities": [{
            "below": "2.1",
            "severity": "medium",
            "identifiers": { "summary": "DOM-based XSS" },
            "info": ["https://code.google.com/p/swfobject/wiki/release_notes", "https://code.google.com/p/swfobject/source/detail?r=181"]
        }],

        "extractors": {
            "filename": ["swfobject_(§§version§§)(.min)?\\.js"],
            "filecontent": ["SWFObject v(§§version§§) "],
            "hashes": {}
        }
    },

    "YUI": {
        "name": "YUI",
        "currentVersion": "3.18.1",
        "website": ["https://yuilibrary.com/"],
        "vulnerabilities": [{
            "atOrAbove": "3.5.0",
            "below": "3.9.2",
            "severity": "high",
            "identifiers": { "CVE": ["CVE-2013-4942"], "summary": "Cross-site scripting (XSS) vulnerability in flashuploader.swf in the Uploader component" },
            "info": ["http://www.cvedetails.com/cve/CVE-2013-4942/"]
        },

            {
                "atOrAbove": "3.2.0",
                "below": "3.9.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2013-4941"], "summary": "Cross-site scripting (XSS) vulnerability in uploader.swf" },
                "info": ["http://www.cvedetails.com/cve/CVE-2013-4941/"]
            },

            {
                "below": "3.10.3",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2013-4940"], "summary": "Cross-site scripting (XSS) vulnerability in io.swf " },
                "info": ["http://www.cvedetails.com/cve/CVE-2013-4940/"]
            },

            {
                "atOrAbove": "3.0.0",
                "below": "3.9.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2013-4939"], "summary": "Cross-site scripting (XSS) vulnerability in io.swf " },
                "info": ["http://www.cvedetails.com/cve/CVE-2013-4939/"]
            },

            {
                "atOrAbove": "2.8.0",
                "below": "2.9.1",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2012-5883"], "summary": "Cross-site scripting (XSS) vulnerability in the Flash component infrastructure in YUI 2.8.0 through 2.9.0 " },
                "info": ["http://www.cvedetails.com/cve/CVE-2012-5883/"]
            },

            {
                "atOrAbove": "2.5.0",
                "below": "2.9.1",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2012-5882"], "summary": "Cross-site scripting (XSS) vulnerability in the Flash component infrastructure in YUI 2.5.0 through 2.9.0 " },
                "info": ["http://www.cvedetails.com/cve/CVE-2012-5882/"]
            },

            {
                "atOrAbove": "2.4.0",
                "below": "2.9.1",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2012-5881"], "summary": "TCross-site scripting (XSS) vulnerability in the Flash component infrastructure in YUI 2.4.0 through 2.9.0 " },
                "info": ["http://www.cvedetails.com/cve/CVE-2012-5881/"]
            },

            {
                "below": "2.9.0",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2010-4710"], "summary": "Cross-site scripting (XSS) vulnerability in the addItem method in the Menu widget " },
                "info": ["http://www.cvedetails.com/cve/CVE-2010-4710/"]
            },

            {
                "atOrAbove": "2.8.0",
                "below": "2.8.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2010-4209"], "summary": "Cross-site scripting (XSS) vulnerability in the Flash component infrastructure in YUI 2.8.0 through 2.8.1" },
                "info": ["http://www.cvedetails.com/cve/CVE-2010-4209/"]
            },

            {
                "atOrAbove": "2.5.0",
                "below": "2.8.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2010-4208"], "summary": "Cross-site scripting (XSS) vulnerability in the Flash component infrastructure in YUI 2.5.0 through 2.8.1" },
                "info": ["http://www.cvedetails.com/cve/CVE-2010-4208/"]
            },

            {
                "atOrAbove": "2.4.0",
                "below": "2.8.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2010-4207"], "summary": "Cross-site scripting (XSS) vulnerability in the Flash component infrastructure in YUI 2.4.0 through 2.8.1" },
                "info": ["http://www.cvedetails.com/cve/CVE-2010-4207/"]
            }
        ],

        "extractors": {
            "func": ["YUI.Version"],
            "filename": ["yui-(§§version§§)(.min)?\\.js"],
            "filecontent": ["\\/\\*[\\s]+YUI (§§version§§)", "/yui/license.(?:html|txt)\nversion: (§§version§§)"],
            "filecontent-require-string": ["YUI", "/yui/license."],
            "hashes": {}
        }
    },

    "prototypejs": {
        "name": "Prototype",
        "currentVersion": "1.7.3",
        "website": ["http://prototypejs.org/download/"],
        "vulnerabilities": [{
            "atOrAbove": "1.6.0",
            "below": "1.6.0.2",
            "severity": "high",
            "identifiers": { "CVE": ["CVE-2008-7220"], "summary": "Unspecified vulnerability in Prototype JavaScript framework (prototypejs) before 1.6.0.2 allows attackers to make cross-site ajax requests via unknown vectors." },
            "info": ["http://www.cvedetails.com/cve/CVE-2008-7220/"]
        },
            {
                "below": "1.5.1.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2008-7220"], "summary": "Unspecified vulnerability in Prototype JavaScript framework (prototypejs) before 1.6.0.2 allows attackers to make cross-site ajax requests via unknown vectors." },
                "info": ["http://www.cvedetails.com/cve/CVE-2008-7220/"]
            }
        ],

        "extractors": {
            "func": ["Prototype.Version"],
            "uri": ["/(§§version§§)/prototype(\\.min)?\\.js"],
            "filename": ["prototype-(§§version§§)(.min)?\\.js"],
            "filecontent": ["Prototype JavaScript framework, version (§§version§§)",
                "Prototype[ ]?=[ ]?\\{[ \r\n\t]*Version:[ ]?(?:'|\")(§§version§§)(?:'|\")"
            ],
            "hashes": {}
        }
    },

    "ember": {
        "name": "EmberJS",
        "currentVersion": {"highest" : "4.3.0", "alternatives" : ["3.28.9"]},
        "website": ["https://github.com/emberjs/ember.js/releases/"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "vulnerabilities": [{
            "below": "1.5.0",
            "severity": "medium",
            "identifiers": {
                "CVE": ["CVE-2014-0046"],
                "summary": "ember-routing-auto-location can be forced to redirect to another domain"
            },

            "info": ["https://github.com/emberjs/ember.js/blob/v1.5.0/CHANGELOG.md"]
        },

            {
                "atOrAbove": "1.3.0-*",
                "below": "1.3.2",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2014-0046"], "summary": "Cross-site scripting (XSS) vulnerability in the link-to helper in Ember.js " },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/1h6FRgr8lXQ"]
            },

            {
                "atOrAbove": "1.2.0-*",
                "below": "1.2.2",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2014-0046"], "summary": "Cross-site scripting (XSS) vulnerability in the link-to helper in Ember.js " },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/1h6FRgr8lXQ"]
            },
            {
                "atOrAbove": "1.4.0-*",
                "below": "1.4.0-beta.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2014-0013", "CVE-2014-0014"], "summary": "Cross-site scripting (XSS) " },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"]
            },

            {
                "atOrAbove": "1.3.0-*",
                "below": "1.3.1",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2014-0013", "CVE-2014-0014"], "summary": "Cross-site scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"]
            },

            {
                "atOrAbove": "1.2.0-*",
                "below": "1.2.1",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2014-0013", "CVE-2014-0014"], "summary": "Cross-site scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"]
            },

            {
                "atOrAbove": "1.1.0-*",
                "below": "1.1.3",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2014-0013", "CVE-2014-0014"], "summary": "Cross-site scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"]
            },

            {
                "atOrAbove": "1.0.0-*",
                "below": "1.0.1",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2014-0013", "CVE-2014-0014"], "summary": "Cross-site scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4", "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"]
            },

            {
                "atOrAbove": "1.0.0-rc.1",
                "below": "1.0.0-rc.1.1",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2013-4170"], "summary": "Cross-site Scripting (XSS) " },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"]
            },

            {
                "atOrAbove": "1.0.0-rc.2",
                "below": "1.0.0-rc.2.1",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2013-4170"], "summary": "Cross-site Scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"]
            },

            {
                "atOrAbove": "1.0.0-rc.3",
                "below": "1.0.0-rc.3.1",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2013-4170"], "summary": "Cross-site Scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"]
            },

            {
                "atOrAbove": "1.0.0-rc.4",
                "below": "1.0.0-rc.4.1",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2013-4170"], "summary": "Cross-site Scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"]
            },

            {
                "atOrAbove": "1.0.0-rc.5",
                "below": "1.0.0-rc.5.1",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2013-4170"], "summary": "Cross-site Scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"]
            },

            {
                "atOrAbove": "1.0.0-rc.6",
                "below": "1.0.0-rc.6.1",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2013-4170"], "summary": "Cross-site Scripting (XSS)" },
                "info": ["https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"]
            },

            {
                "below": "0.9.7.1",
                "info": ["https://github.com/emberjs/ember.js/blob/master/CHANGELOG"]
            },

            {
                "below": "0.9.7",
                "severity": "high",
                "identifiers": {
                    "bug": "699",
                    "summary": "Bound attributes insecurely escaped."
                },

                "info": ["https://github.com/emberjs/ember.js/issues/699"]
            }
        ],

        "extractors": {
            "func": ["Ember.VERSION"],
            "uri": ["/(?:v)?(§§version§§)/ember(\\.min)?\\.js"],
            "filename": ["ember-(§§version§§)(\\.min)?\\.js"],
            "filecontent": [
                "Project:   Ember -(?:.*\n){9,11}// Version: v(§§version§§)",
                "// Version: v(§§version§§)(.*\n){10,15}(Ember Debug|@module ember|@class ember)",
                "Ember.VERSION[ ]?=[ ]?(?:'|\")(§§version§§)(?:'|\")"
            ],

            "hashes": {}
        }
    },

    "dojo": {
        "name": "Dojo Toolkit",
        "currentVersion": "1.16",
        "website": ["https://dojotoolkit.org/"],
        "vulnerabilities": [{
            "atOrAbove": "0.4",
            "below": "0.4.4",
            "severity": "high",
            "identifiers": { "CVE": ["CVE-2010-2276", "CVE-2010-2272"], "summary": "Unspecified vulnerability in iframe_history.html" },
            "info": ["http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2272/"]
        },

            {
                "atOrAbove": "1.0",
                "below": "1.0.3",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"], "summary": "Unspecified vulnerability in iframe_history.html" },
                "info": ["http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/"]
            },

            {
                "atOrAbove": "1.1",
                "below": "1.1.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"], "summary": "Unspecified vulnerability in iframe_history.html" },
                "info": ["http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/"]
            },

            {
                "atOrAbove": "1.2",
                "below": "1.2.4",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"], "summary": "Unspecified vulnerability in iframe_history.html" },
                "info": ["http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/"]
            },

            {
                "atOrAbove": "1.3",
                "below": "1.3.3",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"], "summary": "Unspecified vulnerability in iframe_history.html" },
                "info": ["http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/"]
            },

            {
                "atOrAbove": "1.4",
                "below": "1.4.2",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2010-2276", "CVE-2010-2274", "CVE-2010-2273"], "summary": "Unspecified vulnerability in iframe_history.html" },
                "info": ["http://dojotoolkit.org/blog/dojo-security-advisory", "http://www.cvedetails.com/cve/CVE-2010-2276/", "http://www.cvedetails.com/cve/CVE-2010-2274/", "http://www.cvedetails.com/cve/CVE-2010-2273/"]
            },

            {
                "below": "1.4.2",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2010-2275"], "summary": "Cross-site scripting (XSS) vulnerability in dijit/tests/_testCommon.js " },
                "info": ["http://www.cvedetails.com/cve/CVE-2010-2275/"]
            },

            {
                "below": "1.1",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2008-6681"], "summary": "Cross-site scripting (XSS) vulnerability in dijit.Editor " },
                "info": ["http://www.cvedetails.com/cve/CVE-2008-6681/"]
            },
            {
                "below" : "1.14",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2018-15494"], "summary": "unescaped string injection in dojox/Grid/DataGrid." },
                "info" : [ "https://dojotoolkit.org/blog/dojo-1-14-released" ]
            }
        ],

        "extractors": {
            "func": ["dojo.version.toString()"],
            "uri": ["/(?:dojo-)?(§§version§§)/dojo(\\.min)?\\.js"],
            "filename": ["dojo-(§§version§§)(\\.min)?\\.js"],
            "filecontentreplace": ["/dojo.version=\\{major:([0-9]+),minor:([0-9]+),patch:([0-9]+)/$1.$2.$3/"],
            "hashes": {
                "73cdd262799aab850abbe694cd3bfb709ea23627": "1.4.1",
                "c8c84eddc732c3cbf370764836a7712f3f873326": "1.4.0",
                "d569ce9efb7edaedaec8ca9491aab0c656f7c8f0": "1.0.0",
                "ad44e1770895b7fa84aff5a56a0f99b855a83769": "1.3.2",
                "8fc10142a06966a8709cd9b8732f7b6db88d0c34": "1.3.1",
                "a09b5851a0a3e9d81353745a4663741238ee1b84": "1.3.0",
                "2ab48d45abe2f54cdda6ca32193b5ceb2b1bc25d": "1.2.3",
                "12208a1e649402e362f528f6aae2c614fc697f8f": "1.2.0",
                "72a6a9fbef9fa5a73cd47e49942199147f905206": "1.1.1"
            }
        }
    },

    "angularjs": {
        "name": "AngularJS",
        "currentVersion": "1.8.2",
        "website": ["https://code.angularjs.org/"],
        "curvers_extractor": "<a href=\"([0-9\\.]{3,})\\/\">",
        "vulnerabilities": [{
            "below": "1.2.0",
            "severity": "high",
            "identifiers": {
                "summary": [
                    "execution of arbitrary javascript",
                    "sandboxing fails",
                    "possible cross-site scripting vulnerabilities"
                ]
            },

            "info": ["https://code.google.com/p/mustache-security/wiki/AngularJS"]
        },

            {
                "below": "1.2.19",
                "severity": "medium",
                "identifiers": {
                    "release": "1.3.0-beta.14",
                    "summary": "execution of arbitrary javascript"
                },

                "info": ["https://github.com/angular/angular.js/blob/b3b5015cb7919708ce179dc3d6f0d7d7f43ef621/CHANGELOG.md"]
            },

            {
                "below": "1.2.24",
                "severity": "medium",
                "identifiers": {
                    "commit": "b39e1d47b9a1b39a9fe34c847a81f589fba522f8",
                    "summary": "execution of arbitrary javascript"
                },

                "info": ["http://avlidienbrunn.se/angular.txt", "https://github.com/angular/angular.js/commit/b39e1d47b9a1b39a9fe34c847a81f589fba522f8"]
            },

            {
                "atOrAbove": "1.3.0-beta.1",
                "below": "1.3.0-beta.14",
                "severity": "medium",
                "identifiers": {
                    "commit": "b39e1d47b9a1b39a9fe34c847a81f589fba522f8",
                    "summary": "execution of arbitrary javascript"
                },

                "info": ["https://github.com/angular/angular.js/blob/b3b5015cb7919708ce179dc3d6f0d7d7f43ef621/CHANGELOG.md"]
            },

            {
                "atOrAbove": "1.3.0-beta.1",
                "below": "1.3.0-rc.1",
                "severity": "medium",
                "identifiers": {
                    "commit": "b39e1d47b9a1b39a9fe34c847a81f589fba522f8",
                    "summary": "execution of arbitrary javascript"
                },

                "info": ["http://avlidienbrunn.se/angular.txt", "https://github.com/angular/angular.js/commit/b39e1d47b9a1b39a9fe34c847a81f589fba522f8"]
            },

            {
                "atOrAbove": "1.3.0",
                "below": "1.3.2",
                "severity": "low",
                "identifiers": {
                    "summary": "server-side xss can bypass CSP"
                },

                "info": ["https://github.com/angular/angular.js/blob/master/CHANGELOG.md"]
            },
            {
                "below" : "1.7.9",
                "severity": "medium",
                "identifiers": {
                    "summary": "Prototype pollution"
                },
                "info" : [ "https://github.com/angular/angular.js/commit/726f49dcf6c23106ddaf5cfd5e2e592841db743a", "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#179-pollution-eradication-2019-11-19" ]
            },
            {
                "below" : "1.8.0",
                "severity": "medium",
                "identifiers": {
                    "summary": "Cross-Site Scripting.",
                    "CVE": [ "CVE-2020-7676" ]
                },
                "info" : [ "https://nvd.nist.gov/vuln/detail/CVE-2020-7676" ]
            }
        ],

        "extractors": {
            "func": ["angular.version.full"],
            "uri": ["/(§§version§§)/angular(\\.min)?\\.js"],
            "filename": ["angular(?:js)?-(§§version§§)(.min)?\\.js"],
            "filecontent": [
                "/\\*[ \n]+AngularJS v(§§version§§)",
                "http://errors.angularjs.org/(§§version§§)/"
            ],

            "hashes": {}
        }
    },

    "backbone.js": {
        "name": "Backbone.js",
        "currentVersion": "1.4.0",
        "website": ["https://backbonejs.org/#changelog"],
        "vulnerabilities": [{
            "below": "0.5.0",
            "severity": "medium",
            "identifiers": {
                "release": "0.5.0",
                "summary": "cross-site scripting vulnerability"
            },

            "info": ["http://backbonejs.org/#changelog"]
        }],

        "extractors": {
            "func": ["Backbone.VERSION"],
            "uri": ["/(§§version§§)/backbone(\\.min)?\\.js"],
            "filename": ["backbone(?:js)?-(§§version§§)(.min)?\\.js"],
            "filecontent": ["//[ ]+Backbone.js (§§version§§)", "a=t.Backbone={}}a.VERSION=\"(§§version§§)\""],
            "hashes": {}
        }
    },

    "mustache.js": {
        "name": "mustache.js",
        "currentVersion": "4.2.0",
        "website": ["https://github.com/janl/mustache.js/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "vulnerabilities": [{
            "below": "0.3.1",
            "severity": "high",
            "identifiers": {
                "bug": "112",
                "summary": "execution of arbitrary javascript"
            },

            "info": ["https://github.com/janl/mustache.js/issues/112"]
        }],
        "extractors": {
            "func": ["Mustache.version"],
            "uri": ["/(§§version§§)/mustache(\\.min)?\\.js"],
            "filename": ["mustache(?:js)?-(§§version§§)(.min)?\\.js"],
            "filecontent": ["name:\"mustache.js\",version:\"(§§version§§)\"",
                "[^a-z]mustache.version[ ]?=[ ]?(?:'|\")(§§version§§)(?:'|\")",
                "exports.name[ ]?=[ ]?\"mustache.js\";[\n ]*exports.version[ ]?=[ ]?(?:'|\")(§§version§§)(?:'|\");"
            ],

            "filecontent-require-string": ["mustache"],
            "hashes": {}
        }
    },

    "handlebars.js": {
        "name": "handlebars.js",
        "currentVersion": "4.7.7",
        "website": ["https://github.com/handlebars-lang/handlebars.js/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "vulnerabilities": [{
            "below": "1.0.0.beta.3",
            "severity": "medium",
            "identifiers": {
                "summary": "insufficiently sanitized input passed to eval()"
            },

            "info": ["https://github.com/wycats/handlebars.js/pull/68"]
        },
            {
                "below" : "4.3.0",
                "severity": "low",
                "identifiers": {
                    "summary": "Unsafe direct call of helperMissing and blockHelperMissing"
                },
                "info" : [
                    "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v430---september-24th-2019"
                ]
            },
            {
                "below" : "4.5.3",
                "severity": "medium",
                "identifiers": {
                    "summary": "Prototype pollution"
                },
                "info" : [
                    "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v453---november-18th-2019"
                ]
            }
        ],
        "extractors": {
            "func": ["Handlebars.VERSION"],
            "uri": ["/(§§version§§)/handlebars(\\.min)?\\.js"],
            "filename": ["handlebars(?:js)?-(§§version§§)(.min)?\\.js"],
            "filecontent": ["Handlebars.VERSION = \"(§§version§§)\";",
                            "Handlebars=\\{VERSION:(?:'|\")(§§version§§)(?:'|\")",
                            "this.Handlebars=\\{\\};[\n\r \t]+\\(function\\([a-z]\\)\\{[a-z].VERSION=(?:'|\")(§§version§§)(?:'|\")",
                            "/\\*+![\\s]+(?:@license)?[\\s]+handlebars v(§§version§§)"
            ],

            "hashes": {}
        }
    },

    "easyXDM": {
        "name": "easyXDM",
        "currentVersion": "2.5.0",
        "website": ["https://github.com/oyvindkinsey/easyXDM/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "vulnerabilities": [{
            "below": "2.4.18",
            "severity": "high",
            "identifiers": { "CVE": ["CVE-2013-5212"], "summary": "Cross-site Scripting (XSS) via easyxdm.swf" },
            "info": ["http://blog.kotowicz.net/2013/09/exploiting-easyxdm-part-1-not-usual.html", "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-5212"]
        },

            {
                "below": "2.4.19",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2014-1403"], "summary": "Cross-site scripting (XSS) vulnerability in name.html " },
                "info": ["http://blog.kotowicz.net/2014/01/xssing-with-shakespeare-name-calling.html", "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1403"]
            }
        ],

        "extractors": {
            "uri": ["/(easyXDM-)?(§§version§§)/easyXDM(\\.min)?\\.js"],
            "filename": ["easyXDM-(§§version§§)(.min)?\\.js"],
            "filecontent": [" \\* easyXDM\n \\* http://easyxdm.net/(?:\r|\n|.)+version:\"(§§version§§)\"",
                "@class easyXDM(?:.|\r|\n)+@version (§§version§§)(\r|\n)"
            ],
            "hashes": { "cf266e3bc2da372c4f0d6b2bd87bcbaa24d5a643": "2.4.6" }
        }
    },

    "plupload": {
        "name": "plupload",
        "currentVersion": "3.1.5",
        "website": ["https://github.com/moxiecode/plupload/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "vulnerabilities": [{
            "below": "1.5.4",
            "severity": "high",
            "identifiers": { "CVE": ["CVE-2012-2401"], "summary": "Same Origin Policy bypass" },
            "info": ["http://www.cvedetails.com/cve/CVE-2012-2401/"]
        },

            {
                "below": "1.5.5",
                "severity": "high",
                "identifiers": { "CVE": ["CVE-2013-0237"], "summary": "Cross-site scripting (XSS) vulnerability in Plupload.as " },
                "info": ["http://www.cvedetails.com/cve/CVE-2013-0237/"]
            }
        ],

        "extractors": {
            "func": ["plupload.VERSION"],
            "uri": ["/(§§version§§)/plupload(\\.min)?\\.js"],
            "filename": ["plupload-(§§version§§)(.min)?\\.js"],
            "filecontent": ["\\* Plupload - multi-runtime File Uploader(\r|\n)+ \\* v§§version§§",
                "var g=\\{VERSION:\"§§version§§\",.*;window.plupload=g\\}"
            ],

            "hashes": {}
        }
    },

    "DOMPurify": {
        "name": "DOMPurify",
        "currentVersion": "2.3.6",
        "website": ["https://github.com/cure53/DOMPurify/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "vulnerabilities": [{
            "below": "0.6.1",
            "severity": "medium",
            "identifiers": {"summary": "Unspecified security issues "},
            "info": ["https://github.com/cure53/DOMPurify/releases/tag/0.6.1"]
        },
            {
                "below" : "2.2.0",
                "severity": "low",
                "identifiers": { "summary": "Possible XSS" },
                "info" : [ "https://github.com/cure53/DOMPurify/releases" ]
            },
            {
                "below" : "2.2.2",
                "severity": "low",
                "identifiers": { "summary": "mXSS bypass and mXSS variation" },
                "info" : [ "https://github.com/cure53/DOMPurify/releases" ]
            },
            {
                "below" : "2.2.3",
                "severity": "low",
                "identifiers": { "summary": "mXSS" },
                "info" : [ "https://github.com/cure53/DOMPurify/releases" ]
            },
            {
                "below" : "2.2.4",
                "severity": "low",
                "identifiers": { "summary": "MathML-based bypass, SVG-related bypass" },
                "info" : [ "https://github.com/cure53/DOMPurify/releases" ]
            }],

        "extractors": {
            "func": ["DOMPurify.version"],
            "filecontent": ["DOMPurify.version = '§§version§§';"],
            "hashes": {}
        }
    },

    "moment.js": {
        "name": "moment.js",
        "currentVersion": "2.29.3",
        "website": ["https://github.com/moment/moment/tags"],
        "curvers_extractor": "<a href=\"\\/.*?\\/.*?\\/releases\\/tag\\/([0-9\\.]{3,})\">",
        "vulnerabilities": [{
            "below": "2.11.2",
            "severity": "medium",
            "identifiers": { "CVE": ["CVE-2016-4055"], "summary": "Denial of Service (DoS)" },
            "info": ["https://nodesecurity.io/advisories/55", "https://www.cvedetails.com/cve/CVE-2016-4055/", "https://github.com/moment/moment/issues/2936"]
        }],

        "extractors": {
            "filecontent": ["^\\/\\/!\\ moment\\.js[\\r|\\n][\\r|\\n]?\\/\\/!\\ version\\ :\\ (§§version§§)(\\r|\\n)"]
        }
    },

    "DWR": {
        "name": "DWR",
        "currentVersion": "",
        "website": [],
        "vulnerabilities": [
            {
                "below": "2.0.11",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2014-5326", "CVE-2014-5325"], "summary": "Cross-site scripting (XSS) / Read arbitrary files via DOM data containing an XML external entity declaration in conjunction with an entity reference" },
                "info": ["http://www.cvedetails.com/cve/CVE-2014-5326/", "http://www.cvedetails.com/cve/CVE-2014-5326/"]
            },

            {
                "above": "3",
                "below": "3.0.RC3",
                "severity": "medium",
                "identifiers": { "CVE": ["CVE-2014-5326", "CVE-2014-5325"], "summary": "Cross-site scripting (XSS) / Read arbitrary files via DOM data containing an XML external entity declaration in conjunction with an entity reference" },
                "info": ["http://www.cvedetails.com/cve/CVE-2014-5326/", "http://www.cvedetails.com/cve/CVE-2014-5326/"]
            }
        ],

        "extractors": {
            "func": ["dwr.version"],
            "filecontent": [
                " dwr-§§version§§.jar"
            ],

            "filecontent-require-string": ["dwr-"]
        }
    },

    "TinyMCE": {
        "name": "TinyMCE",
        "currentVersion": "6.0.2",
        "website": ["https://github.com/tinymce/tinymce/tags"],
        "curvers_extractor": "<a href=\"\\/.*?\\/.*?\\/releases\\/tag\\/([0-9\\.]{3,})\">",
        "vulnerabilities": [
            {
                "atOrAbove": "4",
                "below": "4.9.7",
                "severity": "medium",
                "identifiers": { "summary": "Cross-site scripting vulnerability in TinyMCE" },
                "info": ["https://github.com/tinymce/tinymce/security/advisories/GHSA-27gm-ghr9-4v95"]
            },
            {
                "atOrAbove": "5",
                "below": "5.1.4",
                "severity": "medium",
                "identifiers": { "summary": "Cross-site scripting vulnerability in TinyMCE" },
                "info": ["https://github.com/tinymce/tinymce/security/advisories/GHSA-27gm-ghr9-4v95"]
            },

            {
                "atOrAbove": "4",
                "below": "4.2.4",
                "severity": "medium",
                "identifiers": { "summary": "Cross-site scripting" },
                "info": ["https://github.com/tinymce/tinymce/blob/c68a5930512d7b37b5dc495bde5f7cbb739e11e7/changelog.txt"]
            },

            {
                "atOrAbove": "4",
                "below": "4.1.11",
                "severity": "medium",
                "identifiers": { "summary": "Cross-site scripting" },
                "info": ["https://github.com/tinymce/tinymce/blob/9c78e4a4f9aad14f3e86094b36f163177f38c248/changelog.txt"]
            },

            {
                "atOrAbove": "4",
                "below": "4.6.4",
                "severity": "medium",
                "identifiers": { "summary": "Cross-site scripting" },
                "info": ["https://github.com/tinymce/tinymce/blob/master/modules/tinymce/CHANGELOG.md"]
            },

            {
                "atOrAbove": "4",
                "below": "4.7.12",
                "severity": "medium",
                "identifiers": { "summary": "Cross-site scripting" },
                "info": ["https://github.com/tinymce/tinymce/blob/master/modules/tinymce/CHANGELOG.md"]
            },
            {
                "atOrAbove": "5",
                "below" : "5.1.6",
                "severity" : "medium",
                "identifiers": { "summary": "Cross-site scripting" },
                "info" : [ "https://www.tiny.cloud/docs/release-notes/release-notes516/#securityfixes" ]
            },
            {
                "atOrAbove": "5",
                "below" : "5.2.2",
                "severity" : "low",
                "identifiers": { "summary": "Media embed content not processing safely in some cases." },
                "info" : [ "https://www.tiny.cloud/docs/release-notes/release-notes522/#securityfixes" ]
            },
            {
                "atOrAbove": "5",
                "below" : "5.4.0",
                "severity" : "low",
                "identifiers": { "summary": "Content in an iframe element parsing as DOM elements instead of text content." },
                "info" : [ "https://www.tiny.cloud/docs/release-notes/release-notes54/#securityfixes" ]
            }

        ],

        "extractors": {
            "uri": ["\/tinymce\/tinymce_(§§version§§)_dev\/tinymce\/js\/tinymce\/"],
            "filecontent-require-string": ["TinyMCE"]
        }
    },
    "Video.js": {
        "name": "Video.js",
        "extractors": {
            "func": [ "videojs.VERSION" ],
            "urlpresignature": "/video.",
            "presignature": "videojs.",
            "uri": [ "/(§§version§§)/video(\\.min)?\\.js" ],
            "filecontent": [ "videojs.VERSION = '(§§version§§)';" ]
        }
    },
    "knockout.js": {
        "name": "knockout.js",
        "currentVersion": "3.5.1",
        "website": ["https://github.com/knockout/knockout/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "ko.version" ],
            "presignature": "knockout",
            "filename": [ "knockout-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "\\* Knockout JavaScript library v(§§version§§)" ]
        }
    },
    "bootstrap.js" : {
        "name": "bootstrap.js",
        "currentVersion": "4.6.1",
        "website": ["https://github.com/twbs/bootstrap/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "func": [ "$.fn.tooltip.Constructor.VERSION", "$.fn.alert.Constructor.VERSION", "$.fn.modal.Constructor.VERSION" ],
            "uri": [ "/(§§version§§)/bootstrap(\\.min)?\\.js", "/(§§version§§)/js/bootstrap(\\.min)?\\.js" ],
            "presignature": "Bootstrap",
            "filecontent": [ "\\* Bootstrap v(§§version§§)" ]
        }
    },
    "typeahead.js" : {
        "name": "typeahead.js",
        "currentVersion": "0.11.1",
        "website": ["https://github.com/twitter/typeahead.js/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "typeahead",
            "filecontent": [ "\\* typeahead.js (§§version§§)", "var VERSION = \"(§§version§§)\"" ]
        }
    },
    "FooTable" : {
        "name": "FooTable",
        "currentVersion": "3.1.6",
        "website": ["https://github.com/fooplugins/FooTable/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "footable",
            "filename": [ "footable-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "FooTable [\\s\\S]* @version (§§version§§)" ]
        }
    },
    "Sortable.js" : {
        "name": "Sortable.js",
        "currentVersion": "1.15.0",
        "website": ["https://github.com/SortableJS/Sortable/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "Sortable.version" ],
            "presignature": "Sortable",
            "filename": [ "Sortable-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "/\\*! Sortable (§§version§§)" ]
        }
    },
    "Image Picker" : {
        "name": "Image Picker",
        "currentVersion": "",
        "website": ["http://rvera.github.com/image-picker"],
        "extractors": {
            "urlpresignature": "image-picker",
            "filename": [ "image-picker-(§§version§§)(.min)?\\.js" ],
            "presignature": "// image picker",
            "filecontent": [ "// Image Picker[\\s\\S]*// Version (§§version§§)" ]
        }
    },
    "jQuery Validation" : {
        "name": "jQuery Validation",
        "currentVersion": "1.19.3",
        "website": ["https://github.com/jquery-validation/jquery-validation/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "urlpresignature": "jquery.validate-",
            "presignature": "jQuery Validation",
            "filename": [ "jquery.validate-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "\\*!? jQuery Validation Plugin -? ?v(§§version§§)" ]
        }
    },
    "ASP.NET SignalR" : {
        "name": "ASP.NET SignalR",
        "currentVersion": "1.1.4",
        "website": ["https://github.com/dotnet/aspnetcore/tree/master/src/SignalR"],
        "extractors": {
            "func": [ "$.signalR.version" ],
            "presignature": "signalR",
            "filename": [ "jquery.signalR-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "\\* ASP.NET SignalR JavaScript Library v(§§version§§)" ]
        }
    },
    "Select2" : {
        "name": "Select2",
        "currentVersion": "4.0.13",
        "website": ["https://github.com/select2/select2/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "select2",
            "filename": [ "select2-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "(?:(?:\\/\\*\\!)|(?:\\s\\*)) Select2 (§§version§§)" ]
        }
    },
    "html5shiv" : {
        "name": "html5shiv",
        "currentVersion": "3.7.3",
        "website": ["https://github.com/aFarkas/html5shiv/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "html5.version" ],
            "presignature": "shiv",
            "filename": [ "html5shiv-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "\\* @preserve HTML5 Shiv (§§version§§)" ]
        }
    },
    "Ion.RangeSlider" : {
        "name": "Ion.RangeSlider",
        "currentVersion": "2.3.1",
        "website": ["https://github.com/IonDen/ion.rangeSlider/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "jQuery('input').first().ionRangeSlider().data('ionRangeSlider').VERSION" ],
            "presignature": "ion.rangeSlider",
            "filename": [ "ion.rangeSlider-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "// Ion\\.RangeSlider[\\s\\S]*// version (§§version§§)", "// Ion\\.RangeSlider[\\s\\S]* \\| version (§§version§§)" ]
        }
    },
    "jsTree" : {
        "name": "jsTree",
        "currentVersion": "3.3.12",
        "website": ["https://github.com/vakata/jstree/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "$.jstree.version" ],
            "presignature": "jstree",
            "filename": [ "jstree-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "/\\*! jsTree - v(§§version§§)", " \\* jsTree (§§version§§)" ]
        }
    },
    "Modernizr" : {
        "name": "Modernizr",
        "currentVersion": "3.12.0",
        "website": ["https://github.com/Modernizr/Modernizr/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "func": [ "Modernizr._version" ],
            "presignature": "modernizr",
            "filename": [ "modernizr-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ " \\* modernizr v(§§version§§)", "/\\*! modernizr (§§version§§)" ]
        }
    },
    "Respond.js" : {
        "name": "Respond.js",
        "currentVersion": "1.4.2",
        "website": ["https://github.com/scottjehl/Respond/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": " Respond.js",
            "filecontent": [ "/\\*! Respond.js v(§§version§§)" ]
        }
    },
    "Fuel UX" : {
        "name": "Fuel UX",
        "currentVersion": "",
        "website": [],
        "extractors": {
            "presignature": "Fuel UX",
            "filename": [ "fuelux-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "\\/\\*\\![\\s]*? \\* Fuel UX v(§§version§§)" ]
        }
    },
    "Bootbox" : {
        "name": "Bootbox",
        "currentVersion": "5.5.3",
        "website": ["https://github.com/makeusabrew/bootbox/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "bootbox",
            "filename": [ "bootbox-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ " \\* bootbox.js \\[?v(§§version§§)\\]?" ]
        }
    },
    "Knockout Mapping" : {
        "name": "Knockout Mapping",
        "currentVersion": "2.4.1",
        "website": ["https://github.com/SteveSanderson/knockout.mapping/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "knockout",
            "filename": [ "knockout.mapping-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "// Knockout Mapping plugin v(§§version§§)" ]
        }
    },
    "jQuery Mask" : {
        "name": "jQuery Mask",
        "currentVersion": "1.14.16",
        "website": ["https://github.com/igorescobar/jQuery-Mask-Plugin/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "jquery.mask",
            "filename": [ "jquery.mask-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "/\\*\\*[\\s]*?\\* jquery\\.mask\\.js[\\s]*?\\* @version: v(§§version§§)" ]
        }
    },
    "Bootstrap 3 Date/Time Picker" : {
        "name": "Bootstrap 3 Date/Time Picker",
        "currentVersion": "4.17.49",
        "website": ["https://github.com/Eonasdan/bootstrap-datetimepicker/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "bootstrap-datetime",
            "filename": [ "bootstrap-datetimepicker-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "/\\*! version : (§§version§§)[\\s\\S]* bootstrap-datetimejs" ]
        }
    },
    "Bootstrap Toggle"  : {
        "name": "Bootstrap Toggle",
        "currentVersion": "2.2.2",
        "website": ["https://github.com/minhur/bootstrap-toggle/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "-toggle",
            "filename": [ "bootstrap2?-toggle-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "\\* Bootstrap Toggle: bootstrap2?-toggle\\.js v(§§version§§)" ]
        }
    },
    "JavaScript Cookie" : {
        "name": "JavaScript Cookie",
        "currentVersion": "3.0.1",
        "website": ["https://github.com/js-cookie/js-cookie/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "urlpresignature": "js.cookie-",
            "presignature": "js-cookie",
            "filename": [ "js.cookie-(§§version§§)(.min)?\\.js" ],
            "filecontent": [ "/\\*! js-cookie v(§§version§§)", "/\\*![\\s\\S]* \\* JavaScript Cookie v(§§version§§)" ]
        }
    },
    "React" : {
        "name": "React",
        "currentVersion": "18.1.0",
        "website": ["https://github.com/facebook/react/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "React.version" ],
            "presignature": "React v",
            "filecontent": [ "/\\*\\*[\\s\\S]*? React v(§§version§§)" ]
        }
    },
    "CKEditor" : {
        "name": "CKEditor",
        "currentVersion": "",
        "website": [],
        "extractors": {
            "func": [ "CKEDITOR.version" ],
            "presignature": ".version"
        }
    },
    "Zepto.js" : {
        "name": "Zepto.js",
        "currentVersion": "1.2.0",
        "website": ["https://github.com/madrobby/zepto/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Zepto v",
            "filecontent": [ "/\\* Zepto v(§§version§§)" ]
        }
    },
    "Hammer.JS" : {
        "name": "Hammer.JS",
        "currentVersion": "2.0.8",
        "website": ["https://github.com/hammerjs/hammer.js/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Hammer.JS",
            "filecontent": [ "/\\*! Hammer\\.JS - v(§§version§§)" ]
        }
    },
    "Vue.js" : {
        "name": "Vue.js",
        "currentVersion": "2.6.14",
        "website": ["https://github.com/vuejs/vue/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "func": [ "Vue.version" ],
            "presignature": "Vue.js",
            "filecontent": [ "/\\*![\\s\\S]* \\* Vue\\.js v(§§version§§)" ]
        }
    },
    "Phaser" : {
        "name": "Phaser",
        "currentVersion": "3.55.2",
        "website": ["https://github.com/photonstorm/phaser/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "Phaser.VERSION" ],
            "presignature": "Phaser",
            "filecontent": [ "/\\* Phaser v(§§version§§)" ]
        }
    },
    "Chart.js" : {
        "name": "Chart.js",
        "currentVersion": "3.7.1",
        "website": ["https://github.com/chartjs/Chart.js/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Chart.js",
            "filecontent": [ "/\\*![\\s\\S]* \\* Chart\\.js[\\s\\S]* \\* Version: (§§version§§)" ]
        }
    },
    "Ramda" : {
        "name": "Ramda",
        "currentVersion": "0.28.0",
        "website": ["https://github.com/ramda/ramda/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Ramda",
            "filecontent": [ "//  Ramda v(§§version§§)" ]
        }
    },
    "reveal.js" : {
        "name": "reveal.js",
        "currentVersion": "4.3.1",
        "website": ["https://github.com/hakimel/reveal.js/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "Reveal.VERSION" ],
            "presignature": "reveal.js"
        }
    },
    "PixiJS" : {
        "name": "PixiJS",
        "currentVersion": "6.3.0",
        "website": ["https://github.com/pixijs/pixi.js/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "pixi.js",
            "filecontent": [ "/\\*![\\s\\S]* \\* pixi.js - v(§§version§§)" ]
        }
    },
    "Fabric.js" : {
        "name": "Fabric.js",
        "currentVersion": "5.2.1",
        "website": ["https://github.com/fabricjs/fabric.js/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "fabric.version" ],
            "presignature": "fabric"
        }
    },
    "Semantic UI" : {
        "name": "Semantic UI",
        "currentVersion": "2.4.1",
        "website": ["https://github.com/Semantic-Org/Semantic-UI/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Semantic UI",
            "filecontent": [ "\\/\\*[\\s]*? \\* # Semantic UI - (§§version§§)" ]
        }
    },
    "Leaflet" : {
        "name": "Leaflet",
        "currentVersion": "1.8.0",
        "website": ["https://github.com/Leaflet/Leaflet/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Leaflet",
            "filecontent": [ "\\/\\*(?:\\s@preserve)?[\\s]+\\ \\* Leaflet (§§version§§)" ]
        }
    },
    "Foundation" : {
        "name": "Foundation",
        "currentVersion": "",
        "website": [],
        "extractors": {
            "func": [ "Foundation.version" ],
            "presignature": "foundation"
        }
    },
    "three.js" : {
        "name": "three.js",
        "currentVersion": "r140",
        "website": ["https://github.com/mrdoob/three.js/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "func": [ "THREE.REVISION" ],
            "presignature": "three"
        }
    },
    "PDF.js" : {
        "name": "PDF.js",
        "currentVersion": "2.13.216",
        "website": ["https://github.com/mozilla/pdf.js/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "func": [ "PDFJS.version" ],
            "presignature": "pdfjsVersion"
        }
    },
    "Intro.js" : {
        "name": "Intro.js",
        "currentVersion": "5.1.0",
        "website": ["https://github.com/usablica/intro.js/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "func": [ "introJs.version" ],
            "presignature": "introJs"
        }
    },
    "axios" : {
        "name": "axios",
        "currentVersion": "0.27.2",
        "website": ["https://github.com/axios/axios/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "axios",
            "filecontent": [ "/\\* axios v(§§version§§)" ]
        }
    },
    "Fingerprintjs2" : {
        "name": "Fingerprintjs2",
        "currentVersion": "3.3.3",
        "website": ["https://github.com/fingerprintjs/fingerprintjs2/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Fingerprint2",
            "func": [ "Fingerprint2.VERSION" ]
        }
    },
    "XRegExp" : {
        "name": "XRegExp",
        "currentVersion": "5.1.0",
        "website": ["https://github.com/slevithan/xregexp/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "XRegExp",
            "func": [ "XRegExp.version" ]
        }
    },
    "DataTables" : {
        "name": "DataTables",
        "currentVersion": "1.10.21",
        "website": ["https://github.com/DataTables/DataTables/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "DataTables",
            "func": [ "jQuery.fn.dataTable.version" ],
            "filecontent": [ "/\\*![\\s\\S]* DataTables (§§version§§)" ]
        }
    },
    "Lazy.js" : {
        "name": "Lazy.js",
        "currentVersion": "0.5.1",
        "website": ["https://github.com/dtao/lazy.js/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "lazy.js",
            "func": [ "Lazy.VERSION" ],
            "filecontent": [ "/\\*! lazy.js (§§version§§)" ]
        }
    },
    "fancyBox" : {
        "name": "fancyBox",
        "currentVersion": "3.5.7",
        "website": ["https://github.com/fancyapps/fancybox/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "fancyBox",
            "filecontent": [ "// fancyBox v(§§version§§)" ]
        }
    },
    "Underscore.js" : {
        "name": "Underscore.js",
        "currentVersion": "1.13.3",
        "website": ["https://github.com/jashkenas/underscore/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Underscore.js",
            "func": [ "_.VERSION" ],
            "filecontent": [ "// *Underscore.js (§§version§§)" ]
        }
    },
    "Lightbox2" : {
        "name": "Lightbox2",
        "currentVersion": "2.11.3",
        "website": ["https://github.com/lokesh/lightbox2/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Lightbox",
            "filecontent": [ "/\\*![\\s\\S]* \\* Lightbox v(§§version§§)" ]
        }
    },
    "SweetAlert2" : {
        "name": "SweetAlert2",
        "currentVersion": "11.4.10",
        "website": ["https://github.com/sweetalert2/sweetalert2/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "SweetAlert2",
            "func": [ "Sweetalert2.version" ]
        }
    },
    "Lodash" : {
        "name": "Lodash",
        "currentVersion": "4.17.21",
        "website": ["https://github.com/lodash/lodash/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Lodash",
            "func": [ "_.VERSION" ]
        }
    },
    "bluebird" : {
        "name": "bluebird",
        "currentVersion": "3.7.2",
        "website": ["https://github.com/petkaantonov/bluebird/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "bluebird",
            "filecontent": [ "\\* bluebird build version (§§version§§)" ],
            "func": [ "Promise.version" ]
        }
    },
    "polymer" : {
        "name": "Polymer",
        "currentVersion": "3.4.1",
        "website": ["https://github.com/Polymer/polymer/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Polymer",
            "func": [ "Polymer.version" ]
        }
    },
    "Mithril" : {
        "name": "Mithril",
        "currentVersion": "1.1.7",
        "website": ["https://github.com/MithrilJS/mithril.js/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "hyperscript",
            "func": [ "m.version" ]
        }
    },
    "ef.js" : {
        "name": "ef.js",
        "currentVersion": "0.14.2",
        "website": ["https://github.com/TheNeuronProject/ef.js/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "e.version",
            "func": [ "ef.version" ]
        }
    },
    "Math.js" : {
        "name": "Math.js",
        "currentVersion": "10.5.1",
        "website": ["https://github.com/josdejong/mathjs/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "* math.js",
            "filecontent": [ "\\* math.js[\\s\\S]* \\* @version (§§version§§)" ],
            "func": [ "math.version" ]
        }
    },
    "list.js" : {
        "name": "List.js",
        "currentVersion": "2.3.1",
        "website": ["https://github.com/javve/list.js/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "List.js",
            "filecontent": [ "// List.js v(§§version§§)" ]
        }
    },
    "RequireJS" : {
        "name": "RequireJS",
        "currentVersion": "2.3.6",
        "website": ["https://github.com/requirejs/requirejs/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "RequireJS",
            "filecontent": [ "@license RequireJS (§§version§§)" ],
            "func": [ "require.version", "requirejs.version" ]
        }
    },
    "Riot.js" : {
        "name": "Riot.js",
        "currentVersion": "6.1.2",
        "website": ["https://github.com/riot/riot/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Riot",
            "filecontent": [ "/\\* Riot v(§§version§§)" ]
        }
    },
    "inferno" : {
        "name": "Inferno",
        "currentVersion": "7.4.11",
        "website": ["https://github.com/infernojs/inferno/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Inferno",
            "func": [ "Inferno.version" ]
        }
    },
    "Marionette.js" : {
        "name": "Marionette.js",
        "currentVersion": "4.1.3",
        "website": ["https://github.com/marionettejs/backbone.marionette/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "MarionetteJS",
            "filecontent": [ "\\* MarionetteJS[\\s\\S]*\\* ----------\\* v(§§version§§)" ],
            "func": [ "Marionette.VERSION" ]
        }
    },
    "gsap" : {
        "name": "GSAP",
        "currentVersion": "3.10.4",
        "website": ["https://github.com/greensock/GSAP/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "GreenSock",
            "filecontent": [ "\\* VERSION: (§§version§§)[\\s\\S]*GreenSock. All rights reserved." ],
            "func": [ "jQuery.gsap.version" ]
        }
    },
    "slick" : {
        "name": "slick",
        "currentVersion": "1.8.1",
        "website": ["https://github.com/kenwheeler/slick/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "slick",
            "filecontent": [ "Version: (§§version§§)[\\s\\S]*Author: Ken Wheeler" ]
        }
    },
    "ScrollReveal" : {
        "name": "ScrollReveal",
        "currentVersion": "4.0.9",
        "website": ["https://github.com/jlmakes/scrollreveal/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "ScrollReveal",
            "filecontent": [ "/\\*! @license ScrollReveal v(§§version§§)" ]
        }
    },
    "MathJax" : {
        "name": "MathJax",
        "currentVersion": "3.2.0",
        "website": ["https://github.com/mathjax/MathJax/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "MathJax.js",
            "func": [ "MathJax.version" ]
        }
    },
    "rickshaw" : {
        "name": "Rickshaw",
        "currentVersion": "1.7.0",
        "website": ["https://github.com/shutterstock/rickshaw/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Rickshaw",
            "func": [ "Rickshaw.version" ],
            "filecontent": [ "version: '(§§version§§)'" ]
        }
    },
    "highcharts" : {
        "name": "Highcharts",
        "currentVersion": "10.1.0",
        "website": ["https://github.com/highcharts/highcharts/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Highcharts",
            "filecontent": [ "Highcharts JS v(§§version§§)" ],
            "func": [ "Highcharts.version" ]
        }
    },
    "snap.svg" : {
        "name": "Snap.svg",
        "currentVersion": "0.5.1",
        "website": ["https://github.com/adobe-webplatform/Snap.svg/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Snap.svg",
            "filecontent": [ "Snap.svg (§§version§§)" ],
            "func": [ "Snap.version" ]
        }
    },
    "flickity" : {
        "name": "Flickity",
        "currentVersion": "2.3.0",
        "website": ["https://github.com/metafizzy/flickity/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "Flickity",
            "filecontent": [ "\\* Flickity[\\s\\S]* v(§§version§§)" ]
        }
    },
    "D3.js" : {
        "name": "D3.js",
        "currentVersion": "7.4.4",
        "website": ["https://github.com/d3/d3/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "d3js.org",
            "filecontent": [ "https://d3js\\.org v(§§version§§)" ],
            "func": [ "d3.version" ]
        }
    },
    "Google Charts" : {
        "name": "Google Charts",
        "currentVersion": "0.1.0",
        "website": ["https://github.com/angular-google-chart/angular-google-chart/tags"],
        "curvers_extractor": "/data-test-selector=\"tag-title\">[\\s]+<a href=\"\\/[a-zA-Z0-9\\-\\_\\.]+\\/[a-zA-Z0-9\\-\\_\\.]+\\/releases\\/tag\\/[v]?([0-9a-z\\.\\-]+)\">/",
        "extractors": {
            "presignature": "Google Chart",
            "filecontent": [ "Google Chart Api Directive Module for AngularJS[\\s\\S]*@version (§§version§§)" ]
        }
    },
    "Ext JS" : {
        "name": "Ext JS",
        "currentVersion": "7.5.1",
        "website": ["https://docs.sencha.com/extjs/"],
        "curvers_extractor": "/Latest version: ([0-9\\.]+)/",
        "extractors": {
            "presignature": "Ext JS",
            "filecontent": [ "Ext JS (§§version§§)" ]
        }
    },
    "clipboard.js" : {
        "name": "clipboard.js",
        "currentVersion": "2.0.9",
        "website": ["https://github.com/zenorocha/clipboard.js/releases"],
        "curvers_extractor": "/class=\"Link--primary\">[\\s]+[v]?([a-z0-9\\.]+)[\\s]+<\\/a><\\/h1>[\\s]+<a href=\"[a-zA-Z0-9\\-\\_\\/\\.]+\\/releases\\/latest\"/",
        "extractors": {
            "presignature": "clipboard.js",
            "filecontent": [ "\\/\\*\\!\\s*?\\*\\s*?clipboard\\.js\\sv(§§version§§)\\s*?\\*\\s*?(?:https:\\/\\/zenorocha\\.github\\.io\\/clipboard\\.js|https:\\/\\/clipboardjs\\.com\\/)" ]
        }
    }

};
