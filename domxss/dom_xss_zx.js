const FOLLOW_UP_CHARACTERS = "\\<>'\":";
const jsSinks = [
    "jQuery.globalEval",
    "eval",
    "Function",
    "execScript",
    "setTimeout",
    "setInterval",
    "setImmediate",
    "msSetImmediate",
    "script.textContent",
    "script.text",
    "script.innerText",
    "script.innerHTML",
    "script.appendChild",
    "script.append",
    "javascriptURL",
    "jQuery.attr.onclick",
    "jQuery.attr.onmouseover",
    "jQuery.attr.onmousedown",
    "jQuery.attr.onmouseup",
    "jQuery.attr.onkeydown",
    "jQuery.attr.onkeypress",
    "jQuery.attr.onkeyup",
    "element.setAttribute.onclick",
    "element.setAttribute.onmouseover",
    "element.setAttribute.onmousedown",
    "element.setAttribute.onmouseup",
    "element.setAttribute.onkeydown",
    "element.setAttribute.onkeypress",
    "element.setAttribute.onkeyup",
    "element.setAttribute.on*"
];
const htmlSinks = [
    "document.write",
    "document.writeln",
    "jQuery",
    "jQuery.$",
    "jQuery.constructor",
    "jQuery.parseHTML",
    "jQuery.has",
    "jQuery.init",
    "jQuery.index",
    "jQuery.add",
    "jQuery.append",
    "jQuery.appendTo",
    "jQuery.after",
    "jQuery.insertAfter",
    "jQuery.before",
    "jQuery.insertBefore",
    "jQuery.html",
    "jQuery.prepend",
    "jQuery.prependTo",
    "jQuery.replaceWith",
    "jQuery.replaceAll",
    "jQuery.wrap",
    "jQuery.wrapAll",
    "jQuery.wrapInner",
    "jQuery.prop.innerHTML",
    "jQuery.prop.outerHTML",
    "element.innerHTML",
    "element.outerHTML",
    "element.insertAdjacentHTML",
    "iframe.srcdoc",
    "createContextualFragment",
    "document.implementation.createHTMLDocument"
];
const urlSinks = [
    "location.href",
    "location.replace",
    "location.assign",
    "location",
    "window.open",
    "iframe.src",
    "script.src",
    "jQuery.attr.href",
    "jQuery.attr.src",
    "jQuery.attr.data",
    "jQuery.attr.action",
    "jQuery.attr.formaction",
    "jQuery.prop.href",
    "jQuery.prop.src",
    "jQuery.prop.data",
    "jQuery.prop.action",
    "jQuery.prop.formaction",
    "form.action",
    "input.formaction",
    "button.formaction",
    "element.setAttribute.href",
    "element.setAttribute.src",
    "element.setAttribute.data",
    "element.setAttribute.action",
    "element.setAttribute.formaction"
];
const sourcesList = [
    "location",
    "location.href",
    "location.hash",
    "location.search",
    "location.pathname",
    "document.URL",
    "window.name",
    "document.referrer",
    "document.documentURI",
    "document.baseURI",
    "document.cookie",
    "URLSearchParams"
];
const interestingSinks = [
    ...jsSinks,
    ...htmlSinks,
    ...urlSinks
];
const sinkRanking = {
    "__proto__": null,
    "jQuery.globalEval": 1,
    "eval": 2,
    "Function": 3,
    "execScript": 4,
    "setTimeout": 5,
    "setInterval": 6,
    "setImmediate": 7,
    "msSetImmediate": 7,
    "script.src": 8,
    "script.textContent": 9,
    "script.text": 10,
    "script.innerText": 11,
    "script.innerHTML": 12,
    "script.appendChild": 13,
    "script.append": 14,
    "document.write": 15,
    "document.writeln": 16,
    "jQuery": 17,
    "jQuery.$": 18,
    "jQuery.constructor": 19,
    "jQuery.parseHTML": 20,
    "jQuery.has": 20,
    "jQuery.init": 20,
    "jQuery.index": 20,
    "jQuery.add": 20,
    "jQuery.append": 20,
    "jQuery.appendTo": 20,
    "jQuery.after": 20,
    "jQuery.insertAfter": 20,
    "jQuery.before": 20,
    "jQuery.insertBefore": 20,
    "jQuery.html": 20,
    "jQuery.prepend": 20,
    "jQuery.prependTo": 20,
    "jQuery.replaceWith": 20,
    "jQuery.replaceAll": 20,
    "jQuery.wrap": 20,
    "jQuery.wrapAll": 20,
    "jQuery.wrapInner": 20,
    "jQuery.prop.innerHTML": 20,
    "jQuery.prop.outerHTML": 20,
    "element.innerHTML": 21,
    "element.outerHTML": 22,
    "element.insertAdjacentHTML": 23,
    "iframe.srcdoc": 24,
    "location.href": 25,
    "location.replace": 26,
    "location.assign": 27,
    "location": 28,
    "window.open": 29,
    "iframe.src": 30,
    "javascriptURL": 31,
    "jQuery.attr.onclick": 32,
    "jQuery.attr.onmouseover": 32,
    "jQuery.attr.onmousedown": 32,
    "jQuery.attr.onmouseup": 32,
    "jQuery.attr.onkeydown": 32,
    "jQuery.attr.onkeypress": 32,
    "jQuery.attr.onkeyup": 32,
    "element.setAttribute.onclick": 33,
    "element.setAttribute.onmouseover": 33,
    "element.setAttribute.onmousedown": 33,
    "element.setAttribute.onmouseup": 33,
    "element.setAttribute.onkeydown": 33,
    "element.setAttribute.onkeypress": 33,
    "element.setAttribute.onkeyup": 33,
    "element.setAttribute.on*": 33,
    "createContextualFragment": 34,
    "document.implementation.createHTMLDocument": 35,
    "xhr.open": 36,
    "xhr.send": 36,
    "fetch": 36,
    "fetch.url": 36,
    "fetch.body": 36,
    "fetch.header": 36,
    "xhr.setRequestHeader.name": 37,
    "xhr.setRequestHeader.value": 38,
    "jQuery.attr.href": 39,
    "jQuery.attr.src": 40,
    "jQuery.attr.data": 41,
    "jQuery.attr.action": 42,
    "jQuery.attr.formaction": 43,
    "jQuery.prop.href": 44,
    "jQuery.prop.src": 45,
    "jQuery.prop.data": 46,
    "jQuery.prop.action": 47,
    "jQuery.prop.formaction": 48,
    "form.action": 49,
    "input.formaction": 50,
    "button.formaction": 51,
    "button.value": 52,
    "element.setAttribute.href": 53,
    "element.setAttribute.src": 54,
    "element.setAttribute.data": 55,
    "element.setAttribute.action": 56,
    "element.setAttribute.formaction": 57,
    "webdatabase.executeSql": 58,
    "document.domain": 59,
    "history.pushState": 60,
    "history.replaceState": 61,
    "xhr.setRequestHeader": 62,
    "websocket": 63,
    "anchor.href": 64,
    "anchor.target": 65,
    "JSON.parse": 66,
    "document.cookie": 67,
    "localStorage.setItem.name": 68,
    "localStorage.setItem.value": 69,
    "sessionStorage.setItem.name": 70,
    "sessionStorage.setItem.value": 71,
    "element.outerText": 72,
    "element.innerText": 73,
    "element.textContent": 74,
    "element.style.cssText": 75,
    "RegExp": 76,
    "window.name": 77,
    "location.pathname": 78,
    "location.protocol": 79,
    "location.host": 80,
    "location.hostname": 81,
    "location.hash": 82,
    "location.search": 83,
    "input.value": 84,
    "input.type": 85,
    "document.evaluate": 86
};
const extensionExcludedSinks = [
    "button.value",
    "webdatabase.executeSql",
    "anchor.target",
    "element.outerText",
    "element.innerText",
    "element.textContent",
    "element.style.cssText",
    "RegExp",
    "input.value",
    "input.type",
    "document.evaluate"
];
const sinksList = Object.keys(sinkRanking).filter(key => !extensionExcludedSinks.includes(key));
const mouseEvents = [
    "mouseover",
    "click",
    "mousedown",
    "mouseup"
];
const keyboardEvents = [
    "keydown",
    "keypress",
    "keyup"
];
const PROTOTYPE_POLLUTION_SOURCE_PREFIX = "Prototype pollution: ";
const PROTOTYPE_POLLUTION_TECHNIQUES = [
    {
        "__proto__": null,
        "source": "constructor[prototype][property]=value",
        "createParam"(_0x30f41f, _0x5f4e9b) {
            return typeof _0x30f41f === "string" && (_0x30f41f = [_0x30f41f]), this.createParamName(_0x30f41f) + "=" + _0x5f4e9b;
        },
        "createParamName"(_0x2a09a8) {
            return typeof _0x2a09a8 === "string" && ("eqyWJ" !== "wycyN" ? _0x2a09a8 = [_0x2a09a8] : _0x550300 += "\\\\" + _0x9eb361), "null]";
        },
        "hashIdentifier": "a3aa3232",
        "searchIdentifier": "a42e5579"
    },
    {
        "__proto__": null,
        "source": "constructor.prototype.property=value",
        "createParam"(_0x2f396e, _0x49bcf7) {
            if (typeof _0x2f396e === "string") {
            }
            return this.createParamName(_0x2f396e) + "=" + _0x49bcf7;
        },
        "createParamName"(array) {
            return typeof array === "string" && (array = [array]), "constructor.prototype." + array.join(".");
        },
        "hashIdentifier": "bf1e103d",
        "searchIdentifier": "b1a3fd5b"
    },
    {
        "__proto__": null,
        "source": "__proto__.property=value",
        "createParam"(_0x2bcfd5, _0xa21a12) {
            return typeof _0x2bcfd5 === "string" && (_0x2bcfd5 = [_0x2bcfd5]), this.createParamName(_0x2bcfd5) + "=" + _0xa21a12;
        },
        "createParamName"(array_uv) {
            if (typeof array_uv === "string") {
            }
            return "__proto__." + array_uv.join(".");
        },
        "hashIdentifier": "c5e2cbce",
        "searchIdentifier": "ccd80966"
    },
    {
        "__proto__": null,
        "source": "__proto__[property]=value",
        "createParam"(_0x318671, _0x227313) {
            typeof _0x318671 === "string" && ("lJWAk" === "lJWAk" ? _0x318671 = [_0x318671] : _0x59d536.proxiedSetterCallback(_0x4f4a65, "hostname", _0x39b69c, _0x3cfa52));
            return this.createParamName(_0x318671) + "=" + _0x227313;
        },
        "createParamName"(_0x3f98de) {
            if (typeof _0x3f98de === "string") {
            }
            return "null]";
        },
        "hashIdentifier": "d0992d86",
        "searchIdentifier": "dcb52823"
    }
];
const PROTOTYPE_POLLUTION_INDEXES = buildIndexes();
Error.stackTraceLimit = 20;
function buildIndexes() {
    let map = new Map();
    for (let _0x48dc37 of PROTOTYPE_POLLUTION_TECHNIQUES) {
        map.set(1, _0x48dc37.hashIdentifier);
        _0xcf8769++;
        map.set(1, _0x48dc37.searchIdentifier);
        _0xcf8769++;
    }
    return map;
}

function resetForms() {
    var _0x241f15;
    var document_length = document.forms.length;
    for (_0x241f15 = 0; _0x241f15 < document_length; _0x241f15++) {
        document.forms._0x241f15.reset();
    }
}

function isInterestingSource(_0x29df5e) {
    return _0x29df5e.includes("Prototype pollution:");
}
function getPPSourceIndex(_0x99650c) {
    for (const _0x28b27f of PROTOTYPE_POLLUTION_TECHNIQUES) {
        if (_0x99650c.includes(_0x28b27f.source)) {
            if (_0x99650c.includes("in hash")) {
                for (const [_0xb74848, _0x429a74] of PROTOTYPE_POLLUTION_INDEXES.entries()) {
                    if (_0x28b27f.hashIdentifier === _0x429a74)
                        return _0xb74848;
                }
            } else {
                if (_0x99650c.includes("in search")) {
                }
            }
        }
    }
    return -1;
}

//以下都是Claude的软件开发

function handleMessage(e) {
    console.log("XSS Found!");
    e.stopPropagation();
}


//遍历所有sink(接收点),为其添加事件监听:
function aitest() {
    for (const sink of sinksList) {
        // 只检测带有属性或方法的sink
        if (window[sink] && typeof window[sink] === "object") {
            for (const event of mouseEvents.concat(keyboardEvents)) {
                window[sink][`on${event}`] = handleMessage;
            }
        }
    }
}

//遍历sourcesList,检测是否包含Payload,如果是,说明此source带入Payload:
function aisourcetest() {
    for (const source of sourcesList) {
        if (window[source] && window[source].includes(payloads["<script>alert(1)</script>"])) {
            console.log(`Source: ${source}`);
        }
    }
}

//根据DOM树结构,一层层上溯,找到Payload被添加的位置:
function traceDOM(element) {
    if (element.innerHTML && element.innerHTML.includes(payloads["<script>alert(1)</script>"])) {
        console.log(`DOM Element: ${element.tagName}`);
    }
    if (element.parentElement) {
        traceDOM(element.parentElement);
    }
}
traceDOM(document.body);
