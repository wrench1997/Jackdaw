/**
 * DOM XSS 检测器
 * 用于检测网页中的 DOM XSS 漏洞
 */
(function() {
    // 定义 DOM XSS 检测器类
    class DOMXSSDetector {
        constructor() {
            // 定义 XSS 源列表
            this.sources = [
                { label: "location", property: "location" },
                { label: "location.href", property: "location.href" },
                { label: "location.hash", property: "location.hash" },
                { label: "location.search", property: "location.search" },
                { label: "location.pathname", property: "location.pathname" },
                { label: "document.URL", property: "document.URL" },
                { label: "window.name", property: "window.name" },
                { label: "document.referrer", property: "document.referrer" },
                { label: "document.documentURI", property: "document.documentURI" },
                { label: "document.baseURI", property: "document.baseURI" },
                { label: "document.cookie", property: "document.cookie" },
                { label: "localStorage", property: "localStorage" },
                { label: "sessionStorage", property: "sessionStorage" },
                { label: "URLSearchParams", property: "URLSearchParams" }
            ];

            // 定义 XSS 接收点列表，按照优先级排序
            this.sinks = [
                // JavaScript 执行接收点 - 高危险性
                { label: "jQuery.globalEval", property: "jQuery.globalEval", priority: 1, category: "js" },
                { label: "eval", property: "eval", priority: 2, category: "js" },
                { label: "Function", property: "Function", priority: 3, category: "js" },
                { label: "execScript", property: "execScript", priority: 4, category: "js" },
                { label: "setTimeout", property: "setTimeout", priority: 5, category: "js" },
                { label: "setInterval", property: "setInterval", priority: 6, category: "js" },
                { label: "setImmediate", property: "setImmediate", priority: 7, category: "js" },
                { label: "msSetImmediate", property: "msSetImmediate", priority: 7, category: "js" },
                { label: "script.src", property: "script.src", priority: 8, category: "js" },
                { label: "script.textContent", property: "script.textContent", priority: 9, category: "js" },
                { label: "script.text", property: "script.text", priority: 10, category: "js" },
                { label: "script.innerText", property: "script.innerText", priority: 11, category: "js" },
                { label: "script.innerHTML", property: "script.innerHTML", priority: 12, category: "js" },
                { label: "script.appendChild", property: "script.appendChild", priority: 13, category: "js" },
                { label: "script.append", property: "script.append", priority: 14, category: "js" },
                
                // HTML 注入接收点 - 中危险性
                { label: "document.write", property: "document.write", priority: 15, category: "html" },
                { label: "document.writeln", property: "document.writeln", priority: 16, category: "html" },
                { label: "jQuery", property: "jQuery", priority: 17, category: "html" },
                { label: "jQuery.$", property: "jQuery.$", priority: 18, category: "html" },
                { label: "jQuery.constructor", property: "jQuery.constructor", priority: 19, category: "html" },
                { label: "jQuery.parseHTML", property: "jQuery.parseHTML", priority: 20, category: "html" },
                { label: "jQuery.html", property: "jQuery.html", priority: 20, category: "html" },
                { label: "jQuery.append", property: "jQuery.append", priority: 20, category: "html" },
                { label: "jQuery.prepend", property: "jQuery.prepend", priority: 20, category: "html" },
                { label: "jQuery.after", property: "jQuery.after", priority: 20, category: "html" },
                { label: "jQuery.before", property: "jQuery.before", priority: 20, category: "html" },
                { label: "jQuery.replaceWith", property: "jQuery.replaceWith", priority: 20, category: "html" },
                { label: "jQuery.prop.innerHTML", property: "jQuery.prop.innerHTML", priority: 20, category: "html" },
                { label: "jQuery.prop.outerHTML", property: "jQuery.prop.outerHTML", priority: 20, category: "html" },
                { label: "element.innerHTML", property: "innerHTML", priority: 21, category: "html" },
                { label: "element.outerHTML", property: "outerHTML", priority: 22, category: "html" },
                { label: "element.insertAdjacentHTML", property: "insertAdjacentHTML", priority: 23, category: "html" },
                { label: "iframe.srcdoc", property: "iframe.srcdoc", priority: 24, category: "html" },
                
                // URL 相关接收点 - 低危险性
                { label: "location.href", property: "location.href", priority: 25, category: "url" },
                { label: "location.replace", property: "location.replace", priority: 26, category: "url" },
                { label: "location.assign", property: "location.assign", priority: 27, category: "url" },
                { label: "location", property: "location", priority: 28, category: "url" },
                { label: "window.open", property: "window.open", priority: 29, category: "url" },
                { label: "iframe.src", property: "iframe.src", priority: 30, category: "url" },
                
                // 事件处理接收点
                { label: "javascriptURL", property: "javascriptURL", priority: 31, category: "event" },
                { label: "jQuery.attr.onclick", property: "jQuery.attr.onclick", priority: 32, category: "event" },
                { label: "jQuery.attr.onmouseover", property: "jQuery.attr.onmouseover", priority: 32, category: "event" },
                { label: "jQuery.attr.onmousedown", property: "jQuery.attr.onmousedown", priority: 32, category: "event" },
                { label: "jQuery.attr.onmouseup", property: "jQuery.attr.onmouseup", priority: 32, category: "event" },
                { label: "jQuery.attr.onkeydown", property: "jQuery.attr.onkeydown", priority: 32, category: "event" },
                { label: "jQuery.attr.onkeypress", property: "jQuery.attr.onkeypress", priority: 32, category: "event" },
                { label: "jQuery.attr.onkeyup", property: "jQuery.attr.onkeyup", priority: 32, category: "event" },
                { label: "element.setAttribute.onclick", property: "element.setAttribute.onclick", priority: 33, category: "event" },
                { label: "element.setAttribute.onmouseover", property: "element.setAttribute.onmouseover", priority: 33, category: "event" },
                { label: "element.setAttribute.onmousedown", property: "element.setAttribute.onmousedown", priority: 33, category: "event" },
                { label: "element.setAttribute.onmouseup", property: "element.setAttribute.onmouseup", priority: 33, category: "event" },
                { label: "element.setAttribute.onkeydown", property: "element.setAttribute.onkeydown", priority: 33, category: "event" },
                { label: "element.setAttribute.onkeypress", property: "element.setAttribute.onkeypress", priority: 33, category: "event" },
                { label: "element.setAttribute.onkeyup", property: "element.setAttribute.onkeyup", priority: 33, category: "event" },
                { label: "element.setAttribute.on*", property: "element.setAttribute.on*", priority: 33, category: "event" }
            ];

            // 定义鼠标事件列表
            this.mouseEvents = [
                "mouseover",
                "click",
                "mousedown",
                "mouseup"
            ];

            // 定义键盘事件列表
            this.keyboardEvents = [
                "keydown",
                "keypress",
                "keyup"
            ];

            // 原型污染技术列表
            this.prototypePollutionTechniques = [
                {
                    source: "constructor[prototype][property]=value",
                    createParam: function(property, value) {
                        if (typeof property === "string") {
                            property = [property];
                        }
                        return this.createParamName(property) + "=" + value;
                    },
                    createParamName: function(property) {
                        if (typeof property === "string") {
                            property = [property];
                        }
                        return "constructor[prototype][" + property.join("][") + "]";
                    },
                    hashIdentifier: "a3aa3232",
                    searchIdentifier: "a42e5579"
                },
                {
                    source: "constructor.prototype.property=value",
                    createParam: function(property, value) {
                        if (typeof property === "string") {
                            property = [property];
                        }
                        return this.createParamName(property) + "=" + value;
                    },
                    createParamName: function(property) {
                        if (typeof property === "string") {
                            property = [property];
                        }
                        return "constructor.prototype." + property.join(".");
                    },
                    hashIdentifier: "bf1e103d",
                    searchIdentifier: "b1a3fd5b"
                },
                {
                    source: "__proto__.property=value",
                    createParam: function(property, value) {
                        if (typeof property === "string") {
                            property = [property];
                        }
                        return this.createParamName(property) + "=" + value;
                    },
                    createParamName: function(property) {
                        if (typeof property === "string") {
                            property = [property];
                        }
                        return "__proto__." + property.join(".");
                    },
                    hashIdentifier: "c5e2cbce",
                    searchIdentifier: "ccd80966"
                },
                {
                    source: "__proto__[property]=value",
                    createParam: function(property, value) {
                        if (typeof property === "string") {
                            property = [property];
                        }
                        return this.createParamName(property) + "=" + value;
                    },
                    createParamName: function(property) {
                        if (typeof property === "string") {
                            property = [property];
                        }
                        return "__proto__[" + property.join("][") + "]";
                    },
                    hashIdentifier: "d0992d86",
                    searchIdentifier: "dcb52823"
                }
            ];

            // 存储检测到的漏洞
            this.detectedVulnerabilities = [];
            
            // 后端集成配置
            this.backendIntegration = {
                enabled: false,
                endpoint: null,
                apiKey: null,
                autoReport: false
            };
            
            // 初始化检测器
            this.init();
        }

        /**
         * 初始化检测器
         */
        init() {
            // 监控 DOM 变化
            this.observeDOM();
            
            // 监控源和接收点
            this.monitorSourcesAndSinks();
            
            // 检查 URL 参数
            this.checkURLParameters();
            
            // 检查 localStorage 和 sessionStorage
            this.checkStorage();
            
            // 检查原型污染
            this.checkPrototypePollution();
            
            // 监控 jQuery 相关操作
            this.monitorjQuery();
            
            console.log("[DOM XSS Detector] 初始化完成");
        }

        /**
         * 监控 DOM 变化
         */
        observeDOM() {
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    if (mutation.type === 'childList') {
                        // 检查新添加的节点
                        mutation.addedNodes.forEach((node) => {
                            if (node.nodeType === 1) { // 元素节点
                                this.checkElement(node);
                            }
                        });
                    } else if (mutation.type === 'attributes') {
                        // 检查属性变化
                        this.checkElementAttributes(mutation.target);
                    }
                });
            });

            // 配置观察选项
            const config = { 
                attributes: true, 
                childList: true, 
                subtree: true,
                attributeFilter: ['src', 'href', 'onclick', 'onmouseover', 'onload', 'onerror', 'onmousedown', 'onmouseup', 'onkeydown', 'onkeypress', 'onkeyup']
            };

            // 开始观察文档
            observer.observe(document, config);
        }

        /**
         * 检查元素是否存在 XSS 漏洞
         * @param {Element} element - 要检查的 DOM 元素
         */
        checkElement(element) {
            // 检查元素的 innerHTML 和 outerHTML
            if (element.innerHTML) {
                this.checkForXSS('innerHTML', element.innerHTML, element);
            }
            
            if (element.outerHTML) {
                this.checkForXSS('outerHTML', element.outerHTML, element);
            }
            
            // 检查脚本元素
            if (element.tagName === 'SCRIPT') {
                if (element.src) {
                    this.checkForXSS('script.src', element.src, element);
                }
                if (element.textContent) {
                    this.checkForXSS('script.textContent', element.textContent, element);
                }
                if (element.text) {
                    this.checkForXSS('script.text', element.text, element);
                }
                if (element.innerText) {
                    this.checkForXSS('script.innerText', element.innerText, element);
                }
            }
            
            // 检查 iframe 元素
            if (element.tagName === 'IFRAME') {
                if (element.src) {
                    this.checkForXSS('iframe.src', element.src, element);
                }
                if (element.srcdoc) {
                    this.checkForXSS('iframe.srcdoc', element.srcdoc, element);
                }
            }
            
            // 检查 a 元素
            if (element.tagName === 'A' && element.href) {
                if (element.href.startsWith('javascript:')) {
                    this.checkForXSS('javascriptURL', element.href, element);
                } else {
                    this.checkForXSS('anchor.href', element.href, element);
                }
            }
            
            // 检查表单元素
            if (element.tagName === 'FORM' && element.action) {
                this.checkForXSS('form.action', element.action, element);
            }
            
            if ((element.tagName === 'INPUT' || element.tagName === 'BUTTON') && element.formAction) {
                this.checkForXSS(`${element.tagName.toLowerCase()}.formaction`, element.formAction, element);
            }
            
            // 递归检查子元素
            if (element.children && element.children.length > 0) {
                Array.from(element.children).forEach(child => {
                    this.checkElement(child);
                });
            }
        }

        /**
         * 检查元素属性是否存在 XSS 漏洞
         * @param {Element} element - 要检查的 DOM 元素
         */
        checkElementAttributes(element) {
            // 检查常见的危险属性
            const dangerousAttrs = [
                'href', 'src', 'data', 'action', 'formaction',
                'onclick', 'onmouseover', 'onload', 'onerror', 
                'onmousedown', 'onmouseup', 'onkeydown', 'onkeypress', 'onkeyup'
            ];
            
            dangerousAttrs.forEach(attr => {
                if (element.hasAttribute(attr)) {
                    const attrValue = element.getAttribute(attr);
                    
                    // 检查事件处理程序属性
                    if (attr.startsWith('on')) {
                        this.checkForXSS(`element.${attr}`, attrValue, element);
                    } else {
                        // 检查其他属性
                        this.checkForXSS(`element.setAttribute.${attr}`, attrValue, element);
                    }
                }
            });
        }

        /**
         * 监控源和接收点
         */
        monitorSourcesAndSinks() {
            // 监控 eval 函数
            this.monitorEval();
            
            // 监控 Function 构造函数
            this.monitorFunction();
            
            // 监控 innerHTML 和 outerHTML
            this.monitorHTMLProperties();
            
            // 监控 location 相关属性
            this.monitorLocationProperties();
            
            // 监控 document.write 和 document.writeln
            this.monitorDocumentWrite();
            
            // 监控 setTimeout 和 setInterval
            this.monitorTimers();
            
            // 监控 setImmediate (如果存在)
            if (typeof window.setImmediate === 'function') {
                this.monitorSetImmediate();
            }
            
            // 监控 window.open
            this.monitorWindowOpen();
            
            // 监控 createElement 和 appendChild
            this.monitorElementCreation();
        }

        /**
         * 监控 eval 函数
         */
        monitorEval() {
            const originalEval = window.eval;
            const self = this;
            
            window.eval = function(code) {
                self.checkForXSS('eval', code);
                return originalEval.apply(this, arguments);
            };
        }

        /**
         * 监控 Function 构造函数
         */
        monitorFunction() {
            const originalFunction = window.Function;
            const self = this;
            
            window.Function = function() {
                const args = Array.from(arguments);
                const functionBody = args.pop();
                
                self.checkForXSS('Function', functionBody);
                
                return originalFunction.apply(this, [...args, functionBody]);
            };
        }

        /**
         * 监控 innerHTML 和 outerHTML
         */
        monitorHTMLProperties() {
            const self = this;
            
            // 监控 Element.prototype.innerHTML
            const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    set: function(value) {
                        self.checkForXSS('innerHTML', value, this);
                        return originalInnerHTMLDescriptor.set.call(this, value);
                    },
                    get: originalInnerHTMLDescriptor.get,
                    configurable: true
                });
            }
            
            // 监控 Element.prototype.outerHTML
            const originalOuterHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
            if (originalOuterHTMLDescriptor && originalOuterHTMLDescriptor.set) {
                Object.defineProperty(Element.prototype, 'outerHTML', {
                    set: function(value) {
                        self.checkForXSS('outerHTML', value, this);
                        return originalOuterHTMLDescriptor.set.call(this, value);
                    },
                    get: originalOuterHTMLDescriptor.get,
                    configurable: true
                });
            }
            
            // 监控 Element.prototype.insertAdjacentHTML
            const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
            Element.prototype.insertAdjacentHTML = function(position, text) {
                self.checkForXSS('insertAdjacentHTML', text, this);
                return originalInsertAdjacentHTML.apply(this, arguments);
            };
        }

 
        /**
         * 监控 location 相关属性
         */
        monitorLocationProperties() {
            const self = this;
            
            try {
                // 尝试监控 location 对象本身
                const originalLocation = window.location;
                
                // 监控 location.replace
                const originalReplace = window.location.replace;
                window.location.replace = function(url) {
                    self.checkForXSS('location.replace', url);
                    return originalReplace.apply(this, arguments);
                };
                
                // 监控 location.assign
                const originalAssign = window.location.assign;
                window.location.assign = function(url) {
                    self.checkForXSS('location.assign', url);
                    return originalAssign.apply(this, arguments);
                };
                
                // 不直接修改 location.href，而是使用代理对象或其他方法监控
                // 例如，可以在页面加载时检查 location.href 的值
                self.checkForXSS('location.href', window.location.href);
                
            } catch (error) {
                console.warn("[DOM XSS Detector] 无法监控某些 location 属性:", error.message);
            }
        }

        /**
         * 监控 document.write 和 document.writeln
         */
        monitorDocumentWrite() {
            const self = this;
            
            // 监控 document.write
            const originalWrite = document.write;
            document.write = function(markup) {
                self.checkForXSS('document.write', markup);
                return originalWrite.apply(this, arguments);
            };
            
            // 监控 document.writeln
            const originalWriteln = document.writeln;
            document.writeln = function(markup) {
                self.checkForXSS('document.writeln', markup);
                return originalWriteln.apply(this, arguments);
            };
        }

        /**
         * 监控 setTimeout 和 setInterval
         */
        monitorTimers() {
            const self = this;
            
            // 监控 setTimeout
            const originalSetTimeout = window.setTimeout;
            window.setTimeout = function(callback, timeout) {
                if (typeof callback === 'string') {
                    self.checkForXSS('setTimeout', callback);
                }
                return originalSetTimeout.apply(this, arguments);
            };
            
            // 监控 setInterval
            const originalSetInterval = window.setInterval;
            window.setInterval = function(callback, timeout) {
                if (typeof callback === 'string') {
                    self.checkForXSS('setInterval', callback);
                }
                return originalSetInterval.apply(this, arguments);
            };
        }

        /**
         * 监控 setImmediate
         */
        monitorSetImmediate() {
            const self = this;
            
            // 监控 setImmediate
            const originalSetImmediate = window.setImmediate;
            window.setImmediate = function(callback) {
                if (typeof callback === 'string') {
                    self.checkForXSS('setImmediate', callback);
                }
                return originalSetImmediate.apply(this, arguments);
            };
            
            // 监控 msSetImmediate (IE特有)
            if (typeof window.msSetImmediate === 'function') {
                const originalMsSetImmediate = window.msSetImmediate;
                window.msSetImmediate = function(callback) {
                    if (typeof callback === 'string') {
                        self.checkForXSS('msSetImmediate', callback);
                    }
                    return originalMsSetImmediate.apply(this, arguments);
                };
            }
        }

        /**
         * 监控 window.open
         */
        monitorWindowOpen() {
            const self = this;
            
            // 监控 window.open
            const originalOpen = window.open;
            window.open = function(url) {
                if (url) {
                    self.checkForXSS('window.open', url);
                }
                return originalOpen.apply(this, arguments);
            };
        }

        /**
         * 监控元素创建和添加
         */
        monitorElementCreation() {
            const self = this;
            
            // 监控 document.createElement
            const originalCreateElement = document.createElement;
            document.createElement = function(tagName) {
                const element = originalCreateElement.apply(this, arguments);
                
                // 特别关注脚本元素
                if (tagName.toLowerCase() === 'script') {
                    // 监控 script.src 设置
                    const originalSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
                    if (originalSrcDescriptor && originalSrcDescriptor.set) {
                        Object.defineProperty(element, 'src', {
                            set: function(value) {
                                self.checkForXSS('script.src', value, this);
                                return originalSrcDescriptor.set.call(this, value);
                            },
                            get: originalSrcDescriptor.get,
                            configurable: true
                        });
                    }
                    
                    // 监控 script.text 设置
                    const originalTextDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'text');
                    if (originalTextDescriptor && originalTextDescriptor.set) {
                        Object.defineProperty(element, 'text', {
                            set: function(value) {
                                self.checkForXSS('script.text', value, this);
                                return originalTextDescriptor.set.call(this, value);
                            },
                            get: originalTextDescriptor.get,
                            configurable: true
                        });
                    }
                }
                
                return element;
            };
            
            // 监控 Node.prototype.appendChild
            const originalAppendChild = Node.prototype.appendChild;
            Node.prototype.appendChild = function(node) {
                if (this.nodeName === 'SCRIPT' && node.nodeType === Node.TEXT_NODE) {
                    self.checkForXSS('script.appendChild', node.textContent, this);
                }
                return originalAppendChild.apply(this, arguments);
            };
            
            // 监控 Element.prototype.append
            if (typeof Element.prototype.append === 'function') {
                const originalAppend = Element.prototype.append;
                Element.prototype.append = function() {
                    if (this.nodeName === 'SCRIPT') {
                        for (let i = 0; i < arguments.length; i++) {
                            const arg = arguments[i];
                            if (typeof arg === 'string') {
                                self.checkForXSS('script.append', arg, this);
                            } else if (arg && arg.nodeType === Node.TEXT_NODE) {
                                self.checkForXSS('script.append', arg.textContent, this);
                            }
                        }
                    }
                    return originalAppend.apply(this, arguments);
                };
            }
        }

        /**
         * 监控 jQuery 相关操作
         */
        monitorjQuery() {
            const self = this;
            
            // 等待 jQuery 加载完成
            const checkjQuery = function() {
                if (window.jQuery) {
                    // 监控 jQuery.globalEval
                    if (jQuery.globalEval) {
                        const originalGlobalEval = jQuery.globalEval;
                        jQuery.globalEval = function(code) {
                            self.checkForXSS('jQuery.globalEval', code);
                            return originalGlobalEval.apply(this, arguments);
                        };
                    }
                    
                    // 监控 jQuery.html
                    if (jQuery.fn.html) {
                        const originalHtml = jQuery.fn.html;
                        jQuery.fn.html = function(value) {
                            if (arguments.length > 0 && typeof value === 'string') {
                                self.checkForXSS('jQuery.html', value, this[0]);
                            }
                            return originalHtml.apply(this, arguments);
                        };
                    }
                    
                    // 监控 jQuery.append
                    if (jQuery.fn.append) {
                        const originalAppend = jQuery.fn.append;
                        jQuery.fn.append = function() {
                            for (let i = 0; i < arguments.length; i++) {
                                const arg = arguments[i];
                                if (typeof arg === 'string') {
                                    self.checkForXSS('jQuery.append', arg, this[0]);
                                }
                            }
                            return originalAppend.apply(this, arguments);
                        };
                    }
                    
                    // 监控 jQuery.appendTo
                    if (jQuery.fn.appendTo) {
                        const originalAppendTo = jQuery.fn.appendTo;
                        jQuery.fn.appendTo = function(target) {
                            if (this[0] && this[0].outerHTML) {
                                self.checkForXSS('jQuery.appendTo', this[0].outerHTML, target);
                            }
                            return originalAppendTo.apply(this, arguments);
                        };
                    }
                    
                    // 监控 jQuery.attr 设置事件处理程序
                    if (jQuery.fn.attr) {
                        const originalAttr = jQuery.fn.attr;
                        jQuery.fn.attr = function(name, value) {
                            if (arguments.length === 2 && typeof name === 'string' && typeof value === 'string') {
                                if (name.startsWith('on')) {
                                    self.checkForXSS(`jQuery.attr.${name}`, value, this[0]);
                                } else if (['href', 'src', 'data', 'action', 'formaction'].includes(name)) {
                                    self.checkForXSS(`jQuery.attr.${name}`, value, this[0]);
                                }
                            }
                            return originalAttr.apply(this, arguments);
                        };
                    }
                    
                    // 监控 jQuery.prop 设置 innerHTML 和 outerHTML
                    if (jQuery.fn.prop) {
                        const originalProp = jQuery.fn.prop;
                        jQuery.fn.prop = function(name, value) {
                            if (arguments.length === 2 && typeof name === 'string' && typeof value === 'string') {
                                if (['innerHTML', 'outerHTML'].includes(name)) {
                                    self.checkForXSS(`jQuery.prop.${name}`, value, this[0]);
                                } else if (['href', 'src', 'data', 'action', 'formaction'].includes(name)) {
                                    self.checkForXSS(`jQuery.prop.${name}`, value, this[0]);
                                }
                            }
                            return originalProp.apply(this, arguments);
                        };
                    }
                    
                    console.log("[DOM XSS Detector] jQuery 监控已启用");
                } else {
                    // 如果 jQuery 尚未加载，稍后再检查
                    setTimeout(checkjQuery, 500);
                }
            };
            
            // 开始检查 jQuery
            checkjQuery();
        }

        /**
         * 检查 URL 参数
         */
        checkURLParameters() {
            const urlParams = new URLSearchParams(window.location.search);
            
            // 检查每个 URL 参数
            for (const [key, value] of urlParams.entries()) {
                // 检查参数值是否包含潜在的 XSS 载荷
                if (this.isPotentialXSSPayload(value)) {
                    this.reportVulnerability({
                        source: { label: 'URL Parameter', property: key },
                        sink: { label: 'Unknown', property: 'Unknown' },
                        value: value,
                        url: window.location.href,
                        severity: 'Medium'
                    });
                }
            }
            
            // 检查 URL 哈希部分
            if (window.location.hash && this.isPotentialXSSPayload(window.location.hash)) {
                this.reportVulnerability({
                    source: { label: 'location.hash', property: 'location.hash' },
                    sink: { label: 'Unknown', property: 'Unknown' },
                    value: window.location.hash,
                    url: window.location.href,
                    severity: 'Medium'
                });
            }
        }

        /**
         * 检查 localStorage 和 sessionStorage
         */
        checkStorage() {
            // 检查 localStorage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                
                if (this.isPotentialXSSPayload(value)) {
                    this.reportVulnerability({
                        source: { label: 'localStorage', property: key },
                        sink: { label: 'Unknown', property: 'Unknown' },
                        value: value,
                        url: window.location.href,
                        severity: 'Medium'
                    });
                }
            }
            
            // 检查 sessionStorage
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const value = sessionStorage.getItem(key);
                
                if (this.isPotentialXSSPayload(value)) {
                    this.reportVulnerability({
                        source: { label: 'sessionStorage', property: key },
                        sink: { label: 'Unknown', property: 'Unknown' },
                        value: value,
                        url: window.location.href,
                        severity: 'Medium'
                    });
                }
            }
            
            // 监控 localStorage.setItem
            const originalLocalStorageSetItem = localStorage.setItem;
            const self = this;
            
            localStorage.setItem = function(key, value) {
                if (self.isPotentialXSSPayload(value)) {
                    self.reportVulnerability({
                        source: { label: 'Unknown', property: 'Unknown' },
                        sink: { label: 'localStorage.setItem', property: key },
                        value: value,
                        url: window.location.href,
                        severity: 'Medium'
                    });
                }
                return originalLocalStorageSetItem.apply(this, arguments);
            };
            
            // 监控 sessionStorage.setItem
            const originalSessionStorageSetItem = sessionStorage.setItem;
            
            sessionStorage.setItem = function(key, value) {
                if (self.isPotentialXSSPayload(value)) {
                    self.reportVulnerability({
                        source: { label: 'Unknown', property: 'Unknown' },
                        sink: { label: 'sessionStorage.setItem', property: key },
                        value: value,
                        url: window.location.href,
                        severity: 'Medium'
                    });
                }
                return originalSessionStorageSetItem.apply(this, arguments);
            };
        }

        /**
         * 检查原型污染
         */
        checkPrototypePollution() {
            const self = this;
            
            // 检查 URL 参数中的原型污染模式
            const urlParams = new URLSearchParams(window.location.search);
            for (const [key, value] of urlParams.entries()) {
                // 检查是否包含原型污染模式
                if (key.includes('__proto__') || key.includes('constructor') || key.includes('prototype')) {
                    this.reportVulnerability({
                        source: { label: 'URL Parameter', property: key },
                        sink: { label: 'Prototype Pollution', property: 'Object.prototype' },
                        value: value,
                        url: window.location.href,
                        severity: 'High',
                        type: 'Prototype Pollution'
                    });
                }
            }
            
            // 检查 URL 哈希中的原型污染模式
            if (window.location.hash) {
                const hashParams = new URLSearchParams(window.location.hash.substring(1));
                for (const [key, value] of hashParams.entries()) {
                    if (key.includes('__proto__') || key.includes('constructor') || key.includes('prototype')) {
                        this.reportVulnerability({
                            source: { label: 'location.hash', property: key },
                            sink: { label: 'Prototype Pollution', property: 'Object.prototype' },
                            value: value,
                            url: window.location.href,
                            severity: 'High',
                            type: 'Prototype Pollution'
                        });
                    }
                }
            }
            
            // 监控 Object.prototype 的修改
            const sensitiveProperties = ['toString', 'valueOf', 'constructor', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString'];
            
            sensitiveProperties.forEach(prop => {
                const originalDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, prop);
                if (originalDescriptor && originalDescriptor.configurable) {
                    Object.defineProperty(Object.prototype, prop, {
                        set: function(value) {
                            self.reportVulnerability({
                                source: { label: 'Unknown', property: 'Unknown' },
                                sink: { label: 'Prototype Pollution', property: `Object.prototype.${prop}` },
                                value: String(value),
                                url: window.location.href,
                                severity: 'Critical',
                                type: 'Prototype Pollution'
                            });
                            
                            if (originalDescriptor.set) {
                                return originalDescriptor.set.call(this, value);
                            }
                        },
                        get: originalDescriptor.get,
                        configurable: originalDescriptor.configurable,
                        enumerable: originalDescriptor.enumerable
                    });
                }
            });
        }

        /**
         * 检查是否存在 XSS 漏洞
         * @param {string} sinkName - 接收点名称
         * @param {string} value - 要检查的值
         * @param {Element} [element] - 相关的 DOM 元素
         */
        checkForXSS(sinkName, value, element) {
            if (!value || typeof value !== 'string') {
                return;
            }
            
            // 检查值是否包含潜在的 XSS 载荷
            if (this.isPotentialXSSPayload(value)) {
                // 尝试确定源
                const source = this.determineSource(value);
                
                // 确定严重性
                const severity = this.determineSeverity(sinkName);
                
                // 确定漏洞类型
                const type = this.determineVulnerabilityType(sinkName);
                
                this.reportVulnerability({
                    source: source,
                    sink: { label: sinkName, property: sinkName },
                    value: value,
                    element: element,
                    url: window.location.href,
                    severity: severity,
                    type: type
                });
            }
        }

        /**
         * 判断值是否包含潜在的 XSS 载荷
         * @param {string} value - 要检查的值
         * @returns {boolean} 是否包含潜在的 XSS 载荷
         */
        isPotentialXSSPayload(value) {
            if (!value || typeof value !== 'string') {
                return false;
            }
            
            // 检查常见的 XSS 载荷模式
            const xssPatterns = [
                // 脚本标签
                /<script\b[^>]*>(.*?)<\/script>/i,
                
                // JavaScript 协议
                /javascript:/i,
                
                // 事件处理程序
                /on\w+\s*=\s*["']?[^"']*["']?/i,
                
                // 常见的 XSS 向量
                /<img\b[^>]*\bonerror\b[^>]*>/i,
                /<iframe\b[^>]*>/i,
                /<svg\b[^>]*\bonload\b[^>]*>/i,
                /<svg\b[^>]*\bonclick\b[^>]*>/i,
                /<svg\b[^>]*\bonerror\b[^>]*>/i,
                /<object\b[^>]*>/i,
                /<embed\b[^>]*>/i,
                /<math\b[^>]*\bxlink:href\b[^>]*>/i,
                
                // JavaScript 函数调用
                /alert\s*\(/i,
                /confirm\s*\(/i,
                /prompt\s*\(/i,
                /eval\s*\(/i,
                /setTimeout\s*\(/i,
                /setInterval\s*\(/i,
                /Function\s*\(/i,
                /document\.write\s*\(/i,
                /document\.cookie/i,
                /\.innerHTML/i,
                /\.outerHTML/i,
                /\.insertAdjacentHTML/i,
                /\.createContextualFragment/i,
                
                // 数据 URI
                /data:text\/html/i,
                /data:application\/javascript/i,
                
                // 表达式
                /expression\s*\(/i,
                
                // 基于 CSS 的攻击
                /url\s*\(\s*["']?javascript:/i,
                
                // 特殊字符序列
                /&#x[0-9a-f]+;/i,  // 十六进制 HTML 实体
                /&#[0-9]+;/i,      // 十进制 HTML 实体
                /\\x[0-9a-f]{2}/i, // 十六进制转义序列
                /\\u[0-9a-f]{4}/i  // Unicode 转义序列
            ];
            
            return xssPatterns.some(pattern => pattern.test(value));
        }

        /**
         * 确定 XSS 载荷的源
         * @param {string} value - 包含 XSS 载荷的值
         * @returns {Object} 源信息
         */
        determineSource(value) {
            // 检查是否来自 URL 参数
            const urlParams = new URLSearchParams(window.location.search);
            for (const [key, paramValue] of urlParams.entries()) {
                if (value.includes(paramValue) && this.isPotentialXSSPayload(paramValue)) {
                    return { label: 'URL Parameter', property: key };
                }
            }
            
            // 检查是否来自 URL 哈希
            if (window.location.hash && value.includes(window.location.hash)) {
                return { label: 'location.hash', property: 'location.hash' };
            }
            
            // 检查是否来自 localStorage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const storageValue = localStorage.getItem(key);
                if (value.includes(storageValue) && this.isPotentialXSSPayload(storageValue)) {
                    return { label: 'localStorage', property: key };
                }
            }
            
            // 检查是否来自 sessionStorage
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const storageValue = sessionStorage.getItem(key);
                if (value.includes(storageValue) && this.isPotentialXSSPayload(storageValue)) {
                    return { label: 'sessionStorage', property: key };
                }
            }
            
            // 检查是否来自 document.cookie
            const cookies = document.cookie.split(';');
            for (const cookie of cookies) {
                const [name, cookieValue] = cookie.trim().split('=');
                if (cookieValue && value.includes(cookieValue) && this.isPotentialXSSPayload(cookieValue)) {
                    return { label: 'document.cookie', property: name };
                }
            }
            
            // 检查是否来自 window.name
            if (window.name && value.includes(window.name) && this.isPotentialXSSPayload(window.name)) {
                return { label: 'window.name', property: 'window.name' };
            }
            
            // 检查是否来自 document.referrer
            if (document.referrer && value.includes(document.referrer)) {
                return { label: 'document.referrer', property: 'document.referrer' };
            }
            
            // 默认源
            return { label: 'Unknown', property: 'Unknown' };
        }

        /**
         * 确定漏洞的严重性
         * @param {string} sinkName - 接收点名称
         * @returns {string} 严重性级别
         */
        determineSeverity(sinkName) {
            // 查找接收点的优先级
            const sink = this.sinks.find(s => s.label === sinkName);
            
            if (sink) {
                // 根据优先级确定严重性
                if (sink.priority <= 14) {
                    return 'Critical'; // JavaScript 执行接收点
                } else if (sink.priority <= 24) {
                    return 'High';     // HTML 注入接收点
                } else if (sink.priority <= 30) {
                    return 'Medium';   // URL 相关接收点
                } else {
                    return 'Low';      // 其他接收点
                }
            }
            
            return 'Medium'; // 默认严重性
        }

        /**
         * 确定漏洞类型
         * @param {string} sinkName - 接收点名称
         * @returns {string} 漏洞类型
         */
        determineVulnerabilityType(sinkName) {
            // 查找接收点的类别
            const sink = this.sinks.find(s => s.label === sinkName);
            
            if (sink) {
                switch (sink.category) {
                    case 'js':
                        return 'DOM-based XSS (JavaScript Execution)';
                    case 'html':
                        return 'DOM-based XSS (HTML Injection)';
                    case 'url':
                        return 'DOM-based XSS (URL Manipulation)';
                    case 'event':
                        return 'DOM-based XSS (Event Handler)';
                    default:
                        return 'DOM-based XSS';
                }
            }
            
            return 'DOM-based XSS'; // 默认类型
        }

        /**
         * 报告发现的漏洞
         * @param {Object} vulnerability - 漏洞信息
         */
        reportVulnerability(vulnerability) {
            // 检查是否已经报告过相同的漏洞
            const isDuplicate = this.detectedVulnerabilities.some(v => 
                v.source.label === vulnerability.source.label &&
                v.source.property === vulnerability.source.property &&
                v.sink.label === vulnerability.sink.label &&
                v.value === vulnerability.value
            );
            
            if (!isDuplicate) {
                console.warn(`[DOM XSS Detector] 检测到潜在的 ${vulnerability.severity} 级别 ${vulnerability.type || 'DOM XSS'} 漏洞:`, vulnerability);
                
                // 添加到已检测漏洞列表
                this.detectedVulnerabilities.push(vulnerability);
                
                // 如果存在回调函数，则调用
                if (typeof window.xssReportCallback === 'function') {
                    window.xssReportCallback(this.detectedVulnerabilities);
                }
                
                // 如果存在显示函数，则调用
                if (typeof window.displayVulnerabilities === 'function') {
                    window.displayVulnerabilities(this.detectedVulnerabilities);
                }
                
                // 如果启用了后端集成，则向后端报告
                if (this.backendIntegration.enabled && this.backendIntegration.autoReport) {
                    this.reportToBackend(vulnerability);
                }
            }
        }

        /**
         * 向后端报告漏洞
         * @param {Object} vulnerability - 漏洞信息
         */
        reportToBackend(vulnerability) {
            if (!this.backendIntegration.endpoint) {
                console.error('[DOM XSS Detector] 后端报告失败: 未配置端点');
                return;
            }
            
            // 准备报告数据
            const reportData = {
                type: vulnerability.type || 'DOM-based XSS',
                severity: vulnerability.severity,
                source: {
                    label: vulnerability.source.label,
                    property: vulnerability.source.property
                },
                sink: {
                    label: vulnerability.sink.label,
                    property: vulnerability.sink.property
                },
                value: vulnerability.value,
                url: vulnerability.url,
                timestamp: new Date().toISOString()
            };
            
            // 发送报告到后端
            fetch(this.backendIntegration.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': this.backendIntegration.apiKey || ''
                },
                body: JSON.stringify(reportData)
            }).catch(error => {
                console.error('[DOM XSS Detector] 后端报告失败:', error);
            });
        }

        /**
         * 配置后端集成
         * @param {Object} config - 配置对象
         * @param {boolean} config.enabled - 是否启用后端集成
         * @param {string} config.endpoint - 后端 API 端点
         * @param {string} config.apiKey - API 密钥
         * @param {boolean} config.autoReport - 是否自动报告漏洞
         */
        configureBackendIntegration(config) {
            this.backendIntegration = {
                ...this.backendIntegration,
                ...config
            };
            
            console.log('[DOM XSS Detector] 后端集成配置已更新');
        }

        /**
         * 清除检测到的漏洞
         */
        clearDetectedVulnerabilities() {
            this.detectedVulnerabilities = [];
        }

        /**
         * 获取检测到的漏洞
         * @returns {Array} 检测到的漏洞列表
         */
        getDetectedVulnerabilities() {
            return this.detectedVulnerabilities;
        }

        /**
         * 获取按严重性分组的漏洞
         * @returns {Object} 按严重性分组的漏洞
         */
        getVulnerabilitiesBySeverity() {
            const result = {
                Critical: [],
                High: [],
                Medium: [],
                Low: []
            };
            
            this.detectedVulnerabilities.forEach(vuln => {
                if (result[vuln.severity]) {
                    result[vuln.severity].push(vuln);
                } else {
                    result.Medium.push(vuln);
                }
            });
            
            return result;
        }

        /**
         * 获取漏洞统计信息
         * @returns {Object} 漏洞统计信息
         */
        getVulnerabilityStatistics() {
            const stats = {
                total: this.detectedVulnerabilities.length,
                bySeverity: {
                    Critical: 0,
                    High: 0,
                    Medium: 0,
                    Low: 0
                },
                byType: {}
            };
            
            this.detectedVulnerabilities.forEach(vuln => {
                // 按严重性统计
                if (stats.bySeverity[vuln.severity] !== undefined) {
                    stats.bySeverity[vuln.severity]++;
                } else {
                    stats.bySeverity.Medium++;
                }
                
                // 按类型统计
                const type = vuln.type || 'DOM-based XSS';
                if (!stats.byType[type]) {
                    stats.byType[type] = 0;
                }
                stats.byType[type]++;
            });
            
            return stats;
        }
    }

    // 创建并导出 DOM XSS 检测器实例
    window.DOMXSSDetector = new DOMXSSDetector();
    
    console.log("[DOM XSS Detector] 已加载");
})();