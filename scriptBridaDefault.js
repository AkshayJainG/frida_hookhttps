'use strict';

// 1 - FRIDA EXPORTS

rpc.exports = {
	
	// BE CAREFUL: Do not use uppercase characters in exported function name (automatically converted lowercase by Pyro)
	
	exportedfunction: function() {
	
		// Do stuff...	
		// This functions can be called from custom plugins or from Brida "Execute method" dedicated tab

	},
	
	// Function executed when executed Brida contextual menu option 1.
	// Input is passed from Brida encoded in ASCII HEX and must be returned in ASCII HEX (because Brida will decode the output
	// from ASCII HEX). Use auxiliary functions for the conversions.
	contextcustom1: function(message) {
		return "6566";
	},
	
	// Function executed when executed Brida contextual menu option 2.
	// Input is passed from Brida encoded in ASCII HEX and must be returned in ASCII HEX (because Brida will decode the output
	// from ASCII HEX). Use auxiliary functions for the conversions.
	contextcustom2: function(message) {
		return "6768";
	},
	
	// Function executed when executed Brida contextual menu option 3.
	// Input is passed from Brida encoded in ASCII HEX and must be returned in ASCII HEX (because Brida will decode the output
	// from ASCII HEX). Use auxiliary functions for the conversions.
	contextcustom3: function(message) {
		return "6768";
	},
	
	// Function executed when executed Brida contextual menu option 4.
	// Input is passed from Brida encoded in ASCII HEX and must be returned in ASCII HEX (because Brida will decode the output
	// from ASCII HEX). Use auxiliary functions for the conversions.
	contextcustom4: function(message) {
		return "6768";
	},

	// **** BE CAREFULL ****
	// Do not remove these functions. They are used by Brida plugin in the "Analyze binary" tab!
	// *********************
	getallclasses: function() {
		var result = []
		if (ObjC.available) {
			for (var className in ObjC.classes) {
				if (ObjC.classes.hasOwnProperty(className)) {
					result.push(className);
				}
			}
		} else if(Java.available) {
			Java.perform(function() {
				Java.enumerateLoadedClasses({
					onMatch: function (className) {
						result.push(className);
					},
					onComplete: function() {
					}
				});
			});
		}
		return result;
	},

	getallmodules: function() {
		var results = {}
		var matches = Process.enumerateModules( {
			onMatch: function (module) {
				results[module['name']] = module['base'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	getmoduleimports: function(importname) {
		var results = {}
		var matches = Module.enumerateImports(importname, {
			onMatch: function (module) {
				results[module['type'] + ": " + module['name']] = module['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	getmoduleexports: function(exportname) {
		var results = {}
		var matches = Module.enumerateExports(exportname, {
			onMatch: function (module) {
				results[module['type'] + ": " + module['name']] = module['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	getclassmethods: function(classname) {
		var results = {}
		if (ObjC.available) {
			var resolver = new ApiResolver("objc");
			var matches = resolver.enumerateMatches("*[" + classname + " *]", {
				onMatch: function (match) {
					results[match['name']] = match['address'];
				},
				onComplete: function () {
				}
			});
		} else if(Java.available) {
			Java.perform(function() {
				results = getJavaMethodArgumentTypes(classname);
			});
		}
		return results;
	},

	findobjcmethods: function(searchstring) {
		var results = {}
		var resolver = new ApiResolver("objc");
		var matches = resolver.enumerateMatches("*[*" + searchstring + "* *]", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		matches = resolver.enumerateMatches("*[* *" + searchstring + "*]", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	findimports: function(searchstring) {
		var results = {}
		var resolver = new ApiResolver("module");
		var matches = resolver.enumerateMatches("imports:*" + searchstring + "*!*", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		matches = resolver.enumerateMatches("imports:*!*" + searchstring + "*", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	findexports: function(searchstring) {
		var results = {}
		var resolver = new ApiResolver("module");
		var matches = resolver.enumerateMatches("exports:*" + searchstring + "*!*", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		matches = resolver.enumerateMatches("exports:*!*" + searchstring + "*", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	detachall: function() {
		Interceptor.detachAll();
	},

	// generic trace
	trace: function (pattern,type,backtrace) {
		// SINGLE EXPORT (ALL EXPORT OF A MODULE CAN BE A MESS AND CRASH THE APP)
		if(type == "export") {
			var res = new ApiResolver("module");
			pattern = "exports:" + pattern;
			var matches = res.enumerateMatchesSync(pattern);
			var targets = uniqBy(matches, JSON.stringify);
			targets.forEach(function(target) {
				traceModule(target.address, target.name, backtrace);
			});
		//OBJC
		} else if(type.startsWith("objc")) {
			if (ObjC.available) {
				var res;
				if(type === "objc_class") {
					res = new ApiResolver("objc");
					pattern = "*[" + pattern + " *]";
				} else if(type === "objc_method") {
					res = new ApiResolver("objc");
				}
				var matches = res.enumerateMatchesSync(pattern);
				var targets = uniqBy(matches, JSON.stringify);
				targets.forEach(function(target) {
					traceObjC(target.address, target.name,backtrace);
				});
			}
		// ANDROID
		} else if(type.startsWith("java")) {
			if(Java.available) {
				Java.perform(function() {
					if(type === "java_class") {
						var methodsDictionary = getJavaMethodArgumentTypes(pattern);
						var targets = Object.keys(methodsDictionary);
						targets.forEach(function(targetMethod) {
							traceJavaMethod(targetMethod,backtrace);
						});
					} else {
						traceJavaMethod(pattern,backtrace);
					}					
				});
			}
		}
	},

	changereturnvalue: function(pattern, type, typeret, newret)	{
		if(ObjC.available) {
			changeReturnValueIOS(pattern, type, typeret, newret);
		} else if(Java.available) {
			Java.perform(function() {
				changeReturnValueAndroid(pattern, type, typeret, newret);
			});
		} else {
			changeReturnValueGeneric(pattern, type, typeret, newret);
		}
	},

	getplatform: function() {

		if(Java.available) {
			return 0;
		} else if(ObjC.available){
			return 1;
		} else {
			return 2;
		}

	}	

}

// 2 - AUXILIARY FUNCTIONS

// Convert a hex string to a byte array
function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

// Convert a ASCII string to a hex string
function stringToHex(str) {
    return str.split("").map(function(c) {
        return ("0" + c.charCodeAt(0).toString(16)).slice(-2);
    }).join("");
}

// Convert a hex string to a ASCII string
function hexToString(hexStr) {
    var hex = hexStr.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

// Convert a byte array to a hex string
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

// remove duplicates from array
function uniqBy(array, key) {
	var seen = {};
	return array.filter(function(item) {
		var k = key(item);
		return seen.hasOwnProperty(k) ? false : (seen[k] = true);
	});
}

/*
This method is used to get Java methods with arguments in bytecode syntex. By simply calling the getDeclaredMethods of a Java Class object
and then calling toString on each Method object we do not get types in bytecode format. For example we get 'byte[]' instead of
'[B'. This function uses overload object of frida to get types in correct bytecode form.
*/
function getJavaMethodArgumentTypes(classname) {	
	if(Java.available) {	
		var results = {};
		Java.perform(function() {
			var hook = Java.use(classname);
			var res = hook.class.getDeclaredMethods();			
			res.forEach(function(s) { 
				//console.log("s " + s);
				var targetClassMethod = parseJavaMethod(s.toString());
				//console.log("targetClassMethod " + targetClassMethod);
				var delim = targetClassMethod.lastIndexOf(".");
				if (delim === -1) return;
				var targetClass = targetClassMethod.slice(0, delim)
				var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
				//console.log("targetClass " + targetClass);
				//console.log("targetMethod " + targetMethod);
				var hookClass = Java.use(targetClass);
				var classMethodOverloads = hookClass[targetMethod].overloads;
				classMethodOverloads.forEach(function(cmo) {
					// overload.argumentTypes is an array of objects representing the arguments. In the "className" field of each object there 
					// is the bytecode form of the class of the current argument 
					var argumentTypes = cmo.argumentTypes;
					var argumentTypesArray = []
					argumentTypes.forEach(function(cmo) {
						argumentTypesArray.push(cmo.className);
					});
					var argumentTypesString = argumentTypesArray.toString();
					// overload.returnType.className contain the bytecode form of the class of the return value
					var currentReturnType = cmo.returnType.className;
					var newPattern = currentReturnType + " " + targetClassMethod + "(" + argumentTypesString + ")";
					//console.log(newPattern);
					results[newPattern] = 0;
				});
				hookClass.$dispose;
			});				
			hook.$dispose;			
		});
		return results;
	}
}

function changeReturnValueIOS(pattern, type, typeret, newret) {
	var res;
	if(type === "objc_method") {
		res = new ApiResolver("objc");
	} else {
		// SINGLE EXPORT
		res = new ApiResolver("module");
		pattern = "exports:" + pattern;
	}
	var matches = res.enumerateMatchesSync(pattern);
	var targets = uniqBy(matches, JSON.stringify);
	targets.forEach(function(target) {
		Interceptor.attach(target.address, {
			onEnter: function(args) {
			},
			onLeave: function(retval) {
				if(typeret === "String") {
					var a1 = ObjC.classes.NSString.stringWithString_(newret);
					try {
						console.log("*** " + pattern + " Replacing " + ObjC.Object(retval) + " with " + a1);						
					} catch(err) {
						console.log("*** " + pattern + " Replacing " + retval + " with " + a1);
					}
					retval.replace(a1);
				} else if(typeret === "Ptr") {
					console.log("*** " + pattern + " Replacing " + ptr(retval) + " with " + ptr(newret));
					retval.replace(ptr(newret));
				} else if(typeret === "Boolean") {
					if(newret === "true") {
						var toRet = 1;
					} else {
						var toRet = 0;
					}
					console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
					retval.replace(toRet);
				} else {
					console.log("*** " + pattern + " Replacing " + retval + " with " + newret);
					retval.replace(newret);
				}
			}
		});
	});	
	console.log("*** Replacing return value of " + pattern + " with " + newret);
}

function changeReturnValueGeneric(pattern, type, typeret, newret) {
	var res = new ApiResolver("module");
	pattern = "exports:" + pattern;
	var matches = res.enumerateMatchesSync(pattern);
	var targets = uniqBy(matches, JSON.stringify);
	targets.forEach(function(target) {
		Interceptor.attach(target.address, {
			onEnter: function(args) {
			},
			onLeave: function(retval) {
				if(typeret === "Ptr") {
					console.log("*** " + pattern + " Replacing " + ptr(retval) + " with " + ptr(newret));
					retval.replace(ptr(newret));
				} else if(typeret === "Boolean") {
					if(newret === "true") {
						var toRet = 1;
					} else {
						var toRet = 0;
					}
					console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
					retval.replace(toRet);
				} else {
					console.log("*** " + pattern + " Replacing " + retval + " with " + newret);
					retval.replace(newret);
				}
			}
		});
	});	
	console.log("*** Replacing return value of " + pattern + " with " + newret);
}

function changeReturnValueAndroid(pattern, type, typeret, newret) {
	if(type === "java_method") {
		var targetClassMethod = parseJavaMethod(pattern);
		//console.log(targetClassMethod);
		var argsTargetClassMethod = getJavaMethodArguments(pattern);
		//console.log(argsTargetClassMethod);
		var delim = targetClassMethod.lastIndexOf(".");
		if (delim === -1) return;
		var targetClass = targetClassMethod.slice(0, delim)
		var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
		//console.log(targetClass);
		//console.log(targetMethod);
		var hook = Java.use(targetClass);
		hook[targetMethod].overload.apply(this,argsTargetClassMethod).implementation = function() {
			var retval = this[targetMethod].apply(this, arguments);
			var toRet = newret;
			if(typeret === "String") {
				var stringClass = Java.use("java.lang.String");
				toRet = stringClass.$new(newret);
			} else if(typeret === "Ptr") {
				toRet = ptr(newret);
			} else if(typeret === "Boolean") {
				if(newret === "true") {
					toRet = true;
				} else {
					toRet = false;
				}
			}			
			console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
			return toRet;
		}
	// SINGLE EXPORT
	} else {
		var res = new ApiResolver("module");
		var pattern = "exports:" + pattern;
		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);
		targets.forEach(function(target) {
			Interceptor.attach(target.address, {
				onEnter: function(args) {
				},
				onLeave: function(retval) {
					var toRet = newret;
					if(typeret === "String") {
						var stringClass = Java.use("java.lang.String");
						var toRet = stringClass.$new(newret);
					} else if(typeret === "ptr") {
						toRet = ptr(newret);
					} else if(typeret === "Boolean") {
						if(newret === "true") {
							var toRet = 1;
						} else {
							var toRet = 0;
						}
						console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
						retval.replace(toRet);
					}				
					console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
					retval.replace(toRet);
				}
			});
		});	
	}
	console.log("*** Replacing return value of " + pattern + " with " + newret);
}

// trace ObjC methods
function traceObjC(impl, name, backtrace) {
	console.log("*** Tracing " + name);
	Interceptor.attach(impl, {
		onEnter: function(args) {
			console.log("*** entered " + name);
			console.log("Caller: " + DebugSymbol.fromAddress(this.returnAddress));
			// print args
			if (name.indexOf(":") !== -1) {
				console.log("Parameters:");
				var par = name.split(":");
				par[0] = par[0].split(" ")[1];
				for (var i = 0; i < par.length - 1; i++) {
					printArg(par[i] + ": ", args[i + 2]);
				}
			}
			if(backtrace === "true") {
				console.log("Backtrace:\n\t" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n\t"));
			}			
		},
		onLeave: function(retval) {
			console.log("*** exiting " + name);
			console.log("Return value:");
			printArg("retval: ", retval);			
		}
	});
}

/*
INPUT LIKE: public boolean a.b.functionName(java.lang.String)
OUTPUT LIKE: a.b.functionName
*/
function parseJavaMethod(method) {
	var parSplit = method.split("(");
	var spaceSplit = parSplit[0].split(" ");
	return spaceSplit[spaceSplit.length - 1];
}

//INPUT LIKE: public boolean a.b.functionName(java.lang.String,java.lang.String)
//OUTPUT LIKE: ["java.lang.String","java.lang.String"]
function getJavaMethodArguments(method) {
	var m = method.match(/.*\((.*)\).*/);
	if(m[1] !== "") {
		return m[1].split(",");
	} else {
		return [];
	}
}

// trace a specific Java Method
function traceJavaMethod(pattern,backtrace) {
	var targetClassMethod = parseJavaMethod(pattern);
	//console.log(targetClassMethod);
	var argsTargetClassMethod = getJavaMethodArguments(pattern);
	//console.log(argsTargetClassMethod);
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;
	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
	var hook = Java.use(targetClass);
	//var overloadCount = hook[targetMethod].overloads.length;
	console.log("*** Tracing " + pattern);
	hook[targetMethod].overload.apply(this,argsTargetClassMethod).implementation = function() {		
		console.log("*** entered " + targetClassMethod);
		// print args
		if (arguments.length) console.log("Parameters:");
		for (var j = 0; j < arguments.length; j++) {
			console.log("\targ[" + j + "]: " + arguments[j]);
		}
		// print backtrace
		if(backtrace === "true") {
			Java.perform(function() {
				var threadClass = Java.use("java.lang.Thread");
				var currentThread = threadClass.currentThread();
				var currentStackTrace = currentThread.getStackTrace();
				console.log("Backtrace:");
				currentStackTrace.forEach(function(st) {
					console.log("\t" + st.toString());
				});
			});
		}
		// print retval
		var retval = this[targetMethod].apply(this, arguments);		
		console.log("*** exiting " + targetClassMethod);
		console.log("Return value:");
		console.log("\tretval: " + retval);
		return retval;
	}
}

// trace Module functions
function traceModule(impl, name, backtrace) {
	console.log("*** Tracing " + name);
	Interceptor.attach(impl, {
		onEnter: function(args) {
			console.log("*** entered " + name);
			if(backtrace === "true") {
				console.log("Backtrace:\n\t" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t"));
			}			
		},
		onLeave: function(retval) {
			console.log("*** exiting " + name);
			console.log("Return value:");
			if(ObjC.available) {
				printArg("retval: ", retval);			
			} else {
				console.log("\tretval: ", retval);
			}			
		}
	});
}

// print helper
function printArg(desc, arg) {
	if(arg != 0x0) {
		try {
			var objectArg = ObjC.Object(arg);				
			console.log("\t(" + objectArg.$className + ") " + desc + objectArg.toString());
		} catch(err2) {
			console.log("\t" + desc + arg);
		}
	} else {
		console.log("\t" + desc + "0x0");
	}
}

// 3 - FRIDA HOOKS (if needed)

if(ObjC.available) {
	
	// Insert here Frida interception methods, if needed 
	// (es. Bypass Pinning, save values, etc.)
	console.log("ObjC.available:");

}else if(Java.available) {

	console.log("Java.available:");
	Java.perform(function() {

/*
hook list:
1.SSLcontext
2.okhttp
3.webview
4.XUtils
5.httpclientandroidlib
6.JSSE
7.network\_security\_config (android 7.0+)
8.Apache Http client (support partly)
*/

// Attempts to bypass SSL pinning implementations in a number of
// ways. These include implementing a new TrustManager that will
// accept any SSL certificate, overriding OkHTTP v3 check()
// method etc.
var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
var SSLContext = Java.use('javax.net.ssl.SSLContext');
var quiet_output = false;

// Helper method to honor the quiet flag.
function quiet_send(data) {

    if (quiet_output) {

        return;
    }

    send(data)
}


// Implement a new TrustManager
// ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
// Java.registerClass() is only supported on ART for now(201803). 所以android 4.4以下不兼容,4.4要切换成ART使用.
/*
06-07 16:15:38.541 27021-27073/mi.sslpinningdemo W/System.err: java.lang.IllegalArgumentException: Required method checkServerTrusted(X509Certificate[], String, String, String) missing
06-07 16:15:38.542 27021-27073/mi.sslpinningdemo W/System.err:     at android.net.http.X509TrustManagerExtensions.<init>(X509TrustManagerExtensions.java:73)
        at mi.ssl.MiPinningTrustManger.<init>(MiPinningTrustManger.java:61)
06-07 16:15:38.543 27021-27073/mi.sslpinningdemo W/System.err:     at mi.sslpinningdemo.OkHttpUtil.getSecPinningClient(OkHttpUtil.java:112)
        at mi.sslpinningdemo.OkHttpUtil.get(OkHttpUtil.java:62)
        at mi.sslpinningdemo.MainActivity$1$1.run(MainActivity.java:36)
*/
var X509Certificate = Java.use("java.security.cert.X509Certificate");
var TrustManager;
try {
    TrustManager = Java.registerClass({
        name: 'org.wooyun.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {
            },
            checkServerTrusted: function (chain, authType) {
            },
            getAcceptedIssuers: function () {
                // var certs = [X509Certificate.$new()];
                // return certs;
                return [];
            }
        }
    });
} catch (e) {
    console.log("registerClass from X509TrustManager >>>>>>>> " + e.message);
}





// Prepare the TrustManagers array to pass to SSLContext.init()
var TrustManagers = [TrustManager.$new()];

try {
    // Prepare a Empty SSLFactory
    var TLS_SSLContext = SSLContext.getInstance("TLS");
    TLS_SSLContext.init(null,TrustManagers,null);
    var EmptySSLFactory = TLS_SSLContext.getSocketFactory();
} catch (e) {
    console.log(e.message);
}

send('Custom, Empty TrustManager ready');

// Get a handle on the init() on the SSLContext class
var SSLContext_init = SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

// Override the init method, specifying our new TrustManager
SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {

    quiet_send('Overriding SSLContext.init() with the custom TrustManager');

    SSLContext_init.call(this, null, TrustManagers, null);
};

/*** okhttp3.x unpinning ***/


// Wrap the logic in a try/catch as not all applications will have
// okhttp as part of the app.
try {

    var CertificatePinner = Java.use('okhttp3.CertificatePinner');

    console.log('OkHTTP 3.x Found');

    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {

        quiet_send('OkHTTP 3.x check() called. Not throwing an exception.');
    }

} catch (err) {

    // If we dont have a ClassNotFoundException exception, raise the
    // problem encountered.
    if (err.message.indexOf('ClassNotFoundException') === 0) {

        throw new Error(err);
    }
}

// Appcelerator Titanium PinningTrustManager

// Wrap the logic in a try/catch as not all applications will have
// appcelerator as part of the app.
try {

    var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');

    send('Appcelerator Titanium Found');

    PinningTrustManager.checkServerTrusted.implementation = function () {

        quiet_send('Appcelerator checkServerTrusted() called. Not throwing an exception.');
    }

} catch (err) {

    // If we dont have a ClassNotFoundException exception, raise the
    // problem encountered.
    if (err.message.indexOf('ClassNotFoundException') === 0) {

        throw new Error(err);
    }
}

/*** okhttp unpinning ***/


try {
    var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
    OkHttpClient.setCertificatePinner.implementation = function(certificatePinner){
        // do nothing
        console.log("OkHttpClient.setCertificatePinner Called!");
        return this;
    };

    // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
    var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(p0, p1){
        // do nothing
        console.log("okhttp Called! [Certificate]");
        return;
    };
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1){
        // do nothing
        console.log("okhttp Called! [List]");
        return;
    };
} catch (e) {
 console.log("com.squareup.okhttp not found");
}

/*** WebView Hooks ***/

/* frameworks/base/core/java/android/webkit/WebViewClient.java */
/* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
var WebViewClient = Java.use("android.webkit.WebViewClient");

WebViewClient.onReceivedSslError.implementation = function (webView,sslErrorHandler,sslError){
    quiet_send("WebViewClient onReceivedSslError invoke");
    //执行proceed方法
    sslErrorHandler.proceed();
    return ;
};

WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function (a,b,c,d){
    quiet_send("WebViewClient onReceivedError invoked");
    return ;
};

WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (){
    quiet_send("WebViewClient onReceivedError invoked");
    return ;
};

/*** JSSE Hooks ***/

/* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
/* public final TrustManager[] getTrustManager() */

var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
TrustManagerFactory.getTrustManagers.implementation = function(){
    quiet_send("TrustManagerFactory getTrustManagers invoked");
    return TrustManagers;
}

var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
/* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
/* public void setDefaultHostnameVerifier(HostnameVerifier) */
HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier){
    quiet_send("HttpsURLConnection.setDefaultHostnameVerifier invoked");
        return null;
};
/* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
/* public void setSSLSocketFactory(SSLSocketFactory) */
HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory){
    quiet_send("HttpsURLConnection.setSSLSocketFactory invoked");
        return null;
};
/* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
/* public void setHostnameVerifier(HostnameVerifier) */
HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier){
    quiet_send("HttpsURLConnection.setHostnameVerifier invoked");
        return null;
};

/*** Xutils3.x hooks ***/
//Implement a new HostnameVerifier
var TrustHostnameVerifier;
try {
    TrustHostnameVerifier = Java.registerClass({
        name: 'org.wooyun.TrustHostnameVerifier',
        implements: [HostnameVerifier],
        method: {
            verify: function (hostname, session) {
                return true;
            }
        }
    });

} catch (e) {
    //java.lang.ClassNotFoundException: Didn't find class "org.wooyun.TrustHostnameVerifier"
    console.log("registerClass from hostnameVerifier >>>>>>>> " + e.message);
}

try {
    var RequestParams = Java.use('org.xutils.http.RequestParams');
    RequestParams.setSslSocketFactory.implementation = function(sslSocketFactory){
        sslSocketFactory = EmptySSLFactory;
        return null;
    }

    RequestParams.setHostnameVerifier.implementation = function(hostnameVerifier){
        hostnameVerifier = TrustHostnameVerifier.$new();
        return null;
    }

} catch (e) {
    console.log("Xutils hooks not Found");
}

/*** httpclientandroidlib Hooks ***/
try {
    var AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
    AbstractVerifier.verify.overload('java.lang.String','[Ljava.lang.String','[Ljava.lang.String','boolean').implementation = function(){
        quiet_send("httpclientandroidlib Hooks");
        return null;
    }
} catch (e) {
    console.log("httpclientandroidlib Hooks not found");
}

/***
android 7.0+ network_security_config TrustManagerImpl hook
apache httpclient partly
***/
var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
// try {
//     var Arrays = Java.use("java.util.Arrays");
//     //apache http client pinning maybe baypass
//     //https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#471
//     TrustManagerImpl.checkTrusted.implementation = function (chain, authType, session, parameters, authType) {
//         quiet_send("TrustManagerImpl checkTrusted called");
//         //Generics currently result in java.lang.Object
//         return Arrays.asList(chain);
//     }
//
// } catch (e) {
//     console.log("TrustManagerImpl checkTrusted nout found");
// }

try {
    // Android 7+ TrustManagerImpl
    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        quiet_send("TrustManagerImpl verifyChain called");
        // Skip all the logic and just return the chain again :P
        //https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/november/bypassing-androids-network-security-configuration/
        // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
        return untrustedChain;
    }
} catch (e) {
    console.log("TrustManagerImpl verifyChain nout found below 7.0");
}
// -- Sample Java
//
// "Generic" TrustManager Example
//
// TrustManager[] trustAllCerts = new TrustManager[] {
//     new X509TrustManager() {
//         public java.security.cert.X509Certificate[] getAcceptedIssuers() {
//             return null;
//         }
//         public void checkClientTrusted(X509Certificate[] certs, String authType) {  }

//         public void checkServerTrusted(X509Certificate[] certs, String authType) {  }

//     }
// };

// SSLContext sslcontect = SSLContext.getInstance("TLS");
// sslcontect.init(null, trustAllCerts, null);

// OkHTTP 3 Pinning Example
// String hostname = "swapi.co";
// CertificatePinner certificatePinner = new CertificatePinner.Builder()
//         .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
//         .build();

// OkHttpClient client = new OkHttpClient.Builder()
//         .certificatePinner(certificatePinner)
//         .build();

// Request request = new Request.Builder()
//         .url("https://swapi.co/api/people/1")
//         .build();

// Response response = client.newCall(request).execute();
});
	
} else
{
	console.log("Nothing");
}


