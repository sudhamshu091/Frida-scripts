
Java.perform(function() {

    console.log("[*] Hooking Methods in com.scottyab.rootbeer.RootBeer Class")

    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.isRooted() Method");
    RootBeer["isRooted"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.isRooted() Method');
        let ret = this.isRooted();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.isRooted() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.isRooted() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.isRootedWithoutBusyBoxCheck() Method");
    RootBeer["isRootedWithoutBusyBoxCheck"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.isRootedWithoutBusyBoxCheck() Method');
        let ret = this.isRootedWithoutBusyBoxCheck();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.isRootedWithoutBusyBoxCheck() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.isRootedWithoutBusyBoxCheck() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.isRootedWithBusyBoxCheck() Method");
    RootBeer["isRootedWithBusyBoxCheck"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.isRootedWithBusyBoxCheck() Method');
        let ret = this.isRootedWithBusyBoxCheck();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.isRootedWithBusyBoxCheck() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.isRootedWithBusyBoxCheck() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.detectTestKeys() Method");
    RootBeer["detectTestKeys"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.detectTestKeys() Method');
        let ret = this.detectTestKeys();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.detectTestKeys() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.detectTestKeys() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.detectRootManagementApps(String[] strArr) Method");
    RootBeer["detectRootManagementApps"].overload("[Ljava.lang.String;").implementation = function(arg) {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.detectRootManagementApps(String[] strArr) Method - Argument: ' + arg);
        let ret = this.detectRootManagementApps(arg);
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.detectRootManagementApps(String[] strArr) Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.detectRootManagementApps(String[] strArr) Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.detectPotentiallyDangerousApps(String[] strArr) Method");
    RootBeer["detectPotentiallyDangerousApps"].overload("[Ljava.lang.String;").implementation = function(args) {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.detectPotentiallyDangerousApps(String[] strArr) Method - Arguments: ' + args);
        let ret = this.detectPotentiallyDangerousApps(args);
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.detectPotentiallyDangerousApps(String[] strArr) Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.detectPotentiallyDangerousApps(String[] strArr) Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.detectRootCloakingApps(String[] strArr) Method");
    RootBeer["detectRootCloakingApps"].overload("[Ljava.lang.String;").implementation = function(args) {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.detectRootCloakingApps(String[] strArr) Method - Arguments: ' + args);
        let ret = this.detectRootCloakingApps(args);
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.detectRootCloakingApps(String[] strArr) Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.detectRootCloakingApps(String[] strArr) Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForSuBinary() Method");
    RootBeer["checkForSuBinary"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForSuBinary() Method');
        let ret = this.checkForSuBinary();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForSuBinary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForSuBinary() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForMagiskBinary() Method");
    RootBeer["checkForMagiskBinary"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForMagiskBinary() Method');
        let ret = this.checkForMagiskBinary();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForMagiskBinary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForMagiskBinary() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForBusyBoxBinary() Method");
    RootBeer["checkForBusyBoxBinary"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForBusyBoxBinary() Method');
        let ret = this.checkForBusyBoxBinary();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForBusyBoxBinary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForBusyBoxBinary() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForBinary(String str) Method");
    RootBeer["checkForBinary"].implementation = function(arg) {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForBinary() Method - Argument : ' + arg);
        let ret = this.checkForBinary(arg);
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForBinary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForBinary() Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.propsReader() Method");
    RootBeer["propsReader"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.propsReader() Method');
        let ret = this.propsReader();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.propsReader() Method = ' + ret);
        var newret = null;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.propsReader() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.mountReader() Method");
    RootBeer["mountReader"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.mountReader() Method');
        let ret = this.mountReader();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.mountReader() Method = ' + ret);
        var newret = null;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.mountReader() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForDangerousProps() Method");
    RootBeer["checkForDangerousProps"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForDangerousProps() Method');
        let ret = this.checkForDangerousProps();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForDangerousProps() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForDangerousProps() Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForRWPaths() Method");
    RootBeer["checkForRWPaths"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForRWPaths() Method');
        let ret = this.checkForRWPaths();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForRWPaths() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForRWPaths() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkSuExists() Method");
    RootBeer["checkSuExists"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkSuExists() Method');
        let ret = this.checkSuExists();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkSuExists() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkSuExists() Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForNativeLibraryReadAccess() Method");
    RootBeer["checkForNativeLibraryReadAccess"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForNativeLibraryReadAccess() Method');
        let ret = this.checkForNativeLibraryReadAccess();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForNativeLibraryReadAccess() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForNativeLibraryReadAccess() Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.canLoadNativeLibrary() Method");
    RootBeer["canLoadNativeLibrary"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.canLoadNativeLibrary() Method');
        let ret = this.canLoadNativeLibrary();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.canLoadNativeLibrary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.canLoadNativeLibrary() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForRootNative() Method");
    RootBeer["checkForRootNative"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForRootNative() Method');
        let ret = this.checkForRootNative();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForRootNative() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForRootNative() Method = ' + newret);
        return newret;
    };

});

Java.perform(function() {

    var use_single_byte = false;
    var complete_bytes = new Array();
    var index = 0;


    var secretKeySpecDef = Java.use('javax.crypto.spec.SecretKeySpec');

    var ivParameterSpecDef = Java.use('javax.crypto.spec.IvParameterSpec');

    var cipherDef = Java.use('javax.crypto.Cipher');

    var cipherDoFinal_1 = cipherDef.doFinal.overload();
    var cipherDoFinal_2 = cipherDef.doFinal.overload('[B');
    var cipherDoFinal_3 = cipherDef.doFinal.overload('[B', 'int');
    var cipherDoFinal_4 = cipherDef.doFinal.overload('[B', 'int', 'int');
    var cipherDoFinal_5 = cipherDef.doFinal.overload('[B', 'int', 'int', '[B');
    var cipherDoFinal_6 = cipherDef.doFinal.overload('[B', 'int', 'int', '[B', 'int');

    var cipherUpdate_1 = cipherDef.update.overload('[B');
    var cipherUpdate_2 = cipherDef.update.overload('[B', 'int', 'int');
    var cipherUpdate_3 = cipherDef.update.overload('[B', 'int', 'int', '[B');
    var cipherUpdate_4 = cipherDef.update.overload('[B', 'int', 'int', '[B', 'int');

    var secretKeySpecDef_init_1 = secretKeySpecDef.$init.overload('[B', 'java.lang.String');

    var secretKeySpecDef_init_2 = secretKeySpecDef.$init.overload('[B', 'int', 'int', 'java.lang.String');

    var ivParameterSpecDef_init_1 = ivParameterSpecDef.$init.overload('[B');

    var ivParameterSpecDef_init_2 = ivParameterSpecDef.$init.overload('[B', 'int', 'int');

    secretKeySpecDef_init_1.implementation = function(arr, alg) {
        var key = b2s(arr);
        send("Creating " + alg + " secret key, plaintext:\\n" + hexdump(key));
        return secretKeySpecDef_init_1.call(this, arr, alg);
    }

    secretKeySpecDef_init_2.implementation = function(arr, off, len, alg) {
        var key = b2s(arr);
        send("Creating " + alg + " secret key, plaintext:\\n" + hexdump(key));
        return secretKeySpecDef_init_2.call(this, arr, off, len, alg);
    }

    /*ivParameterSpecDef_init_1.implementation = function(arr)
    {
        var iv = b2s(arr);
        send("Creating IV:\\n" + hexdump(iv));
        return ivParameterSpecDef_init_1.call(this, arr);
    }

    ivParameterSpecDef_init_2.implementation = function(arr, off, len)
    {
        var iv = b2s(arr);
        send("Creating IV, plaintext:\\n" + hexdump(iv));
        return ivParameterSpecDef_init_2.call(this, arr, off, len);
    }*/

    cipherDoFinal_1.implementation = function() {
        var ret = cipherDoFinal_1.call(this);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_2.implementation = function(arr) {
        addtoarray(arr);
        var ret = cipherDoFinal_2.call(this, arr);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_3.implementation = function(arr, a) {
        addtoarray(arr);
        var ret = cipherDoFinal_3.call(this, arr, a);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_4.implementation = function(arr, a, b) {
        addtoarray(arr);
        var ret = cipherDoFinal_4.call(this, arr, a, b);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_5.implementation = function(arr, a, b, c) {
        addtoarray(arr);
        var ret = cipherDoFinal_5.call(this, arr, a, b, c);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_6.implementation = function(arr, a, b, c, d) {
        addtoarray(arr);
        var ret = cipherDoFinal_6.call(this, arr, a, b, c, d);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, c);
        return ret;
    }

    cipherUpdate_1.implementation = function(arr) {
        addtoarray(arr);
        return cipherUpdate_1.call(this, arr);
    }

    cipherUpdate_2.implementation = function(arr, a, b) {
        addtoarray(arr);
        return cipherUpdate_2.call(this, arr, a, b);
    }

    cipherUpdate_3.implementation = function(arr, a, b, c) {
        addtoarray(arr);
        return cipherUpdate_3.call(this, arr, a, b, c);
    }

    cipherUpdate_4.implementation = function(arr, a, b, c, d) {
        addtoarray(arr);
        return cipherUpdate_4.call(this, arr, a, b, c, d);
    }

    function info(iv, alg, plain, encoded) {
        send("Performing encryption/decryption");
        if (iv) {
            send("Initialization Vector: \\n" + hexdump(b2s(iv)));
        } else {
            send("Initialization Vector: " + iv);
        }
        send("Algorithm: " + alg);
        send("In: \\n" + hexdump(b2s(plain)));
        send("Out: \\n" + hexdump(b2s(encoded)));
        complete_bytes = [];
        index = 0;
    }

    function hexdump(buffer, blockSize) {
        blockSize = blockSize || 16;
        var lines = [];
        var hex = "0123456789ABCDEF";
        for (var b = 0; b < buffer.length; b += blockSize) {
            var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
            var addr = ("0000" + b.toString(16)).slice(-4);
            var codes = block.split('').map(function(ch) {
                var code = ch.charCodeAt(0);
                return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
            }).join("");
            codes += "   ".repeat(blockSize - block.length);
            var chars = block.replace(/[\\x00-\\x1F\\x20]/g, '.');
            chars += " ".repeat(blockSize - block.length);
            lines.push(addr + " " + codes + "  " + chars);
        }
        return lines.join("\\n");
    }

    function b2s(array) {
        var result = "";
        for (var i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }

    function modulus(x, n) {
        return ((x % n) + n) % n;
    }

    function addtoarray(arr) {
        for (var i = 0; i < arr.length; i++) {
            complete_bytes[index] = arr[i];
            index = index + 1;
        }
    }
});

setTimeout(function() {
    Java.perform(function() {
        console.log("");
        console.log("[.] Debug check bypass");

        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            //console.log('isDebuggerConnected Bypassed !');
            return false;
        }


    });
}, 0);

/*
    frida --codeshare meerkati/universal-android-debugging-bypass -f YOUR_BINARY
    Universal Android Debugging Bypass frida script v0.1
    
    Useful when bypassing USB debugging detection on Android!
    If it doesn't work, remove the conditional statement
    
*/

setTimeout(function() {
    Java.perform(function() {
        var androidSettings = ['adb_enabled'];
        var sdkVersion = Java.use('android.os.Build$VERSION');
        console.log("SDK Version : " + sdkVersion.SDK_INT.value);

        /* API 16 or lower Settings.Global Hook */
        if (sdkVersion.SDK_INT.value <= 16) {
            var settingSecure = Java.use('android.provider.Settings$Secure');

            settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                //console.log("[*]settingSecure.getInt(cr,name) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Secure.getInt(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getInt(cr, name);
                return ret;
            }

            settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
                //console.log("[*]settingSecure.getInt(cr,name,def) : " + name);
                if (name == (androidSettings[0])) {
                    console.log('[+]Secure.getInt(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getInt(cr, name, def);
                return ret;
            }

            settingSecure.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                //console.log("[*]settingSecure.getFloat(cr,name) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Secure.getFloat(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getFloat(cr, name)
                return ret;
            }

            settingSecure.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function(cr, name, def) {
                //console.log("[*]settingSecure.getFloat(cr,name,def) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Secure.getFloat(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getFloat(cr, name, def);
                return ret;
            }

            settingSecure.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                //console.log("[*]settingSecure.getLong(cr,name) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Secure.getLong(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getLong(cr, name)
                return ret;
            }

            settingSecure.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function(cr, name, def) {
                //console.log("[*]settingSecure.getLong(cr,name,def) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Secure.getLong(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getLong(cr, name, def);
                return ret;
            }

            settingSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                //console.log("[*]settingSecure.getString(cr,name) : " + name);
                if (name == androidSettings[0]) {
                    var stringClass = Java.use("java.lang.String");
                    var stringInstance = stringClass.$new("0");

                    console.log('[+]Secure.getString(cr, name) Bypassed');
                    return stringInstance;
                }
                var ret = this.getString(cr, name);
                return ret;
            }
        }

        /* API 17 or higher Settings.Global Hook */
        if (sdkVersion.SDK_INT.value >= 17) {
            var settingGlobal = Java.use('android.provider.Settings$Global');

            settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                //console.log("[*]settingGlobal.getInt(cr,name) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Global.getInt(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getInt(cr, name);
                return ret;
            }

            settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
                //console.log("[*]settingGlobal.getInt(cr,name,def) : " + name);
                if (name == (androidSettings[0])) {
                    console.log('[+]Global.getInt(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getInt(cr, name, def);
                return ret;
            }

            settingGlobal.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                //console.log("[*]settingGlobal.getFloat(cr,name) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Global.getFloat(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getFloat(cr, name);
                return ret;
            }

            settingGlobal.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function(cr, name, def) {
                //console.log("[*]settingGlobal.getFloat(cr,name,def) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Global.getFloat(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getFloat(cr, name, def);
                return ret;
            }

            settingGlobal.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                //console.log("[*]settingGlobal.getLong(cr,name) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Global.getLong(cr, name) Bypassed');
                    return 0;
                }
                var ret = this.getLong(cr, name);
                return ret;
            }

            settingGlobal.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function(cr, name, def) {
                //console.log("[*]settingGlobal.getLong(cr,name,def) : " + name);
                if (name == androidSettings[0]) {
                    console.log('[+]Global.getLong(cr, name, def) Bypassed');
                    return 0;
                }
                var ret = this.getLong(cr, name, def);
                return ret;
            }

            settingGlobal.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                //console.log("[*]settingGlobal.getString(cr,name) : " + name);
                if (name == androidSettings[0]) {
                    var stringClass = Java.use("java.lang.String");
                    var stringInstance = stringClass.$new("0");

                    console.log('[+]Global.getString(cr, name) Bypassed');
                    return stringInstance;
                }
                var ret = this.getString(cr, name);
                return ret;
            }
        }
    });
}, 0);

function bypass_developerMode_check() {
    var settingSecure = Java.use('android.provider.Settings$Secure');
    settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
        console.log("[!] settingSecure.getInt(cr,name) : " + name);
        console.log('[+] 1.Secure.getInt(' + name + ') Bypassed');
        return 0;
    }
    settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        console.log("[!] settingSecure.getInt(cr,name) : " + name);
        console.log('[+] 2.Secure.getInt(' + name + ') Bypassed');
        return 0;
    }
    var settingGlobal = Java.use('android.provider.Settings$Global');
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
        console.log("[!] settingGlobal.getInt(cr,name) : " + name);
        console.log('[+] 1.Global.getInt(' + name + ') Bypassed');
        return 0;
    }
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        console.log("[!] settingGlobal.getInt(cr,name) : " + name);
        console.log('[+] 2.Global.getInt(' + name + ') Bypassed');
        return 0;
    }
}

// Main
Java.perform(function() {
    bypass_developerMode_check();
});

/*  Android ssl certificate pinning bypass script for various methods
	by Maurizio Siddu
	
	Run with:
	frida -U -f [APP_ID] -l frida_multiple_unpinning.js --no-pause
*/

setTimeout(function() {
	Java.perform(function () {
		console.log('');
		console.log('======');
		console.log('[#] Android Bypass for various Certificate Pinning methods [#]');
		console.log('======');


		var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
		var SSLContext = Java.use('javax.net.ssl.SSLContext');
	
		
		// TrustManager (Android < 7) //
		////////////////////////////////
		var TrustManager = Java.registerClass({
			// Implement a custom TrustManager
			name: 'dev.asd.test.TrustManager',
			implements: [X509TrustManager],
			methods: {
				checkClientTrusted: function (chain, authType) {},
				checkServerTrusted: function (chain, authType) {},
				getAcceptedIssuers: function () {return []; }
			}
		});
		// Prepare the TrustManager array to pass to SSLContext.init()
		var TrustManagers = [TrustManager.$new()];
		// Get a handle on the init() on the SSLContext class
		var SSLContext_init = SSLContext.init.overload(
			'[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
		try {
			// Override the init method, specifying the custom TrustManager
			SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
				console.log('[+] Bypassing Trustmanager (Android < 7) request');
				SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
			};
		} catch (err) {
			console.log('[-] TrustManager (Android < 7) pinner not found');
			//console.log(err);
		}

	 
	
		// OkHTTPv3 (quadruple bypass) //
		/////////////////////////////////
		try {
			// Bypass OkHTTPv3 {1}
			var okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');    
			okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {                              
				console.log('[+] Bypassing OkHTTPv3 {1}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] OkHTTPv3 {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass OkHTTPv3 {2}
			// This method of CertificatePinner.check could be found in some old Android app
			var okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');    
			okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing OkHTTPv3 {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] OkHTTPv3 {2} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass OkHTTPv3 {3}
			var okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');    
			okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
				console.log('[+] Bypassing OkHTTPv3 {3}: ' + a);
				return;
			};
		} catch(err) {
			console.log('[-] OkHTTPv3 {3} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass OkHTTPv3 {4}
			var okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');    
			//okhttp3_Activity_4['check$okhttp'].implementation = function (a, b) {
			okhttp3_Activity_4.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (a, b) {		
				console.log('[+] Bypassing OkHTTPv3 {4}: ' + a);
				return;
			};
		} catch(err) {
			console.log('[-] OkHTTPv3 {4} pinner not found');
			//console.log(err);
		}

	
	
		// Trustkit (triple bypass) //
		//////////////////////////////
		try {
			// Bypass Trustkit {1}
			var trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
			trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
				console.log('[+] Bypassing Trustkit {1}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Trustkit {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass Trustkit {2}
			var trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
			trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing Trustkit {2}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Trustkit {2} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass Trustkit {3}
			var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
			trustkit_PinningTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function (chain, authType) {
				console.log('[+] Bypassing Trustkit {3}');
				return;
			};
		} catch (err) {
			console.log('[-] Trustkit {3} pinner not found');
			//console.log(err);
		}
		
	
	
  
		// TrustManagerImpl (Android > 7) //
		////////////////////////////////////
		try {
			var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
			TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
	
			
				console.log('[+] Bypassing TrustManagerImpl (Android > 7): ' + host);
				return untrustedChain;
			};   
		} catch (err) {
			console.log('[-] TrustManagerImpl (Android > 7) pinner not found');
			//console.log(err);
		}   
  
  
		
		// Appcelerator Titanium PinningTrustManager //
		///////////////////////////////////////////////
		try {
			var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
			appcelerator_PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
				console.log('[+] Bypassing Appcelerator PinningTrustManager');
				return;
			};
		} catch (err) {
			console.log('[-] Appcelerator PinningTrustManager pinner not found');
			//console.log(err);
		}



		// Fabric PinningTrustManager //
		////////////////////////////////
		try {
			var fabric_PinningTrustManager = Java.use('io.fabric.sdk.android.services.network.PinningTrustManager');
			fabric_PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
				console.log('[+] Bypassing Fabric PinningTrustManager');
				return;
			};
		} catch (err) {
			console.log('[-] Fabric PinningTrustManager pinner not found');
			//console.log(err);
		}



		// OpenSSLSocketImpl Conscrypt //
		/////////////////////////////////
		try {
			var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
			OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
				console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt');
			};
		} catch (err) {
			console.log('[-] OpenSSLSocketImpl Conscrypt pinner not found');
			//console.log(err);        
		}



		// OpenSSLEngineSocketImpl Conscrypt //
		///////////////////////////////////////
		try {
			var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
			OpenSSLSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (a, b) {
				console.log('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
			};
		} catch (err) {
			console.log('[-] OpenSSLEngineSocketImpl Conscrypt pinner not found');
			//console.log(err);
		}



		// OpenSSLSocketImpl Apache Harmony //
		//////////////////////////////////////
		try {
			var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
			OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
				console.log('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
			};
		} catch (err) {
			console.log('[-] OpenSSLSocketImpl Apache Harmony pinner not found');
			//console.log(err);      
		}



		// PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin) //
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////
		try {
			var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
			phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
				console.log('[+] Bypassing PhoneGap sslCertificateChecker: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] PhoneGap sslCertificateChecker pinner not found');
			//console.log(err);
		}



		// IBM MobileFirst pinTrustedCertificatePublicKey (double bypass) //
		////////////////////////////////////////////////////////////////////
		try {
			// Bypass IBM MobileFirst {1}
			var WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
			WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
				console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
				return;
			};
			} catch (err) {
			console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass IBM MobileFirst {2}
			var WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
			WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
				console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
				return;
			};
		} catch (err) {
			console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {2} pinner not found');
			//console.log(err);
		}



		// IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass) //
		///////////////////////////////////////////////////////////////////////////////////////////////////////
		try {
			// Bypass IBM WorkLight {1}
			var worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + a);                
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass IBM WorkLight {2}
			var worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {2} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass IBM WorkLight {3}
			var worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {3} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass IBM WorkLight {4}
			var worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {4} pinner not found');
			//console.log(err);
		}




		// Conscrypt CertPinManager //
		//////////////////////////////
		try {
			var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
			conscrypt_CertPinManager_Activity.checkChainPinning.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
				console.log('[+] Bypassing Conscrypt CertPinManager: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Conscrypt CertPinManager pinner not found');
			//console.log(err);
		}
		
		

		// Conscrypt CertPinManager (Legacy)//
		////////////////////////////////////
		try {
			var legacy_conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
			legacy_conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
				console.log('[+] Bypassing Conscrypt CertPinManager (Legacy): ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Conscrypt CertPinManager (Legacy) pinner not found');
			//console.log(err);
		}

               


		// CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager //
		///////////////////////////////////////////////////////////////////////////////////
		try {
			var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
			cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
				console.log('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] CWAC-Netsecurity CertPinManager pinner not found');
			//console.log(err);
		}



		// Worklight Androidgap WLCertificatePinningPlugin //
		/////////////////////////////////////////////////////
		try {
			var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
			androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
				console.log('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found');
			//console.log(err);
		}



		// Netty FingerprintTrustManagerFactory //
		//////////////////////////////////////////
		try {
			var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
			//NOTE: sometimes this below implementation could be useful 
			//var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
			netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
				console.log('[+] Bypassing Netty FingerprintTrustManagerFactory');
			};
		} catch (err) {
			console.log('[-] Netty FingerprintTrustManagerFactory pinner not found');
			//console.log(err);
		}



		// Squareup CertificatePinner [OkHTTP<v3] (double bypass) //
		////////////////////////////////////////////////////////////
		try {
			// Bypass Squareup CertificatePinner  {1}
			var Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
			Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing Squareup CertificatePinner {1}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Squareup CertificatePinner {1} pinner not found');
			//console.log(err);
		}
		try {
			// Bypass Squareup CertificatePinner {2}
			var Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
			Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
				console.log('[+] Bypassing Squareup CertificatePinner {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Squareup CertificatePinner {2} pinner not found');
			//console.log(err);
		}



		// Squareup OkHostnameVerifier [OkHTTP v3] (double bypass) //
		/////////////////////////////////////////////////////////////
		try {
			// Bypass Squareup OkHostnameVerifier {1}
			var Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
			Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
				console.log('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Squareup OkHostnameVerifier pinner not found');
			//console.log(err);
		}    
		try {
			// Bypass Squareup OkHostnameVerifier {2}
			var Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
			Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
				console.log('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Squareup OkHostnameVerifier pinner not found');
			//console.log(err);
		}


		
		// Android WebViewClient (double bypass) //
		///////////////////////////////////////////
		try {
			// Bypass WebViewClient {1} (deprecated from Android 6)
			var AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
				console.log('[+] Bypassing Android WebViewClient check {1}');
			};
		} catch (err) {
			console.log('[-] Android WebViewClient {1} check not found');
			//console.log(err)
		}
		try {
			// Bypass WebViewClient {2}
			var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
				console.log('[+] Bypassing Android WebViewClient check {2}');
			};
		} catch (err) {
			console.log('[-] Android WebViewClient {2} check not found');
			//console.log(err)
		}
		
		


		// Apache Cordova WebViewClient //
		//////////////////////////////////
		try {
			var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
			CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
				console.log('[+] Bypassing Apache Cordova WebViewClient check');
				obj3.proceed();
			};
		} catch (err) {
			console.log('[-] Apache Cordova WebViewClient check not found');
			//console.log(err);
		}



		// Boye AbstractVerifier //
		///////////////////////////
		try {
			var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
			boye_AbstractVerifier.verify.implementation = function (host, ssl) {
				console.log('[+] Bypassing Boye AbstractVerifier check: ' + host);
			};
		} catch (err) {
			console.log('[-] Boye AbstractVerifier check not found');
			//console.log(err);
		}
		
		
		
		// Chromium Cronet //
		/////////////////////    
        try {
            var CronetEngineBuilderImpl_Activity = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
            // Setting argument to TRUE (default is TRUE) to disable Public Key pinning for local trust anchors
            CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.overload('boolean').implementation = function (a) {
                console.log("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
                var cronet_obj = CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                return cronet_obj;
            };
            // Bypassing Chromium Cronet pinner
            CronetEngine_Activity.addPublicKeyPins.overload('java.lang.String', 'java.util.Set', 'boolean', 'java.util.Date').implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
                console.log("[+] Bypassing Chromium Cronet pinner: " + hostName);
                var cronet_obj = CronetEngine_Activity.addPublicKeyPins.call(this, hostName, pinsSha256,includeSubdomains, expirationDate);
                return cronet_obj;
                };
        } catch (err) {
            console.log('[-] Chromium Cronet pinner not found')
            //console.log(err);
        }
	
//////////////////////////////////////////////////////////////////////////////////////////////////////	
//////////////////////////////////////////////////////////////////////////////////////////////////////
		/*
		Original author: Daniele Linguaglossa
		28/07/2021 -    Edited by Simone Quatrini
						Code amended to correctly run on the latest frida version
						Added controls to exclude Magisk Manager
		*/
		//Java.perform(function() {
		console.log("");
	    console.log("[.] Now Running the fridaantiroot bypass - Modified by Tejas");
		var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
			"com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
			"com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
			"com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
			"de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
			"com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
			"eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
		];

		var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

		var RootProperties = {
			"ro.build.selinux": "1",
			"ro.debuggable": "0",
			"service.adb.root": "0",
			"ro.secure": "1"
		};

		var RootPropertiesKeys = [];

		for (var k in RootProperties) RootPropertiesKeys.push(k);

		var PackageManager = Java.use("android.app.ApplicationPackageManager");

		var Runtime = Java.use('java.lang.Runtime');

		var NativeFile = Java.use('java.io.File');

		var String = Java.use('java.lang.String');

		var SystemProperties = Java.use('android.os.SystemProperties');

		var BufferedReader = Java.use('java.io.BufferedReader');

		var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

		var StringBuffer = Java.use('java.lang.StringBuffer');

		var loaded_classes = Java.enumerateLoadedClassesSync();

		send("Loaded " + loaded_classes.length + " classes!");

		var useKeyInfo = false;

		var useProcessManager = false;

		send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

		if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
			try {
				//useProcessManager = true;
				//var ProcessManager = Java.use('java.lang.ProcessManager');
			} catch (err) {
				send("ProcessManager Hook failed: " + err);
			}
		} else {
			send("ProcessManager hook not loaded");
		}

		var KeyInfo = null;

		if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
			try {
				//useKeyInfo = true;
				//var KeyInfo = Java.use('android.security.keystore.KeyInfo');
			} catch (err) {
				send("KeyInfo Hook failed: " + err);
			}
		} else {
			send("KeyInfo hook not loaded");
		}

		PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
			var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
			if (shouldFakePackage) {
				send("Bypass root check for package: " + pname);
				pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
			}
			return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
		};

		NativeFile.exists.implementation = function() {
			var name = NativeFile.getName.call(this);
			var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
			if (shouldFakeReturn) {
				send("Bypass return value for binary: " + name);
				return false;
			} else {
				return this.exists.call(this);
			}
		};

		var exec = Runtime.exec.overload('[Ljava.lang.String;');
		var exec1 = Runtime.exec.overload('java.lang.String');
		var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
		var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
		var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
		var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

		exec5.implementation = function(cmd, env, dir) {
			if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
				var fakeCmd = "grep";
				send("Bypass " + cmd + " command");
				return exec1.call(this, fakeCmd);
			}
			if (cmd == "su") {
				var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
				send("Bypass " + cmd + " command");
				return exec1.call(this, fakeCmd);
			}
			return exec5.call(this, cmd, env, dir);
		};

		exec4.implementation = function(cmdarr, env, file) {
			for (var i = 0; i < cmdarr.length; i = i + 1) {
				var tmp_cmd = cmdarr[i];
				if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
					var fakeCmd = "grep";
					send("Bypass " + cmdarr + " command");
					return exec1.call(this, fakeCmd);
				}

				if (tmp_cmd == "su") {
					var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
					send("Bypass " + cmdarr + " command");
					return exec1.call(this, fakeCmd);
				}
			}
			return exec4.call(this, cmdarr, env, file);
		};

		exec3.implementation = function(cmdarr, envp) {
			for (var i = 0; i < cmdarr.length; i = i + 1) {
				var tmp_cmd = cmdarr[i];
				if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
					var fakeCmd = "grep";
					send("Bypass " + cmdarr + " command");
					return exec1.call(this, fakeCmd);
				}

				if (tmp_cmd == "su") {
					var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
					send("Bypass " + cmdarr + " command");
					return exec1.call(this, fakeCmd);
				}
			}
			return exec3.call(this, cmdarr, envp);
		};

		exec2.implementation = function(cmd, env) {
			if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
				var fakeCmd = "grep";
				send("Bypass " + cmd + " command");
				return exec1.call(this, fakeCmd);
			}
			if (cmd == "su") {
				var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
				send("Bypass " + cmd + " command");
				return exec1.call(this, fakeCmd);
			}
			return exec2.call(this, cmd, env);
		};

		exec.implementation = function(cmd) {
			for (var i = 0; i < cmd.length; i = i + 1) {
				var tmp_cmd = cmd[i];
				if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
					var fakeCmd = "grep";
					send("Bypass " + cmd + " command");
					return exec1.call(this, fakeCmd);
				}

				if (tmp_cmd == "su") {
					var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
					send("Bypass " + cmd + " command");
					return exec1.call(this, fakeCmd);
				}
			}

			return exec.call(this, cmd);
		};

		exec1.implementation = function(cmd) {
			if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
				var fakeCmd = "grep";
				send("Bypass " + cmd + " command");
				return exec1.call(this, fakeCmd);
			}
			if (cmd == "su") {
				var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
				send("Bypass " + cmd + " command");
				return exec1.call(this, fakeCmd);
			}
			return exec1.call(this, cmd);
		};

		String.contains.implementation = function(name) {
			if (name == "test-keys") {
				send("Bypass test-keys check");
				return false;
			}
			return this.contains.call(this, name);
		};

		var get = SystemProperties.get.overload('java.lang.String');

		get.implementation = function(name) {
			if (RootPropertiesKeys.indexOf(name) != -1) {
				send("Bypass " + name);
				return RootProperties[name];
			}
			return this.get.call(this, name);
		};

		Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
			onEnter: function(args) {
				var path = Memory.readCString(args[0]);
				path = path.split("/");
				var executable = path[path.length - 1];
				var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
				if (shouldFakeReturn) {
					Memory.writeUtf8String(args[0], "/notexists");
					send("Bypass native fopen");
				}
			},
			onLeave: function(retval) {

			}
		});

		Interceptor.attach(Module.findExportByName("libc.so", "system"), {
			onEnter: function(args) {
				var cmd = Memory.readCString(args[0]);
				send("SYSTEM CMD: " + cmd);
				if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
					send("Bypass native system: " + cmd);
					Memory.writeUtf8String(args[0], "grep");
				}
				if (cmd == "su") {
					send("Bypass native system: " + cmd);
					Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
				}
			},
			onLeave: function(retval) {

			}
		});

		/*

		TO IMPLEMENT:

		Exec Family

		int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
		int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
		int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
		int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
		int execv(const char *path, char *const argv[]);
		int execve(const char *path, char *const argv[], char *const envp[]);
		int execvp(const char *file, char *const argv[]);
		int execvpe(const char *file, char *const argv[], char *const envp[]);

		*/


		BufferedReader.readLine.overload('boolean').implementation = function() {
			var text = this.readLine.overload('boolean').call(this);
			if (text === null) {
				// just pass , i know it's ugly as hell but test != null won't work :(
			} else {
				var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
				if (shouldFakeRead) {
					send("Bypass build.prop file read");
					text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
				}
			}
			return text;
		};

		var executeCommand = ProcessBuilder.command.overload('java.util.List');

		ProcessBuilder.start.implementation = function() {
			var cmd = this.command.call(this);
			var shouldModifyCommand = false;
			for (var i = 0; i < cmd.size(); i = i + 1) {
				var tmp_cmd = cmd.get(i).toString();
				if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
					shouldModifyCommand = true;
				}
			}
			if (shouldModifyCommand) {
				send("Bypass ProcessBuilder " + cmd);
				this.command.call(this, ["grep"]);
				return this.start.call(this);
			}
			if (cmd.indexOf("su") != -1) {
				send("Bypass ProcessBuilder " + cmd);
				this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
				return this.start.call(this);
			}

			return this.start.call(this);
		};

		if (useProcessManager) {
			var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
			var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

			ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
				var fake_cmd = cmd;
				for (var i = 0; i < cmd.length; i = i + 1) {
					var tmp_cmd = cmd[i];
					if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
						var fake_cmd = ["grep"];
						send("Bypass " + cmdarr + " command");
					}

					if (tmp_cmd == "su") {
						var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
						send("Bypass " + cmdarr + " command");
					}
				}
				return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
			};

			ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
				var fake_cmd = cmd;
				for (var i = 0; i < cmd.length; i = i + 1) {
					var tmp_cmd = cmd[i];
					if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
						var fake_cmd = ["grep"];
						send("Bypass " + cmdarr + " command");
					}

					if (tmp_cmd == "su") {
						var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
						send("Bypass " + cmdarr + " command");
					}
				}
				return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
			};
		}

		if (useKeyInfo) {
			KeyInfo.isInsideSecureHardware.implementation = function() {
				send("Bypass isInsideSecureHardware");
				return true;
			}
		}
//		});	
//////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////
	});
	
}, 0);

/*
	Universal Android Biometric Bypass v0.4
	author: ax - github.com/ax
	Updated Android biometric bypass script (from Kamil Breński, Krzysztof Pranczk and Mateusz Fruba, August 2019)
	This script will bypass authentication when the crypto object is not used.
	The authentication implementation relies on the callback onAuthenticationSucceded being called. 
    Bypass fingerprint authentication if the app accept NULL cryptoObject in onAuthenticationSucceeded(...).
    This script should automatically bypass fingerprint when authenticate(...) method will be called.
*/

Java.perform(function () {
    //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
    try { hookBiometricPrompt_authenticate(); }
    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
    try { hookBiometricPrompt_authenticate2(); }
    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
    try { hookFingerprintManagerCompat_authenticate(); }
    catch (error) { console.log("hookFingerprintManagerCompat_authenticate failed"); }
    try { hookFingerprintManager_authenticate(); }
    catch (error) { console.log("hookFingerprintManager_authenticate failed"); }
});


var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');


});

function getArgsTypes(overloads) {
	// there should be just one overload for the constructor
	// overloads.len == 1 check
    var results = []
	var i,j;
    for (i in overloads) {
		console.log('[*] Overload number ind: '+i);
        //if (overloads[i].hasOwnProperty('argumentTypes')) {
           var parameters = []
           for (j in overloads[i].argumentTypes) {
               parameters.push("'" + overloads[i].argumentTypes[j].className + "'")
           }
       // }
        results.push('(' + parameters.join(', ') + ');')
    }
    return results.join('\n')
}

function getAuthResult(resultObj, cryptoInst) {
	//var clax = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
	var clax = resultObj;
	var resu = getArgsTypes(clax['$init'].overloads);
	//console.log(resu);
	resu = resu.replace(/\'android\.hardware\.biometrics\.BiometricPrompt\$CryptoObject\'/, 'cryptoInst');
	resu = resu.replace(/\'android\.hardware\.fingerprint\.FingerprintManager\$CryptoObject\'/, 'cryptoInst');
	resu = resu.replace('\'int\'', '0');
	resu = resu.replace('\'boolean\'', 'false');
	resu = resu.replace(/'.*'/, 'null');
	//console.log(resu);
	resu = "resultObj.$new"+resu;
	var authenticationResultInst = eval(resu);
    console.log("cryptoInst:, " + cryptoInst + " class: " + cryptoInst.$className);
    return authenticationResultInst;
}

function getBiometricPromptAuthResult() {
    var sweet_cipher = null;
    var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
    var cryptoInst = cryptoObj.$new(sweet_cipher);
    var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
    return authenticationResultInst
}

function hookBiometricPrompt_authenticate() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("Hooking BiometricPrompt.authenticate()...");
    biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
        console.log("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    	console.log("[BiometricPrompt.BiometricPrompt()]: callback.onAuthenticationSucceeded(NULL) called!");
    }
}

function hookBiometricPrompt_authenticate2() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("Hooking BiometricPrompt.authenticate2()...");
    biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
        console.log("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto + ", cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    }
}

function hookFingerprintManagerCompat_authenticate() {
    /*
    void authenticate (FingerprintManagerCompat.CryptoObject crypto, 
                    int flags, 
                    CancellationSignal cancel, 
                    FingerprintManagerCompat.AuthenticationCallback callback, 
                    Handler handler)
    */
    var fingerprintManagerCompat = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
        cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
        authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
        }
        catch (error) {
            console.log("FingerprintManagerCompat class not found!");
            return
        }
    }
    console.log("Hooking FingerprintManagerCompat.authenticate()...");
    var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
    fingerprintManagerCompat_authenticate.implementation = function (crypto, flags, cancel, callback, handler) {
        console.log("[FingerprintManagerCompat.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        //console.log(enumMethods(callback.$className));
        callback['onAuthenticationFailed'].implementation = function () {
            console.log("[onAuthenticationFailed()]:");
            var sweet_cipher = null;
            var cryptoInst = cryptoObj.$new(sweet_cipher);
            var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
            callback.onAuthenticationSucceeded(authenticationResultInst);
        }
        return this.authenticate(crypto, flags, cancel, callback, handler);
    }
}

function hookFingerprintManager_authenticate() {
    /*
    public void authenticate (FingerprintManager.CryptoObject crypto, 
                    CancellationSignal cancel, 
                    int flags, 
                    FingerprintManager.AuthenticationCallback callback, 
                    Handler handler)
Error: authenticate(): has more than one overload, use .overload(<signature>) to choose from:
    .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler')
    .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler', 'int')
    */
    var fingerprintManager = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        }
        catch (error) {
            console.log("FingerprintManager class not found!");
            return
        }
    }
    console.log("Hooking FingerprintManager.authenticate()...");



    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
    fingerprintManager_authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
        console.log("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        var sweet_cipher = null;
        var cryptoInst = cryptoObj.$new(sweet_cipher);
        var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
        callback.onAuthenticationSucceeded(authenticationResultInst);
        return this.authenticate(crypto, cancel, flags, callback, handler);
    }
}


function enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();

    return ownMethods;
}

function bypass_developerMode_check() {
    var settingSecure = Java.use('android.provider.Settings$Secure');
    settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
        console.log("[!] settingSecure.getInt(cr,name) : " + name);
        console.log('[+] 1.Secure.getInt(' + name + ') Bypassed');
        return 0;
    }
    settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        console.log("[!] settingSecure.getInt(cr,name) : " + name);
        console.log('[+] 2.Secure.getInt(' + name + ') Bypassed');
        return 0;
    }
    var settingGlobal = Java.use('android.provider.Settings$Global');
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
        console.log("[!] settingGlobal.getInt(cr,name) : " + name);
        console.log('[+] 1.Global.getInt(' + name + ') Bypassed');
        return 0;
    }
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        console.log("[!] settingGlobal.getInt(cr,name) : " + name);
        console.log('[+] 2.Global.getInt(' + name + ') Bypassed');
        return 0;
    }
}

// Main
Java.perform(function() {
    bypass_developerMode_check();
});

// Author: Rohindh
// Github: https://github.com/RohindhR
// Date: 08/03/2024
// Version: 1.0
// Description: Frida script for bypassing React Native Jail Monkey checks
// Tested and developed for Jail Monkey version 2.8.0 (https://www.npmjs.com/package/jail-monkey/v/2.8.0) and Frida version 16.2.1
// Usage: frida -U -f com.example.appname --codeshare RohindhR/react-native-jail-monkey-bypass-all-checks
// Note: This script is for educational purposes only. Do not use it for illegal activities.
//      I am not responsible for any damage done by this script.
//      Use this script at your own risk.

Java.perform(function() {
    // Bypassing Root, Hook, Mock Location, External Storage, ADB checks
    Java.use('com.gantix.JailMonkey.JailMonkeyModule').getConstants.implementation = function() {
        var hashmap = this.getConstants();
        hashmap.put('isJailBroken', Java.use("java.lang.Boolean").$new(false));
        console.log(`Root Check Bypassed : ✅`);

        hashmap.put('hookDetected', Java.use("java.lang.Boolean").$new(false));
        console.log(`Hook Check Bypassed : ✅`);

        hashmap.put('canMockLocation', Java.use("java.lang.Boolean").$new(false));
        console.log(`Mock Location Check Bypassed : ✅`);

        hashmap.put('isOnExternalStorage', Java.use("java.lang.Boolean").$new(false));
        console.log(`External Storage Check Bypassed : ✅`);

        hashmap.put('AdbEnabled', Java.use("java.lang.Boolean").$new(false));
        console.log(`ADB Check Bypassed : ✅`);

        return hashmap;
    }

    // Bypassing Rooted Check
    let RootedCheckClass = Java.use("com.gantix.JailMonkey.Rooted.RootedCheck")
    RootedCheckClass.getResultByDetectionMethod.implementation = function() {
        let map = this.getResultByDetectionMethod();
        map.put("jailMonkey", Java.use("java.lang.Boolean").$new(false));
        return map;
    }

    // Bypassing Root detection method's result of RootBeer library
    var RootBeerResultsClass = Java.use("com.gantix.JailMonkey.Rooted.RootedCheck$RootBeerResults");
    RootBeerResultsClass.isJailBroken.implementation = function() {
        return false;
    };

    RootBeerResultsClass.toNativeMap.implementation = function() {
        var map = this.toNativeMap.call(this);
        map.put("detectRootManagementApps", Java.use("java.lang.Boolean").$new(false));
        map.put("detectPotentiallyDangerousApps", Java.use("java.lang.Boolean").$new(false));
        map.put("checkForSuBinary", Java.use("java.lang.Boolean").$new(false));
        map.put("checkForDangerousProps", Java.use("java.lang.Boolean").$new(false));
        map.put("checkForRWPaths", Java.use("java.lang.Boolean").$new(false));
        map.put("detectTestKeys", Java.use("java.lang.Boolean").$new(false));
        map.put("checkSuExists", Java.use("java.lang.Boolean").$new(false));
        map.put("checkForRootNative", Java.use("java.lang.Boolean").$new(false));
        map.put("checkForMagiskBinary", Java.use("java.lang.Boolean").$new(false));

        console.log("Root detection method's result bypass : ✅");

        return map;
    };

    // Bypassing Development settings check
    Java.use("com.gantix.JailMonkey.JailMonkeyModule").isDevelopmentSettingsMode.overload("com.facebook.react.bridge.Promise").implementation = function(p) {
        p.resolve(Java.use("java.lang.Boolean").$new(false));
        console.log("isDevelopmentSettingsMode Check Bypassed : ✅");
    }

    // Bypassing Debugger check
    Java.use("com.gantix.JailMonkey.JailMonkeyModule").isDebuggedMode.overload("com.facebook.react.bridge.Promise").implementation = function(p) {
        p.resolve(Java.use("java.lang.Boolean").$new(false));
        console.log("isDebuggerConnected Check Bypassed : ✅");
    }
})

setTimeout(function() {
	Java.perform(function() {
		console.log('');
		console.log('======');
		console.log('[#] Android Bypass for various Certificate Pinning methods [#]');
		console.log('======');
		
		var errDict = {};

		// TrustManager (Android < 7) //
		////////////////////////////////
		var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
		var SSLContext = Java.use('javax.net.ssl.SSLContext');
		var TrustManager = Java.registerClass({
			// Implement a custom TrustManager
			name: 'dev.asd.test.TrustManager',
			implements: [X509TrustManager],
			methods: {
				checkClientTrusted: function(chain, authType) {},
				checkServerTrusted: function(chain, authType) {},
				getAcceptedIssuers: function() {return []; }
			}
		});
		// Prepare the TrustManager array to pass to SSLContext.init()
		var TrustManagers = [TrustManager.$new()];
		// Get a handle on the init() on the SSLContext class
		var SSLContext_init = SSLContext.init.overload(
			'[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
		try {
			// Override the init method, specifying the custom TrustManager
			SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
				console.log('[+] Bypassing Trustmanager (Android < 7) pinner');
				SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
			};
		} catch (err) {
			console.log('[-] TrustManager (Android < 7) pinner not found');
			//console.log(err);
		}



	
		// OkHTTPv3 (quadruple bypass) //
		/////////////////////////////////
		try {
			// Bypass OkHTTPv3 {1}
			var okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
			okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				console.log('[+] Bypassing OkHTTPv3 {1}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] OkHTTPv3 {1} pinner not found');
			//console.log(err);
			errDict[err] = ['okhttp3.CertificatePinner', 'check'];
		}
		try {
			// Bypass OkHTTPv3 {2}
			// This method of CertificatePinner.check is deprecated but could be found in some old Android apps
			var okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
			okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
				console.log('[+] Bypassing OkHTTPv3 {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] OkHTTPv3 {2} pinner not found');
			//console.log(err);
			//errDict[err] = ['okhttp3.CertificatePinner', 'check'];
		}
		try {
			// Bypass OkHTTPv3 {3}
			var okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
			okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(a, b) {
				console.log('[+] Bypassing OkHTTPv3 {3}: ' + a);
				return;
			};
		} catch(err) {
			console.log('[-] OkHTTPv3 {3} pinner not found');
			//console.log(err);
			errDict[err] = ['okhttp3.CertificatePinner', 'check'];
		}
		try {
			// Bypass OkHTTPv3 {4}
			var okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner'); 
			//okhttp3_Activity_4['check$okhttp'].implementation = function(a, b) {
			okhttp3_Activity_4.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(a, b) {		
				console.log('[+] Bypassing OkHTTPv3 {4}: ' + a);
				return;
			};
		} catch(err) {
			console.log('[-] OkHTTPv3 {4} pinner not found');
			//console.log(err);
			errDict[err] = ['okhttp3.CertificatePinner', 'check$okhttp'];
		}
	

	
		// Trustkit (triple bypass) //
		//////////////////////////////
		try {
			// Bypass Trustkit {1}
			var trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
			trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
				console.log('[+] Bypassing Trustkit {1}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Trustkit {1} pinner not found');
			//console.log(err);
			errDict[err] = ['com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', 'verify'];
		}
		try {
			// Bypass Trustkit {2}
			var trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
			trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
				console.log('[+] Bypassing Trustkit {2}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Trustkit {2} pinner not found');
			//console.log(err);
			errDict[err] = ['com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', 'verify'];
		}
		try {
			// Bypass Trustkit {3}
			var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
			trustkit_PinningTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
				console.log('[+] Bypassing Trustkit {3}');
			};
		} catch (err) {
			console.log('[-] Trustkit {3} pinner not found');
			//console.log(err);
			errDict[err] = ['com.datatheorem.android.trustkit.pinning.PinningTrustManager', 'checkServerTrusted'];
		}
		
	
	
  
		// TrustManagerImpl (Android > 7) //
		////////////////////////////////////
		try {
			// Bypass TrustManagerImpl (Android > 7) {1}
			var array_list = Java.use("java.util.ArrayList");
			var TrustManagerImpl_Activity_1 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
			TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = function(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
				console.log('[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check for: '+ host);
				return array_list.$new();
			};
		} catch (err) {
			console.log('[-] TrustManagerImpl (Android > 7) checkTrustedRecursive check not found');
			//console.log(err);
			errDict[err] = ['com.android.org.conscrypt.TrustManagerImpl', 'checkTrustedRecursive'];
		}  
		try {
			// Bypass TrustManagerImpl (Android > 7) {2} (probably no more necessary)
			var TrustManagerImpl_Activity_2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
			TrustManagerImpl_Activity_2.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
				console.log('[+] Bypassing TrustManagerImpl (Android > 7) verifyChain check for: ' + host);
				return untrustedChain;
			};   
		} catch (err) {
			console.log('[-] TrustManagerImpl (Android > 7) verifyChain check not found');
			//console.log(err);
			errDict[err] = ['com.android.org.conscrypt.TrustManagerImpl', 'verifyChain'];  
		}

  
  
		

		// Appcelerator Titanium PinningTrustManager //
		///////////////////////////////////////////////
		try {
			var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
			appcelerator_PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
				console.log('[+] Bypassing Appcelerator PinningTrustManager');
				return;
			};
		} catch (err) {
			console.log('[-] Appcelerator PinningTrustManager pinner not found');
			//console.log(err);
			errDict[err] = ['appcelerator.https.PinningTrustManager', 'checkServerTrusted'];  
		}




		// Fabric PinningTrustManager //
		////////////////////////////////
		try {
			var fabric_PinningTrustManager = Java.use('io.fabric.sdk.android.services.network.PinningTrustManager');
			fabric_PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
				console.log('[+] Bypassing Fabric PinningTrustManager');
				return;
			};
		} catch (err) {
			console.log('[-] Fabric PinningTrustManager pinner not found');
			//console.log(err);
			errDict[err] = ['io.fabric.sdk.android.services.network.PinningTrustManager', 'checkServerTrusted'];  
		}




		// OpenSSLSocketImpl Conscrypt (double bypass) //
		/////////////////////////////////////////////////
		try {
			var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
			OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, JavaObject, authMethod) {
				console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {1}');
			};
		} catch (err) {
			console.log('[-] OpenSSLSocketImpl Conscrypt {1} pinner not found');
			//console.log(err);
			errDict[err] = ['com.android.org.conscrypt.OpenSSLSocketImpl', 'verifyCertificateChain'];
		}
		try {
			var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
			OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certChain, authMethod) {
				console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {2}');
			};
		} catch (err) {
			console.log('[-] OpenSSLSocketImpl Conscrypt {2} pinner not found');
			//console.log(err);
			errDict[err] = ['com.android.org.conscrypt.OpenSSLSocketImpl', 'verifyCertificateChain'];  
		}




		// OpenSSLEngineSocketImpl Conscrypt //
		///////////////////////////////////////
		try {
			var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
			OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function(a, b) {
				console.log('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
			};
		} catch (err) {
			console.log('[-] OpenSSLEngineSocketImpl Conscrypt pinner not found');
			//console.log(err);
			errDict[err] = ['com.android.org.conscrypt.OpenSSLEngineSocketImpl', 'verifyCertificateChain'];
		}




		// OpenSSLSocketImpl Apache Harmony //
		//////////////////////////////////////
		try {
			var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
			OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function(asn1DerEncodedCertificateChain, authMethod) {
				console.log('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
			};
		} catch (err) {
			console.log('[-] OpenSSLSocketImpl Apache Harmony pinner not found');
			//console.log(err);
			errDict[err] = ['org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl', 'verifyCertificateChain'];   
		}




		// PhoneGap sslCertificateChecker //
		////////////////////////////////////
		try {
			var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
			phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
				console.log('[+] Bypassing PhoneGap sslCertificateChecker: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] PhoneGap sslCertificateChecker pinner not found');
			//console.log(err);
			errDict[err] = ['nl.xservices.plugins.sslCertificateChecker', 'execute'];
		}




		// IBM MobileFirst pinTrustedCertificatePublicKey (double bypass) //
		////////////////////////////////////////////////////////////////////
		try {
			// Bypass IBM MobileFirst {1}
			var WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
			WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function(cert) {
				console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
				return;
			};
			} catch (err) {
			console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found');
			//console.log(err);
			errDict[err] = ['com.worklight.wlclient.api.WLClient', 'pinTrustedCertificatePublicKey'];
		}
		try {
			// Bypass IBM MobileFirst {2}
			var WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
			WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function(cert) {
				console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
				return;
			};
		} catch (err) {
			console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {2} pinner not found');
			//console.log(err);
			errDict[err] = ['com.worklight.wlclient.api.WLClient', 'pinTrustedCertificatePublicKey'];
		}




		// IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass) //
		///////////////////////////////////////////////////////////////////////////////////////////////////////
		try {
			// Bypass IBM WorkLight {1}
			var worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function(a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found');
			//console.log(err);
			errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
		}
		try {
			// Bypass IBM WorkLight {2}
			var worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {2} pinner not found');
			//console.log(err);
			errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
		}
		try {
			// Bypass IBM WorkLight {3}
			var worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {3} pinner not found');
			//console.log(err);
			errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
		}
		try {
			// Bypass IBM WorkLight {4}
			var worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
			worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
				console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {4} pinner not found');
			//console.log(err);
			errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
		}




		// Conscrypt CertPinManager //
		//////////////////////////////
		try {
			var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
			conscrypt_CertPinManager_Activity.checkChainPinning.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				console.log('[+] Bypassing Conscrypt CertPinManager: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Conscrypt CertPinManager pinner not found');
			//console.log(err);
			errDict[err] = ['com.android.org.conscrypt.CertPinManager', 'checkChainPinning'];
		}
		
		


		// Conscrypt CertPinManager (Legacy) //
		///////////////////////////////////////
		try {
			var legacy_conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
			legacy_conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				console.log('[+] Bypassing Conscrypt CertPinManager (Legacy): ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Conscrypt CertPinManager (Legacy) pinner not found');
			//console.log(err);
			errDict[err] = ['com.android.org.conscrypt.CertPinManager', 'isChainValid'];
		}
		   
			   


		// CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager //
		///////////////////////////////////////////////////////////////////////////////////
		try {
			var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
			cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				console.log('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] CWAC-Netsecurity CertPinManager pinner not found');
			//console.log(err);
			errDict[err] = ['com.commonsware.cwac.netsecurity.conscrypt.CertPinManager', 'isChainValid'];
		}




		// Worklight Androidgap WLCertificatePinningPlugin //
		/////////////////////////////////////////////////////
		try {
			var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
			androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function(a, b, c) {
				console.log('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found');
			//console.log(err);
			errDict[err] = ['com.worklight.androidgap.plugin.WLCertificatePinningPlugin', 'execute'];
		}




		// Netty FingerprintTrustManagerFactory //
		//////////////////////////////////////////
		try {
			var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
			//NOTE: sometimes this below implementation could be useful 
			//var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
			netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function(type, chain) {
				console.log('[+] Bypassing Netty FingerprintTrustManagerFactory');
			};
		} catch (err) {
			console.log('[-] Netty FingerprintTrustManagerFactory pinner not found');
			//console.log(err);
			errDict[err] = ['io.netty.handler.ssl.util.FingerprintTrustManagerFactory', 'checkTrusted'];
		}




		// Squareup CertificatePinner [OkHTTP<v3] (double bypass) //
		////////////////////////////////////////////////////////////
		try {
			// Bypass Squareup CertificatePinner  {1}
			var Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
			Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(a, b) {
				console.log('[+] Bypassing Squareup CertificatePinner {1}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Squareup CertificatePinner {1} pinner not found');
			//console.log(err);
			errDict[err] = ['com.squareup.okhttp.CertificatePinner', 'check'];
		}
		try {
			// Bypass Squareup CertificatePinner {2}
			var Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
			Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
				console.log('[+] Bypassing Squareup CertificatePinner {2}: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Squareup CertificatePinner {2} pinner not found');
			//console.log(err);
			errDict[err] = ['com.squareup.okhttp.CertificatePinner', 'check'];
		}




		// Squareup OkHostnameVerifier [OkHTTP v3] (double bypass) //
		/////////////////////////////////////////////////////////////
		try {
			// Bypass Squareup OkHostnameVerifier {1}
			var Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
			Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
				console.log('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Squareup OkHostnameVerifier check not found');
			//console.log(err);
			errDict[err] = ['com.squareup.okhttp.internal.tls.OkHostnameVerifier', 'verify'];
		}
		try {
			// Bypass Squareup OkHostnameVerifier {2}
			var Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
			Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
				console.log('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Squareup OkHostnameVerifier check not found');
			//console.log(err);
			errDict[err] = ['com.squareup.okhttp.internal.tls.OkHostnameVerifier', 'verify'];
		}


		

		// Android WebViewClient (quadruple bypass) //
		//////////////////////////////////////////////
		try {
			// Bypass WebViewClient {1} (deprecated from Android 6)
			var AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
				console.log('[+] Bypassing Android WebViewClient check {1}');
			};
		} catch (err) {
			console.log('[-] Android WebViewClient {1} check not found');
			//console.log(err)
			errDict[err] = ['android.webkit.WebViewClient', 'onReceivedSslError'];
		}
		// Not working properly temporarily disused
		//try {
		//	// Bypass WebViewClient {2}
		//	var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
		//	AndroidWebViewClient_Activity_2.onReceivedHttpError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceResponse').implementation = function(obj1, obj2, obj3) {
		//		console.log('[+] Bypassing Android WebViewClient check {2}');
		//	};
		//} catch (err) {
		//	console.log('[-] Android WebViewClient {2} check not found');
		//	//console.log(err)
		//	errDict[err] = ['android.webkit.WebViewClient', 'onReceivedHttpError'];
		//}
		try {
			// Bypass WebViewClient {3}
			var AndroidWebViewClient_Activity_3 = Java.use('android.webkit.WebViewClient');
			//AndroidWebViewClient_Activity_3.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(obj1, obj2, obj3, obj4) {
			AndroidWebViewClient_Activity_3.onReceivedError.implementation = function(view, errCode, description, failingUrl) {
				console.log('[+] Bypassing Android WebViewClient check {3}');
			};
		} catch (err) {
			console.log('[-] Android WebViewClient {3} check not found');
			//console.log(err)
			errDict[err] = ['android.webkit.WebViewClient', 'onReceivedError'];
		}
		try {
			// Bypass WebViewClient {4}
			var AndroidWebViewClient_Activity_4 = Java.use('android.webkit.WebViewClient');
			AndroidWebViewClient_Activity_4.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function(obj1, obj2, obj3) {
				console.log('[+] Bypassing Android WebViewClient check {4}');
			};
		} catch (err) {
			console.log('[-] Android WebViewClient {4} check not found');
			//console.log(err)
			errDict[err] = ['android.webkit.WebViewClient', 'onReceivedError'];
		}
		



		// Apache Cordova WebViewClient //
		//////////////////////////////////
		try {
			var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
			CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(obj1, obj2, obj3) {
				console.log('[+] Bypassing Apache Cordova WebViewClient check');
				obj3.proceed();
			};
		} catch (err) {
			console.log('[-] Apache Cordova WebViewClient check not found');
			//console.log(err);
		}




		// Boye AbstractVerifier //
		///////////////////////////
		try {
			var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
			boye_AbstractVerifier.verify.implementation = function(host, ssl) {
				console.log('[+] Bypassing Boye AbstractVerifier check for: ' + host);
			};
		} catch (err) {
			console.log('[-] Boye AbstractVerifier check not found');
			//console.log(err);
			errDict[err] = ['ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier', 'verify'];
		}



		// Apache AbstractVerifier (quadruple bypass) //
		////////////////////////////////////////////////
		try {
			var apache_AbstractVerifier_1 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
			apache_AbstractVerifier_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(a, b) {
				console.log('[+] Bypassing Apache AbstractVerifier {1} check for: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Apache AbstractVerifier {1} check not found');
			//console.log(err);
			errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
		}
				try {
			var apache_AbstractVerifier_2 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
			apache_AbstractVerifier_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function(a, b) {
				console.log('[+] Bypassing Apache AbstractVerifier {2} check for: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Apache AbstractVerifier {2} check not found');
			//console.log(err);
			errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
		}
				try {
			var apache_AbstractVerifier_3 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
			apache_AbstractVerifier_3.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(a, b) {
				console.log('[+] Bypassing Apache AbstractVerifier {3} check for: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Apache AbstractVerifier {3} check not found');
			//console.log(err);
			errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
		}
				try {
			var apache_AbstractVerifier_4 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
			apache_AbstractVerifier_4.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function(a, b, c, d) {
				console.log('[+] Bypassing Apache AbstractVerifier {4} check for: ' + a);
				return;
			};
		} catch (err) {
			console.log('[-] Apache AbstractVerifier {4} check not found');
			//console.log(err);
			errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
		}




		// Chromium Cronet //
		/////////////////////
		try {
			var CronetEngineBuilderImpl_Activity = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
			// Setting argument to TRUE (default is TRUE) to disable Public Key pinning for local trust anchors
			CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.overload('boolean').implementation = function(a) {
				console.log("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
				var cronet_obj_1 = CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
				return cronet_obj_1;
			};
			// Bypassing Chromium Cronet pinner
			CronetEngine_Activity.addPublicKeyPins.overload('java.lang.String', 'java.util.Set', 'boolean', 'java.util.Date').implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
				console.log("[+] Bypassing Chromium Cronet pinner: " + hostName);
				var cronet_obj_2 = CronetEngine_Activity.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
				return cronet_obj_2;
			};
		} catch (err) {
			console.log('[-] Chromium Cronet pinner not found')
			//console.log(err);
		}




		// Flutter Pinning packages http_certificate_pinning and ssl_pinning_plugin (double bypass) //
		//////////////////////////////////////////////////////////////////////////////////////////////
		try {
			// Bypass HttpCertificatePinning.check {1}
			var HttpCertificatePinning_Activity = Java.use('diefferson.http_certificate_pinning.HttpCertificatePinning');
			HttpCertificatePinning_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c ,d, e) {
				console.log('[+] Bypassing Flutter HttpCertificatePinning : ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Flutter HttpCertificatePinning pinner not found');
			//console.log(err);
			errDict[err] = ['diefferson.http_certificate_pinning.HttpCertificatePinning', 'checkConnexion'];
		}
		try {
			// Bypass SslPinningPlugin.check {2}
			var SslPinningPlugin_Activity = Java.use('com.macif.plugin.sslpinningplugin.SslPinningPlugin');
			SslPinningPlugin_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c ,d, e) {
				console.log('[+] Bypassing Flutter SslPinningPlugin: ' + a);
				return true;
			};
		} catch (err) {
			console.log('[-] Flutter SslPinningPlugin pinner not found');
			//console.log(err);
			errDict[err] = ['com.macif.plugin.sslpinningplugin.SslPinningPlugin', 'checkConnexion'];
		}
		
		
		
		
		// Unusual/obfuscated pinners bypass //
		///////////////////////////////////////
		try {
			// Iterating all caught pinner errors and try to overload them 
			for (var key in errDict) {
				var errStr = key;
				var targetClass = errDict[key][0]
				var targetFunc = errDict[key][1]
				var retType = Java.use(targetClass)[targetFunc].returnType.type;
				//console.log("errDict content: "+errStr+" "+targetClass+"."+targetFunc);
				if (String(errStr).includes('.overload')) {
					overloader(errStr, targetClass, targetFunc,retType);
				}
			}
		} catch (err) {
			//console.log('[-] The pinner "'+targetClass+'.'+targetFunc+'" is not unusual/obfuscated, skipping it..');
			//console.log(err);
		}



		
		// Dynamic SSLPeerUnverifiedException Bypasser                               //
		// An useful technique to bypass SSLPeerUnverifiedException failures raising //
		// when the Android app uses some uncommon SSL Pinning methods or an heavily //
		// code obfuscation. Inspired by an idea of: https://github.com/httptoolkit  //
		///////////////////////////////////////////////////////////////////////////////
		try {
			var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
			UnverifiedCertError.$init.implementation = function (reason) {
				try {
					var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
					var exceptionStackIndex = stackTrace.findIndex(stack =>
						stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
					);
					// Retrieve the method raising the SSLPeerUnverifiedException
					var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
					var className = callingFunctionStack.getClassName();
					var methodName = callingFunctionStack.getMethodName();
					var callingClass = Java.use(className);
					var callingMethod = callingClass[methodName];
					console.log('\x1b[36m[!] Unexpected SSLPeerUnverifiedException occurred related to the method "'+className+'.'+methodName+'"\x1b[0m');
					//console.log("Stacktrace details:\n"+stackTrace);
					// Checking if the SSLPeerUnverifiedException was generated by an usually negligible (not blocking) method
					if (className == 'com.android.org.conscrypt.ActiveSession' || className == 'com.google.android.gms.org.conscrypt.ActiveSession') {
						throw 'Reason: skipped SSLPeerUnverifiedException bypass since the exception was raised from a (usually) non blocking method on the Android app';
					}
					else {
						console.log('\x1b[34m[!] Starting to dynamically circumvent the SSLPeerUnverifiedException for the method "'+className+'.'+methodName+'"...\x1b[0m');
						var retTypeName = callingMethod.returnType.type;			
						// Skip it when the calling method was already bypassed with Frida
						if (!(callingMethod.implementation)) {
							// Trying to bypass (via implementation) the SSLPeerUnverifiedException if due to an uncommon SSL Pinning method
							callingMethod.implementation = function() {
								console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+className+'.'+methodName+'" via Frida function implementation\x1b[0m');
								returner(retTypeName);
							}
						}
					}
				} catch (err2) {
					// Dynamic circumvention via function implementation does not works, then trying via function overloading
					if (String(err2).includes('.overload')) {
						overloader(err2, className, methodName, retTypeName);
					} else {
						if (String(err2).includes('SSLPeerUnverifiedException')) {
							console.log('\x1b[36m[-] Failed to dynamically circumvent SSLPeerUnverifiedException -> '+err2+'\x1b[0m');
						} else {
							//console.log('\x1b[36m[-] Another kind of exception raised during overloading  -> '+err2+'\x1b[0m');
						}
					}
				}
				//console.log('\x1b[36m[+] SSLPeerUnverifiedException hooked\x1b[0m');
				return this.$init(reason);
			};
		} catch (err1) {
			//console.log('\x1b[36m[-] SSLPeerUnverifiedException not found\x1b[0m');
			//console.log('\x1b[36m'+err1+'\x1b[0m');
		}
		
 
	});
	
}, 0);




function returner(typeName) {
	// This is a improvable rudimentary fix, if not works you can patch it manually
	//console.log("typeName: "+typeName)
	if (typeName === undefined || typeName === 'void') {
		return;
	} else if (typeName === 'boolean') {
		return true;
	} else {
		return null;
	}
}


function overloader(errStr, targetClass, targetFunc, retType) {
	// One ring to overload them all.. ;-)
	var tClass = Java.use(targetClass);
	var tFunc = tClass[targetFunc];
	var params = [];
	var argList = [];
	var overloads = tFunc.overloads;
	var returnTypeName = retType;
	var splittedList = String(errStr).split('.overload');
	for (var n=1; n<splittedList.length; n++) {
		var extractedOverload = splittedList[n].trim().split('(')[1].slice(0,-1).replaceAll("'","");
		// Discarding useless error strings
		if (extractedOverload.includes('<signature>')) {
			continue;
		}
		console.log('\x1b[34m[!] Found the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"\x1b[0m');
		// Check if extractedOverload is empty
		if (!extractedOverload) {
			// Overloading method withouth arguments
			tFunc.overload().implementation = function() {
				var printStr = printer();
				console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
				returner(returnTypeName);
			}
		} else {
			// Check if extractedOverload has multiple arguments
			if (extractedOverload.includes(',')) {
				argList = extractedOverload.split(', ');
			} 
			// Considering max 8 arguments for the method to overload (Note: increase it, if needed)
			if (argList.length == 0) {
				tFunc.overload(extractedOverload).implementation = function(a) {
					var printStr = printer();
					console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
					returner(returnTypeName);
				}
			} else if (argList.length == 2) {
				tFunc.overload(argList[0], argList[1]).implementation = function(a,b) {
					var printStr = printer(a);
					console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
					returner(returnTypeName);
				}
			} else if (argList.length == 3) {
				tFunc.overload(argList[0], argList[1], argList[2]).implementation = function(a,b,c) {
					var printStr = printer(a,b);
					console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
					returner(returnTypeName);
				}
			} else if (argList.length == 4) {
				tFunc.overload(argList[0], argList[1], argList[2], argList[3]).implementation = function(a,b,c,d) {
					var printStr = printer(a,b,c);
					console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
					returner(returnTypeName);
				}
			}  else if (argList.length == 5) {
				tFunc.overload(argList[0], argList[1], argList[2], argList[3], argList[4]).implementation = function(a,b,c,d,e) {
					var printStr = printer(a,b,c,d);
					console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
					returner(returnTypeName);
				}
			}  else if (argList.length == 6) {
				tFunc.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5]).implementation = function(a,b,c,d,e,f) {
					var printStr = printer(a,b,c,d,e);
					console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
					returner(returnTypeName);
				}
			}  else if (argList.length == 7) {
				tFunc.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5], argList[6]).implementation = function(a,b,c,d,e,f,g) {
					var printStr = printer(a,b,c,d,e,f);
					console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
					returner(returnTypeName);
				}
			}  else if (argList.length == 8) {
				tFunc.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5], argList[6], argList[7]).implementation = function(a,b,c,d,e,f,g,h) {
					var printStr = printer(a,b,c,d,e,f,g);
					console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "'+targetClass+'.'+targetFunc+'('+extractedOverload+')"'+printStr+'\x1b[0m');
					returner(returnTypeName);
				}
			}
		}
		
	}
}


function printer(a,b,c,d,e,f,g,h) {
	// Build the string to print for the overloaded pinner
	var printList = [];
	var printStr = '';
	if (typeof a === 'string') {
		printList.push(a);
	}
	if (typeof b === 'string') {
		printList.push(b);
	}
	if (typeof c === 'string') {
		printList.push(c);
	}
	if (typeof d === 'string') {
		printList.push(d);
	}
	if (typeof e === 'string') {
		printList.push(e);
	}
	if (typeof f === 'string') {
		printList.push(f);
	}
	if (typeof g === 'string') {
		printList.push(g);
	}
	if (typeof h === 'string') {
		printList.push(h);
	}
	if (printList.length !== 0) {
		printStr = ' check for:';
		for (var i=0; i<printList.length; i++) {
			printStr += ' '+printList[i];
		}
	}
	return printStr;
}


Java.perform(function() {
 
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
 
    ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
        // console.log('Bypassing SSL Pinning');
        var k = array_list.$new();
        return k;
    }
 
}, 0);
 
 
Java.perform(function() {
 
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.android.vending.billing.InAppBillingService.COIN","com.topjohnwu.magisk"
    ];
 
    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk","magisk"];
 
    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };
 
    var RootPropertiesKeys = [];
 
    for (var k in RootProperties) RootPropertiesKeys.push(k);
 
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
 
    var Runtime = Java.use('java.lang.Runtime');
 
    var NativeFile = Java.use('java.io.File');
 
    var String = Java.use('java.lang.String');
 
    var SystemProperties = Java.use('android.os.SystemProperties');
 
    var BufferedReader = Java.use('java.io.BufferedReader');
 
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
 
    var StringBuffer = Java.use('java.lang.StringBuffer');
 
    var loaded_classes = Java.enumerateLoadedClassesSync();
 
    send("Loaded " + loaded_classes.length + " classes!");
 
    var useKeyInfo = false;
 
    var useProcessManager = false;
 
    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));
 
    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {
            //useProcessManager = true;
            //var ProcessManager = Java.use('java.lang.ProcessManager');
        } catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }
 
    var KeyInfo = null;
 
    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }
 
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.call(this, pname, flags);
    };
 
    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };
 
    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');
 
    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "which") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass which command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };
 
    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
 
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };
 
    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
 
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };
 
    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };
 
    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
 
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }
 
        return exec.call(this, cmd);
    };
 
    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };
 
    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };
 
    var get = SystemProperties.get.overload('java.lang.String');
 
    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };
 
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path1 = Memory.readCString(args[0]);
            var path = path1.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/ggezxxx");
                send("Bypass native fopen >> "+path1);
            }
        },
        onLeave: function(retval) {
 
        }
    });
 
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path1 = Memory.readCString(args[0]);
            var path = path1.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/ggezxxx");
                send("Bypass native fopen >> "+path1);
            }
        },
        onLeave: function(retval) {
 
        }
    });
 
    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function(retval) {
 
        }
    });

 
    BufferedReader.readLine.overload().implementation = function() {
        var text = this.readLine.call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };
 
    var executeCommand = ProcessBuilder.command.overload('java.util.List');
 
    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }
 
        return this.start.call(this);
    };
 
    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');
 
        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }
 
                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };
 
        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }
 
                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }
 
    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            send("Bypass isInsideSecureHardware");
            return true;
        }
    }
 
});


setTimeout(function () {
    // pattern bytes
    var pattern = "ff 03 05 d1 fd 7b 0f a9 bc de 05 94 08 0a 80 52 48"
    // library name
    var module = "libflutter.so"
    // define your arm version
    var armversion = 8
    // expected return value
    var expectedReturnValue = true
    
    // random string, you may ignore this
    console.log("Horangi - Bypass Flutter SSL Pinning")
    // enumerate all process
    Process.enumerateModules().forEach(v => {
        // if the module matches with our library
        if(v['name'] == module) {
            // debugging purposes
            console.log("Base: ", v['base'], "| Size: ", v['size'], "\n")
            // scanning memory - synchronous version
            // compare it based on base, size and pattern
            Memory.scanSync(v['base'], v['size'], pattern).forEach(mem => {
                // assign address to variable offset
                var offset = mem['address']
                if(armversion === 7) {
                    // armv7 add 1
                    offset = offset.add(1)
                }
                // another debugging purposes
                console.log("Address:",offset,"::", mem['size'])
                // hook to the address
                Interceptor.attach(offset, {
                    // when leaving the address, 
                    onLeave: function(retval) {
                        // execute this debugging purpose (again)
                        console.log("ReturnValue",offset,"altered from", +retval,"to", +expectedReturnValue)
                        // replace the return value to expectedReturnValue
                        retval.replace(+expectedReturnValue);
                    }
                })
            })
        }
    });
}, 1000)

function bypass_developerMode_check() {
    var settingSecure = Java.use('android.provider.Settings$Secure');
    settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
        console.log("[!] settingSecure.getInt(cr,name) : " + name);
        console.log('[+] 1.Secure.getInt(' + name + ') Bypassed');
        return 0;
    }
    settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        console.log("[!] settingSecure.getInt(cr,name) : " + name);
        console.log('[+] 2.Secure.getInt(' + name + ') Bypassed');
        return 0;
    }
    var settingGlobal = Java.use('android.provider.Settings$Global');
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
        console.log("[!] settingGlobal.getInt(cr,name) : " + name);
        console.log('[+] 1.Global.getInt(' + name + ') Bypassed');
        return 0;
    }
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        console.log("[!] settingGlobal.getInt(cr,name) : " + name);
        console.log('[+] 2.Global.getInt(' + name + ') Bypassed');
        return 0;
    }
}

// Main
Java.perform(function() {
    bypass_developerMode_check();
});

/* 
   Bypass react-native-device-info emulator detection
   $ frida --codeshare khantsithu1998/bypass-react-native-emulator-detection -U -f <your-application-package-name>
   By Khant Si Thu (https://twitter.com/KhantZero)
*/

if (Java.available) {
    Java.perform(function() {
        try {
            var Activity = Java.use("com.learnium.RNDeviceInfo.RNDeviceModule");
            Activity.isEmulator.implementation = function() {
                Promise.resolve(false)
            }
        } catch (error) {
            console.log("[-] Error Detected");
            console.log((error.stack));
        }
    });
} else {
    console.log("")
    console.log("[-] Java is Not available");
}

const commonPaths = [
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/failsafe/su",
    "/system/bin/su",
    "/su/bin/su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/sd/xbin/su",
    "/system/xbin/busybox",
    "/system/xbin/daemonsu",
    "/system/xbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/cache/su",
    "/data/su",
    "/dev/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk",
    "/data/adb/magisk",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/data/adb/magisk.img",
    "/data/adb/magisk.db",
    "/data/adb/magisk_simple",
    "/init.magisk.rc",
    "/system/xbin/ku.sud",
    "/data/adb/ksu",
    "/data/adb/ksud",
];

const ROOTmanagementApp = [
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.topjohnwu.magisk",
    "me.weishu.kernelsu",
];

/**
 * Bypass Emulator Detection
 * @param {any} function(
 * @returns {any}
 */
Java.perform(function() {

    Java.use("android.os.Build").PRODUCT.value = "gracerltexx";
    Java.use("android.os.Build").MANUFACTURER.value = "samsung";
    Java.use("android.os.Build").BRAND.value = "samsung";
    Java.use("android.os.Build").DEVICE.value = "gracerlte";
    Java.use("android.os.Build").MODEL.value = "SM-N935F";
    Java.use("android.os.Build").HARDWARE.value = "samsungexynos8890";
    Java.use("android.os.Build").FINGERPRINT.value =
        "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys";


    try {
        Java.use("java.io.File").exists.implementation = function() {
            var name = Java.use("java.io.File").getName.call(this);
            var catched = ["qemud", "qemu_pipe", "drivers", "cpuinfo"].indexOf(name) > -1;
            if (catched) {
                console.log("the pipe " + name + " existence is hooked");
                return false;
            } else {
                return this.exists.call(this);
            }
        };
    } catch (err) {
        console.log("[-] java.io.File.exists never called [-]");
    }

    // rename the package names
    try {
        Java.use("android.app.ApplicationPackageManager").getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(name, flag) {
            var catched = ["com.example.android.apis", "com.android.development"].indexOf(name) >
                -1;
            if (catched) {
                console.log("the package " + name + " is renamed with fake name");
                name = "fake.package.name";
            }
            return this.getPackageInfo.call(this, name, flag);
        };
    } catch (err) {
        console.log(
            "[-] ApplicationPackageManager.getPackageInfo never called [-]"
        );
    }

    // hook the `android_getCpuFamily` method
    // https://android.googlesource.com/platform/ndk/+/master/sources/android/cpufeatures/cpu-features.c#1067
    // Note: If you pass "null" as the first parameter for "Module.findExportByName" it will search in all modules
    try {
        Interceptor.attach(Module.findExportByName(null, "android_getCpuFamily"), {
            onLeave: function(retval) {
                // const int ANDROID_CPU_FAMILY_X86 = 2;
                // const int ANDROID_CPU_FAMILY_X86_64 = 5;
                if ([2, 5].indexOf(retval) > -1) {
                    // const int ANDROID_CPU_FAMILY_ARM64 = 4;
                    retval.replace(4);
                }
            },
        });
    } catch (err) {
        console.log("[-] android_getCpuFamily never called [-]");
        // TODO: trace RegisterNatives in case the libraries are stripped.
    }
});

/**
 * Bypass Root Detection
 * @param {any} function(
 * @returns {any}
 */
setTimeout(function() {
    function stackTraceHere(isLog) {
        var Exception = Java.use("java.lang.Exception");
        var Log = Java.use("android.util.Log");
        var stackinfo = Log.getStackTraceString(Exception.$new());
        if (isLog) {
            console.log(stackinfo);
        } else {
            return stackinfo;
        }
    }

    function stackTraceNativeHere(isLog) {
        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join("\n\t");
        console.log(backtrace);
    }

    function bypassJavaFileCheck() {
        var UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            var stack = stackTraceHere(false);

            const filename = file.getAbsolutePath();

            if (filename.indexOf("magisk") >= 0) {
                console.log("Anti Root Detect - check file: " + filename);
                return false;
            }

            if (commonPaths.indexOf(filename) >= 0) {
                console.log("Anti Root Detect - check file: " + filename);
                return false;
            }

            return this.checkAccess(file, access);
        };
    }

    function bypassNativeFileCheck() {
        var fopen = Module.findExportByName("libc.so", "fopen");
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (retval.toInt32() != 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        console.log("Anti Root Detect - fopen : " + this.inputPath);
                        retval.replace(ptr(0x0));
                    }
                }
            },
        });

        var access = Module.findExportByName("libc.so", "access");
        Interceptor.attach(access, {
            onEnter: function(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (retval.toInt32() == 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        console.log("Anti Root Detect - access : " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            },
        });
    }

    function setProp() {
        var Build = Java.use("android.os.Build");
        var TAGS = Build.class.getDeclaredField("TAGS");
        TAGS.setAccessible(true);
        TAGS.set(null, "release-keys");

        var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT");
        FINGERPRINT.setAccessible(true);
        FINGERPRINT.set(
            null,
            "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys"
        );

        // Build.deriveFingerprint.inplementation = function(){
        //     var ret = this.deriveFingerprint() //该函数无法通过反射调用
        //     console.log(ret)
        //     return ret
        // }

        var system_property_get = Module.findExportByName(
            "libc.so",
            "__system_property_get"
        );
        Interceptor.attach(system_property_get, {
            onEnter(args) {
                this.key = args[0].readCString();
                this.ret = args[1];
            },
            onLeave(ret) {
                if (this.key == "ro.build.fingerprint") {
                    var tmp =
                        "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys";
                    var p = Memory.allocUtf8String(tmp);
                    Memory.copy(this.ret, p, tmp.length + 1);
                }
            },
        });
    }

    //android.app.PackageManager
    function bypassRootAppCheck() {
        var ApplicationPackageManager = Java.use(
            "android.app.ApplicationPackageManager"
        );
        ApplicationPackageManager.getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(str, i) {
            // console.log(str)
            if (ROOTmanagementApp.indexOf(str) >= 0) {
                console.log("Anti Root Detect - check package : " + str);
                str = "ashen.one.ye.not.found";
            }
            return this.getPackageInfo(str, i);
        };

        //shell pm check
    }

    function bypassShellCheck() {
        var String = Java.use("java.lang.String");

        var ProcessImpl = Java.use("java.lang.ProcessImpl");
        ProcessImpl.start.implementation = function(
            cmdarray,
            env,
            dir,
            redirects,
            redirectErrorStream
        ) {
            if (cmdarray[0] == "mount") {
                console.log("Anti Root Detect - Shell : " + cmdarray.toString());
                arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                return ProcessImpl.start.apply(this, arguments);
            }

            if (cmdarray[0] == "getprop") {
                console.log("Anti Root Detect - Shell : " + cmdarray.toString());
                const prop = ["ro.secure", "ro.debuggable"];
                if (prop.indexOf(cmdarray[1]) >= 0) {
                    arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                    return ProcessImpl.start.apply(this, arguments);
                }
            }

            if (cmdarray[0].indexOf("which") >= 0) {
                const prop = ["su"];
                if (prop.indexOf(cmdarray[1]) >= 0) {
                    console.log("Anti Root Detect - Shell : " + cmdarray.toString());
                    arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                    return ProcessImpl.start.apply(this, arguments);
                }
            }

            return ProcessImpl.start.apply(this, arguments);
        };
    }

    console.log("Attach");
    bypassNativeFileCheck();
    bypassJavaFileCheck();
    setProp();
    bypassRootAppCheck();
    bypassShellCheck();


    Java.perform(function() {
        var RootPackages = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "eu.chainfire.supersu.pro",
            "com.kingouser.com",
            "com.topjohnwu.magisk",
        ];

        var RootBinaries = [
            "su",
            "busybox",
            "supersu",
            "Superuser.apk",
            "KingoUser.apk",
            "SuperSu.apk",
            "magisk",
        ];

        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1",
        };

        var RootPropertiesKeys = [];

        for (var k in RootProperties) RootPropertiesKeys.push(k);

        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        var Runtime = Java.use("java.lang.Runtime");

        var NativeFile = Java.use("java.io.File");

        var String = Java.use("java.lang.String");

        var SystemProperties = Java.use("android.os.SystemProperties");

        var BufferedReader = Java.use("java.io.BufferedReader");

        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");

        var StringBuffer = Java.use("java.lang.StringBuffer");

        var loaded_classes = Java.enumerateLoadedClassesSync();

        send("Loaded " + loaded_classes.length + " classes!");

        var useKeyInfo = false;

        var useProcessManager = false;

        send("loaded: " + loaded_classes.indexOf("java.lang.ProcessManager"));

        if (loaded_classes.indexOf("java.lang.ProcessManager") != -1) {
            try {
                //useProcessManager = true;
                //var ProcessManager = Java.use('java.lang.ProcessManager');
            } catch (err) {
                send("ProcessManager Hook failed: " + err);
            }
        } else {
            send("ProcessManager hook not loaded");
        }

        var KeyInfo = null;

        if (loaded_classes.indexOf("android.security.keystore.KeyInfo") != -1) {
            try {
                //useKeyInfo = true;
                //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            } catch (err) {
                send("KeyInfo Hook failed: " + err);
            }
        } else {
            send("KeyInfo hook not loaded");
        }

        PackageManager.getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(pname, flags) {
            var shouldFakePackage = RootPackages.indexOf(pname) > -1;
            if (shouldFakePackage) {
                send("Bypass root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo
                .overload("java.lang.String", "int")
                .call(this, pname, flags);
        };

        NativeFile.exists.implementation = function() {
            var name = NativeFile.getName.call(this);
            var shouldFakeReturn = RootBinaries.indexOf(name) > -1;
            if (shouldFakeReturn) {
                send("Bypass return value for binary: " + name);
                return false;
            } else {
                return this.exists.call(this);
            }
        };

        var exec = Runtime.exec.overload("[Ljava.lang.String;");
        var exec1 = Runtime.exec.overload("java.lang.String");
        var exec2 = Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;");
        var exec3 = Runtime.exec.overload(
            "[Ljava.lang.String;",
            "[Ljava.lang.String;"
        );
        var exec4 = Runtime.exec.overload(
            "[Ljava.lang.String;",
            "[Ljava.lang.String;",
            "java.io.File"
        );
        var exec5 = Runtime.exec.overload(
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.io.File"
        );

        exec5.implementation = function(cmd, env, dir) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec5.call(this, cmd, env, dir);
        };

        exec4.implementation = function(cmdarr, env, file) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec4.call(this, cmdarr, env, file);
        };

        exec3.implementation = function(cmdarr, envp) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec3.call(this, cmdarr, envp);
        };

        exec2.implementation = function(cmd, env) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec2.call(this, cmd, env);
        };

        exec.implementation = function(cmd) {
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
            }

            return exec.call(this, cmd);
        };

        exec1.implementation = function(cmd) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec1.call(this, cmd);
        };

        String.contains.implementation = function(name) {
            if (name == "test-keys") {
                send("Bypass test-keys check");
                return false;
            }
            return this.contains.call(this, name);
        };

        var get = SystemProperties.get.overload("java.lang.String");

        get.implementation = function(name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                send("Bypass " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };

        Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
            onEnter: function(args) {
                var path = Memory.readCString(args[0]);
                path = path.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = RootBinaries.indexOf(executable) > -1;
                if (shouldFakeReturn) {
                    Memory.writeUtf8String(args[0], "/notexists");
                    send("Bypass native fopen");
                }
            },
            onLeave: function(retval) {},
        });

        Interceptor.attach(Module.findExportByName("libc.so", "system"), {
            onEnter: function(args) {
                var cmd = Memory.readCString(args[0]);
                send("SYSTEM CMD: " + cmd);
                if (
                    cmd.indexOf("getprop") != -1 ||
                    cmd == "mount" ||
                    cmd.indexOf("build.prop") != -1 ||
                    cmd == "id"
                ) {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(
                        args[0],
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"
                    );
                }
            },
            onLeave: function(retval) {},
        });

        /*

        TO IMPLEMENT:

        Exec Family

        int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
        int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
        int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execv(const char *path, char *const argv[]);
        int execve(const char *path, char *const argv[], char *const envp[]);
        int execvp(const char *file, char *const argv[]);
        int execvpe(const char *file, char *const argv[], char *const envp[]);

        */

        BufferedReader.readLine.overload("boolean").implementation = function() {
            var text = this.readLine.overload("boolean").call(this);
            if (text === null) {
                // just pass , i know it's ugly as hell but test != null won't work :(
            } else {
                var shouldFakeRead = text.indexOf("ro.build.tags=test-keys") > -1;
                if (shouldFakeRead) {
                    send("Bypass build.prop file read");
                    text = text.replace(
                        "ro.build.tags=test-keys",
                        "ro.build.tags=release-keys"
                    );
                }
            }
            return text;
        };

        var executeCommand = ProcessBuilder.command.overload("java.util.List");

        ProcessBuilder.start.implementation = function() {
            var cmd = this.command.call(this);
            var shouldModifyCommand = false;
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd.indexOf("mount") != -1 ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd.indexOf("id") != -1
                ) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, [
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                ]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };

        if (useProcessManager) {
            var ProcManExec = ProcessManager.exec.overload(
                "[Ljava.lang.String;",
                "[Ljava.lang.String;",
                "java.io.File",
                "boolean"
            );
            var ProcManExecVariant = ProcessManager.exec.overload(
                "[Ljava.lang.String;",
                "[Ljava.lang.String;",
                "java.lang.String",
                "java.io.FileDescriptor",
                "java.io.FileDescriptor",
                "java.io.FileDescriptor",
                "boolean"
            );

            ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (
                        tmp_cmd.indexOf("getprop") != -1 ||
                        tmp_cmd == "mount" ||
                        tmp_cmd.indexOf("build.prop") != -1 ||
                        tmp_cmd == "id"
                    ) {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = [
                            "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                        ];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
            };

            ProcManExecVariant.implementation = function(
                cmd,
                env,
                directory,
                stdin,
                stdout,
                stderr,
                redirect
            ) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (
                        tmp_cmd.indexOf("getprop") != -1 ||
                        tmp_cmd == "mount" ||
                        tmp_cmd.indexOf("build.prop") != -1 ||
                        tmp_cmd == "id"
                    ) {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = [
                            "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                        ];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExecVariant.call(
                    this,
                    fake_cmd,
                    env,
                    directory,
                    stdin,
                    stdout,
                    stderr,
                    redirect
                );
            };
        }

        if (useKeyInfo) {
            KeyInfo.isInsideSecureHardware.implementation = function() {
                send("Bypass isInsideSecureHardware");
                return true;
            };
        }
    });

}, 0);

/**
 * Bypass Multiple SSL Pinning
 * @param {any} function(
 * @returns {any}
 */
setTimeout(function() {
    Java.perform(function() {
        console.log("---");
        console.log("Unpinning Android app...");

        /// -- Generic hook to protect against SSLPeerUnverifiedException -- ///

        // In some cases, with unusual cert pinning approaches, or heavy obfuscation, we can't
        // match the real method & package names. This is a problem! Fortunately, we can still
        // always match built-in types, so here we spot all failures that use the built-in cert
        // error type (notably this includes OkHttp), and after the first failure, we dynamically
        // generate & inject a patch to completely disable the method that threw the error.
        try {
            const UnverifiedCertError = Java.use(
                "javax.net.ssl.SSLPeerUnverifiedException"
            );
            UnverifiedCertError.$init.implementation = function(str) {
                console.log(
                    "  --> Unexpected SSL verification failure, adding dynamic patch..."
                );

                try {
                    const stackTrace = Java.use("java.lang.Thread")
                        .currentThread()
                        .getStackTrace();
                    const exceptionStackIndex = stackTrace.findIndex(
                        (stack) =>
                        stack.getClassName() ===
                        "javax.net.ssl.SSLPeerUnverifiedException"
                    );
                    const callingFunctionStack = stackTrace[exceptionStackIndex + 1];

                    const className = callingFunctionStack.getClassName();
                    const methodName = callingFunctionStack.getMethodName();

                    console.log(`      Thrown by ${className}->${methodName}`);

                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];

                    if (callingMethod.implementation) return; // Already patched by Frida - skip it

                    console.log("      Attempting to patch automatically...");
                    const returnTypeName = callingMethod.returnType.type;

                    callingMethod.implementation = function() {
                        console.log(
                            `  --> Bypassing ${className}->${methodName} (automatic exception patch)`
                        );

                        // This is not a perfect fix! Most unknown cases like this are really just
                        // checkCert(cert) methods though, so doing nothing is perfect, and if we
                        // do need an actual return value then this is probably the best we can do,
                        // and at least we're logging the method name so you can patch it manually:

                        if (returnTypeName === "void") {
                            return;
                        } else {
                            return null;
                        }
                    };

                    console.log(
                        `      [+] ${className}->${methodName} (automatic exception patch)`
                    );
                } catch (e) {
                    console.log("      [ ] Failed to automatically patch failure");
                }

                return this.$init(str);
            };
            console.log("[+] SSLPeerUnverifiedException auto-patcher");
        } catch (err) {
            console.log("[ ] SSLPeerUnverifiedException auto-patcher");
        }

        /// -- Specific targeted hooks: -- ///

        // HttpsURLConnection
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(
                hostnameVerifier
            ) {
                console.log(
                    "  --> Bypassing HttpsURLConnection (setDefaultHostnameVerifier)"
                );
                return; // Do nothing, i.e. don't change the hostname verifier
            };
            console.log("[+] HttpsURLConnection (setDefaultHostnameVerifier)");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setDefaultHostnameVerifier)");
        }
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setSSLSocketFactory.implementation = function(
                SSLSocketFactory
            ) {
                console.log("  --> Bypassing HttpsURLConnection (setSSLSocketFactory)");
                return; // Do nothing, i.e. don't change the SSL socket factory
            };
            console.log("[+] HttpsURLConnection (setSSLSocketFactory)");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setSSLSocketFactory)");
        }
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setHostnameVerifier.implementation = function(
                hostnameVerifier
            ) {
                console.log("  --> Bypassing HttpsURLConnection (setHostnameVerifier)");
                return; // Do nothing, i.e. don't change the hostname verifier
            };
            console.log("[+] HttpsURLConnection (setHostnameVerifier)");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setHostnameVerifier)");
        }

        // SSLContext
        try {
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const SSLContext = Java.use("javax.net.ssl.SSLContext");

            const TrustManager = Java.registerClass({
                // Implement a custom TrustManager
                name: "dev.asd.test.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() {
                        return [];
                    },
                },
            });

            // Prepare the TrustManager array to pass to SSLContext.init()
            const TrustManagers = [TrustManager.$new()];

            // Get a handle on the init() on the SSLContext class
            const SSLContext_init = SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            );

            // Override the init method, specifying the custom TrustManager
            SSLContext_init.implementation = function(
                keyManager,
                trustManager,
                secureRandom
            ) {
                console.log("  --> Bypassing Trustmanager (Android < 7) request");
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
            console.log("[+] SSLContext");
        } catch (err) {
            console.log("[ ] SSLContext");
        }

        // TrustManagerImpl (Android > 7)
        try {
            const array_list = Java.use("java.util.ArrayList");
            const TrustManagerImpl = Java.use(
                "com.android.org.conscrypt.TrustManagerImpl"
            );

            // This step is notably what defeats the most common case: network security config
            TrustManagerImpl.checkTrustedRecursive.implementation = function(
                a1,
                a2,
                a3,
                a4,
                a5,
                a6
            ) {
                console.log("  --> Bypassing TrustManagerImpl checkTrusted ");
                return array_list.$new();
            };

            TrustManagerImpl.verifyChain.implementation = function(
                untrustedChain,
                trustAnchorChain,
                host,
                clientAuth,
                ocspData,
                tlsSctData
            ) {
                console.log("  --> Bypassing TrustManagerImpl verifyChain: " + host);
                return untrustedChain;
            };
            console.log("[+] TrustManagerImpl");
        } catch (err) {
            console.log("[ ] TrustManagerImpl");
        }

        // OkHTTPv3 (quadruple bypass)
        try {
            // Bypass OkHTTPv3 {1}
            const okhttp3_Activity_1 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_1.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 (list): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 (list)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 (list)");
        }
        try {
            // Bypass OkHTTPv3 {2}
            // This method of CertificatePinner.check could be found in some old Android app
            const okhttp3_Activity_2 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_2.check.overload(
                "java.lang.String",
                "java.security.cert.Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 (cert): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 (cert)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 (cert)");
        }
        try {
            // Bypass OkHTTPv3 {3}
            const okhttp3_Activity_3 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_3.check.overload(
                "java.lang.String",
                "[Ljava.security.cert.Certificate;"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 (cert array): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 (cert array)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 (cert array)");
        }
        try {
            // Bypass OkHTTPv3 {4}
            const okhttp3_Activity_4 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_4["check$okhttp"].implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 ($okhttp): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 ($okhttp)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 ($okhttp)");
        }

        // Trustkit (triple bypass)
        try {
            // Bypass Trustkit {1}
            const trustkit_Activity_1 = Java.use(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
            );
            trustkit_Activity_1.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing Trustkit OkHostnameVerifier(SSLSession): " + a
                );
                return true;
            };
            console.log("[+] Trustkit OkHostnameVerifier(SSLSession)");
        } catch (err) {
            console.log("[ ] Trustkit OkHostnameVerifier(SSLSession)");
        }
        try {
            // Bypass Trustkit {2}
            const trustkit_Activity_2 = Java.use(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
            );
            trustkit_Activity_2.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Trustkit OkHostnameVerifier(cert): " + a);
                return true;
            };
            console.log("[+] Trustkit OkHostnameVerifier(cert)");
        } catch (err) {
            console.log("[ ] Trustkit OkHostnameVerifier(cert)");
        }
        try {
            // Bypass Trustkit {3}
            const trustkit_PinningTrustManager = Java.use(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager"
            );
            trustkit_PinningTrustManager.checkServerTrusted.implementation =
                function() {
                    console.log("  --> Bypassing Trustkit PinningTrustManager");
                };
            console.log("[+] Trustkit PinningTrustManager");
        } catch (err) {
            console.log("[ ] Trustkit PinningTrustManager");
        }

        // Appcelerator Titanium
        try {
            const appcelerator_PinningTrustManager = Java.use(
                "appcelerator.https.PinningTrustManager"
            );
            appcelerator_PinningTrustManager.checkServerTrusted.implementation =
                function() {
                    console.log("  --> Bypassing Appcelerator PinningTrustManager");
                };
            console.log("[+] Appcelerator PinningTrustManager");
        } catch (err) {
            console.log("[ ] Appcelerator PinningTrustManager");
        }

        // OpenSSLSocketImpl Conscrypt
        try {
            const OpenSSLSocketImpl = Java.use(
                "com.android.org.conscrypt.OpenSSLSocketImpl"
            );
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function(
                certRefs,
                JavaObject,
                authMethod
            ) {
                console.log("  --> Bypassing OpenSSLSocketImpl Conscrypt");
            };
            console.log("[+] OpenSSLSocketImpl Conscrypt");
        } catch (err) {
            console.log("[ ] OpenSSLSocketImpl Conscrypt");
        }

        // OpenSSLEngineSocketImpl Conscrypt
        try {
            const OpenSSLEngineSocketImpl_Activity = Java.use(
                "com.android.org.conscrypt.OpenSSLEngineSocketImpl"
            );
            OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload(
                "[Ljava.lang.Long;",
                "java.lang.String"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OpenSSLEngineSocketImpl Conscrypt: " + b);
            };
            console.log("[+] OpenSSLEngineSocketImpl Conscrypt");
        } catch (err) {
            console.log("[ ] OpenSSLEngineSocketImpl Conscrypt");
        }

        // OpenSSLSocketImpl Apache Harmony
        try {
            const OpenSSLSocketImpl_Harmony = Java.use(
                "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl"
            );
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation =
                function(asn1DerEncodedCertificateChain, authMethod) {
                    console.log("  --> Bypassing OpenSSLSocketImpl Apache Harmony");
                };
            console.log("[+] OpenSSLSocketImpl Apache Harmony");
        } catch (err) {
            console.log("[ ] OpenSSLSocketImpl Apache Harmony");
        }

        // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)
        try {
            const phonegap_Activity = Java.use(
                "nl.xservices.plugins.sslCertificateChecker"
            );
            phonegap_Activity.execute.overload(
                "java.lang.String",
                "org.json.JSONArray",
                "org.apache.cordova.CallbackContext"
            ).implementation = function(a, b, c) {
                console.log("  --> Bypassing PhoneGap sslCertificateChecker: " + a);
                return true;
            };
            console.log("[+] PhoneGap sslCertificateChecker");
        } catch (err) {
            console.log("[ ] PhoneGap sslCertificateChecker");
        }

        // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
        try {
            // Bypass IBM MobileFirst {1}
            const WLClient_Activity_1 = Java.use(
                "com.worklight.wlclient.api.WLClient"
            );
            WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload(
                "java.lang.String"
            ).implementation = function(cert) {
                console.log(
                    "  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): " +
                    cert
                );
                return;
            };
            console.log(
                "[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string)"
            );
        }
        try {
            // Bypass IBM MobileFirst {2}
            const WLClient_Activity_2 = Java.use(
                "com.worklight.wlclient.api.WLClient"
            );
            WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload(
                "[Ljava.lang.String;"
            ).implementation = function(cert) {
                console.log(
                    "  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string array): " +
                    cert
                );
                return;
            };
            console.log(
                "[+] IBM MobileFirst pinTrustedCertificatePublicKey (string array)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string array)"
            );
        }

        // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
        try {
            // Bypass IBM WorkLight {1}
            const worklight_Activity_1 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_1.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSocket"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket): " +
                    a
                );
                return;
            };
            console.log(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)"
            );
        }
        try {
            // Bypass IBM WorkLight {2}
            const worklight_Activity_2 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_2.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (cert): " +
                    a
                );
                return;
            };
            console.log(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)"
            );
        }
        try {
            // Bypass IBM WorkLight {3}
            const worklight_Activity_3 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_3.verify.overload(
                "java.lang.String",
                "[Ljava.lang.String;",
                "[Ljava.lang.String;"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (string string): " +
                    a
                );
                return;
            };
            console.log(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)"
            );
        }
        try {
            // Bypass IBM WorkLight {4}
            const worklight_Activity_4 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_4.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession): " +
                    a
                );
                return true;
            };
            console.log(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)"
            );
        }

        // Conscrypt CertPinManager
        try {
            const conscrypt_CertPinManager_Activity = Java.use(
                "com.android.org.conscrypt.CertPinManager"
            );
            conscrypt_CertPinManager_Activity.isChainValid.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Conscrypt CertPinManager: " + a);
                return true;
            };
            console.log("[+] Conscrypt CertPinManager");
        } catch (err) {
            console.log("[ ] Conscrypt CertPinManager");
        }

        // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager
        try {
            const cwac_CertPinManager_Activity = Java.use(
                "com.commonsware.cwac.netsecurity.conscrypt.CertPinManager"
            );
            cwac_CertPinManager_Activity.isChainValid.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing CWAC-Netsecurity CertPinManager: " + a);
                return true;
            };
            console.log("[+] CWAC-Netsecurity CertPinManager");
        } catch (err) {
            console.log("[ ] CWAC-Netsecurity CertPinManager");
        }

        // Worklight Androidgap WLCertificatePinningPlugin
        try {
            const androidgap_WLCertificatePinningPlugin_Activity = Java.use(
                "com.worklight.androidgap.plugin.WLCertificatePinningPlugin"
            );
            androidgap_WLCertificatePinningPlugin_Activity.execute.overload(
                "java.lang.String",
                "org.json.JSONArray",
                "org.apache.cordova.CallbackContext"
            ).implementation = function(a, b, c) {
                console.log(
                    "  --> Bypassing Worklight Androidgap WLCertificatePinningPlugin: " +
                    a
                );
                return true;
            };
            console.log("[+] Worklight Androidgap WLCertificatePinningPlugin");
        } catch (err) {
            console.log("[ ] Worklight Androidgap WLCertificatePinningPlugin");
        }

        // Netty FingerprintTrustManagerFactory
        try {
            const netty_FingerprintTrustManagerFactory = Java.use(
                "io.netty.handler.ssl.util.FingerprintTrustManagerFactory"
            );
            netty_FingerprintTrustManagerFactory.checkTrusted.implementation =
                function(type, chain) {
                    console.log("  --> Bypassing Netty FingerprintTrustManagerFactory");
                };
            console.log("[+] Netty FingerprintTrustManagerFactory");
        } catch (err) {
            console.log("[ ] Netty FingerprintTrustManagerFactory");
        }

        // Squareup CertificatePinner [OkHTTP<v3] (double bypass)
        try {
            // Bypass Squareup CertificatePinner {1}
            const Squareup_CertificatePinner_Activity_1 = Java.use(
                "com.squareup.okhttp.CertificatePinner"
            );
            Squareup_CertificatePinner_Activity_1.check.overload(
                "java.lang.String",
                "java.security.cert.Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Squareup CertificatePinner (cert): " + a);
                return;
            };
            console.log("[+] Squareup CertificatePinner (cert)");
        } catch (err) {
            console.log("[ ] Squareup CertificatePinner (cert)");
        }
        try {
            // Bypass Squareup CertificatePinner {2}
            const Squareup_CertificatePinner_Activity_2 = Java.use(
                "com.squareup.okhttp.CertificatePinner"
            );
            Squareup_CertificatePinner_Activity_2.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Squareup CertificatePinner (list): " + a);
                return;
            };
            console.log("[+] Squareup CertificatePinner (list)");
        } catch (err) {
            console.log("[ ] Squareup CertificatePinner (list)");
        }

        // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass)
        try {
            // Bypass Squareup OkHostnameVerifier {1}
            const Squareup_OkHostnameVerifier_Activity_1 = Java.use(
                "com.squareup.okhttp.internal.tls.OkHostnameVerifier"
            );
            Squareup_OkHostnameVerifier_Activity_1.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Squareup OkHostnameVerifier (cert): " + a);
                return true;
            };
            console.log("[+] Squareup OkHostnameVerifier (cert)");
        } catch (err) {
            console.log("[ ] Squareup OkHostnameVerifier (cert)");
        }
        try {
            // Bypass Squareup OkHostnameVerifier {2}
            const Squareup_OkHostnameVerifier_Activity_2 = Java.use(
                "com.squareup.okhttp.internal.tls.OkHostnameVerifier"
            );
            Squareup_OkHostnameVerifier_Activity_2.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing Squareup OkHostnameVerifier (SSLSession): " + a
                );
                return true;
            };
            console.log("[+] Squareup OkHostnameVerifier (SSLSession)");
        } catch (err) {
            console.log("[ ] Squareup OkHostnameVerifier (SSLSession)");
        }

        // Android WebViewClient (double bypass)
        try {
            // Bypass WebViewClient {1} (deprecated from Android 6)
            const AndroidWebViewClient_Activity_1 = Java.use(
                "android.webkit.WebViewClient"
            );
            AndroidWebViewClient_Activity_1.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.SslErrorHandler",
                "android.net.http.SslError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Android WebViewClient (SslErrorHandler)");
            };
            console.log("[+] Android WebViewClient (SslErrorHandler)");
        } catch (err) {
            console.log("[ ] Android WebViewClient (SslErrorHandler)");
        }
        try {
            // Bypass WebViewClient {2}
            const AndroidWebViewClient_Activity_2 = Java.use(
                "android.webkit.WebViewClient"
            );
            AndroidWebViewClient_Activity_2.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.WebResourceRequest",
                "android.webkit.WebResourceError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Android WebViewClient (WebResourceError)");
            };
            console.log("[+] Android WebViewClient (WebResourceError)");
        } catch (err) {
            console.log("[ ] Android WebViewClient (WebResourceError)");
        }

        // Apache Cordova WebViewClient
        try {
            const CordovaWebViewClient_Activity = Java.use(
                "org.apache.cordova.CordovaWebViewClient"
            );
            CordovaWebViewClient_Activity.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.SslErrorHandler",
                "android.net.http.SslError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Apache Cordova WebViewClient");
                obj3.proceed();
            };
        } catch (err) {
            console.log("[ ] Apache Cordova WebViewClient");
        }

        // Boye AbstractVerifier
        try {
            const boye_AbstractVerifier = Java.use(
                "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier"
            );
            boye_AbstractVerifier.verify.implementation = function(host, ssl) {
                console.log("  --> Bypassing Boye AbstractVerifier: " + host);
            };
        } catch (err) {
            console.log("[ ] Boye AbstractVerifier");
        }

        // Appmattus
        try {
            const appmatus_Activity = Java.use(
                "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor"
            );
            appmatus_Activity["intercept"].implementation = function(a) {
                console.log("  --> Bypassing Appmattus (Transparency)");
                return a.proceed(a.request());
            };
            console.log("[+] Appmattus (CertificateTransparencyInterceptor)");
        } catch (err) {
            console.log("[ ] Appmattus (CertificateTransparencyInterceptor)");
        }

        try {
            const CertificateTransparencyTrustManager = Java.use(
                "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager"
            );
            CertificateTransparencyTrustManager["checkServerTrusted"].overload(
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String"
            ).implementation = function(x509CertificateArr, str) {
                console.log(
                    "  --> Bypassing Appmattus (CertificateTransparencyTrustManager)"
                );
            };
            CertificateTransparencyTrustManager["checkServerTrusted"].overload(
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String",
                "java.lang.String"
            ).implementation = function(x509CertificateArr, str, str2) {
                console.log(
                    "  --> Bypassing Appmattus (CertificateTransparencyTrustManager)"
                );
                return Java.use("java.util.ArrayList").$new();
            };
            console.log("[+] Appmattus (CertificateTransparencyTrustManager)");
        } catch (err) {
            console.log("[ ] Appmattus (CertificateTransparencyTrustManager)");
        }

        console.log("Unpinning setup completed");
        console.log("---");
    });
}, 0);

/*
	Universal Android Biometric Bypass v0.4
	author: ax - github.com/ax
	Updated Android biometric bypass script (from Kamil Breński, Krzysztof Pranczk and Mateusz Fruba, August 2019)
	This script will bypass authentication when the crypto object is not used.
	The authentication implementation relies on the callback onAuthenticationSucceded being called. 
    Bypass fingerprint authentication if the app accept NULL cryptoObject in onAuthenticationSucceeded(...).
    This script should automatically bypass fingerprint when authenticate(...) method will be called.
*/

Java.perform(function () {
    //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
    try { hookBiometricPrompt_authenticate(); }
    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
    try { hookBiometricPrompt_authenticate2(); }
    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
    try { hookFingerprintManagerCompat_authenticate(); }
    catch (error) { console.log("hookFingerprintManagerCompat_authenticate failed"); }
    try { hookFingerprintManager_authenticate(); }
    catch (error) { console.log("hookFingerprintManager_authenticate failed"); }
});


var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');


});

function getArgsTypes(overloads) {
	// there should be just one overload for the constructor
	// overloads.len == 1 check
    var results = []
	var i,j;
    for (i in overloads) {
		console.log('[*] Overload number ind: '+i);
        //if (overloads[i].hasOwnProperty('argumentTypes')) {
           var parameters = []
           for (j in overloads[i].argumentTypes) {
               parameters.push("'" + overloads[i].argumentTypes[j].className + "'")
           }
       // }
        results.push('(' + parameters.join(', ') + ');')
    }
    return results.join('\n')
}

function getAuthResult(resultObj, cryptoInst) {
	//var clax = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
	var clax = resultObj;
	var resu = getArgsTypes(clax['$init'].overloads);
	//console.log(resu);
	resu = resu.replace(/\'android\.hardware\.biometrics\.BiometricPrompt\$CryptoObject\'/, 'cryptoInst');
	resu = resu.replace(/\'android\.hardware\.fingerprint\.FingerprintManager\$CryptoObject\'/, 'cryptoInst');
	resu = resu.replace('\'int\'', '0');
	resu = resu.replace('\'boolean\'', 'false');
	resu = resu.replace(/'.*'/, 'null');
	//console.log(resu);
	resu = "resultObj.$new"+resu;
	var authenticationResultInst = eval(resu);
    console.log("cryptoInst:, " + cryptoInst + " class: " + cryptoInst.$className);
    return authenticationResultInst;
}

function getBiometricPromptAuthResult() {
    var sweet_cipher = null;
    var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
    var cryptoInst = cryptoObj.$new(sweet_cipher);
    var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
    return authenticationResultInst
}

function hookBiometricPrompt_authenticate() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("Hooking BiometricPrompt.authenticate()...");
    biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
        console.log("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    	console.log("[BiometricPrompt.BiometricPrompt()]: callback.onAuthenticationSucceeded(NULL) called!");
    }
}

function hookBiometricPrompt_authenticate2() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("Hooking BiometricPrompt.authenticate2()...");
    biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
        console.log("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto + ", cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    }
}

function hookFingerprintManagerCompat_authenticate() {
    /*
    void authenticate (FingerprintManagerCompat.CryptoObject crypto, 
                    int flags, 
                    CancellationSignal cancel, 
                    FingerprintManagerCompat.AuthenticationCallback callback, 
                    Handler handler)
    */
    var fingerprintManagerCompat = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
        cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
        authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
        }
        catch (error) {
            console.log("FingerprintManagerCompat class not found!");
            return
        }
    }
    console.log("Hooking FingerprintManagerCompat.authenticate()...");
    var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
    fingerprintManagerCompat_authenticate.implementation = function (crypto, flags, cancel, callback, handler) {
        console.log("[FingerprintManagerCompat.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        //console.log(enumMethods(callback.$className));
        callback['onAuthenticationFailed'].implementation = function () {
            console.log("[onAuthenticationFailed()]:");
            var sweet_cipher = null;
            var cryptoInst = cryptoObj.$new(sweet_cipher);
            var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
            callback.onAuthenticationSucceeded(authenticationResultInst);
        }
        return this.authenticate(crypto, flags, cancel, callback, handler);
    }
}

function hookFingerprintManager_authenticate() {
    /*
    public void authenticate (FingerprintManager.CryptoObject crypto, 
                    CancellationSignal cancel, 
                    int flags, 
                    FingerprintManager.AuthenticationCallback callback, 
                    Handler handler)
Error: authenticate(): has more than one overload, use .overload(<signature>) to choose from:
    .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler')
    .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler', 'int')
    */
    var fingerprintManager = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        }
        catch (error) {
            console.log("FingerprintManager class not found!");
            return
        }
    }
    console.log("Hooking FingerprintManager.authenticate()...");



    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
    fingerprintManager_authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
        console.log("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        var sweet_cipher = null;
        var cryptoInst = cryptoObj.$new(sweet_cipher);
        var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
        callback.onAuthenticationSucceeded(authenticationResultInst);
        return this.authenticate(crypto, cancel, flags, callback, handler);
    }
}


function enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();

    return ownMethods;
}

Java.perform(function () { let M2pECDHAlgorithm = Java.use("m2p.dcb.sdk.encryption.ecdhalgorithm.M2pECDHAlgorithm");
    M2pECDHAlgorithm["generateSecretKey"].implementation = function () {
        console.log(`M2pECDHAlgorithm.generateSecretKey is called`);
        let result = this["generateSecretKey"]();
        console.log(`M2pECDHAlgorithm.generateSecretKey result=${result}`);
        return result;
    }; });

    Java.perform(function () { let M2pECDHAlgorithm = Java.use("m2p.dcb.sdk.encryption.ecdhalgorithm.M2pECDHAlgorithm");
        M2pECDHAlgorithm["aesEncryption"].implementation = function (str, str2) {
            console.log(`M2pECDHAlgorithm.aesEncryption is called: str=${str}, str2=${str2}`);
            let result = this["aesEncryption"](str, str2);
            console.log(`M2pECDHAlgorithm.aesEncryption result=${result}`);
            return result;
        }; });