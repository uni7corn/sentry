// Hook dlsym，让检测代码拿到的是真实libc地址，而非Frida trampoline
var dlsymPtr = Module.findExportByName(null, "dlsym");
var originalDlsym = new NativeFunction(dlsymPtr, 'pointer', ['pointer', 'pointer']);

// 预先缓存关键函数的原始地址
var libc = Process.getModuleByName("libc.so");
var targetFuncs = ["open", "read", "write", "strcmp", "malloc", "free", "connect", "socket"];
var originalAddrs = {};

targetFuncs.forEach(function(name) {
    var addr = libc.findExportByName(name);
    if (addr) {
        originalAddrs[name] = addr;
        console.log("[+] Cached original " + name + " at " + addr);
    }
});

Interceptor.replace(dlsymPtr, new NativeCallback(function(handle, symbol) {
    var symName = symbol.readCString();
    
    // 对被检测的函数，返回原始libc地址
    if (originalAddrs[symName]) {
        console.log("[*] dlsym(" + symName + ") -> returning original address");
        return originalAddrs[symName];
    }
    
    // 其他函数正常处理
    return originalDlsym(handle, symbol);
}, 'pointer', ['pointer', 'pointer']));

console.log("[✓] dlsym bypass loaded - GOT detection should fail");
