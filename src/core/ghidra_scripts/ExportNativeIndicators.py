# @author LucidByte
# @category MalwareAnalysis
# @keybinding
# @menupath

import os, json, re
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Listing
from ghidra.program.model.symbol import SourceType, SymbolTable

class ExportNativeIndicators(GhidraScript):
    def run(self):
        if len(getScriptArgs()) < 1:
            print("Usage: ExportNativeIndicators.py <output_json>")
            return
        
        output_path = getScriptArgs()[0]
        results = {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "jni_functions": [],
            "suspicious_names": []
        }
        
        listing = currentProgram.getListing()
        for func in listing.getFunctions(True):
            fname = func.getName()
            fentry = str(func.getEntryPoint())
            
            if fname.startswith("Java_") or fname.startswith("JNI_"):
                results["jni_functions"].append({
                    "name": fname,
                    "address": fentry,
                    "signature": str(func.getSignature())
                })
            
            suspicious = ["crypto", "encrypt", "decrypt", "key", "secret", 
                         "inject", "hook", "root", "su", "priv", "hide"]
            for kw in suspicious:
                if kw in fname.lower():
                    results["suspicious_names"].append({
                        "function": fname,
                        "address": fentry,
                        "keyword": kw,
                        "risk": "High"
                    })
                    break
            
            results["functions"].append({"name": fname, "address": fentry})
        
        symbol_table = currentProgram.getSymbolTable()
        for sym in symbol_table.getSymbolIterator():
            if sym.isExternalEntryPoint():
                sym_name = sym.getName()
                results["imports"].append({
                    "name": sym_name,
                    "address": str(sym.getAddress()),
                    "risk": self._assess_import_risk(sym_name)
                })
        
        for sym in symbol_table.getSymbolIterator():
            if sym.getSource() == SourceType.USER_DEFINED and sym.isGlobal():
                sname = sym.getName()
                if sname.startswith("Java_") or sname.startswith("JNI_"):
                    results["exports"].append({
                        "name": sname,
                        "address": str(sym.getAddress())
                    })
        
        try:
            mem = currentProgram.getMemory()
            for block in mem.getBlocks():
                if block.isInitialized() and block.isRead():
                    try:
                        size = min(2*1024*1024, int(block.getSize()))
                        data = block.getBytes(block.getStart(), size)
                        strings = re.findall(b'[\x20-\x7E]{8,}', data)
                        for s in strings[:50]:
                            try:
                                decoded = s.decode('ascii')
                                if any(kw in decoded.lower() for kw in 
                                       ['http', 'https', '.so', '.apk', '192.168', '10.', '172.', 'api', 'token', 'key']):
                                    results["strings"].append(decoded[:150])
                            except:
                                pass
                    except:
                        pass
        except:
            pass
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print("Export: {} funcs, {} imports, {} JNI".format(
            len(results['functions']),
            len(results['imports']),
            len(results['jni_functions'])
        ))
    
    def _assess_import_risk(self, import_name):
        critical = ["exec", "system", "popen", "dlopen", "dlsym", "mmap", 
                    "ptrace", "getuid", "setuid", "chmod", "chown", "kill", "fork"]
        high = ["socket", "connect", "send", "recv", "open", "read", "write", 
                "close", "ioctl", "fcntl", "getenv", "putenv"]
        
        name_lower = import_name.lower()
        for kw in critical:
            if kw in name_lower:
                return "Critical"
        for kw in high:
            if kw in name_lower:
                return "High"
        return "Low"