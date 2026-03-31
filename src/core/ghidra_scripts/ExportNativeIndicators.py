# @author LucidByte
# @category MalwareAnalysis
# @keybinding
# @menupath

import os
import json
import re
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
        
        # === 1. Сбор функций (работает даже без анализа) ===
        listing = currentProgram.getListing()
        func_iter = listing.getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            fname = func.getName()
            fentry = str(func.getEntryPoint())
            
            # JNI функции — критично для Android
            if fname.startswith("Java_") or fname.startswith("JNI_"):
                results["jni_functions"].append({
                    "name": fname,
                    "address": fentry,
                    "signature": str(func.getSignature())
                })
            
            # Подозрительные имена
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
        
        # === 2. Сбор импортов (внешние символы) — работает без анализа ===
        symbol_table = currentProgram.getSymbolTable()
        sym_iter = symbol_table.getSymbolIterator()
        while sym_iter.hasNext():
            sym = sym_iter.next()
            if sym.isExternalEntryPoint():
                sym_name = sym.getName()
                results["imports"].append({
                    "name": sym_name,
                    "address": str(sym.getAddress()),
                    "risk": self._assess_import_risk(sym_name)
                })
        
        # === 3. Сбор экспортов (JNI entry points) ===
        sym_iter2 = symbol_table.getSymbolIterator()
        while sym_iter2.hasNext():
            sym = sym_iter2.next()
            if sym.getSource() == SourceType.USER_DEFINED and sym.isGlobal():
                sname = sym.getName()
                if sname.startswith("Java_") or sname.startswith("JNI_"):
                    results["exports"].append({
                        "name": sname,
                        "address": str(sym.getAddress())
                    })
        
        # === 4. Строки из памяти (работает без анализа) ===
        try:
            mem = currentProgram.getMemory()
            blocks = mem.getBlocks()
            while blocks.hasNext():
                block = blocks.next()
                if block.isInitialized() and block.isRead():
                    try:
                        size = min(2*1024*1024, int(block.getSize()))
                        data = block.getBytes(block.getStart(), size)
                        # ASCII строки 8+ символов
                        strings = re.findall(b'[\x20-\x7E]{8,}', data)
                        count = 0
                        for s in strings:
                            if count >= 50:
                                break
                            try:
                                decoded = s.decode('ascii')
                                # Фильтр: только сетевые/подозрительные
                                keywords = ['http', 'https', '.so', '.apk', '192.168', '10.', '172.', 'api', 'token', 'key']
                                found = False
                                for kw in keywords:
                                    if kw in decoded.lower():
                                        found = True
                                        break
                                if found:
                                    results["strings"].append(decoded[:150])
                                    count += 1
                            except:
                                pass
                    except:
                        pass
        except:
            pass
        
        # === 5. Сохранение ===
        f = open(output_path, "w")
        try:
            f.write(json.dumps(results, indent=2, ensure_ascii=False))
        finally:
            f.close()
        
        # Вывод статистики (Jython-совместимый)
        print("✓ Export: {} funcs, {} imports, {} JNI".format(
            len(results['functions']),
            len(results['imports']),
            len(results['jni_functions'])
        ))
    
    def _assess_import_risk(self, import_name):
        """Оценка риска импортируемой функции"""
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