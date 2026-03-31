"""
Native Library Analyzer for PyGhidra
Анализ .so библиотек через PyGhidra API (Python 3)
"""

import json
import re
from typing import Dict, List, Any

try:
    import pyghidra
    PYGHIDRA_AVAILABLE = True
except ImportError:
    PYGHIDRA_AVAILABLE = False


class NativeIndicatorExtractor:
    """Извлечение индикаторов угроз из native библиотек через PyGhidra"""
    
    def __init__(self, program):
        self.program = program
        self.results = {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "jni_functions": [],
            "suspicious_names": []
        }
    
    def extract_all(self) -> Dict[str, Any]:
        """Извлечь все индикаторы"""
        self._extract_functions()
        self._extract_imports()
        self._extract_exports()
        self._extract_strings()
        return self.results
    
    def _extract_functions(self):
        """Сбор функций"""
        func_manager = self.program.getFunctionManager()
        for func in func_manager.getFunctions(True):
            fname = func.getName()
            fentry = str(func.getEntryPoint())
            
            # JNI функции
            if fname.startswith("Java_") or fname.startswith("JNI_"):
                self.results["jni_functions"].append({
                    "name": fname,
                    "address": fentry,
                    "signature": str(func.getSignature())
                })
            
            # Подозрительные имена
            suspicious = ["crypto", "encrypt", "decrypt", "key", "secret", 
                         "inject", "hook", "root", "su", "priv", "hide"]
            for kw in suspicious:
                if kw in fname.lower():
                    self.results["suspicious_names"].append({
                        "function": fname,
                        "address": fentry,
                        "keyword": kw,
                        "risk": "High"
                    })
                    break
            
            self.results["functions"].append({"name": fname, "address": fentry})
    
    def _extract_imports(self):
        """Сбор импортов (внешние символы)"""
        symbol_table = self.program.getSymbolTable()
        for symbol in symbol_table.getAllSymbols(True):
            if symbol.isExternalEntryPoint():
                sym_name = symbol.getName()
                self.results["imports"].append({
                    "name": sym_name,
                    "address": str(symbol.getAddress()),
                    "risk": self._assess_import_risk(sym_name)
                })
    
    def _extract_exports(self):
        """Сбор экспортов (JNI entry points)"""
        from ghidra.program.model.symbol import SourceType
        symbol_table = self.program.getSymbolTable()
        for symbol in symbol_table.getAllSymbols(True):
            if symbol.getSource() == SourceType.USER_DEFINED and symbol.isGlobal():
                sname = symbol.getName()
                if sname.startswith("Java_") or sname.startswith("JNI_"):
                    self.results["exports"].append({
                        "name": sname,
                        "address": str(symbol.getAddress())
                    })
    
    def _extract_strings(self):
        """Извлечение строк из памяти"""
        mem = self.program.getMemory()
        for block in mem.getBlocks():
            if block.isInitialized() and block.isRead():
                try:
                    size = min(2 * 1024 * 1024, int(block.getSize()))
                    data = block.getBytes(block.getStart(), size)
                    strings = re.findall(b'[\x20-\x7E]{8,}', data)
                    count = 0
                    for s in strings:
                        if count >= 50:
                            break
                        try:
                            decoded = s.decode('ascii')
                            keywords = ['http', 'https', '.so', '.apk', '192.168', '10.', '172.', 'api', 'token', 'key']
                            if any(kw in decoded.lower() for kw in keywords):
                                self.results["strings"].append(decoded[:150])
                                count += 1
                        except:
                            pass
                except:
                    pass
    
    def _assess_import_risk(self, import_name: str) -> str:
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


def analyze_native_library(lib_path: str, output_json: str) -> Dict[str, Any]:
    """
    Анализ одной native библиотеки через PyGhidra
    
    Args:
        lib_path: Путь к .so файлу
        output_json: Путь для сохранения результатов
    
    Returns:
        Dict с результатами анализа
    """
    if not PYGHIDRA_AVAILABLE:
        raise ImportError("PyGhidra не установлен. Выполните: pip install pyghidra")
    
    print(f"🔍 Анализ: {lib_path}")
    
    # Открытие программы через PyGhidra
    with pyghidra.open_program(lib_path, analyze=False) as program:
        # Запуск анализа
        print("  ▶ Запуск анализа...")
        program.analyze()
        
        # Извлечение индикаторов
        extractor = NativeIndicatorExtractor(program)
        results = extractor.extract_all()
        
        # Сохранение результатов
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Export: {len(results['functions'])} funcs, "
              f"{len(results['imports'])} imports, "
              f"{len(results['jni_functions'])} JNI")
        
        return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python native_analyzer.py <lib_path> <output_json>")
        sys.exit(1)
    
    analyze_native_library(sys.argv[1], sys.argv[2])