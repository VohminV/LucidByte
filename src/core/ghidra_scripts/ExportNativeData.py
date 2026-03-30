# @author LucidByte
# @category Analysis

import os
import json
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Listing
from ghidra.program.model.symbol import RefType

class ExportNativeData(GhidraScript):
    def run(self):
        if len(getScriptArgs()) < 1:
            print("Usage: ExportNativeData.py <output_json_path>")
            return
        
        output_path = getScriptArgs()[0]
        results = {"functions": [], "native_calls": [], "imports": []}
        
        listing = currentProgram.getListing()
        
        # === ИСПРАВЛЕНИЕ: Работаем с функциями, а не инструкциями ===
        for func in listing.getFunctions(True):
            func_info = {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "calling_convention": func.getCallingConventionName()
            }
            results["functions"].append(func_info)
            
            # Проверяем имя на подозрительные паттерны
            func_name = func.getName().lower()
            suspicious = ["jni", "native", "crypto", "encrypt", "decrypt", "key", "secret"]
            for pattern in suspicious:
                if pattern in func_name:
                    results["native_calls"].append({
                        "function": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "pattern": pattern,
                        "risk": "High"
                    })
        
        # === Собираем импорты (внешние вызовы) ===
        symbol_table = currentProgram.getSymbolTable()
        for symbol in symbol_table.getSymbolIterator():
            if symbol.isExternalEntryPoint():
                results["imports"].append({
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress())
                })
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Native экспорт завершён: {output_path}")
        print(f"  • Функций: {len(results['functions'])}")
        print(f"  • Подозрительных: {len(results['native_calls'])}")
