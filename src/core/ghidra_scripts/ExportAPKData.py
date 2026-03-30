# @author LucidByte
# @category Analysis
# @keybinding
# @menupath
# @toolbar

import os
import json
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Listing

class ExportAPKData(GhidraScript):
    def run(self):
        if len(getScriptArgs()) < 1:
            print("Usage: ExportAPKData.py <output_json_path>")
            return
        
        output_path = getScriptArgs()[0]
        results = {"functions": [], "api_calls": [], "strings": [], "permissions": []}
        
        listing = currentProgram.getListing()
        
        # Сбор функций
        for func in listing.getFunctions(True):
            results["functions"].append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature())
            })
        
        # Поиск опасных вызовов
        dangerous = ["Runtime.exec", "ProcessBuilder", "DexClassLoader", 
                     "getDeviceId", "SmsManager", "AccessibilityService"]
        
        for func in listing.getFunctions(True):
            for instr in listing.getInstructions(func.getBody(), True):
                mnemonic = instr.getMnemonicString()
                if "INVOKE" in mnemonic or "CALL" in mnemonic:
                    for ref in instr.getOpObjects(0):
                        ref_str = str(ref)
                        for api in dangerous:
                            if api.lower() in ref_str.lower():
                                results["api_calls"].append({
                                    "function": func.getName(),
                                    "address": str(instr.getAddress()),
                                    "api": api,
                                    "risk": "High"
                                })
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Экспорт завершён: {output_path}")