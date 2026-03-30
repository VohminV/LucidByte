import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class RenameMapping:
    original_name: str
    new_name: str
    confidence: float
    source: str

class Deobfuscator:
    def __init__(self, language_model_manager=None):
        self.language_model = language_model_manager
        self.rename_mappings: List[RenameMapping] = []
        self.decrypted_strings: Dict[str, str] = {}
        
        self.common_method_names = [
            "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
            "onClick", "onTouch", "onKeyDown", "onKeyUp",
            "getString", "getInt", "getBoolean", "setString", "setInt",
            "execute", "run", "call", "invoke", "process", "handle",
            "send", "receive", "read", "write", "open", "close",
            "encrypt", "decrypt", "encode", "decode", "hash", "verify",
            "connect", "disconnect", "upload", "download", "request", "response"
        ]
        
        self.common_class_names = [
            "Activity", "Service", "BroadcastReceiver", "ContentProvider",
            "Fragment", "Dialog", "Adapter", "ViewHolder",
            "Manager", "Helper", "Util", "Utils", "Factory", "Builder",
            "Controller", "Presenter", "ViewModel", "Repository",
            "Client", "Server", "Request", "Response", "Handler", "Callback"
        ]

    def analyze_obfuscation_level(self, decompiled_path: str) -> float:
        path = Path(decompiled_path)
        total_classes = 0
        obfuscated_classes = 0
        
        for file_path in path.rglob("*.java"):
            total_classes += 1
            class_name = file_path.stem
            
            if len(class_name) <= 2 or class_name[0].islower():
                obfuscated_classes += 1
        
        if total_classes == 0:
            return 0.0
        
        return obfuscated_classes / total_classes

    def suggest_renames(self, code_content: str, file_name: str) -> List[RenameMapping]:
        mappings = []
        
        pattern = r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\('
        matches = re.findall(pattern, code_content)
        
        for method_name in matches[:20]:
            if len(method_name) <= 2:
                suggested_name = self._suggest_method_name(code_content, method_name)
                mappings.append(RenameMapping(
                    original_name=method_name,
                    new_name=suggested_name,
                    confidence=0.7,
                    source="heuristic"
                ))
        
        return mappings

    def _suggest_method_name(self, code_content: str, original_name: str) -> str:
        if self.language_model:
            try:
                prompt = f"""Проанализируй этот метод и предложи осмысленное имя.
                Код метода:
                {code_content[:500]}
                
                Предложи только одно имя метода на английском языке."""
                
                response = self.language_model.send_request(prompt)
                if response:
                    return response.strip()[:30]
            except Exception:
                pass
        
        for common_name in self.common_method_names:
            if common_name.lower() in code_content.lower():
                return common_name
        
        return f"processed_{original_name}"

    def decrypt_strings(self, code_content: str) -> Dict[str, str]:
        decrypted = {}
        
        base64_pattern = r'Base64\.(?:decode|getDecoder)\s*\(\s*\)\s*\.(?:decode|decodeToString)\s*\(\s*"([^"]+)"'
        matches = re.findall(base64_pattern, code_content)
        
        for encoded_string in matches:
            try:
                import base64
                decoded = base64.b64decode(encoded_string).decode('utf-8', errors='ignore')
                decrypted[encoded_string] = decoded
            except Exception:
                continue
        
        xor_pattern = r'xor\s*\(\s*"([^"]+)"\s*,\s*(\d+)'
        matches = re.findall(xor_pattern, code_content)
        
        for encoded_string, key in matches:
            try:
                key_int = int(key)
                decoded = ''.join(chr(ord(c) ^ key_int) for c in encoded_string)
                decrypted[f"xor_{encoded_string}"] = decoded
            except Exception:
                continue
        
        self.decrypted_strings.update(decrypted)
        return decrypted

    def apply_renames(self, file_path: Path, mappings: List[RenameMapping]) -> bool:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()
            
            for mapping in mappings:
                content = re.sub(
                    f'\\b{re.escape(mapping.original_name)}\\b',
                    mapping.new_name,
                    content
                )
            
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(content)
            
            self.rename_mappings.extend(mappings)
            return True
            
        except Exception as exception:
            print(f"Ошибка применения переименований: {exception}")
            return False

    def get_deobfuscation_summary(self) -> str:
        summary = "=== Деобфускация ===\n\n"
        summary += f"Переименований применено: {len(self.rename_mappings)}\n"
        summary += f"Строк расшифровано: {len(self.decrypted_strings)}\n\n"
        
        if self.decrypted_strings:
            summary += "Расшифрованные строки:\n"
            for original, decoded in list(self.decrypted_strings.items())[:10]:
                summary += f"  {original[:30]}... -> {decoded[:50]}\n"
        
        return summary