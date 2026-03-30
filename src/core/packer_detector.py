import os
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class PackerSignature:
    name: str
    description: str
    file_patterns: List[str]
    class_patterns: List[str]
    string_patterns: List[str]
    risk_level: int

class PackerDetector:
    def __init__(self):
        self.signatures = self._load_packer_signatures()
        self.detected_packers: List[PackerSignature] = []

    def _load_packer_signatures(self) -> List[PackerSignature]:
        return [
            PackerSignature(
                name="ProGuard",
                description="Стандартный обфускатор Android",
                file_patterns=["proguard.map", "proguard.txt"],
                class_patterns=["a.", "b.", "c."],
                string_patterns=["ProGuard"],
                risk_level=3
            ),
            PackerSignature(
                name="DexGuard",
                description="Коммерческий обфускатор с защитой от реверс-инжиниринга",
                file_patterns=["dexguard.apk"],
                class_patterns=["com.guardsquare"],
                string_patterns=["DexGuard", "StringEncryption"],
                risk_level=6
            ),
            PackerSignature(
                name="Allatori",
                description="Обфускатор Java и Android",
                file_patterns=["allatori.xml"],
                class_patterns=["com.allatori"],
                string_patterns=["Allatori"],
                risk_level=5
            ),
            PackerSignature(
                name="DashO",
                description="Обфускатор от PreEmptive Solutions",
                file_patterns=["dasho.xml"],
                class_patterns=["com.preemptive"],
                string_patterns=["DashO"],
                risk_level=5
            ),
            PackerSignature(
                name="Native Lib Packer",
                description="Упаковщик нативных библиотек",
                file_patterns=["libpacker.so", "libprotect.so"],
                class_patterns=["com.pack"],
                string_patterns=["unpack", "extract", "decrypt"],
                risk_level=8
            ),
            PackerSignature(
                name="String Encryption",
                description="Шифрование строк для скрытия логики",
                file_patterns=[],
                class_patterns=[],
                string_patterns=["decryptString", "getString", "Base64"],
                risk_level=7
            ),
            PackerSignature(
                name="Reflection Packer",
                description="Использование рефлексии для скрытия вызовов",
                file_patterns=[],
                class_patterns=[],
                string_patterns=["Class.forName", "getMethod", "invoke"],
                risk_level=8
            ),
            PackerSignature(
                name="Dynamic Code Loader",
                description="Загрузка кода во время выполнения",
                file_patterns=[],
                class_patterns=["DexClassLoader", "PathClassLoader"],
                string_patterns=["loadDex", "loadClass"],
                risk_level=9
            )
        ]

    def detect_packers(self, decompiled_path: str) -> List[PackerSignature]:
        self.detected_packers = []
        path = Path(decompiled_path)
        
        all_files = []
        all_classes = []
        all_strings = []
        
        for file_path in path.rglob("*"):
            if file_path.is_file():
                all_files.append(file_path.name.lower())
                
                if file_path.suffix in [".java", ".smali"]:
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                            content = file.read()
                            all_classes.extend(self._extract_class_names(content))
                            all_strings.extend(self._extract_strings(content))
                    except Exception:
                        continue
        
        for signature in self.signatures:
            match_score = 0
            
            for pattern in signature.file_patterns:
                if any(pattern.lower() in file_name for file_name in all_files):
                    match_score += 2
            
            for pattern in signature.class_patterns:
                if any(pattern in class_name for class_name in all_classes):
                    match_score += 2
            
            for pattern in signature.string_patterns:
                if any(pattern in string for string in all_strings):
                    match_score += 1
            
            if match_score >= 2:
                self.detected_packers.append(signature)
        
        print(f"Обнаружено упаковщиков: {len(self.detected_packers)}")
        return self.detected_packers

    def _extract_class_names(self, content: str) -> List[str]:
        import re
        pattern = r'class\s+([a-zA-Z0-9_$.]+)'
        return re.findall(pattern, content)

    def _extract_strings(self, content: str) -> List[str]:
        import re
        pattern = r'"([^"]*)"'
        return re.findall(pattern, content)

    def get_packer_summary(self) -> str:
        summary = "=== Обнаруженные Упаковщики ===\n\n"
        
        if not self.detected_packers:
            summary += "Упаковщики не обнаружены\n"
            return summary
        
        for packer in self.detected_packers:
            summary += f"Название: {packer.name}\n"
            summary += f"Описание: {packer.description}\n"
            summary += f"Уровень риска: {packer.risk_level}/10\n\n"
        
        return summary

    def get_total_risk_score(self) -> int:
        if not self.detected_packers:
            return 0
        
        max_risk = max(packer.risk_level for packer in self.detected_packers)
        return max_risk