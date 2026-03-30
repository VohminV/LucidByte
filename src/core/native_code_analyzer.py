import os
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class NativeFunction:
    name: str
    address: str
    size: int
    is_dangerous: bool
    description: str

class NativeCodeAnalyzer:
    def __init__(self, ghidra_path: str = "ghidra", enable_capstone: bool = True):
        self.ghidra_path = ghidra_path
        self.enable_capstone = enable_capstone
        self.analyzed_libraries: List[str] = []
        self.found_functions: List[NativeFunction] = []
        self.dangerous_patterns = [
            "JNI_OnLoad",
            "system",
            "exec",
            "dlopen",
            "dlsym",
            "pthread_create",
            "mmap",
            "mprotect"
        ]

    def find_native_libraries(self, decompiled_path: str) -> List[Path]:
        so_files = []
        path = Path(decompiled_path)
        
        for lib_path in path.rglob("lib*.so"):
            so_files.append(lib_path)
        
        for arm_path in path.rglob("armeabi*"):
            for lib_path in arm_path.rglob("*.so"):
                so_files.append(lib_path)
        
        print(f"Найдено нативных библиотек: {len(so_files)}")
        return so_files

    def analyze_library(self, library_path: Path) -> List[NativeFunction]:
        functions = []
        
        try:
            if self.enable_capstone:
                functions = self._analyze_with_capstone(library_path)
            else:
                functions = self._analyze_with_ghidra(library_path)
            
            self.analyzed_libraries.append(str(library_path))
            self.found_functions.extend(functions)
            
        except Exception as exception:
            print(f"Ошибка анализа библиотеки {library_path}: {exception}")
        
        return functions

    def _analyze_with_capstone(self, library_path: Path) -> List[NativeFunction]:
        functions = []
        
        try:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
            
            with open(library_path, "rb") as file:
                binary_data = file.read()
            
            disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            
            for instruction in disassembler.disasm(binary_data[:100000], 0x1000):
                for pattern in self.dangerous_patterns:
                    if pattern.lower() in instruction.mnemonic.lower():
                        function = NativeFunction(
                            name=instruction.mnemonic,
                            address=hex(instruction.address),
                            size=instruction.size,
                            is_dangerous=True,
                            description=f"Подозрительная инструкция: {pattern}"
                        )
                        functions.append(function)
                        break
        
        except ImportError:
            print("Библиотека Capstone не установлена")
        
        return functions

    def _analyze_with_ghidra(self, library_path: Path) -> List[NativeFunction]:
        functions = []
        
        try:
            command_list = [
                self.ghidra_path,
                "-scriptPath", "scripts",
                "-postScript", "ExportFunctions.py",
                "-project", "LucidByteProject",
                str(library_path)
            ]
            
            result = subprocess.run(
                command_list,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print(f"Анализ Ghidra завершен для {library_path.name}")
            
        except subprocess.TimeoutExpired:
            print(f"Превышено время анализа для {library_path.name}")
        except Exception as exception:
            print(f"Ошибка Ghidra: {exception}")
        
        return functions

    def get_dangerous_native_functions(self) -> List[NativeFunction]:
        return [func for func in self.found_functions if func.is_dangerous]

    def get_analysis_summary(self) -> str:
        summary = "=== Анализ Нативного Кода ===\n\n"
        summary += f"Проанализировано библиотек: {len(self.analyzed_libraries)}\n"
        summary += f"Всего функций: {len(self.found_functions)}\n"
        summary += f"Опасных функций: {len(self.get_dangerous_native_functions())}\n\n"
        
        for function in self.get_dangerous_native_functions()[:10]:
            summary += f"  - {function.name} @ {function.address}: {function.description}\n"
        
        return summary