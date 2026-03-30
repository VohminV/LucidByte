import subprocess
from pathlib import Path
from typing import List, Optional

class Decompiler:
    def __init__(self, decompiler_command: str = "jadx", output_directory: str = "temp/decompiled"):
        self.command = decompiler_command
        self.output_path = Path(output_directory)
        self.output_path.mkdir(parents=True, exist_ok=True)

    def decompile_apk(self, apk_file_path: str) -> bool:
        source_path = Path(apk_file_path)
        
        if not source_path.exists():
            print("Файл для декомпиляции не найден")
            return False

        try:
            command_list = [
                self.command,
                "--decomp",
                "--output-dir", str(self.output_path),
                "--no-res",
                str(source_path)
            ]
            
            process_result = subprocess.run(
                command_list, 
                check=True, 
                capture_output=True, 
                text=True
            )
            print("Декомпиляция APK завершена успешно")
            return True
            
        except subprocess.CalledProcessError as error:
            print(f"Ошибка процесса декомпиляции: {error}")
            print(f"Вывод ошибки: {error.stderr}")
            return False
        except FileNotFoundError:
            print("Утилита декомпилятора не найдена в системе. Установите jadx.")
            return False

    def decompile_jar(self, jar_file_path: str) -> bool:
        source_path = Path(jar_file_path)
        
        if not source_path.exists():
            print("Файл для декомпиляции не найден")
            return False

        try:
            command_list = [
                self.command,
                "--decomp",
                "--output-dir", str(self.output_path),
                str(source_path)
            ]
            
            subprocess.run(command_list, check=True)
            print("Декомпиляция JAR завершена успешно")
            return True
            
        except subprocess.CalledProcessError as error:
            print(f"Ошибка процесса декомпиляции: {error}")
            return False
        except FileNotFoundError:
            print("Утилита декомпилятора не найдена в системе")
            return False

    def get_decompiled_files(self) -> List[Path]:
        java_files = []
        if self.output_path.exists():
            for file_path in self.output_path.rglob("*.java"):
                java_files.append(file_path)
        return java_files

    def get_manifest_file(self) -> Optional[Path]:
        manifest_path = self.output_path / "AndroidManifest.xml"
        if manifest_path.exists():
            return manifest_path
        return None

    def get_all_source_code(self) -> str:
        all_code = ""
        for file_path in self.get_decompiled_files():
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    all_code += f"\n=== Файл: {file_path.name} ===\n"
                    all_code += file.read()
            except Exception:
                continue
        return all_code

    def cleanup(self):
        if self.output_path.exists():
            for file_path in self.output_path.rglob("*.java"):
                file_path.unlink()