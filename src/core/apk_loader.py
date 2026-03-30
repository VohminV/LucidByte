import os
import shutil
from pathlib import Path
from typing import Optional

class ApkLoader:
    def __init__(self, temp_directory: str = "temp/apk"):
        self.temp_path = Path(temp_directory)
        self.temp_path.mkdir(parents=True, exist_ok=True)
        self.loaded_apk_path: Optional[Path] = None

    def load_apk(self, apk_file_path: str) -> bool:
        source_path = Path(apk_file_path)
        
        if not source_path.exists():
            print("Файл APK не найден")
            return False

        if not source_path.suffix.lower() in [".apk", ".jar", ".dex"]:
            print("Неподдерживаемый формат файла")
            return False

        try:
            # Копирование файла во временную директорию
            destination_path = self.temp_path / source_path.name
            shutil.copy2(source_path, destination_path)
            self.loaded_apk_path = destination_path
            print(f"APK файл загружен: {destination_path}")
            return True
            
        except Exception as exception:
            print(f"Ошибка загрузки APK: {exception}")
            return False

    def get_apk_path(self) -> Optional[Path]:
        return self.loaded_apk_path

    def cleanup(self):
        if self.temp_path.exists():
            shutil.rmtree(self.temp_path)
            self.temp_path.mkdir(parents=True, exist_ok=True)
        self.loaded_apk_path = None