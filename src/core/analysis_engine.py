import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Callable
import zipfile
import re
import platform

class AnalysisEngine:
    """Ядро статического анализа APK файлов"""
    
    def __init__(self, temp_dir: str = "temp"):
        self.temp_dir = Path(temp_dir)
        self.decompiled_dir = self.temp_dir / "decompiled"
        self.apk_path: Optional[Path] = None
        self.manifest_data: str = ""
        self.strings_data: List[str] = []
        self.permissions: List[Dict] = []
        self.threats: List[Dict] = []
        self.progress_callback: Optional[Callable] = None
        self.log_callback: Optional[Callable] = None
        
    def set_progress_callback(self, callback: Callable[[int, str], None]):
        """Установка колбэка для обновления прогресса"""
        self.progress_callback = callback
        
    def set_log_callback(self, callback: Callable[[str], None]):
        """Установка колбэка для логирования"""
        self.log_callback = callback
        
    def _log(self, message: str):
        if self.log_callback:
            self.log_callback(message)
            
    def _progress(self, value: int, message: str):
        if self.progress_callback:
            self.progress_callback(value, message)
    
    def analyze_apk(self, apk_path: str) -> bool:
        """Запуск полного цикла анализа APK"""
        try:
            self.apk_path = Path(apk_path)
            self._log(f"=" * 60)
            self._log(f"Начало анализа: {apk_path}")
            self._log(f"=" * 60)
            
            # Очистка предыдущих результатов
            if self.decompiled_dir.exists():
                shutil.rmtree(self.decompiled_dir)
                self._log("🗑 Предыдущие результаты удалены")
            self.decompiled_dir.mkdir(parents=True, exist_ok=True)
            self._log(f"📁 Директория создана: {self.decompiled_dir}")
            
            # Этап 1: Декомпиляция через JADX
            self._progress(10, "Декомпиляция JADX...")
            jadx_success = self._decompile_with_jadx()
            if not jadx_success:
                self._log("⚠ JADX не найден, пробуем распаковку ZIP")
                self._extract_as_zip()
            else:
                self._log("✓ JADX декомпиляция успешна")
            
            # Этап 2: Парсинг AndroidManifest.xml
            self._progress(40, "Парсинг манифеста...")
            self._parse_manifest()
            
            # Этап 3: Извлечение строк
            self._progress(60, "Извлечение строк...")
            self._extract_strings()
            
            # Этап 4: Анализ угроз
            self._progress(80, "Анализ угроз...")
            self._analyze_threats()
            
            self._progress(100, "Анализ завершен")
            self._log("=" * 60)
            self._log("✓ Анализ успешно завершен")
            self._log(f"📊 Файлов: {len(list(self.decompiled_dir.rglob('*.java')))}")
            self._log(f"⚠ Угроз: {len(self.threats)}")
            self._log(f"🔐 Разрешений: {len(self.permissions)}")
            self._log("=" * 60)
            return True
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            self._log(f"✗ Ошибка анализа: {str(e)}")
            self._log(f"📋 Traceback:\n{error_trace}")
            return False
    
    def _find_jadx(self) -> Optional[str]:
        """Поиск исполняемого файла jadx в системе"""
        self._log("🔍 Поиск jadx...")
        
        # Список возможных имен и путей
        jadx_names = ["jadx", "jadx.bat", "jadx.exe"]
        jadx_paths = [
            r"C:\Program Files\jadx\bin\jadx.bat",
            r"C:\Program Files\jadx\bin\jadx.exe",
            r"C:\jadx\bin\jadx.bat",
            r"C:\jadx\bin\jadx.exe",
            r"C:\Tools\jadx\bin\jadx.bat",
            r"C:\Tools\jadx\bin\jadx.exe",
            os.path.expanduser(r"~\jadx\bin\jadx.bat"),
            os.path.expanduser(r"~\jadx\bin\jadx.exe"),
            "jadx",
            "jadx.bat",
            "jadx.exe"
        ]
        
        # Проверяем через shutil.which (PATH)
        for name in jadx_names:
            found = shutil.which(name)
            if found:
                self._log(f"✓ jadx найден в PATH: {found}")
                return found
        
        # Проверяем явные пути
        for path in jadx_paths:
            if os.path.exists(path):
                self._log(f"✓ jadx найден: {path}")
                return path
        
        # Поиск в текущей директории
        local_paths = [
            "./jadx/bin/jadx.bat",
            "./jadx/bin/jadx.exe",
            "../jadx/bin/jadx.bat",
            "../jadx/bin/jadx.exe",
        ]
        for path in local_paths:
            if os.path.exists(path):
                full_path = os.path.abspath(path)
                self._log(f"✓ jadx найден локально: {full_path}")
                return full_path
        
        self._log("✗ jadx не найден в системе")
        return None
    
    def _decompile_with_jadx(self) -> bool:
        """Декомпиляция с помощью jadx"""
        jadx_cmd = self._find_jadx()
        
        if not jadx_cmd:
            return False
        
        # Подготовка аргументов
        output_dir = str(self.decompiled_dir.absolute())
        input_file = str(self.apk_path.absolute())
        
        self._log(f"📥 Входной файл: {input_file}")
        self._log(f"📤 Выходная директория: {output_dir}")
        
        # Формирование команды
        is_windows = platform.system() == "Windows"
        is_batch = jadx_cmd.endswith(('.bat', '.cmd'))
        
        if is_windows and is_batch:
            # Для Windows .bat файлов используем shell=True
            cmd = f'"{jadx_cmd}" -d "{output_dir}" -j 1 --no-replace-consts --show-bad-code "{input_file}"'
            self._log(f"🔧 Команда: {cmd}")
            
            try:
                process = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    encoding='utf-8',
                    errors='ignore'
                )
            except Exception as e:
                self._log(f"✗ Ошибка запуска: {e}")
                return False
        else:
            # Для Linux/Mac или прямых исполняемых файлов
            cmd = [
                jadx_cmd,
                "-d", output_dir,
                "-j", "1",
                "--no-replace-consts",
                "--show-bad-code",
                input_file
            ]
            self._log(f"🔧 Команда: {' '.join(cmd)}")
            
            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    encoding='utf-8',
                    errors='ignore'
                )
            except Exception as e:
                self._log(f"✗ Ошибка запуска: {e}")
                return False
        
        # Анализ результата
        if process.returncode == 0:
            self._log("✓ jadx завершил работу успешно")
            # Проверяем, что файлы действительно созданы
            java_files = list(self.decompiled_dir.rglob("*.java"))
            if java_files:
                self._log(f"✓ Создано Java файлов: {len(java_files)}")
                return True
            else:
                self._log("⚠ jadx завершил успешно, но файлы не созданы")
                return False
        else:
            self._log(f"⚠ jadx вернул код ошибки: {process.returncode}")
            if process.stdout:
                self._log(f"stdout: {process.stdout[:500]}")
            if process.stderr:
                self._log(f"stderr: {process.stderr[:500]}")
            return False
    
    def _extract_as_zip(self):
        """Альтернативная распаковка как ZIP архива"""
        try:
            self._log("📦 Распаковка APK как ZIP архива...")
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.decompiled_dir)
            
            extracted_files = list(self.decompiled_dir.rglob("*"))
            self._log(f"✓ Распаковано файлов: {len(extracted_files)}")
            
            # Поиск и декомпиляция classes.dex если есть
            dex_files = list(self.decompiled_dir.rglob("classes.dex"))
            if dex_files:
                self._log(f"⚠ Найдено DEX файлов: {len(dex_files)} (требуется jadx для декомпиляции)")
            
        except zipfile.BadZipFile:
            self._log("✗ Файл не является корректным ZIP архивом")
        except Exception as e:
            self._log(f"✗ Ошибка распаковки ZIP: {e}")
    
    def _parse_manifest(self):
        """Парсинг AndroidManifest.xml"""
        manifest_path = self.decompiled_dir / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            # Поиск в поддиректориях
            for f in self.decompiled_dir.rglob("AndroidManifest.xml"):
                manifest_path = f
                self._log(f"📄 Манифест найден: {manifest_path}")
                break
        
        if manifest_path.exists():
            try:
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.manifest_data = f.read()
                
                self._log(f"✓ Манифест прочитан ({len(self.manifest_data)} байт)")
                
                # Парсинг разрешений
                permissions = re.findall(
                    r'android:name="(android\.permission\.[^"]+)"',
                    self.manifest_data
                )
                self.permissions = [
                    {"name": p, "risk": self._assess_permission_risk(p)}
                    for p in permissions
                ]
                self._log(f"✓ Найдено разрешений: {len(self.permissions)}")
                
                # Парсинг имени пакета
                package_match = re.search(r'package="([^"]+)"', self.manifest_data)
                if package_match:
                    self._log(f"📦 Пакет: {package_match.group(1)}")
                
            except Exception as e:
                self._log(f"⚠ Ошибка парсинга манифеста: {e}")
                self.manifest_data = "Ошибка чтения манифеста"
        else:
            self._log("⚠ AndroidManifest.xml не найден")
            self.manifest_data = "AndroidManifest.xml не найден"
    
    def _assess_permission_risk(self, permission: str) -> str:
        """Оценка риска разрешения"""
        dangerous = {
            "READ_SMS": "Critical",
            "SEND_SMS": "Critical",
            "RECEIVE_SMS": "Critical",
            "READ_CONTACTS": "High",
            "WRITE_CONTACTS": "High",
            "ACCESS_FINE_LOCATION": "High",
            "ACCESS_COARSE_LOCATION": "High",
            "RECORD_AUDIO": "High",
            "READ_CALL_LOG": "Critical",
            "WRITE_CALL_LOG": "Critical",
            "PROCESS_OUTGOING_CALLS": "Critical",
            "CAMERA": "Medium",
            "READ_EXTERNAL_STORAGE": "Medium",
            "WRITE_EXTERNAL_STORAGE": "Medium",
            "INTERNET": "Low",
            "ACCESS_NETWORK_STATE": "Low",
            "WAKE_LOCK": "Low",
            "RECEIVE_BOOT_COMPLETED": "Medium",
            "SYSTEM_ALERT_WINDOW": "High",
            "BIND_ACCESSIBILITY_SERVICE": "Critical",
        }
        for key, risk in dangerous.items():
            if key in permission:
                return risk
        return "Low"
    
    def _extract_strings(self):
        """Извлечение строк из файлов"""
        strings = set()
        java_files = list(self.decompiled_dir.rglob("*.java"))
        
        self._log(f"🔍 Сканирование {len(java_files)} Java файлов...")
        
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Поиск строк в кавычках (минимум 10 символов)
                    found = re.findall(r'"([^"]{10,})"', content)
                    strings.update(found)
            except Exception as e:
                continue
        
        # Сортировка и ограничение
        self.strings_data = sorted(list(strings))[:500]
        self._log(f"✓ Извлечено уникальных строк: {len(self.strings_data)}")
    
    def _analyze_threats(self):
        """Анализ потенциальных угроз"""
        threat_patterns = [
            {"pattern": "Runtime.getRuntime().exec", "risk": "Critical", "desc": "Выполнение системных команд"},
            {"pattern": "ProcessBuilder", "risk": "Critical", "desc": "Создание процессов"},
            {"pattern": "DexClassLoader", "risk": "High", "desc": "Динамическая загрузка кода"},
            {"pattern": "PathClassLoader", "risk": "High", "desc": "Загрузка классов из пути"},
            {"pattern": "getDeviceId", "risk": "High", "desc": "Сбор идентификаторов устройства"},
            {"pattern": "getSubscriberId", "risk": "High", "desc": "Получение IMSI"},
            {"pattern": "getSimSerialNumber", "risk": "High", "desc": "Получение серийного номера SIM"},
            {"pattern": "SmsManager", "risk": "Critical", "desc": "Отправка/чтение SMS"},
            {"pattern": "TelephonyManager", "risk": "Medium", "desc": "Доступ к телеметрии"},
            {"pattern": "setWallpaper", "risk": "Medium", "desc": "Изменение системы"},
            {"pattern": "installPackage", "risk": "Critical", "desc": "Установка приложений"},
            {"pattern": "deletePackage", "risk": "Critical", "desc": "Удаление приложений"},
            {"pattern": "Cipher", "risk": "Medium", "desc": "Шифрование данных"},
            {"pattern": "SecretKeySpec", "risk": "Medium", "desc": "Криптографические ключи"},
            {"pattern": "Base64", "risk": "Low", "desc": "Кодирование данных"},
            {"pattern": "URL(", "risk": "Medium", "desc": "Сетевые запросы"},
            {"pattern": "HttpURLConnection", "risk": "Medium", "desc": "HTTP соединение"},
            {"pattern": "Socket(", "risk": "Medium", "desc": "Сокет соединение"},
            {"pattern": "SharedPreferences", "risk": "Low", "desc": "Хранение данных"},
            {"pattern": "FileOutputStream", "risk": "Medium", "desc": "Запись в файл"},
        ]
        
        java_files = list(self.decompiled_dir.rglob("*.java"))
        self._log(f"🔍 Анализ угроз в {len(java_files)} файлах...")
        
        processed_files = 0
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for threat in threat_patterns:
                        if threat["pattern"] in content:
                            rel_path = str(file_path.relative_to(self.decompiled_dir))
                            self.threats.append({
                                "file": rel_path,
                                "pattern": threat["pattern"],
                                "risk": threat["risk"],
                                "desc": threat["desc"]
                            })
                processed_files += 1
                if processed_files % 1000 == 0:
                    self._log(f"📊 Обработано файлов: {processed_files}")
            except Exception as e:
                continue
        
        # Группировка одинаковых угроз
        unique_threats = []
        seen = set()
        for t in self.threats:
            key = (t["file"], t["pattern"])
            if key not in seen:
                seen.add(key)
                unique_threats.append(t)
        
        self.threats = unique_threats
        self._log(f"✓ Найдено уникальных угроз: {len(self.threats)}")
        
        # Статистика по уровням риска
        risk_counts = {}
        for t in self.threats:
            risk_counts[t["risk"]] = risk_counts.get(t["risk"], 0) + 1
        for risk, count in sorted(risk_counts.items()):
            self._log(f"  {risk}: {count}")
    
    def get_decompiled_files(self) -> List[Path]:
        """Получение списка декомпилированных файлов"""
        if not self.decompiled_dir.exists():
            return []
        return sorted(list(self.decompiled_dir.rglob("*.java")))
    
    def get_file_content(self, file_path: str) -> str:
        """Чтение содержимого файла"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return f"Ошибка чтения: {e}"
    
    def get_statistics(self) -> Dict:
        """Получение статистики анализа"""
        return {
            "total_files": len(list(self.decompiled_dir.rglob("*.java"))),
            "total_threats": len(self.threats),
            "total_permissions": len(self.permissions),
            "total_strings": len(self.strings_data),
            "critical_threats": sum(1 for t in self.threats if t["risk"] == "Critical"),
            "high_threats": sum(1 for t in self.threats if t["risk"] == "High"),
            "medium_threats": sum(1 for t in self.threats if t["risk"] == "Medium"),
            "low_threats": sum(1 for t in self.threats if t["risk"] == "Low"),
        }