import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Callable
import zipfile
import re
import platform
from collections import defaultdict

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
        self.statistics: Dict = {}
        self.progress_callback: Optional[Callable] = None
        self.log_callback: Optional[Callable] = None
        
    def set_progress_callback(self, callback: Callable[[int, str], None]):
        self.progress_callback = callback
        
    def set_log_callback(self, callback: Callable[[str], None]):
        self.log_callback = callback
        
    def _log(self, message: str):
        if self.log_callback:
            self.log_callback(message)
            
    def _progress(self, value: int, message: str):
        if self.progress_callback:
            self.progress_callback(value, message)
    
    def analyze_apk(self, apk_path: str) -> bool:
        try:
            self.apk_path = Path(apk_path)
            self._log("=" * 70)
            self._log("🔍 LUCIDBYTE ANALYSIS ENGINE")
            self._log("=" * 70)
            self._log(f"📁 Файл: {apk_path}")
            self._log(f"📊 Размер: {os.path.getsize(apk_path) / 1024 / 1024:.2f} MB")
            self._log("=" * 70)
            
            if self.decompiled_dir.exists():
                shutil.rmtree(self.decompiled_dir)
                self._log("🗑 Предыдущие результаты удалены")
            self.decompiled_dir.mkdir(parents=True, exist_ok=True)
            self._log(f"📁 Директория создана: {self.decompiled_dir}")
            
            self._progress(10, "Декомпиляция JADX...")
            jadx_success = self._decompile_with_jadx()
            if not jadx_success:
                self._log("⚠ JADX не завершил работу, пробуем распаковку ZIP")
                self._extract_as_zip()
            else:
                self._log("✓ JADX декомпиляция успешна")
            
            self._progress(40, "Парсинг манифеста...")
            self._parse_manifest()
            
            self._progress(60, "Извлечение строк...")
            self._extract_strings()
            
            self._progress(80, "Анализ угроз...")
            self._analyze_threats()
            
            self._progress(95, "Сбор статистики...")
            self._collect_statistics()
            
            self._progress(100, "Анализ завершен")
            self._log("=" * 70)
            self._log("✓ АНАЛИЗ УСПЕШНО ЗАВЕРШЕН")
            self._log("=" * 70)
            self._log(f"📊 Файлов Java: {self.statistics.get('total_java_files', 0):,}")
            self._log(f"⚠ Угроз всего: {self.statistics.get('total_threats', 0):,}")
            self._log(f"🔴 Критических: {self.statistics.get('critical_threats', 0)}")
            self._log(f"🟠 Высоких: {self.statistics.get('high_threats', 0)}")
            self._log(f"🟡 Средних: {self.statistics.get('medium_threats', 0)}")
            self._log(f"🟢 Низких: {self.statistics.get('low_threats', 0)}")
            self._log(f"🔐 Разрешений: {self.statistics.get('total_permissions', 0)}")
            self._log(f"💬 Строк: {self.statistics.get('total_strings', 0)}")
            self._log(f"📦 Пакет: {self.statistics.get('package_name', 'N/A')}")
            self._log("=" * 70)
            return True
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            self._log(f"✗ Ошибка анализа: {str(e)}")
            self._log(f"📋 Traceback:\n{error_trace}")
            return False
    
    def _find_jadx(self) -> Optional[str]:
        self._log("🔍 Поиск jadx...")
        
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
        
        for name in jadx_names:
            found = shutil.which(name)
            if found:
                self._log(f"✓ jadx найден в PATH: {found}")
                return found
        
        for path in jadx_paths:
            if os.path.exists(path):
                self._log(f"✓ jadx найден: {path}")
                return path
        
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
        """Декомпиляция с помощью jadx - ИСПРАВЛЕННАЯ ВЕРСИЯ"""
        jadx_cmd = self._find_jadx()
        
        if not jadx_cmd:
            return False
        
        output_dir = str(self.decompiled_dir.absolute())
        input_file = str(self.apk_path.absolute())
        
        self._log(f"📥 Входной файл: {input_file}")
        self._log(f"📤 Выходная директория: {output_dir}")
        
        is_windows = platform.system() == "Windows"
        is_batch = jadx_cmd.endswith(('.bat', '.cmd'))
        
        # ИСПРАВЛЕНИЕ: Удалён флаг -J-Xmx4G
        if is_windows and is_batch:
            cmd = f'"{jadx_cmd}" -d "{output_dir}" -j 4 --no-replace-consts --show-bad-code --no-inline-methods "{input_file}"'
            self._log(f"🔧 Команда: {cmd}")
            
            try:
                # JAVA_OPTS через переменную окружения
                env = os.environ.copy()
                env['JAVA_OPTS'] = '-Xmx4G'
                
                process = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=900,
                    encoding='utf-8',
                    errors='ignore',
                    env=env
                )
            except Exception as e:
                self._log(f"✗ Ошибка запуска: {e}")
                return False
        else:
            cmd = [
                jadx_cmd,
                "-d", output_dir,
                "-j", "4",
                "--no-replace-consts",
                "--show-bad-code",
                "--no-inline-methods",
                input_file
            ]
            self._log(f"🔧 Команда: {' '.join(cmd)}")
            
            try:
                env = os.environ.copy()
                env['JAVA_OPTS'] = '-Xmx4G'
                
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=900,
                    encoding='utf-8',
                    errors='ignore',
                    env=env
                )
            except Exception as e:
                self._log(f"✗ Ошибка запуска: {e}")
                return False
        
        if process.returncode == 0:
            self._log("✓ jadx завершил работу успешно")
            java_files = list(self.decompiled_dir.rglob("*.java"))
            if java_files:
                self._log(f"✓ Создано Java файлов: {len(java_files):,}")
                return True
            else:
                self._log("⚠ jadx завершил успешно, но файлы не созданы")
                return False
        else:
            self._log(f"⚠ jadx вернул код ошибки: {process.returncode}")
            
            if process.stdout:
                lines = process.stdout.strip().split('\n')
                self._log("📋 Вывод jadx:")
                for line in lines[-15:]:
                    self._log(f"  {line}")
            
            if process.stderr:
                lines = process.stderr.strip().split('\n')
                self._log("📋 Ошибки:")
                for line in lines[-15:]:
                    self._log(f"  {line}")
            
            java_files = list(self.decompiled_dir.rglob("*.java"))
            if java_files:
                self._log(f"⚠ Частичный успех: {len(java_files):,} файлов создано")
                return True
            return False
    
    def _extract_as_zip(self):
        try:
            self._log("📦 Распаковка APK как ZIP архива...")
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.decompiled_dir)
            
            extracted_files = list(self.decompiled_dir.rglob("*"))
            self._log(f"✓ Распаковано файлов: {len(extracted_files):,}")
            
            dex_files = list(self.decompiled_dir.rglob("classes.dex"))
            if dex_files:
                self._log(f"⚠ Найдено DEX файлов: {len(dex_files)} (требуется jadx для декомпиляции)")
            
        except zipfile.BadZipFile:
            self._log("✗ Файл не является корректным ZIP архивом")
        except Exception as e:
            self._log(f"✗ Ошибка распаковки ZIP: {e}")
    
    def _parse_manifest(self):
        manifest_path = self.decompiled_dir / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            for f in self.decompiled_dir.rglob("AndroidManifest.xml"):
                manifest_path = f
                self._log(f"📄 Манифест найден: {manifest_path}")
                break
        
        if manifest_path.exists():
            try:
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.manifest_data = f.read()
                
                self._log(f"✓ Манифест прочитан ({len(self.manifest_data):,} байт)")
                
                permissions = set()
                
                found = re.findall(r'android:name="(android\.permission\.[^"]+)"', self.manifest_data)
                permissions.update(found)
                self._log(f"  • Формат 1 (android:name): {len(found)} разрешений")
                
                found = re.findall(r'<uses-permission[^>]*android:name="([^"]+)"', self.manifest_data)
                permissions.update([p for p in found if p.startswith('android.permission.')])
                self._log(f"  • Формат 2 (uses-permission): {len(found)} разрешений")
                
                found = re.findall(r'<permission[^>]*android:name="([^"]+)"', self.manifest_data)
                permissions.update([p for p in found if p.startswith('android.permission.')])
                self._log(f"  • Формат 3 (permission): {len(found)} разрешений")
                
                found = re.findall(r'name="(android\.permission\.[^"]+)"', self.manifest_data)
                permissions.update(found)
                self._log(f"  • Формат 4 (универсальный): {len(found)} разрешений")
                
                found = re.findall(r'<uses-permission-sdk-23[^>]*android:name="([^"]+)"', self.manifest_data)
                permissions.update([p for p in found if p.startswith('android.permission.')])
                self._log(f"  • Формат 5 (sdk-23): {len(found)} разрешений")
                
                self.permissions = []
                for perm in sorted(permissions):
                    risk = self._assess_permission_risk(perm)
                    self.permissions.append({
                        "name": perm,
                        "risk": risk,
                        "category": self._get_permission_category(perm)
                    })
                
                self._log(f"✓ Найдено уникальных разрешений: {len(self.permissions)}")
                
                package_match = re.search(r'package="([^"]+)"', self.manifest_data)
                if package_match:
                    self.statistics['package_name'] = package_match.group(1)
                    self._log(f"📦 Пакет: {package_match.group(1)}")
                
                version_match = re.search(r'versionName="([^"]+)"', self.manifest_data)
                if version_match:
                    self.statistics['version_name'] = version_match.group(1)
                    self._log(f"📌 Версия: {version_match.group(1)}")
                
                version_code_match = re.search(r'versionCode="([^"]+)"', self.manifest_data)
                if version_code_match:
                    self.statistics['version_code'] = version_code_match.group(1)
                    self._log(f"📌 Код версии: {version_code_match.group(1)}")
                
                min_sdk_match = re.search(r'minSdkVersion="([^"]+)"', self.manifest_data)
                if min_sdk_match:
                    self.statistics['min_sdk'] = min_sdk_match.group(1)
                    self._log(f"📱 Мин. SDK: {min_sdk_match.group(1)}")
                
                target_sdk_match = re.search(r'targetSdkVersion="([^"]+)"', self.manifest_data)
                if target_sdk_match:
                    self.statistics['target_sdk'] = target_sdk_match.group(1)
                    self._log(f"📱 Целевой SDK: {target_sdk_match.group(1)}")
                
            except Exception as e:
                self._log(f"⚠ Ошибка парсинга манифеста: {e}")
                self.manifest_data = "Ошибка чтения манифеста"
        else:
            self._log("⚠ AndroidManifest.xml не найден")
            self.manifest_data = "AndroidManifest.xml не найден"
    
    def _get_permission_category(self, permission: str) -> str:
        categories = {
            "SMS": ["READ_SMS", "SEND_SMS", "RECEIVE_SMS"],
            "CONTACTS": ["READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"],
            "LOCATION": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"],
            "CAMERA": ["CAMERA"],
            "MICROPHONE": ["RECORD_AUDIO"],
            "PHONE": ["READ_PHONE_STATE", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS"],
            "STORAGE": ["READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"],
            "CALENDAR": ["READ_CALENDAR", "WRITE_CALENDAR"],
            "SENSORS": ["BODY_SENSORS"],
            "NETWORK": ["INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE"],
            "SYSTEM": ["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "RECEIVE_BOOT_COMPLETED"],
        }
        
        for category, keywords in categories.items():
            for keyword in keywords:
                if keyword in permission:
                    return category
        return "OTHER"
    
    def _assess_permission_risk(self, permission: str) -> str:
        dangerous = {
            "READ_SMS": "Critical",
            "SEND_SMS": "Critical",
            "RECEIVE_SMS": "Critical",
            "READ_CONTACTS": "High",
            "WRITE_CONTACTS": "High",
            "GET_ACCOUNTS": "High",
            "ACCESS_FINE_LOCATION": "High",
            "ACCESS_COARSE_LOCATION": "High",
            "RECORD_AUDIO": "High",
            "READ_CALL_LOG": "Critical",
            "WRITE_CALL_LOG": "Critical",
            "PROCESS_OUTGOING_CALLS": "Critical",
            "READ_PHONE_STATE": "High",
            "CAMERA": "Medium",
            "READ_EXTERNAL_STORAGE": "Medium",
            "WRITE_EXTERNAL_STORAGE": "Medium",
            "INTERNET": "Low",
            "ACCESS_NETWORK_STATE": "Low",
            "ACCESS_WIFI_STATE": "Low",
            "WAKE_LOCK": "Low",
            "RECEIVE_BOOT_COMPLETED": "Medium",
            "SYSTEM_ALERT_WINDOW": "High",
            "BIND_ACCESSIBILITY_SERVICE": "Critical",
            "REQUEST_INSTALL_PACKAGES": "High",
            "BIND_DEVICE_ADMIN": "Critical",
            "READ_CALENDAR": "Medium",
            "WRITE_CALENDAR": "Medium",
            "BODY_SENSORS": "High",
            "ANSWER_PHONE_CALLS": "High",
            "READ_PHONE_NUMBERS": "Critical",
        }
        for key, risk in dangerous.items():
            if key in permission:
                return risk
        return "Low"
    
    def _extract_strings(self):
        strings = set()
        java_files = list(self.decompiled_dir.rglob("*.java"))
        
        self._log(f"🔍 Сканирование {len(java_files):,} Java файлов...")
        
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    found = re.findall(r'"([^"]{10,})"', content)
                    strings.update(found)
            except:
                continue
        
        self.strings_data = sorted(list(strings))[:500]
        self._log(f"✓ Извлечено уникальных строк: {len(self.strings_data)}")
    
    def _analyze_threats(self):
        threat_patterns = [
            {"pattern": "Runtime.getRuntime().exec", "risk": "Critical", "desc": "Выполнение системных команд", "category": "Code Execution"},
            {"pattern": "ProcessBuilder", "risk": "Critical", "desc": "Создание процессов", "category": "Code Execution"},
            {"pattern": "DexClassLoader", "risk": "High", "desc": "Динамическая загрузка кода", "category": "Code Injection"},
            {"pattern": "PathClassLoader", "risk": "High", "desc": "Загрузка классов из пути", "category": "Code Injection"},
            {"pattern": "getDeviceId", "risk": "High", "desc": "Сбор идентификаторов устройства", "category": "Data Collection"},
            {"pattern": "getSubscriberId", "risk": "High", "desc": "Получение IMSI", "category": "Data Collection"},
            {"pattern": "getSimSerialNumber", "risk": "High", "desc": "Получение серийного номера SIM", "category": "Data Collection"},
            {"pattern": "getAndroidId", "risk": "Medium", "desc": "Получение Android ID", "category": "Data Collection"},
            {"pattern": "SmsManager", "risk": "Critical", "desc": "Отправка/чтение SMS", "category": "SMS Control"},
            {"pattern": "TelephonyManager", "risk": "Medium", "desc": "Доступ к телеметрии", "category": "Data Collection"},
            {"pattern": "setWallpaper", "risk": "Medium", "desc": "Изменение системы", "category": "System Modification"},
            {"pattern": "installPackage", "risk": "Critical", "desc": "Установка приложений", "category": "App Control"},
            {"pattern": "deletePackage", "risk": "Critical", "desc": "Удаление приложений", "category": "App Control"},
            {"pattern": "Cipher", "risk": "Medium", "desc": "Шифрование данных", "category": "Cryptography"},
            {"pattern": "SecretKeySpec", "risk": "Medium", "desc": "Криптографические ключи", "category": "Cryptography"},
            {"pattern": "Base64", "risk": "Low", "desc": "Кодирование данных", "category": "Data Encoding"},
            {"pattern": "URL(", "risk": "Medium", "desc": "Сетевые запросы", "category": "Network"},
            {"pattern": "HttpURLConnection", "risk": "Medium", "desc": "HTTP соединение", "category": "Network"},
            {"pattern": "OkHttpClient", "risk": "Medium", "desc": "HTTP клиент OkHttp", "category": "Network"},
            {"pattern": "Socket(", "risk": "Medium", "desc": "Сокет соединение", "category": "Network"},
            {"pattern": "ServerSocket", "risk": "High", "desc": "Серверный сокет", "category": "Network"},
            {"pattern": "SharedPreferences", "risk": "Low", "desc": "Хранение данных", "category": "Data Storage"},
            {"pattern": "FileOutputStream", "risk": "Medium", "desc": "Запись в файл", "category": "Data Storage"},
            {"pattern": "FileInputStream", "risk": "Medium", "desc": "Чтение из файла", "category": "Data Storage"},
            {"pattern": "delete(", "risk": "Medium", "desc": "Удаление файлов", "category": "File Operations"},
            {"pattern": "mkdir", "risk": "Low", "desc": "Создание директорий", "category": "File Operations"},
            {"pattern": "ContextWrapper", "risk": "Low", "desc": "Контекст приложения", "category": "Android API"},
            {"pattern": "getApplicationContext", "risk": "Low", "desc": "Получение контекста", "category": "Android API"},
            {"pattern": "startActivity", "risk": "Medium", "desc": "Запуск активити", "category": "Android API"},
            {"pattern": "startService", "risk": "Medium", "desc": "Запуск сервиса", "category": "Android API"},
            {"pattern": "BroadcastReceiver", "risk": "Medium", "desc": "Получатель широковещания", "category": "Android API"},
            {"pattern": "AlarmManager", "risk": "Medium", "desc": "Планировщик задач", "category": "Android API"},
            {"pattern": "PowerManager", "risk": "Low", "desc": "Управление питанием", "category": "Android API"},
            {"pattern": "WifiManager", "risk": "Medium", "desc": "Управление WiFi", "category": "Android API"},
            {"pattern": "Bluetooth", "risk": "Medium", "desc": "Управление Bluetooth", "category": "Android API"},
            {"pattern": "LocationManager", "risk": "High", "desc": "Управление геолокацией", "category": "Data Collection"},
            {"pattern": "AudioRecord", "risk": "High", "desc": "Запись аудио", "category": "Data Collection"},
            {"pattern": "MediaRecorder", "risk": "High", "desc": "Запись медиа", "category": "Data Collection"},
            {"pattern": "Camera", "risk": "High", "desc": "Доступ к камере", "category": "Data Collection"},
            {"pattern": "ClipboardManager", "risk": "Medium", "desc": "Доступ к буферу", "category": "Data Collection"},
            {"pattern": "KeyguardManager", "risk": "Medium", "desc": "Управление блокировкой", "category": "Security"},
            {"pattern": "DevicePolicyManager", "risk": "Critical", "desc": "Администратор устройства", "category": "Security"},
            {"pattern": "AccessibilityService", "risk": "Critical", "desc": "Служба доступности", "category": "Security"},
            {"pattern": "UsageStatsManager", "risk": "High", "desc": "Статистика использования", "category": "Data Collection"},
            {"pattern": "AppOpsManager", "risk": "High", "desc": "Операции приложений", "category": "Security"},
        ]
        
        java_files = list(self.decompiled_dir.rglob("*.java"))
        self._log(f"🔍 Анализ угроз в {len(java_files):,} файлах...")
        
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
                                "desc": threat["desc"],
                                "category": threat["category"]
                            })
                processed_files += 1
                if processed_files % 2000 == 0:
                    self._log(f"📊 Обработано файлов: {processed_files:,}")
            except Exception as e:
                continue
        
        unique_threats = []
        seen = set()
        for t in self.threats:
            key = (t["file"], t["pattern"])
            if key not in seen:
                seen.add(key)
                unique_threats.append(t)
        
        self.threats = unique_threats
        self._log(f"✓ Найдено уникальных угроз: {len(self.threats):,}")
        
        risk_counts = defaultdict(int)
        category_counts = defaultdict(int)
        for t in self.threats:
            risk_counts[t["risk"]] += 1
            category_counts[t["category"]] += 1
        
        self._log("📊 Распределение по рискам:")
        for risk in ["Critical", "High", "Medium", "Low"]:
            count = risk_counts.get(risk, 0)
            if count > 0:
                self._log(f"  {risk}: {count}")
        
        self._log("📊 Распределение по категориям:")
        for category, count in sorted(category_counts.items(), key=lambda x: -x[1])[:10]:
            self._log(f"  {category}: {count}")
    
    def _collect_statistics(self):
        java_files = list(self.decompiled_dir.rglob("*.java"))
        xml_files = list(self.decompiled_dir.rglob("*.xml"))
        dex_files = list(self.decompiled_dir.rglob("*.dex"))
        
        risk_counts = defaultdict(int)
        category_counts = defaultdict(int)
        permission_risks = defaultdict(int)
        
        for t in self.threats:
            risk_counts[t["risk"]] += 1
            category_counts[t["category"]] += 1
        
        for p in self.permissions:
            permission_risks[p["risk"]] += 1
        
        self.statistics = {
            "total_java_files": len(java_files),
            "total_xml_files": len(xml_files),
            "total_dex_files": len(dex_files),
            "total_files": len(list(self.decompiled_dir.rglob("*"))),
            "total_threats": len(self.threats),
            "critical_threats": risk_counts.get("Critical", 0),
            "high_threats": risk_counts.get("High", 0),
            "medium_threats": risk_counts.get("Medium", 0),
            "low_threats": risk_counts.get("Low", 0),
            "total_permissions": len(self.permissions),
            "dangerous_permissions": permission_risks.get("Critical", 0) + permission_risks.get("High", 0),
            "total_strings": len(self.strings_data),
            "threat_categories": dict(category_counts),
            "permission_categories": defaultdict(int),
            "apk_size_mb": os.path.getsize(self.apk_path) / 1024 / 1024 if self.apk_path else 0,
        }
        
        for p in self.permissions:
            self.statistics["permission_categories"][p["category"]] += 1
        self.statistics["permission_categories"] = dict(self.statistics["permission_categories"])
    
    def get_decompiled_files(self) -> List[Path]:
        if not self.decompiled_dir.exists():
            return []
        return sorted(list(self.decompiled_dir.rglob("*.java")))
    
    def get_file_content(self, file_path: str) -> str:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return f"Ошибка чтения: {e}"
    
    def get_statistics(self) -> Dict:
        return self.statistics
    
    def get_threats_by_category(self) -> Dict[str, List[Dict]]:
        result = defaultdict(list)
        for threat in self.threats:
            result[threat["category"]].append(threat)
        return dict(result)
    
    def get_threats_by_risk(self) -> Dict[str, List[Dict]]:
        result = defaultdict(list)
        for threat in self.threats:
            result[threat["risk"]].append(threat)
        return dict(result)
    
    def get_critical_threats(self) -> List[Dict]:
        return [t for t in self.threats if t["risk"] == "Critical"]
    
    def get_dangerous_permissions(self) -> List[Dict]:
        return [p for p in self.permissions if p["risk"] in ["Critical", "High"]]