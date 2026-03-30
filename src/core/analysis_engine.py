import os
import sys
import subprocess
import shutil
import json
import re
import zipfile
import platform
from pathlib import Path
from typing import Dict, List, Optional, Callable, Set, Tuple
from collections import defaultdict
from datetime import datetime


class AnalysisEngine:
    """
    Ядро статического анализа APK файлов (Malware-Optimized Pipeline)
    
    Приоритеты:
    🔴 Critical: DEX + Native (.so)
    🟠 High: assets/ + strings.xml + network indicators
    🟡 Medium: AndroidManifest.xml
    🔵 Low: META-INF, metadata
    """
    
    # Системные библиотеки — НЕ анализировать
    SYSTEM_LIBS = {
        'libc++_shared.so', 'libc++.so', 'liblog.so', 'libm.so', 'libz.so',
        'libdl.so', 'libstdc++.so', 'libssl.so', 'libcrypto.so', 'libEGL.so',
        'libGLESv1_CM.so', 'libGLESv2.so', 'libGLESv3.so', 'libjnigraphics.so',
        'libandroid.so', 'libOpenSLES.so', 'libmediandk.so', 'libvulkan.so'
    }
    
    # Директории для пропуска (не несут угроз)
    SKIP_DIRS = {'res/drawable', 'res/layout', 'res/font', 'res/anim', 'res/color', 'res/mipmap'}
    
    # Сетевые индикаторы (regex)
    NETWORK_PATTERNS = {
        'url': re.compile(r'https?://[^\s"\'<>]+', re.I),
        'ip': re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b'),
        'domain': re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?'),
        'websocket': re.compile(r'wss?://[^\s"\'<>]+', re.I),
    }
    
    # Индикаторы динамической загрузки
    DYNAMIC_LOAD_PATTERNS = [
        'DexClassLoader', 'PathClassLoader', 'URLClassLoader',
        'loadLibrary', 'System.load', 'System.loadLibrary',
        'Runtime.exec', 'ProcessBuilder'
    ]
    
    def __init__(self, temp_dir: str = "temp"):
        self.temp_dir = Path(temp_dir)
        self.decompiled_dir = self.temp_dir / "decompiled"
        self.ghidra_scripts_dir = Path(__file__).parent / "ghidra_scripts"
        self.apk_path: Optional[Path] = None
        
        # Результаты анализа
        self.manifest_data: str = ""
        self.manifest_info: Dict = {}
        self.permissions: List[Dict] = []
        self.strings_data: List[str] = []
        self.network_indicators: Dict[str, List[str]] = defaultdict(list)
        self.dynamic_load_calls: List[Dict] = []
        self.native_data: Dict = {}
        self.threats: List[Dict] = []
        self.osint_data: Dict = {}
        self.signature_info: Dict = {}
        
        # Статистика и оценка риска
        self.statistics: Dict = {}
        self.risk_score: int = 0
        
        # Колбэки
        self.progress_callback: Optional[Callable] = None
        self.log_callback: Optional[Callable] = None
        self.use_ghidra: bool = True
        
    def set_progress_callback(self, callback: Callable[[int, str], None]):
        self.progress_callback = callback
        
    def set_log_callback(self, callback: Callable[[str], None]):
        self.log_callback = callback
        
    def enable_ghidra(self, enabled: bool = True):
        self.use_ghidra = enabled
        self._log(f"🔧 Ghidra: {'включён' if enabled else 'отключён'}")
    
    def _log(self, message: str):
        if self.log_callback:
            self.log_callback(message)
        
    def _progress(self, value: int, message: str):
        if self.progress_callback:
            self.progress_callback(value, message)

    # ==================== MAIN ANALYSIS PIPELINE ====================
    
    def analyze_apk(self, apk_path: str) -> bool:
        try:
            self.apk_path = Path(apk_path)
            self._log("=" * 70)
            self._log("🔍 LUCIDBYTE ANALYSIS ENGINE (Malware-Optimized)")
            self._log("=" * 70)
            self._log(f"📁 Файл: {apk_path}")
            self._log(f"📊 Размер: {os.path.getsize(apk_path) / 1024 / 1024:.2f} MB")
            self._log("=" * 70)
            
            # Очистка
            if self.decompiled_dir.exists():
                shutil.rmtree(self.decompiled_dir)
            self.decompiled_dir.mkdir(parents=True, exist_ok=True)
            
            # === ЭТАП 1: Быстрый анализ (2-10 сек) ===
            self._progress(5, "Распаковка и быстрый анализ...")
            self._extract_apk_structure()
            
            # === ЭТАП 2: Manifest + Permissions (🟡 Medium) ===
            self._progress(15, "Анализ манифеста...")
            self._parse_manifest_fast()
            
            # === ЭТАП 3: OSINT ресурсы (🟠 High) ===
            self._progress(25, "Извлечение OSINT-индикаторов...")
            self._extract_osint_resources()
            self._extract_network_indicators()
            
            # === ЭТАП 4: DEX анализ через jadx (🔴 Critical) ===
            self._progress(40, "Анализ DEX (jadx)...")
            self._analyze_dex_fast()
            
            # === ЭТАП 5: Native библиотеки (🔴 Critical, только если нужно) ===
            if self.use_ghidra:
                self._progress(70, "Анализ native библиотек...")
                self._analyze_native_selective()
            
            # === ЭТАП 6: Сбор угроз и расчет риска ===
            self._progress(90, "Расчет риска и сбор результатов...")
            self._correlate_threats()
            self._calculate_risk_score()
            
            self._progress(100, "Анализ завершен")
            self._log("=" * 70)
            self._log(f"✓ АНАЛИЗ ЗАВЕРШЕН | 🎯 Risk Score: {self.risk_score}/100")
            self._log("=" * 70)
            self._print_summary()
            return True
            
        except Exception as e:
            import traceback
            self._log(f"✗ Ошибка анализа: {str(e)}")
            self._log(f"📋 Traceback:\n{traceback.format_exc()}")
            return False

    # ==================== APK EXTRACTION ====================
    
    def _extract_apk_structure(self):
        """Распаковка APK с фильтрацией директорий"""
        self._log("📦 Распаковка APK...")
        
        with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                # Пропускаем ненужные директории
                if any(member.startswith(skip) for skip in self.SKIP_DIRS):
                    continue
                # Извлекаем только важное
                if self._is_important_file(member):
                    try:
                        zip_ref.extract(member, self.decompiled_dir)
                    except:
                        pass
        
        # Подсчет извлеченных файлов
        stats = self._count_extracted_files()
        self._log(f"✓ Извлечено: {stats['total']} файлов")
        if stats['so_files']:
            self._log(f"  • Native .so: {stats['so_files']}")
        if stats['dex_files']:
            self._log(f"  • DEX файлы: {stats['dex_files']}")
        if stats['assets']:
            self._log(f"  • Assets: {stats['assets']}")
    
    def _is_important_file(self, filepath: str) -> bool:
        """Фильтр: извлекать только потенциально опасные файлы"""
        filepath_lower = filepath.lower()
        
        # Всегда извлекать
        if any(filepath_lower.endswith(ext) for ext in [
            '.xml', '.dex', '.so', '.json', '.js', '.lua', '.py', '.txt', '.dat'
        ]):
            return True
        
        # Важные директории
        important_dirs = ['assets/', 'lib/', 'META-INF/', 'res/values/', 'res/raw/', 'kotlin/']
        if any(filepath_lower.startswith(d) for d in important_dirs):
            return True
        
        # resources.arsc — может содержать строки
        if filepath_lower == 'resources.arsc':
            return True
        
        return False
    
    def _count_extracted_files(self) -> Dict:
        return {
            'total': len(list(self.decompiled_dir.rglob('*'))),
            'so_files': len(list(self.decompiled_dir.rglob('*.so'))),
            'dex_files': len(list(self.decompiled_dir.rglob('*.dex'))),
            'assets': len(list((self.decompiled_dir / 'assets').rglob('*'))) if (self.decompiled_dir / 'assets').exists() else 0,
        }

    # ==================== MANIFEST ANALYSIS (🟡 Medium) ====================
    
    def _parse_manifest_fast(self):
        """Быстрый парсинг манифеста с фокусом на угрозы"""
        manifest_path = self.decompiled_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            self._log("⚠ AndroidManifest.xml не найден")
            return
        
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                self.manifest_data = content
            
            # Парсинг через regex (быстрее чем XML parser для больших файлов)
            self._parse_permissions_fast(content)
            self._parse_app_info_fast(content)
            
            self._log(f"✓ Манифест: {len(self.permissions)} разрешений, пакет: {self.manifest_info.get('package', 'N/A')}")
            
        except Exception as e:
            self._log(f"⚠ Ошибка парсинга манифеста: {e}")
    
    def _parse_permissions_fast(self, content: str):
        """Извлечение разрешений с оценкой риска"""
        permissions = set()
        
        # Все возможные форматы записи разрешений
        patterns = [
            r'android:name="(android\.permission\.[^"]+)"',
            r'<uses-permission[^>]*android:name="([^"]+)"',
            r'name="(android\.permission\.[^"]+)"',
        ]
        
        for pattern in patterns:
            found = re.findall(pattern, content)
            permissions.update(p for p in found if p.startswith('android.permission.'))
        
        # Оценка риска
        self.permissions = []
        for perm in sorted(permissions):
            risk = self._assess_permission_risk(perm)
            category = self._get_permission_category(perm)
            self.permissions.append({"name": perm, "risk": risk, "category": category})
            
            # Немедленно добавляем критические разрешения в угрозы
            if risk == "Critical":
                self.threats.append({
                    "source": "manifest",
                    "pattern": perm,
                    "risk": "Critical",
                    "desc": f"Опасное разрешение: {perm}",
                    "category": "Permission"
                })
    
    def _parse_app_info_fast(self, content: str):
        """Извлечение базовой информации о приложении"""
        self.manifest_info = {}
        
        # Пакет и версии
        if match := re.search(r'package="([^"]+)"', content):
            self.manifest_info['package'] = match.group(1)
        if match := re.search(r'versionName="([^"]+)"', content):
            self.manifest_info['version'] = match.group(1)
        if match := re.search(r'targetSdkVersion="(\d+)"', content):
            self.manifest_info['target_sdk'] = int(match.group(1))
        
        # Компоненты (активити, сервисы, ресиверы)
        self.manifest_info['components'] = {
            'activities': len(re.findall(r'<activity[^>]*>', content)),
            'services': len(re.findall(r'<service[^>]*>', content)),
            'receivers': len(re.findall(r'<receiver[^>]*>', content)),
            'providers': len(re.findall(r'<provider[^>]*>', content)),
        }
    
    def _assess_permission_risk(self, permission: str) -> str:
        dangerous = {
            'READ_SMS': 'Critical', 'SEND_SMS': 'Critical', 'RECEIVE_SMS': 'Critical',
            'READ_CONTACTS': 'High', 'WRITE_CONTACTS': 'High',
            'ACCESS_FINE_LOCATION': 'High', 'ACCESS_COARSE_LOCATION': 'High',
            'RECORD_AUDIO': 'High', 'READ_CALL_LOG': 'Critical',
            'BIND_ACCESSIBILITY_SERVICE': 'Critical', 'SYSTEM_ALERT_WINDOW': 'High',
            'REQUEST_INSTALL_PACKAGES': 'High', 'BIND_DEVICE_ADMIN': 'Critical',
            'READ_PHONE_NUMBERS': 'Critical', 'ANSWER_PHONE_CALLS': 'High',
        }
        for key, risk in dangerous.items():
            if key in permission:
                return risk
        return 'Low'
    
    def _get_permission_category(self, permission: str) -> str:
        categories = {
            'SMS': ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS'],
            'CONTACTS': ['READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS'],
            'LOCATION': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'],
            'CAMERA': ['CAMERA'], 'MICROPHONE': ['RECORD_AUDIO'],
            'PHONE': ['READ_PHONE_STATE', 'READ_CALL_LOG'],
            'STORAGE': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'],
            'NETWORK': ['INTERNET', 'ACCESS_NETWORK_STATE'],
            'SYSTEM': ['SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE'],
        }
        for cat, keywords in categories.items():
            for kw in keywords:
                if kw in permission:
                    return cat
        return 'OTHER'

    # ==================== OSINT RESOURCES (🟠 High) ====================
    
    def _extract_osint_resources(self):
        """Извлечение строк, конфигов, payload из ресурсов"""
        self._log("🔍 Анализ ресурсов...")
        
        # 1. strings.xml — URL, API keys, токены
        strings_xml = self.decompiled_dir / "res" / "values" / "strings.xml"
        if strings_xml.exists():
            self._parse_strings_xml(strings_xml)
        
        # 2. assets/ — payload, конфиги, вторичный DEX
        assets_dir = self.decompiled_dir / "assets"
        if assets_dir.exists():
            self._scan_assets(assets_dir)
        
        # 3. res/raw/ — бинарные конфиги
        raw_dir = self.decompiled_dir / "res" / "raw"
        if raw_dir.exists():
            self._scan_raw_resources(raw_dir)
        
        # 4. resources.arsc — скрытые строки
        arsc_file = self.decompiled_dir / "resources.arsc"
        if arsc_file.exists():
            self._extract_strings_from_arsc(arsc_file)
        
        self._log(f"✓ OSINT: {len(self.osint_data.get('urls', []))} URL, "
                 f"{len(self.osint_data.get('api_keys', []))} API keys")
    
    def _parse_strings_xml(self, filepath: Path):
        """Парсинг strings.xml с поиском индикаторов"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Извлечение всех строк
            strings = re.findall(r'<string[^>]*name="([^"]+)"[^>]*>([^<]+)</string>', content)
            
            for name, value in strings:
                # Поиск сетевых индикаторов
                for net_type, pattern in self.NETWORK_PATTERNS.items():
                    if matches := pattern.findall(value):
                        self.network_indicators[net_type].extend(matches)
                        self.osint_data.setdefault('urls', []).extend(matches)
                
                # Поиск API keys / токенов
                if self._looks_like_api_key(value):
                    self.osint_data.setdefault('api_keys', []).append({
                        'name': name, 'value': value[:50] + '...' if len(value) > 50 else value
                    })
                
                # Подозрительные команды
                suspicious = ['su', 'chmod', 'rm -rf', 'wget', 'curl', 'sh -c']
                for cmd in suspicious:
                    if cmd in value.lower():
                        self.threats.append({
                            'source': f'strings.xml:{name}',
                            'pattern': cmd,
                            'risk': 'High',
                            'desc': f'Подозрительная команда в ресурсах',
                            'category': 'Hidden_Command'
                        })
                        
        except Exception as e:
            self._log(f"⚠ Ошибка парсинга strings.xml: {e}")
    
    def _scan_assets(self, assets_dir: Path):
        """Сканирование assets/ на наличие payload и конфигов"""
        for filepath in assets_dir.rglob('*'):
            if filepath.is_file():
                try:
                    content = filepath.read_text(errors='ignore')
                    
                    # Поиск JSON конфигов
                    if filepath.suffix == '.json':
                        try:
                            config = json.loads(content)
                            self.osint_data.setdefault('configs', []).append({
                                'file': str(filepath.relative_to(self.decompiled_dir)),
                                'keys': list(config.keys())[:10]
                            })
                        except:
                            pass
                    
                    # Поиск JS/Lua payload
                    if filepath.suffix in ['.js', '.lua', '.py']:
                        self.osint_data.setdefault('scripts', []).append(
                            str(filepath.relative_to(self.decompiled_dir))
                        )
                    
                    # Поиск сетевых индикаторов в любом файле
                    for net_type, pattern in self.NETWORK_PATTERNS.items():
                        if matches := pattern.findall(content):
                            self.network_indicators[net_type].extend(matches[:20])  # Лимит
                            self.osint_data.setdefault('urls', []).extend(matches[:20])
                    
                    # Поиск индикаторов динамической загрузки
                    for dyn_pattern in self.DYNAMIC_LOAD_PATTERNS:
                        if dyn_pattern in content:
                            self.dynamic_load_calls.append({
                                'file': str(filepath.relative_to(self.decompiled_dir)),
                                'pattern': dyn_pattern,
                                'risk': 'High'
                            })
                            
                except:
                    continue
    
    def _scan_raw_resources(self, raw_dir: Path):
        """Сканирование res/raw/ на бинарные конфиги"""
        for filepath in raw_dir.rglob('*'):
            if filepath.is_file():
                try:
                    # Пробуем прочитать как текст
                    content = filepath.read_text(errors='ignore')
                    
                    # Поиск строк и индикаторов
                    for net_type, pattern in self.NETWORK_PATTERNS.items():
                        if matches := pattern.findall(content):
                            self.network_indicators[net_type].extend(matches[:10])
                    
                except:
                    # Бинарный файл — извлекаем только ASCII строки
                    try:
                        with open(filepath, 'rb') as f:
                            data = f.read(1024*1024)  # Лимит 1MB
                        strings = re.findall(b'[\x20-\x7E]{10,}', data)
                        for s in strings[:20]:
                            decoded = s.decode('ascii', errors='ignore')
                            for net_type, pattern in self.NETWORK_PATTERNS.items():
                                if matches := pattern.findall(decoded):
                                    self.network_indicators[net_type].extend(matches[:5])
                    except:
                        pass
    
    def _extract_strings_from_arsc(self, arsc_path: Path):
        """Простое извлечение строк из resources.arsc (без apktool)"""
        try:
            with open(arsc_path, 'rb') as f:
                data = f.read(2*1024*1024)  # Лимит 2MB
            
            # Поиск UTF-16 строк (формат Android)
            strings = re.findall(b'(?:[\x00][\x20-\x7E]){5,}', data)
            for s in strings[:50]:
                try:
                    decoded = s.decode('utf-16-le', errors='ignore')
                    # Фильтр: только потенциально интересные
                    if any(kw in decoded.lower() for kw in ['http', 'api', 'key', 'token', 'secret']):
                        self.osint_data.setdefault('arsc_strings', []).append(decoded[:100])
                except:
                    pass
                    
        except Exception as e:
            self._log(f"⚠ Ошибка чтения resources.arsc: {e}")
    
    def _looks_like_api_key(self, value: str) -> bool:
        """Эвристика для определения API ключей"""
        # Длинные строки с определенными паттернами
        if len(value) < 20:
            return False
        # Паттерны ключей
        key_patterns = [
            r'[A-Za-z0-9]{32,}',  # Длинные alphanumeric
            r'AIza[A-Za-z0-9_-]{35}',  # Google API key
            r'sk-[A-Za-z0-9]{48}',  # OpenAI key
            r'gh[pousr]_[A-Za-z0-9]{36}',  # GitHub token
        ]
        return any(re.match(p, value) for p in key_patterns)
    
    def _extract_network_indicators(self):
        """Дополнительный поиск сетевых индикаторов во всех файлах"""
        self._log("🔍 Поиск сетевых индикаторов...")
        
        for filepath in self.decompiled_dir.rglob('*'):
            if not filepath.is_file():
                continue
            if filepath.suffix in ['.png', '.jpg', '.gif', '.webp', '.so', '.dex']:
                continue  # Пропускаем бинарные
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(512*1024)  # Лимит 512KB на файл
                
                for net_type, pattern in self.NETWORK_PATTERNS.items():
                    matches = pattern.findall(content)
                    if matches:
                        # Уникализация и лимит
                        unique = list(set(matches))[:10]
                        self.network_indicators[net_type].extend(unique)
                        
            except:
                continue
        
        # Уникализация результатов
        for net_type in self.network_indicators:
            self.network_indicators[net_type] = list(set(self.network_indicators[net_type]))[:50]
        
        total_urls = sum(len(v) for v in self.network_indicators.values())
        self._log(f"✓ Найдено сетевых индикаторов: {total_urls}")

    # ==================== DEX ANALYSIS VIA JADX (🔴 Critical) ====================
    
    def _analyze_dex_fast(self):
        """Быстрый анализ DEX через jadx с фокусом на угрозы"""
        jadx_cmd = self._find_jadx()
        if not jadx_cmd:
            self._log("⚠ jadx не найден, пропускаем DEX анализ")
            return
        
        output_dir = str(self.decompiled_dir.absolute())
        input_file = str(self.apk_path.absolute())
        
        self._log(f"📥 JADX вход: {input_file}")
        self._log(f"📤 JADX выход: {output_dir}")
        
        is_windows = platform.system() == "Windows"
        is_batch = jadx_cmd.endswith(('.bat', '.cmd'))
        
        # Формирование команды
        if is_windows and is_batch:
            cmd = f'"{jadx_cmd}" -d "{output_dir}" -j 4 --no-replace-consts --show-bad-code --no-inline-methods "{input_file}"'
            env = os.environ.copy()
            env['JAVA_OPTS'] = '-Xmx4G'
            
            try:
                process = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True,
                    timeout=900, encoding='utf-8', errors='ignore', env=env
                )
            except Exception as e:
                self._log(f"✗ Ошибка jadx: {e}")
                return
        else:
            cmd = [jadx_cmd, "-d", output_dir, "-j", "4", "--no-replace-consts",
                   "--show-bad-code", "--no-inline-methods", input_file]
            env = os.environ.copy()
            env['JAVA_OPTS'] = '-Xmx4G'
            
            try:
                process = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=900, encoding='utf-8', errors='ignore', env=env
                )
            except Exception as e:
                self._log(f"✗ Ошибка jadx: {e}")
                return
        
        # Обработка результатов
        java_files = list(self.decompiled_dir.rglob("*.java"))
        if java_files:
            self._log(f"✓ Создано Java файлов: {len(java_files):,}")
            self._scan_java_for_threats(java_files)
        else:
            self._log("⚠ jadx не создал Java файлы")
    
    def _find_jadx(self) -> Optional[str]:
        self._log("🔍 Поиск jadx...")
        
        jadx_names = ["jadx", "jadx.bat", "jadx.exe"]
        for name in jadx_names:
            found = shutil.which(name)
            if found:
                self._log(f"✓ jadx найден в PATH: {found}")
                return found
        
        jadx_paths = [
            r"C:\jadx\bin\jadx.bat", r"C:\jadx\bin\jadx.exe",
            r"C:\Program Files\jadx\bin\jadx.bat",
        ]
        for path in jadx_paths:
            if os.path.exists(path):
                self._log(f"✓ jadx найден: {path}")
                return path
        
        self._log("✗ jadx не найден")
        return None
    
    def _scan_java_for_threats(self, java_files: List[Path]):
        """Сканирование Java файлов на угрозы"""
        threat_patterns = [
            {"pattern": "Runtime.getRuntime().exec", "risk": "Critical", "desc": "Выполнение системных команд", "category": "Code Execution"},
            {"pattern": "ProcessBuilder", "risk": "Critical", "desc": "Создание процессов", "category": "Code Execution"},
            {"pattern": "DexClassLoader", "risk": "High", "desc": "Динамическая загрузка кода", "category": "Code Injection"},
            {"pattern": "getDeviceId", "risk": "High", "desc": "Сбор идентификаторов устройства", "category": "Data Collection"},
            {"pattern": "SmsManager", "risk": "Critical", "desc": "Отправка/чтение SMS", "category": "SMS Control"},
            {"pattern": "AccessibilityService", "risk": "Critical", "desc": "Служба доступности", "category": "Security"},
            {"pattern": "Cipher", "risk": "Medium", "desc": "Шифрование данных", "category": "Cryptography"},
            {"pattern": "HttpURLConnection", "risk": "Medium", "desc": "HTTP соединение", "category": "Network"},
        ]
        
        self._log(f"🔍 Анализ угроз в {len(java_files):,} файлах...")
        
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
            except:
                continue
        
        # Уникализация
        unique = []
        seen = set()
        for t in self.threats:
            key = (t["file"], t["pattern"])
            if key not in seen:
                seen.add(key)
                unique.append(t)
        self.threats = unique
        
        self._log(f"✓ Найдено уникальных угроз: {len(self.threats):,}")

    # ==================== NATIVE LIBS ANALYSIS VIA GHIDRA (🔴 Critical) ====================
    
    def _analyze_native_selective(self):
        """Пофайловый анализ .so с оптимизацией через -noanalysis и properties"""
        ghidra_home = self._find_ghidra()
        if not ghidra_home:
            return
        
        so_files = list(self.decompiled_dir.rglob("*.so"))
        if not so_files:
            self._log("ℹ Native библиотеки не найдены")
            return
        
        # Фильтрация: пропускаем системные библиотеки
        target_libs = [f for f in so_files if self._should_analyze_library(f.name)]
        if not target_libs:
            self._log("✓ Все .so библиотеки пропущены (системные)")
            return
        
        self._log(f"📦 К анализу: {len(target_libs)} из {len(so_files)} библиотек")
        
        project_location = str((self.temp_dir / "ghidra_native").resolve())
        project_name = "Native_Malware_Analysis"
        script_dir = str(self.ghidra_scripts_dir.resolve())
        
        # Создаём скрипт и properties-файл
        self.ghidra_scripts_dir.mkdir(parents=True, exist_ok=True)
        script_path = self.ghidra_scripts_dir / "ExportNativeIndicators.py"
        props_path = self.ghidra_scripts_dir / "analysis.properties"
        
        if not script_path.exists():
            self._create_native_ghidra_script(script_path)
        if not props_path.exists():
            self._create_analysis_properties(props_path)
        
        is_windows = platform.system() == "Windows"
        analyzer_cmd = os.path.join(ghidra_home, "support", "analyzeHeadless.bat" if is_windows else "analyzeHeadless")
        
        # === ПОФИЛОВАЯ ОБРАБОТКА С -noanalysis ===
        for idx, lib_path in enumerate(target_libs):
            lib_name = lib_path.name
            output_json = str((self.decompiled_dir / f"ghidra_{lib_name}.json").resolve())
            log_file = str((self.temp_dir / f"ghidra_{lib_name}.log").resolve())
            
            # Формируем команду с ключевыми оптимизациями
            cmd = [
                analyzer_cmd,
                project_location,
                project_name,
                "-import", str(lib_path.resolve()),
                "-noanalysis",  # 🔥 КЛЮЧЕВОЙ ФЛАГ: отключаем полный автоанализ
                "-propertiesFile", str(props_path),  # 🔥 Загружаем настройки анализаторов
                "-scriptPath", script_dir,
                "-postScript", "ExportNativeIndicators.py", output_json,
                "-log", log_file,
                "-quiet"
            ]
            
            self._log(f"[{idx+1}/{len(target_libs)}] 🔄 Анализ: {lib_name}")
            self._progress(50 + idx * 40 // len(target_libs), f"Native: {lib_name}")
            
            try:
                env = os.environ.copy()
                env["GHIDRA_PROJECT_DIR"] = project_location
                env["_JAVA_OPTIONS"] = "-Xmx2G"  # Ограничиваем память на библиотеку
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=env,
                    encoding="utf-8",
                    errors="ignore"
                )
                
                # Читаем вывод в реальном времени
                for line in process.stdout:
                    line = line.strip()
                    if self.log_callback and any(kw in line for kw in ["ERROR", "WARN"]):
                        self._log(f"  [Ghidra:{lib_name}] {line}")
                    # Прогресс по ключевым фразам
                    if "Importing" in line:
                        self._progress(52 + idx * 40 // len(target_libs), f"Импорт: {lib_name}")
                    elif "Script" in line or "Export" in line:
                        self._progress(55 + idx * 40 // len(target_libs), f"Экспорт: {lib_name}")
                
                process.wait(timeout=300)  # 5 минут максимум на библиотеку
                
                if process.returncode == 0 and os.path.exists(output_json):
                    self._parse_native_json(output_json, lib_name)
                    self._log(f"✓ Завершено: {lib_name} ({os.path.getsize(output_json)/1024:.1f} KB)")
                else:
                    self._log(f"⚠ Ошибка {lib_name}: код {process.returncode}")
                    
            except subprocess.TimeoutExpired:
                self._log(f"✗ Таймаут: {lib_name} (>5 мин)")
            except Exception as e:
                self._log(f"✗ Ошибка {lib_name}: {e}")
    
    def _should_analyze_library(self, lib_name: str) -> bool:
        """Фильтрация библиотек: анализировать только кастомные"""
        if lib_name in self.SYSTEM_LIBS:
            self._log(f"⊘ Пропущена системная: {lib_name}")
            return False
        # Всё остальное — кастомные библиотеки, потенциально вредоносные
        self._log(f"✓ Кастомная библиотека: {lib_name}")
        return True
    
    def _find_ghidra(self) -> Optional[str]:
        self._log("🔍 Поиск Ghidra...")
        possible_paths = [
            os.environ.get("GHIDRA_HOME"),
            r"C:\ghidra_12.0.4_PUBLIC", r"C:\ghidra_12.0_PUBLIC",
            r"C:\ghidra_11.2_PUBLIC",
        ]
        for path in possible_paths:
            if path and os.path.exists(path):
                analyzer = Path(path) / "support" / ("analyzeHeadless.bat" if platform.system() == "Windows" else "analyzeHeadless")
                if analyzer.exists():
                    self._log(f"✓ Ghidra найден: {path}")
                    return str(Path(path).resolve())
        self._log("✗ Ghidra не найден")
        return None
    
    def _create_native_ghidra_script(self, script_path: Path):
        """Скрипт для извлечения malware-индикаторов (БЕЗ тяжёлого анализа)"""
        script_content = '''# @author LucidByte
# @category MalwareAnalysis
# @keybinding
# @menupath

import os, json
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Listing
from ghidra.program.model.symbol import SourceType, SymbolTable

class ExportNativeIndicators(GhidraScript):
    def run(self):
        if len(getScriptArgs()) < 1:
            print("Usage: ExportNativeIndicators.py <output_json>")
            return
        
        output_path = getScriptArgs()[0]
        results = {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "jni_functions": [],
            "suspicious_names": []
        }
        
        # === 1. Сбор функций (работает даже без анализа) ===
        listing = currentProgram.getListing()
        for func in listing.getFunctions(True):
            fname = func.getName()
            fentry = str(func.getEntryPoint())
            
            # JNI функции — критично для Android
            if fname.startswith("Java_") or fname.startswith("JNI_"):
                results["jni_functions"].append({
                    "name": fname,
                    "address": fentry,
                    "signature": str(func.getSignature())
                })
            
            # Подозрительные имена
            suspicious = ["crypto", "encrypt", "decrypt", "key", "secret", 
                         "inject", "hook", "root", "su", "priv", "hide"]
            for kw in suspicious:
                if kw in fname.lower():
                    results["suspicious_names"].append({
                        "function": fname,
                        "address": fentry,
                        "keyword": kw,
                        "risk": "High"
                    })
                    break
            
            results["functions"].append({"name": fname, "address": fentry})
        
        # === 2. Сбор импортов (внешние символы) — работает без анализа ===
        symbol_table = currentProgram.getSymbolTable()
        for sym in symbol_table.getSymbolIterator():
            if sym.isExternalEntryPoint():
                sym_name = sym.getName()
                results["imports"].append({
                    "name": sym_name,
                    "address": str(sym.getAddress()),
                    "risk": self._assess_import_risk(sym_name)
                })
        
        # === 3. Сбор экспортов (JNI entry points) ===
        for sym in symbol_table.getSymbolIterator():
            if sym.getSource() == SourceType.USER_DEFINED and sym.isGlobal():
                sname = sym.getName()
                if sname.startswith("Java_") or sname.startswith("JNI_"):
                    results["exports"].append({
                        "name": sname,
                        "address": str(sym.getAddress())
                    })
        
        # === 4. Строки из памяти (работает без анализа) ===
        try:
            mem = currentProgram.getMemory()
            for block in mem.getBlocks():
                if block.isInitialized() and block.isRead():
                    try:
                        size = min(2*1024*1024, int(block.getSize()))
                        data = block.getBytes(block.getStart(), size)
                        # ASCII строки 8+ символов
                        import re
                        strings = re.findall(b'[\\x20-\\x7E]{8,}', data)
                        for s in strings[:50]:  # Лимит на блок
                            try:
                                decoded = s.decode('ascii')
                                # Фильтр: только сетевые/подозрительные
                                if any(kw in decoded.lower() for kw in 
                                       ['http', 'https', '.so', '.apk', '192.168', '10.', '172.', 'api', 'token', 'key']):
                                    results["strings"].append(decoded[:150])
                            except:
                                pass
                    except:
                        pass
        except:
            pass
        
        # === 5. Сохранение ===
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Export: {len(results['functions'])} funcs, "
              f"{len(results['imports'])} imports, "
              f"{len(results['jni_functions'])} JNI")
    
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
'''
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        self._log(f"📝 Скрипт создан: {script_path}")
    
    def _create_analysis_properties(self, props_path: Path):
        """Создание файла настроек анализаторов для Ghidra Headless"""
        content = """# Ghidra Headless Analysis Properties - Malware Optimized
# Отключаем тяжёлые анализаторы для скорости

# === ОТКЛЮЧЕНО (тяжёлые) ===
Decompiler Switch Analyzer=false
Stack Analyzer=false
Data Reference Analyzer=false
Constant Reference Analyzer=false
Demangler GNU=false
Call Graph Analyzer=false
Version Tracking Analyzer=false
Create Address Tables=false
Create Address Tables (RO)=false
Apply Data Archives=false

# === ВКЛЮЧЕНО (минимально необходимые) ===
Function ID Analyzer=true
ELF Scalar Operand Analyzer=true
String Reference Analyzer=true
Symbol Analyzer=true
ELF Program Header Analyzer=true
ELF Section Header Analyzer=true
External Symbol Analyzer=true

# === НАСТРОЙКИ ===
analysis.timeout.per.file=300
"""
        with open(props_path, "w", encoding="utf-8") as f:
            f.write(content)
        self._log(f"📝 Создан analysis.properties: {props_path}")
    
    def _parse_native_json(self, json_path: str, lib_name: str):
        """Парсинг результатов анализа одной библиотеки"""
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Интеграция импортов в угрозы
            for imp in data.get("imports", []):
                if imp.get("risk") in ["Critical", "High"]:
                    self.threats.append({
                        "file": f"native:{lib_name}",
                        "pattern": imp["name"],
                        "risk": imp["risk"],
                        "desc": f"Опасный native импорт: {imp['name']}",
                        "category": "Native_Import"
                    })
            
            # JNI функции
            for jni in data.get("jni_functions", []):
                self.threats.append({
                    "file": f"native:{lib_name}",
                    "pattern": jni["name"],
                    "risk": "Medium",
                    "desc": f"JNI entry point: {jni['name']}",
                    "category": "Native_JNI"
                })
            
            # Подозрительные функции
            for susp in data.get("suspicious_names", []):
                self.threats.append({
                    "file": f"native:{lib_name}",
                    "pattern": susp["keyword"],
                    "risk": susp["risk"],
                    "desc": f"Подозрительная функция: {susp['function']}",
                    "category": "Native_Suspicious"
                })
            
            # Сохранение для статистики
            self.native_data[lib_name] = data
            
            self._log(f"✓ {lib_name}: {len(data.get('imports', []))} imports, {len(data.get('jni_functions', []))} JNI")
            
        except Exception as e:
            self._log(f"⚠ Ошибка парсинга {json_path}: {e}")

    # ==================== THREAT CORRELATION & RISK SCORE ====================
    
    def _correlate_threats(self):
        """Корреляция угроз из разных источников"""
        # Добавляем сетевые индикаторы как угрозы
        for url in self.network_indicators.get('url', []):
            if any(kw in url.lower() for kw in ['malware', 'evil', 'hack', 'exploit']):
                self.threats.append({
                    "source": "network_indicator",
                    "pattern": url,
                    "risk": "High",
                    "desc": f"Подозрительный URL: {url}",
                    "category": "Network"
                })
        
        # Добавляем индикаторы динамической загрузки
        for dyn in self.dynamic_load_calls:
            self.threats.append({
                "source": dyn["file"],
                "pattern": dyn["pattern"],
                "risk": dyn["risk"],
                "desc": f"Динамическая загрузка: {dyn['pattern']}",
                "category": "Code_Injection"
            })
        
        # Уникализация
        unique = []
        seen = set()
        for t in self.threats:
            key = (t.get("file", t.get("source")), t["pattern"])
            if key not in seen:
                seen.add(key)
                unique.append(t)
        self.threats = unique
    
    def _calculate_risk_score(self):
        """Расчет итогового risk score (0-100)"""
        score = 0
        
        # Угрозы по уровню риска
        score += sum(1 for t in self.threats if t["risk"] == "Critical") * 15
        score += sum(1 for t in self.threats if t["risk"] == "High") * 8
        score += sum(1 for t in self.threats if t["risk"] == "Medium") * 3
        score += sum(1 for t in self.threats if t["risk"] == "Low") * 1
        
        # Опасные разрешения
        dangerous_perms = sum(1 for p in self.permissions if p["risk"] in ["Critical", "High"])
        score += dangerous_perms * 5
        
        # Native угрозы (более весомые)
        native_threats = sum(1 for t in self.threats if t["category"].startswith("Native_"))
        score += native_threats * 10
        
        # Сетевые индикаторы
        suspicious_urls = sum(1 for u in self.network_indicators.get('url', []) 
                            if any(kw in u.lower() for kw in ['malware', 'evil', 'hack']))
        score += suspicious_urls * 12
        
        # Динамическая загрузка
        score += len(self.dynamic_load_calls) * 10
        
        # Нормализация 0-100
        self.risk_score = min(score, 100)
        self._log(f"🎯 Risk Score: {self.risk_score}/100")
    
    def _print_summary(self):
        """Печать краткого отчета"""
        risk_counts = defaultdict(int)
        for t in self.threats:
            risk_counts[t["risk"]] += 1
        
        self._log(f"📊 Файлов Java: {len(list(self.decompiled_dir.rglob('*.java'))):,}")
        self._log(f"📦 Native .so: {len(list(self.decompiled_dir.rglob('*.so')))}")
        self._log(f"⚠ Угроз всего: {len(self.threats):,}")
        self._log(f"🔴 Critical: {risk_counts.get('Critical', 0)}")
        self._log(f"🟠 High: {risk_counts.get('High', 0)}")
        self._log(f"🟡 Medium: {risk_counts.get('Medium', 0)}")
        self._log(f"🟢 Low: {risk_counts.get('Low', 0)}")
        self._log(f"🔐 Разрешений: {len(self.permissions)}")
        self._log(f"🌐 URL индикаторов: {len(self.network_indicators.get('url', []))}")
        self._log(f"📦 Пакет: {self.manifest_info.get('package', 'N/A')}")

    # ==================== STATISTICS ====================
    
    def _collect_statistics(self):
        java_files = list(self.decompiled_dir.rglob("*.java"))
        xml_files = list(self.decompiled_dir.rglob("*.xml"))
        dex_files = list(self.decompiled_dir.rglob("*.dex"))
        so_files = list(self.decompiled_dir.rglob("*.so"))
        
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
            "total_so_files": len(so_files),
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
            "permission_categories": {},
            "network_indicators": {k: len(v) for k, v in self.network_indicators.items()},
            "native_libs_analyzed": len(self.native_data),
            "apk_size_mb": os.path.getsize(self.apk_path) / 1024 / 1024 if self.apk_path else 0,
            "risk_score": self.risk_score,
        }
        
        perm_cats = defaultdict(int)
        for p in self.permissions:
            perm_cats[p["category"]] += 1
        self.statistics["permission_categories"] = dict(perm_cats)
        self.statistics["package_name"] = self.manifest_info.get("package", "N/A")
        self.statistics["version_name"] = self.manifest_info.get("version", "N/A")
        self.statistics["min_sdk"] = self.manifest_info.get("min_sdk", "N/A")
        self.statistics["target_sdk"] = self.manifest_info.get("target_sdk", "N/A")

    # ==================== PUBLIC ACCESSORS ====================
    
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

    def get_network_indicators(self) -> Dict[str, List[str]]:
        return dict(self.network_indicators)

    def get_native_analysis_results(self) -> Dict:
        return self.native_data

    def get_osint_data(self) -> Dict:
        return self.osint_data

    def get_risk_score(self) -> int:
        return self.risk_score