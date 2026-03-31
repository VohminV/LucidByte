import os
import sys
import subprocess
import shutil
import json
import re
import zipfile
import platform
from pathlib import Path
from typing import Dict, List, Optional, Callable
from collections import defaultdict
from datetime import datetime

try:
    import pyghidra
    import jpype
    PYGHIDRA_AVAILABLE = True
except ImportError:
    PYGHIDRA_AVAILABLE = False

try:
    from elftools.elf.elffile import ELFFile
    ELF_TOOLS_AVAILABLE = True
except ImportError:
    ELF_TOOLS_AVAILABLE = False


class AnalysisEngine:
    """
    Ядро статического анализа файлов APK (Издание PyGhidra)
    Архитектура Готовая к Производству - Python 3 Native
    """

    SYSTEM_LIBS = {
        'libc++_shared.so', 'libc++.so', 'liblog.so', 'libm.so', 'libz.so',
        'libdl.so', 'libstdc++.so', 'libssl.so', 'libcrypto.so', 'libEGL.so',
        'libGLESv1_CM.so', 'libGLESv2.so', 'libGLESv3.so', 'libjnigraphics.so',
        'libandroid.so', 'libOpenSLES.so', 'libmediandk.so', 'libvulkan.so'
    }

    SKIP_DIRS = {
        'res/drawable', 'res/layout', 'res/font', 'res/anim', 'res/color', 'res/mipmap'
    }

    NETWORK_PATTERNS = {
        'url': re.compile(r'https?://[^\s "\'<>]+', re.I),
        'ip': re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b'),
        'domain': re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?'),
        'websocket': re.compile(r'wss?://[^\s "\'<>]+', re.I),
    }

    DYNAMIC_LOAD_PATTERNS = [
        'DexClassLoader', 'PathClassLoader', 'URLClassLoader',
        'loadLibrary', 'System.load', 'System.loadLibrary',
        'Runtime.exec', 'ProcessBuilder'
    ]

    def __init__(self, temp_dir: str = "temp"):
        self.temp_dir = Path(temp_dir)
        self.decompiled_dir = self.temp_dir / "decompiled"
        self.ghidra_scripts_dir = Path(__file__).parent / "ghidra_scripts"
        self.ghidra_input_dir = self.temp_dir / "ghidra_input"
        # ✅ ДОБАВЛЕНО: Директория для отчетов анализа Ghidra
        self.ghidra_report_dir = self.temp_dir / "ghidra_reports"
        self.apk_path: Optional[Path] = None

        # ✅ ИСПРАВЛЕНО: Все переменные с корректными именами
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

        self.statistics: Dict = {}
        self.risk_score: int = 0

        self.progress_callback: Optional[Callable] = None
        self.log_callback: Optional[Callable] = None
        self.use_ghidra: bool = True
        self.ghidra_initialized: bool = False

    def set_progress_callback(self, callback: Callable[[int, str], None]):
        self.progress_callback = callback

    def set_log_callback(self, callback: Callable[[str], None]):
        self.log_callback = callback

    def enable_ghidra(self, enabled: bool = True):
        self.use_ghidra = enabled
        self._log(f"🔧 Ghidra: {'включён' if enabled else 'отключён'}")
        if enabled and not PYGHIDRA_AVAILABLE:
            self._log("⚠ PyGhidra не установлен! Выполните: pip install pyghidra")

    def _log(self, message: str):
        if self.log_callback:
            self.log_callback(message)

    def _progress(self, value: int, message: str):
        if self.progress_callback:
            self.progress_callback(value, message)

    # ==================== ARCHITECTURE DETECTION ====================

    def _get_arch_from_path(self, path: Path) -> str:
        parts = path.as_posix().split("/")
        if len(parts) >= 2:
            parent = parts[-2]
            arch_map = {
                'arm64-v8a': 'aarch64',
                'armeabi-v7a': 'arm',
                'x86_64': 'x86_64',
                'x86': 'x86',
            }
            return arch_map.get(parent, parent)
        return "unknown"

    def _get_arch_from_elf(self, path: Path) -> str:
        if not ELF_TOOLS_AVAILABLE:
            return self._get_arch_from_path(path)
        try:
            with open(path, 'rb') as file_handle:
                elf = ELFFile(file_handle)
                machine = elf.header['e_machine']
                arch_map = {
                    'EM_X86_64': 'x86_64',
                    'EM_386': 'x86',
                    'EM_ARM': 'arm',
                    'EM_AARCH64': 'aarch64',
                }
                return arch_map.get(machine, machine)
        except Exception:
            return self._get_arch_from_path(path)

    def _get_arch(self, path: Path) -> str:
        return self._get_arch_from_elf(path)

    # ==================== MAIN ANALYSIS PIPELINE ====================

    def analyze_apk(self, apk_path: str) -> bool:
        try:
            self.apk_path = Path(apk_path)
            self._log("=" * 70)
            self._log("🔍 LUCIDBYTE ANALYSIS ENGINE (Издание PyGhidra)")
            self._log("=" * 70)
            self._log(f"📁 Файл: {apk_path}")
            self._log(f"📊 Размер: {os.path.getsize(apk_path) / 1024 / 1024:.2f} Мегабайт")
            self._log(f"🔧 PyGhidra: {'доступен' if PYGHIDRA_AVAILABLE else 'НЕ доступен'}")
            self._log("=" * 70)

            if self.decompiled_dir.exists():
                shutil.rmtree(self.decompiled_dir)
            self.decompiled_dir.mkdir(parents=True, exist_ok=True)
            self.ghidra_input_dir.mkdir(parents=True, exist_ok=True)
            # ✅ ДОБАВЛЕНО: Создание директории для отчетов
            self.ghidra_report_dir.mkdir(parents=True, exist_ok=True)

            self._progress(5, "Распаковка и быстрый анализ...")
            self._extract_apk_structure()

            self._progress(15, "Анализ манифеста...")
            self._parse_manifest_fast()

            self._progress(25, "Извлечение OSINT-индикаторов...")
            self._extract_osint_resources()
            self._extract_network_indicators()

            self._progress(40, "Анализ DEX (jadx)...")
            self._analyze_dex_fast()

            if self.use_ghidra:
                if not PYGHIDRA_AVAILABLE:
                    self._log("⚠ PyGhidra не установлен, пропускаем анализ native библиотек")
                else:
                    self._progress(70, "Анализ native библиотек (PyGhidra)...")
                    self._analyze_native_pyghidra()

            self._progress(90, "Расчет риска и сбор результатов...")
            self._correlate_threats()
            self._calculate_risk_score()

            self._progress(100, "Анализ завершен")
            self._log("=" * 70)
            self._log(f"✓ АНАЛИЗ ЗАВЕРШЕН | 🎯 Оценка Риска: {self.risk_score}/100")
            self._log("=" * 70)
            self._print_summary()
            return True

        except Exception as exception:
            import traceback
            self._log(f"✗ Ошибка анализа: {str(exception)}")
            self._log(f"📋 Трассировка:\n{traceback.format_exc()}")
            return False

    # ==================== APK EXTRACTION ====================

    def _extract_apk_structure(self):
        self._log("📦 Распаковка APK...")

        with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                if any(member.startswith(skip) for skip in self.SKIP_DIRS):
                    continue
                if self._is_important_file(member):
                    try:
                        zip_ref.extract(member, self.decompiled_dir)
                    except Exception:
                        pass

        stats = self._count_extracted_files()
        self._log(f"✓ Извлечено: {stats['total']} файлов")
        if stats['so_files']:
            self._log(f"  • Native .so: {stats['so_files']}")
        if stats['dex_files']:
            self._log(f"  • DEX файлы: {stats['dex_files']}")

    def _is_important_file(self, filepath: str) -> bool:
        filepath_lower = filepath.lower()
        if any(filepath_lower.endswith(ext) for ext in [
            '.xml', '.dex', '.so', '.json', '.js', '.lua', '.py', '.txt', '.dat'
        ]):
            return True
        important_dirs = ['assets/', 'lib/', 'META-INF/', 'res/values/', 'res/raw/', 'kotlin/']
        if any(filepath_lower.startswith(directory) for directory in important_dirs):
            return True
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

    # ==================== MANIFEST ANALYSIS ====================

    def _parse_manifest_fast(self):
        manifest_path = self.decompiled_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            self._log("⚠ AndroidManifest.xml не найден")
            return

        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                content = file_handle.read()
                self.manifest_data = content
            self._parse_permissions_fast(content)
            self._parse_app_info_fast(content)
            self._log(f"✓ Манифест: {len(self.permissions)} разрешений, пакет: {self.manifest_info.get('package', 'N/A')}")
        except Exception as exception:
            self._log(f"⚠ Ошибка парсинга манифеста: {exception}")

    def _parse_permissions_fast(self, content: str):
        permissions = set()
        patterns = [
            r'android:name="(android\.permission[^ "]+)"',
            r'<uses-permission[^>]*android:name="([^ "]+)"',
            r'name="(android\.permission[^ "]+)"',
        ]
        for pattern in patterns:
            found = re.findall(pattern, content)
            permissions.update(permission for permission in found if permission.startswith('android.permission.'))

        self.permissions = []
        for permission in sorted(permissions):
            risk = self._assess_permission_risk(permission)
            category = self._get_permission_category(permission)
            self.permissions.append({"name": permission, "risk": risk, "category": category})
            if risk == "Critical":
                self.threats.append({
                    "source": "manifest", "pattern": permission, "risk": "Critical",
                    "desc": f"Опасное разрешение: {permission}", "category": "Permission"
                })

    def _parse_app_info_fast(self, content: str):
        self.manifest_info = {}
        if match := re.search(r'package="([^ "]+)"', content):
            self.manifest_info['package'] = match.group(1)
        if match := re.search(r'versionName="([^ "]+)"', content):
            self.manifest_info['version'] = match.group(1)
        if match := re.search(r'targetSdkVersion="(\d+)"', content):
            self.manifest_info['target_sdk'] = int(match.group(1))
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
        for category, keywords in categories.items():
            for keyword in keywords:
                if keyword in permission:
                    return category
        return 'OTHER'

    # ==================== OSINT RESOURCES ====================

    def _extract_osint_resources(self):
        self._log("🔍 Анализ ресурсов...")
        strings_xml = self.decompiled_dir / "res" / "values" / "strings.xml"
        if strings_xml.exists():
            self._parse_strings_xml(strings_xml)
        assets_dir = self.decompiled_dir / "assets"
        if assets_dir.exists():
            self._scan_assets(assets_dir)
        raw_dir = self.decompiled_dir / "res" / "raw"
        if raw_dir.exists():
            self._scan_raw_resources(raw_dir)
        arsc_file = self.decompiled_dir / "resources.arsc"
        if arsc_file.exists():
            self._extract_strings_from_arsc(arsc_file)
        self._log(f"✓ OSINT: {len(self.osint_data.get('urls', []))} URL, {len(self.osint_data.get('api_keys', []))} Ключи API")

    def _parse_strings_xml(self, filepath: Path):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file_handle:
                content = file_handle.read()
            strings = re.findall(r'<string[^>]*name="([^ "]+)"[^>]*>([^<]+)</string>', content)
            for name, value in strings:
                for net_type, pattern in self.NETWORK_PATTERNS.items():
                    if matches := pattern.findall(value):
                        self.network_indicators[net_type].extend(matches)
                        self.osint_data.setdefault('urls', []).extend(matches)
                if self._looks_like_api_key(value):
                    self.osint_data.setdefault('api_keys', []).append({
                        'name': name, 'value': value[:50] + '...' if len(value) > 50 else value
                    })
                suspicious = ['su', 'chmod', 'rm -rf', 'wget', 'curl', 'sh -c']
                for command in suspicious:
                    if command in value.lower():
                        self.threats.append({
                            'source': f'strings.xml:{name}', 'pattern': command, 'risk': 'High',
                            'desc': 'Подозрительная команда в ресурсах', 'category': 'Hidden_Command'
                        })
        except Exception as exception:
            self._log(f"⚠ Ошибка парсинга strings.xml: {exception}")

    def _scan_assets(self, assets_dir: Path):
        for filepath in assets_dir.rglob('*'):
            if filepath.is_file():
                try:
                    content = filepath.read_text(errors='ignore')
                    if filepath.suffix == '.json':
                        try:
                            config = json.loads(content)
                            self.osint_data.setdefault('configs', []).append({
                                'file': str(filepath.relative_to(self.decompiled_dir)),
                                'keys': list(config.keys())[:10]
                            })
                        except Exception:
                            pass
                    if filepath.suffix in ['.js', '.lua', '.py']:
                        self.osint_data.setdefault('scripts', []).append(
                            str(filepath.relative_to(self.decompiled_dir))
                        )
                    for net_type, pattern in self.NETWORK_PATTERNS.items():
                        if matches := pattern.findall(content):
                            self.network_indicators[net_type].extend(matches[:20])
                            self.osint_data.setdefault('urls', []).extend(matches[:20])
                    for dyn_pattern in self.DYNAMIC_LOAD_PATTERNS:
                        if dyn_pattern in content:
                            self.dynamic_load_calls.append({
                                'file': str(filepath.relative_to(self.decompiled_dir)),
                                'pattern': dyn_pattern, 'risk': 'High'
                            })
                except Exception:
                    continue

    def _scan_raw_resources(self, raw_dir: Path):
        for filepath in raw_dir.rglob('*'):
            if filepath.is_file():
                try:
                    content = filepath.read_text(errors='ignore')
                    for net_type, pattern in self.NETWORK_PATTERNS.items():
                        if matches := pattern.findall(content):
                            self.network_indicators[net_type].extend(matches[:10])
                except Exception:
                    try:
                        with open(filepath, 'rb') as file_handle:
                            data = file_handle.read(1024 * 1024)
                        strings = re.findall(b'[\x20-\x7E]{10,}', data)
                        for string_byte in strings[:20]:
                            decoded = string_byte.decode('ascii', errors='ignore')
                            for net_type, pattern in self.NETWORK_PATTERNS.items():
                                if matches := pattern.findall(decoded):
                                    self.network_indicators[net_type].extend(matches[:5])
                    except Exception:
                        pass

    def _extract_strings_from_arsc(self, arsc_path: Path):
        try:
            with open(arsc_path, 'rb') as file_handle:
                data = file_handle.read(2 * 1024 * 1024)
            strings = re.findall(b'(?:[\x00][\x20-\x7E]){5,}', data)
            for string_byte in strings[:50]:
                try:
                    decoded = string_byte.decode('utf-16-le', errors='ignore')
                    if any(keyword in decoded.lower() for keyword in ['http', 'api', 'key', 'token', 'secret']):
                        self.osint_data.setdefault('arsc_strings', []).append(decoded[:100])
                except Exception:
                    pass
        except Exception as exception:
            self._log(f"⚠ Ошибка чтения resources.arsc: {exception}")

    def _looks_like_api_key(self, value: str) -> bool:
        if len(value) < 20:
            return False
        key_patterns = [
            r'[A-Za-z0-9]{32,}', r'AIza[A-Za-z0-9_-]{35}',
            r'sk-[A-Za-z0-9]{48}', r'gh[pousr]_[A-Za-z0-9]{36}',
        ]
        return any(re.match(pattern, value) for pattern in key_patterns)

    def _extract_network_indicators(self):
        self._log("🔍 Поиск сетевых индикаторов...")
        for filepath in self.decompiled_dir.rglob('*'):
            if not filepath.is_file():
                continue
            if filepath.suffix in ['.png', '.jpg', '.gif', '.webp', '.so', '.dex']:
                continue
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    content = file_handle.read(512 * 1024)
                for net_type, pattern in self.NETWORK_PATTERNS.items():
                    if matches := pattern.findall(content):
                        unique = list(set(matches))[:10]
                        self.network_indicators[net_type].extend(unique)
            except Exception:
                continue
        for net_type in self.network_indicators:
            self.network_indicators[net_type] = list(set(self.network_indicators[net_type]))[:50]
        total_urls = sum(len(value_list) for value_list in self.network_indicators.values())
        self._log(f"✓ Найдено сетевых индикаторов: {total_urls}")

    # ==================== DEX ANALYSIS VIA JADX ====================

    def _analyze_dex_fast(self):
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

        if is_windows and is_batch:
            command = f'"{jadx_cmd}" -d "{output_dir}" -j 4 --no-replace-consts --show-bad-code --no-inline-methods "{input_file}"'
            environment = os.environ.copy()
            environment['JAVA_OPTS'] = '-Xmx4G'
            try:
                subprocess.run(command, shell=True, capture_output=True, text=True,
                               timeout=900, encoding='utf-8', errors='ignore', env=environment)
            except Exception as exception:
                self._log(f"✗ Ошибка jadx: {exception}")
                return
        else:
            command = [jadx_cmd, "-d", output_dir, "-j", "4", "--no-replace-consts",
                       "--show-bad-code", "--no-inline-methods", input_file]
            environment = os.environ.copy()
            environment['JAVA_OPTS'] = '-Xmx4G'
            try:
                subprocess.run(command, capture_output=True, text=True,
                               timeout=900, encoding='utf-8', errors='ignore', env=environment)
            except Exception as exception:
                self._log(f"✗ Ошибка jadx: {exception}")
                return

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
            if found := shutil.which(name):
                self._log(f"✓ jadx найден в PATH: {found}")
                return found
        jadx_paths = [r"C:\jadx\bin\jadx.bat", r"C:\jadx\bin\jadx.exe", r"C:\Program Files\jadx\bin\jadx.bat"]
        for path in jadx_paths:
            if os.path.exists(path):
                self._log(f"✓ jadx найден: {path}")
                return path
        self._log("✗ jadx не найден")
        return None

    def _scan_java_for_threats(self, java_files: List[Path]):
        """Основной метод сканирования Java файлов на угрозы"""
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
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    content = file_handle.read()

                for threat in threat_patterns:
                    if threat["pattern"] in content:
                        relative_path = str(file_path.relative_to(self.decompiled_dir))
                        self.threats.append({
                            "file": relative_path, "pattern": threat["pattern"],
                            "risk": threat["risk"], "desc": threat["desc"],
                            "category": threat["category"]
                        })
            except Exception:
                continue

        unique = []
        seen = set()
        for threat in self.threats:
            key = (threat["file"], threat["pattern"])
            if key not in seen:
                seen.add(key)
                unique.append(threat)
        self.threats = unique
        self._log(f"✓ Найдено уникальных угроз: {len(self.threats):,}")

    # ==================== NATIVE LIBS ANALYSIS (PYGHIDRA) ====================

    def _initialize_ghidra_environment(self):
        if self.ghidra_initialized:
            return
        if not PYGHIDRA_AVAILABLE:
            raise ImportError("PyGhidra не установлен")
        if not os.environ.get('JAVA_HOME'):
            self._log("⚠ Переменная окружения JAVA_HOME не установлена.")
        self._log("🔧 Инициализация PyGhidra...")
        try:
            if pyghidra.started():
                self._log("✓ Виртуальная Машина Java уже запущена")
                self.ghidra_initialized = True
                return
            pyghidra.start()
            self.ghidra_initialized = True
            self._log("✓ PyGhidra успешно инициализирован")
        except Exception as exception:
            self._log(f"✗ Ошибка инициализации PyGhidra: {exception}")
            raise

    def _analyze_native_pyghidra(self):
        if not PYGHIDRA_AVAILABLE:
            self._log("⚠ PyGhidra не установлен")
            return

        so_files = list(self.decompiled_dir.rglob("*.so"))
        if not so_files:
            self._log("ℹ Native библиотеки не найдены")
            return

        target_libs = [file for file in so_files if self._should_analyze_library(file.name)]
        if not target_libs:
            self._log("✓ Все .so библиотеки пропущены (системные)")
            return

        self._log(f"📦 К анализу: {len(target_libs)} из {len(so_files)} библиотек")

        try:
            self._initialize_ghidra_environment()
        except Exception as exception:
            self._log(f"✗ Не удалось инициализировать окружение Ghidra: {exception}")
            self.ghidra_initialized = False
            return

        script_dir = Path(__file__).parent.resolve()
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))

        for idx, lib_path in enumerate(target_libs):
            lib_name = lib_path.name
            arch = self._get_arch(lib_path)
            # ✅ ИСПРАВЛЕНО: Сохранение в специализированную директорию отчетов
            output_json = str((self.ghidra_report_dir / f"ghidra_{lib_name}.json").resolve())

            self._log(f"[{idx + 1}/{len(target_libs)}] 🔄 Анализ: {lib_name} (arch: {arch})")
            self._progress(50 + idx * 40 // len(target_libs), f"Native: {lib_name}")

            try:
                from native_analyzer import analyze_native_library
                results = analyze_native_library(str(lib_path.resolve()), output_json, jvm_already_started=True)
                self._parse_native_json(output_json, lib_name)
                self._log(f"✓ Завершено: {lib_name} ({os.path.getsize(output_json) / 1024:.1f} Килобайт)")
            except Exception as exception:
                self._log(f"✗ Ошибка {lib_name}: {exception}")
                import traceback
                self._log(f"📋 Трассировка:\n{traceback.format_exc()}")

    def _should_analyze_library(self, lib_name: str) -> bool:
        if lib_name in self.SYSTEM_LIBS:
            self._log(f"⊘ Пропущена системная: {lib_name}")
            return False
        self._log(f"✓ Кастомная библиотека: {lib_name}")
        return True

    def _parse_native_json(self, json_path: str, lib_name: str):
        try:
            with open(json_path, "r", encoding="utf-8") as file_handle:
                data = json.load(file_handle)

            for imp in data.get("imports", []):
                if imp.get("risk") in ["Critical", "High"]:
                    self.threats.append({
                        "file": f"native:{lib_name}",
                        "pattern": imp["name"],
                        "risk": imp["risk"],
                        "desc": f"Опасный native импорт: {imp['name']}",
                        "category": "Native_Import"
                    })

            for jni in data.get("jni_functions", []):
                self.threats.append({
                    "file": f"native:{lib_name}",
                    "pattern": jni["name"],
                    "risk": "Medium",
                    "desc": f"JNI entry point: {jni['name']}",
                    "category": "Native_JNI"
                })

            for susp in data.get("suspicious_names", []):
                self.threats.append({
                    "file": f"native:{lib_name}",
                    "pattern": susp["keyword"],
                    "risk": susp["risk"],
                    "desc": f"Подозрительная функция: {susp['function']}",
                    "category": "Native_Suspicious"
                })

            self.native_data[lib_name] = data
            self._log(f"✓ {lib_name}: {len(data.get('imports', []))} imports, {len(data.get('jni_functions', []))} JNI")
        except Exception as exception:
            self._log(f"⚠ Ошибка парсинга {json_path}: {exception}")

    # ==================== THREAT CORRELATION & RISK SCORE ====================

    def _correlate_threats(self):
        for url in self.network_indicators.get('url', []):
            if any(keyword in url.lower() for keyword in ['malware', 'evil', 'hack', 'exploit']):
                self.threats.append({
                    "source": "network_indicator", "pattern": url, "risk": "High",
                    "desc": f"Подозрительный URL: {url}", "category": "Network"
                })
        for dyn in self.dynamic_load_calls:
            self.threats.append({
                "source": dyn["file"], "pattern": dyn["pattern"], "risk": dyn["risk"],
                "desc": f"Динамическая загрузка: {dyn['pattern']}", "category": "Code_Injection"
            })
        unique = []
        seen = set()
        for threat in self.threats:
            key = (threat.get("file", threat.get("source")), threat["pattern"])
            if key not in seen:
                seen.add(key)
                unique.append(threat)
        self.threats = unique

    def _calculate_risk_score(self):
        score = 0
        score += sum(1 for threat in self.threats if threat["risk"] == "Critical") * 15
        score += sum(1 for threat in self.threats if threat["risk"] == "High") * 8
        score += sum(1 for threat in self.threats if threat["risk"] == "Medium") * 3
        score += sum(1 for threat in self.threats if threat["risk"] == "Low") * 1
        dangerous_perms = sum(1 for permission in self.permissions if permission["risk"] in ["Critical", "High"])
        score += dangerous_perms * 5
        if self.ghidra_initialized:
            native_threats = sum(1 for threat in self.threats if threat["category"].startswith("Native_"))
            score += native_threats * 10
        suspicious_urls = sum(1 for url in self.network_indicators.get('url', [])
                              if any(keyword in url.lower() for keyword in ['malware', 'evil', 'hack']))
        score += suspicious_urls * 12
        score += len(self.dynamic_load_calls) * 10
        self.risk_score = min(score, 100)
        self._log(f"🎯 Оценка Риска: {self.risk_score}/100")

    def _print_summary(self):
        risk_counts = defaultdict(int)
        for threat in self.threats:
            risk_counts[threat["risk"]] += 1
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

    # ==================== PUBLIC ACCESSORS ====================

    def get_decompiled_files(self) -> List[Path]:
        if not self.decompiled_dir.exists():
            return []
        return sorted(list(self.decompiled_dir.rglob("*.java")))

    def get_file_content(self, file_path: str) -> str:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                return file_handle.read()
        except Exception as exception:
            return f"Ошибка чтения: {exception}"

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
        return [threat for threat in self.threats if threat["risk"] == "Critical"]

    def get_dangerous_permissions(self) -> List[Dict]:
        return [permission for permission in self.permissions if permission["risk"] in ["Critical", "High"]]

    def get_network_indicators(self) -> Dict[str, List[str]]:
        return dict(self.network_indicators)

    def get_native_analysis_results(self) -> Dict:
        return self.native_data

    def get_osint_data(self) -> Dict:
        return self.osint_data

    def get_risk_score(self) -> int:
        return self.risk_score

    # ==================== NEW METHODS FOR WORKER ====================

    def get_call_graph_data(self) -> Dict[str, List[str]]:
        """
        Построение упрощенного графа зависимостей классов на основе декомпилированных Java файлов.
        Возвращает словарь {ИмяКласса: [СписокИспользуемыхКлассов]}
        """
        graph_data = defaultdict(list)
        java_files = list(self.decompiled_dir.rglob("*.java"))
        
        # Ограничим количество файлов для производительности
        if len(java_files) > 200:
            java_files = java_files[:200]
            
        known_classes = set()
        # Сначала соберем все известные классы
        for file_path in java_files:
            class_name = file_path.stem
            known_classes.add(class_name)
            
        # Теперь найдем связи
        for file_path in java_files:
            source_class = file_path.stem
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Ищем упоминания других классов (упрощенно по именам)
                for target_class in known_classes:
                    if target_class != source_class and target_class in content:
                        # Проверка на слово целиком, чтобы избежать частичных совпадений
                        if re.search(r'\b' + re.escape(target_class) + r'\b', content):
                            if target_class not in graph_data[source_class]:
                                graph_data[source_class].append(target_class)
                                # Ограничим количество связей для одного узла
                                if len(graph_data[source_class]) >= 10:
                                    break
            except Exception:
                continue
                
        return dict(graph_data)

    def save_consolidated_report(self, filename_prefix: str) -> Path:
        """
        Сохранение консолидированного отчета о анализе в формате JSON.
        """
        report_data = {
            "manifest_info": self.manifest_info,
            "permissions": self.permissions,
            "threats": self.threats,
            "network_indicators": dict(self.network_indicators),
            "osint_data": self.osint_data,
            "native_data": self.native_data,
            "risk_score": self.risk_score,
            "statistics": self.statistics,
            "generated_at": datetime.now().isoformat()
        }
        
        report_path = self.ghidra_report_dir / f"{filename_prefix}_consolidated.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        return report_path