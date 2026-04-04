import os
import sys
import subprocess
import shutil
import json
import re
import zipfile
import platform
import math
import gc
import logging
from pathlib import Path
from typing import Dict, List, Optional, Callable, Set, Tuple
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

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

try:
    from .signature_manager import SignatureManager
    from .signature_scanner import SignatureScanner, SignatureScanResult
    SIGNATURE_MODULES_AVAILABLE = True
except ImportError as exception:
    SIGNATURE_MODULES_AVAILABLE = False
    logger.warning(f"Не удалось импортировать сигнатурные модули: {exception}. Сигнатурный анализ отключён.")

try:
    from .native_analyzer import analyze_native_library
    NATIVE_ANALYZER_AVAILABLE = True
except ImportError:
    NATIVE_ANALYZER_AVAILABLE = False


class WhitelistFilter:
    """Фильтр ложных срабатываний для легитимных компонентов"""
    LEGITIMATE_PACKAGES = {
        'com.google.', 'androidx.', 'org.jetbrains.', 'com.facebook.',
        'com.amazonaws.', 'io.firebase.', 'com.crashlytics.', 'com.microsoft.',
        'com.squareup.okhttp', 'com.google.gson', 'com.android.volley'
    }
    LEGITIMATE_CLASSES = {
        'Gson', 'OkHttpClient', 'Firebase', 'Crashlytics', 'Fabric',
        'AdMob', 'PlayServices', 'SupportFragment', 'AppCompatActivity'
    }

    @classmethod
    def is_legitimate_package(cls, package_name: str) -> bool:
        if not package_name:
            return False
        for prefix in cls.LEGITIMATE_PACKAGES:
            if package_name.startswith(prefix):
                return True
        return False

    @classmethod
    def is_legitimate_class(cls, class_name: str) -> bool:
        for legit in cls.LEGITIMATE_CLASSES:
            if legit in class_name:
                return True
        return False


class CertificateAnalyzer:
    """Анализ сертификатов подписи пакета приложения"""
    def __init__(self, application_package_path: Path):
        self.application_package_path = application_package_path
        self.certificate_info: Dict = {}

    def analyze(self) -> Dict:
        try:
            with zipfile.ZipFile(self.application_package_path, 'r') as zip_reference:
                meta_inf_files = [file_path for file_path in zip_reference.namelist()
                                  if file_path.startswith('META-INF/') and
                                  (file_path.endswith('.RSA') or file_path.endswith('.DSA') or file_path.endswith('.EC'))]
                if not meta_inf_files:
                    self.certificate_info['signed'] = False
                    self.certificate_info['risk'] = 'High'
                    self.certificate_info['reason'] = 'Отсутствие цифровой подписи'
                    return self.certificate_info

                self.certificate_info['signed'] = True
                certificate_name = meta_inf_files[0].split('/')[-1]
                if 'debug' in certificate_name.lower() or 'androiddebugkey' in certificate_name.lower():
                    self.certificate_info['debug_cert'] = True
                    self.certificate_info['risk'] = 'Medium'
                    self.certificate_info['reason'] = 'Использован отладочный сертификат'
                else:
                    self.certificate_info['debug_cert'] = False
                    self.certificate_info['risk'] = 'Low'
                    self.certificate_info['reason'] = 'Стандартный сертификат разработчика'
        except Exception as exception:
            self.certificate_info['error'] = str(exception)
            self.certificate_info['risk'] = 'Unknown'
        return self.certificate_info


class EntropyCalculator:
    """Вычисление энтропии для обнаружения упаковки и шифрования"""
    @staticmethod
    def calculate(data: bytes) -> float:
        if not data:
            return 0.0
        frequency = defaultdict(int)
        for byte_value in data:
            frequency[byte_value] += 1
        entropy = 0.0
        data_length = len(data)
        for count in frequency.values():
            if count > 0:
                probability = count / data_length
                entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def is_packed(entropy_value: float) -> bool:
        return entropy_value > 7.0


class MitreAttackMobileMapper:
    """Сопоставление обнаруженных угроз с таксономией Mitre Att And Ck для мобильных систем"""
    TECHNIQUE_MAPPING = {
        'Data_Collection': 'T1415',
        'Data_Exfiltration': 'T1416',
        'DynamicLoading': 'T1641',
        'Native_AntiDebug': 'T1620',
        'Native_JNI': 'T1622',
        'Code_Execution': 'T1414',
        'Permission': 'T1438',
        'Certificate': 'T1550',
        'Behavioral_Chain': 'T1480',
        'Hidden_Command': 'T1610',
        'Packing': 'T1513',
        'Network_Exfiltration': 'T1416',
        'Cryptography': 'T1573',
        'Anti_emulator': 'T1612',
        'Anti_debugger': 'T1620'
    }

    @classmethod
    def map_category_to_technique(cls, category: str) -> Optional[str]:
        return cls.TECHNIQUE_MAPPING.get(category)


class PrivacyComplianceAnalyzer:
    """Анализ соответствия принципам конфиденциальности и минимизации сбора данных"""
    SENSITIVE_SOURCES = {'getDeviceId', 'getImei', 'getLastKnownLocation', 'getContacts', 'READ_SMS', 'RECORD_AUDIO'}
    DECLARED_PURPOSES = {'INTERNET': ['Network', 'Analytics'], 'ACCESS_FINE_LOCATION': ['Location'], 'CAMERA': ['Camera']}

    @classmethod
    def analyze_data_minimization(cls, taint_flows: List[Dict], declared_permissions: List[Dict]) -> List[Dict]:
        violations = []
        declared_categories = set()
        for permission in declared_permissions:
            category = permission.get('category')
            if category:
                declared_categories.add(category)

        for flow in taint_flows:
            source = flow.get('source', '')
            sink = flow.get('sink', '')
            if source in cls.SENSITIVE_SOURCES and sink not in ['SharedPreferences', 'FileOutputStream']:
                source_category = None
                for perm in declared_permissions:
                    if perm.get('name', '').replace('android.permission.', '') == source or perm.get('category') == source:
                        source_category = perm.get('category')
                        break
                if source_category and source_category not in declared_categories:
                    violations.append({
                        'type': 'undeclared_data_usage',
                        'source': source,
                        'sink': sink,
                        'description': f"Сбор данных из источника {source} без явного объявления в разрешении {source_category}",
                        'severity': 'High'
                    })
        return violations


class UnpackingHeuristicDetector:
    """Эвристическое обнаружение признаков упаковки и обфускации кода"""
    PACKER_SIGNATURES = ['DexClassLoader', 'loadClass', 'defineClass', 'BaseDexClassLoader', 'InMemoryDexClassLoader']
    OBFUSCATION_PATTERNS = re.compile(r'(?:a|b|c|d|e|f|g)\d+\s*()')

    @classmethod
    def detect_packer_indicators(cls, java_files: List[Path], entropy_info: Dict) -> List[Dict]:
        indicators = []
        high_entropy_count = len(entropy_info.get('high_entropy_files', []))
        if high_entropy_count > 0:
            indicators.append({'type': 'high_entropy_files', 'count': high_entropy_count, 'severity': 'Medium'})

        for file_path in java_files[:100]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    content = file_handle.read()
                for signature in cls.PACKER_SIGNATURES:
                    if signature in content:
                        indicators.append({'type': 'packer_loader', 'signature': signature, 'file': str(file_path.name), 'severity': 'High'})
                if cls.OBFUSCATION_PATTERNS.search(content):
                    indicators.append({'type': 'obfuscation_detected', 'file': str(file_path.name), 'severity': 'Medium'})
            except Exception:
                continue
        return indicators


class DynamicAnalysisPreparer:
    """Подготовка конфигурации для последующего динамического анализа в эмулированной среде"""
    def __init__(self):
        self.frida_hooks: List[str] = []
        self.expected_syscalls: List[str] = []
        self.target_endpoints: List[str] = []

    def prepare_runtime_hooks(self, threats: List[Dict], network_indicators: Dict) -> Dict:
        for threat in threats:
            category = threat.get('category', '')
            if category == 'Native_AntiDebug':
                self.frida_hooks.append('Interceptor.attach(Module.getExportByName(null, "ptrace"), {onEnter: function(args) { console.log("ptrace intercepted"); }});')
            elif category == 'Data_Exfiltration':
                self.frida_hooks.append('Interceptor.attach(Module.getExportByName("libc.so", "sendto"), {onEnter: function(args) { console.log("sendto called"); }});')
        
        self.expected_syscalls = list(set([threat.get('pattern', '') for threat in threats if 'syscall' in threat.get('category', '').lower()]))
        self.target_endpoints = network_indicators.get('url', []) + network_indicators.get('ip', [])
        
        return {
            'frida_hooks': self.frida_hooks,
            'target_endpoints': self.target_endpoints,
            'expected_syscalls': self.expected_syscalls,
            'emulation_profile': 'malware_sandbox_heavy_monitoring'
        }


class AnalysisEngine:
    """Ядро статического анализа файлов с расширенными модулями оценки рисков и таксономий"""
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
        'url': re.compile(r'https?://[^\s"\'><]+', re.I),
        'ip': re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b'),
        'domain': re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?'),
        'websocket': re.compile(r'wss?://[^\s"\'><]+', re.I),
    }
    TAINT_SOURCES = {
        'getDeviceId', 'getImei', 'getSubscriberId', 'getSimSerialNumber',
        'getLastKnownLocation', 'requestLocationUpdates', 'query', 'getContacts',
        'getSystemService', 'getTelephonyManager', 'LocationManager', 'ContentResolver',
        'getAccountId', 'getAuthToken'
    }
    TAINT_SINKS = {
        'sendto', 'connect', 'HttpURLConnection', 'URL', 'Socket', 'DatagramSocket',
        'write', 'FileOutputStream', 'SharedPreferences', 'exec', 'dlopen', 'JNI',
        'System.loadLibrary', 'System.load', 'Runtime.getRuntime().exec', 'ProcessBuilder'
    }
    CRITICAL_FLOW_PATTERNS = [
        r'getDeviceId.*(?:encrypt|cipher|digest|base64).*sendto|HttpURLConnection|Socket|write',
        r'getLocation.*(?:encrypt|cipher|pack|compress).*connect|send',
        r'getContacts.*(?:encrypt|zip|base64).*HttpURLConnection|Socket',
        r'getImei.*(?:aes|rsa|des).*write|sendto'
    ]
    WEAK_CRYPTO_ALGORITHMS = ['AES/ECB', 'DES/ECB', 'DESede/ECB', 'Blowfish/ECB', 'RC4', 'MD5', 'SHA1']
    CRYPTO_PATTERNS = {
        'cipher_init': re.compile(r'Cipher\.getInstance\(["\']([^"\']+)["\']\)', re.I),
        'iv_param': re.compile(r'IvParameterSpec\s*\(.*byte\s*\[\].*\{(.*?)\}.*\)', re.S),
        'static_key': re.compile(r'(?:byte\s*\[\]\s*\w+\s*=\s*new\s*byte\s*\[\].*\{(.*?)\})', re.S)
    }
    ANTI_ANALYSIS_PATTERNS = {
        'emulator': ['ro.product.model', 'ro.hardware', 'goldfish', 'genymotion', 'isEmulator', 'android.test', 'sdk.google'],
        'debugger': ['isDebuggerConnected', 'waitForDebugger', 'Debug.isDebuggerConnected', 'ptrace', 'android_debuggable'],
        'timing': ['currentTimeMillis', 'nanoTime', 'elapsedRealtime', 'System.nanoTime'],
        'obfuscation': ['Class.forName', 'Method.invoke', 'getDeclaredMethod', 'getDeclaredField']
    }
    DYNAMIC_LOAD_PATTERNS = [
        'DexClassLoader', 'PathClassLoader', 'URLClassLoader', 'InMemoryDexClassLoader',
        'loadLibrary', 'System.load', 'System.loadLibrary',
        'Runtime.exec', 'ProcessBuilder'
    ]
    BEHAVIOR_PATTERNS = {
        'sms_intercept': ['SmsManager', 'receiveSms', 'READ_SMS'],
        'overlay_attack': ['SYSTEM_ALERT_WINDOW', 'TYPE_PHONE', 'FLAG_LAYOUT_NO_LIMITS'],
        'accessibility_abuse': ['AccessibilityService', 'onAccessibilityEvent', 'BIND_ACCESSIBILITY_SERVICE'],
        'banking_trojan': ['keyguard', 'lockscreen', 'overlay', 'bank', 'payment'],
        'reflection_obfuscation': ['Class.forName', 'Method.invoke', 'getDeclaredMethod']
    }

    def __init__(self, temporary_directory: str = "temporary"):
        self.temporary_directory = Path(temporary_directory)
        self.decompiled_directory = self.temporary_directory / "decompiled"
        self.ghidra_scripts_directory = Path(__file__).parent / "ghidra_scripts"
        self.ghidra_input_directory = self.temporary_directory / "ghidra_input"
        self.ghidra_report_directory = self.temporary_directory / "ghidra_reports"
        self.application_package_path: Optional[Path] = None

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
        self.certificate_info: Dict = {}
        self.entropy_info: Dict = {}
        self.statistics: Dict = {}
        self.risk_score: int = 0
        self.call_graph: Dict[str, List[str]] = {}
        self.taint_flows: List[Dict] = []
        self.behavioral_chains: List[Dict] = []
        self.crypto_findings: List[Dict] = []
        self.anti_analysis_findings: List[Dict] = []
        self.structure_findings: List[Dict] = []
        self.unpacking_indicators: List[Dict] = []
        self.privacy_violations: List[Dict] = []
        self.dynamic_analysis_config: Dict = {}
        self.ml_features: Dict[str, float] = {}

        self.progress_callback: Optional[Callable] = None
        self.log_callback: Optional[Callable] = None
        self.use_ghidra: bool = True
        self.ghidra_initialized: bool = False
        self.resources_cleaned: bool = False
        
        if SIGNATURE_MODULES_AVAILABLE:
            self.signature_manager: Optional[SignatureManager] = SignatureManager()
            self.signature_scanner: Optional[SignatureScanner] = SignatureScanner(self.signature_manager)
        else:
            self.signature_manager = None
            self.signature_scanner = None

    def set_progress_callback(self, callback: Callable[[int, str], None]):
        self.progress_callback = callback

    def set_log_callback(self, callback: Callable[[str], None]):
        self.log_callback = callback

    def enable_ghidra(self, enabled: bool = True):
        self.use_ghidra = enabled
        self._log(f"Модуль анализа машинного кода включён при заданном параметре {enabled}")
        if enabled and not PYGHIDRA_AVAILABLE:
            self._log("Модуль анализа машинного кода не установлен. Выполните установку пакета.")

    def _log(self, message: str):
        if self.log_callback:
            self.log_callback(message)

    def _progress(self, value: int, message: str):
        if self.progress_callback:
            self.progress_callback(value, message)

    def _locate_jadx_executable(self) -> Optional[str]:
        """Поиск исполняемого файла инструмента декомпиляции в системном окружении"""
        candidates = ["jadx", "jadx.bat", "jadx.cmd"]
        for candidate in candidates:
            try:
                subprocess.run(
                    [candidate, "--version"],
                    capture_output=True,
                    check=True,
                    timeout=10,
                    shell=False
                )
                return candidate
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                continue
        return None

    def _decompile_with_jadx(self) -> bool:
        """Декомпиляция байт-кода приложения в читаемый исходный код на языке программирования Java"""
        jadx_executable = self._locate_jadx_executable()
        if not jadx_executable:
            self._log("Инструмент автоматической декомпиляции не обнаружен в системном пути.")
            self._log("Необходимо загрузить актуальную версию инструмента и добавить каталог bin в переменную окружения PATH.")
            return False

        output_directory = self.decompiled_directory / "jadx_sources"
        if output_directory.exists():
            try:
                shutil.rmtree(output_directory)
            except Exception:
                pass
        output_directory.mkdir(parents=True, exist_ok=True)

        command_line = [
            jadx_executable,
            "-d", str(output_directory.absolute()),
            "--deobf",
            "--show-bad-code",
            "--no-imports",
            "--no-debug-info",
            "--escape-unicode",
            str(self.application_package_path.absolute())
        ]

        self._log(f"Запуск внешней процедуры декомпиляции: {' '.join(command_line)}")
        try:
            process = subprocess.run(
                command_line,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=900,
                shell=False
            )

            raw_output = process.stdout
            try:
                output_text = raw_output.decode('utf-8', errors='replace')
            except Exception:
                output_text = raw_output.decode('cp866', errors='replace')
            except Exception:
                output_text = raw_output.decode('cp1251', errors='replace')

            if output_text.strip():
                for line in output_text.splitlines():
                    if line.strip():
                        self._log(f"[ДЕКОМПИЛЯТОР] {line.strip()}")

            # Проверка фактического результата работы инструмента по количеству созданных файлов
            generated_java_files = len(list(output_directory.rglob("*.java")))

            if process.returncode == 0:
                self._log(f"Декомпиляция успешно завершена. Получено файлов исходного кода: {generated_java_files}")
                return True
            elif generated_java_files > 0:
                self._log(f"Декомпиляция завершена с частичными ошибками (код возврата: {process.returncode}).")
                self._log(f"Успешно извлечено {generated_java_files} файлов исходного кода. Анализ будет продолжен на основании доступных данных.")
                return True
            else:
                self._log(f"Процедура декомпиляции завершилась неудачно (код возврата: {process.returncode}). Исходные файлы не сгенерированы.")
                return False

        except subprocess.TimeoutExpired:
            self._log("Превышен допустимый лимит времени выполнения процедуры декомпиляции.")
            return False
        except Exception as execution_exception:
            self._log(f"Непредвиденная ошибка при вызове внешнего инструмента: {execution_exception}")
            return False

    def cleanup_resources(self):
        """Освобождение вычислительных ресурсов и временных файлов"""
        if self.resources_cleaned:
            return
        if self.decompiled_directory.exists():
            try:
                shutil.rmtree(self.decompiled_directory)
            except Exception:
                pass
        if self.ghidra_input_directory.exists():
            try:
                shutil.rmtree(self.ghidra_input_directory)
            except Exception:
                pass
        if self.ghidra_report_directory.exists():
            try:
                shutil.rmtree(self.ghidra_report_directory)
            except Exception:
                pass
        gc.collect()
        self.resources_cleaned = True

    def __del__(self):
        self.cleanup_resources()

    def _get_arch_from_path(self, path: Path) -> str:
        parts = path.as_posix().split("/")
        if len(parts) >= 2:
            parent = parts[-2]
            architecture_mapping = {
                'arm64-v8a': 'aarch64', 'armeabi-v7a': 'arm',
                'x86_64': 'x86_64', 'x86': 'x86',
            }
            return architecture_mapping.get(parent, parent)
        return "unknown"

    def _get_arch_from_elf(self, path: Path) -> str:
        if not ELF_TOOLS_AVAILABLE:
            return self._get_arch_from_path(path)
        try:
            with open(path, 'rb') as file_handle:
                elf = ELFFile(file_handle)
                machine = elf.header['e_machine']
                architecture_mapping = {
                    'EM_X86_64': 'x86_64', 'EM_386': 'x86',
                    'EM_ARM': 'arm', 'EM_AARCH64': 'aarch64',
                }
                return architecture_mapping.get(machine, machine)
        except Exception:
            return self._get_arch_from_path(path)

    def _get_architecture(self, path: Path) -> str:
        return self._get_arch_from_elf(path)

    def analyze_application_package(self, application_package_path: str) -> bool:
        try:
            self.application_package_path = Path(application_package_path)
            self._log("=" * 70)
            self._log("Аналитический Движок Для Статического Анализа")
            self._log("=" * 70)
            self._log(f"Целевой файл: {application_package_path}")
            self._log(f"Размер файла: {os.path.getsize(application_package_path) / 1024 / 1024:.2f} Мегабайт")
            self._log(f"Модуль анализа машинного кода: доступен, если {PYGHIDRA_AVAILABLE}")
            self._log(f"Модуль сигнатурного сканирования: доступен, если {SIGNATURE_MODULES_AVAILABLE}")
            self._log("=" * 70)

            if self.decompiled_directory.exists():
                shutil.rmtree(self.decompiled_directory)
            self.decompiled_directory.mkdir(parents=True, exist_ok=True)
            self.ghidra_input_directory.mkdir(parents=True, exist_ok=True)
            self.ghidra_report_directory.mkdir(parents=True, exist_ok=True)

            self._progress(5, "Выполняется сигнатурная проверка...")
            signature_threat_detected = self._perform_signature_scan()
            if signature_threat_detected:
                self._log("Обнаружена известная угроза по сигнатуре. Анализ прекращён.")
                self._progress(100, "Анализ завершен. Совпадение по сигнатуре.")
                self._calculate_weighted_risk()
                self._print_summary()
                return True

            self._progress(15, "Распаковка структуры и быстрый анализ...")
            self._extract_package_structure()

            self._progress(20, "Декомпиляция байт-кода в исходный код...")
            jadx_success = self._decompile_with_jadx()
            if not jadx_success:
                self._log("Продолжение анализа без декомпилированных исходных файлов.")

            self._progress(30, "Анализ манифеста приложения...")
            self._parse_manifest_fast()

            self._progress(40, "Извлечение индикаторов открытой разведки...")
            self._extract_open_source_intelligence_resources()

            self._progress(50, "Расширенный анализ байт-кода и исходного кода...")
            self._analyze_bytecode_advanced()

            self._progress(60, "Анализ криптографических реализаций...")
            self._analyze_cryptography()

            self._progress(65, "Анализ защит от отладки и эмуляции...")
            self._analyze_anti_analysis()

            self._progress(70, "Анализ сетевой разведки...")
            self._extract_network_indicators()
            self._analyze_network_intelligence()

            self._progress(75, "Анализ энтропии и упаковка кода...")
            self._analyze_entropy()
            self.unpacking_indicators = UnpackingHeuristicDetector.detect_packer_indicators(
                list(self.decompiled_directory.rglob("*.java")), self.entropy_info
            )

            self._progress(80, "Анализ сертификата...")
            self._analyze_certificate()

            self._progress(85, "Анализ потоков данных...")
            self._perform_taint_analysis()
            self.privacy_violations = PrivacyComplianceAnalyzer.analyze_data_minimization(
                self.taint_flows, self.permissions
            )

            if self.use_ghidra:
                if not PYGHIDRA_AVAILABLE:
                    self._log("Модуль анализа машинного кода не установлен, пропускаем анализ собственных библиотек")
                else:
                    self._progress(90, "Анализ собственных библиотек...")
                    self._analyze_native_libraries()

            self._progress(95, "Поиск поведенческих цепочек...")
            self._detect_behavioral_chains()

            self._progress(97, "Подготовка к динамическому анализу...")
            self.dynamic_analysis_config = DynamicAnalysisPreparer().prepare_runtime_hooks(self.threats, self.network_indicators)

            self._progress(98, "Извлечение признаков для машинного обучения...")
            self.ml_features = self.extract_machine_learning_features()

            self._progress(99, "Расчет взвешенного риска и сбор результатов...")
            self._correlate_threats()
            self._build_call_graph()
            self._calculate_weighted_risk()

            self._progress(100, "Анализ завершен")
            self._log("=" * 70)
            self._log(f"АНАЛИЗ ЗАВЕРШЕН. Оценка Риска: {self.risk_score} из 100")
            self._log("=" * 70)
            self._print_summary()
            return True

        except Exception as exception:
            import traceback
            self._log(f"Ошибка анализа: {str(exception)}")
            self._log(f"Трассировка выполнения:\n{traceback.format_exc()}")
            return False

    def _analyze_native_libraries(self) -> None:
        """Анализ собственных бинарных библиотек с использованием модуля глубокого анализа машинного кода"""
        try:
            from .native_analyzer import analyze_native_library
        except ImportError as import_exception:
            self._log(f"Не удалось импортировать модуль анализа бинарных библиотек: {import_exception}")
            return

        native_files = list(self.decompiled_directory.rglob("*.so"))
        if not native_files:
            self._log("Собственные бинарные библиотеки не обнаружены в структуре приложения.")
            return

        total_count = len(native_files)
        self._log(f"Начало анализа собственных бинарных библиотек. Количество файлов: {total_count}")

        for index, library_path in enumerate(native_files, 1):
            progress_offset = 90 + int((index / total_count) * 5)
            
            if library_path.name in self.SYSTEM_LIBS:
                self._log(f"Пропуск стандартной системной библиотеки: {library_path.name}")
                continue

            self._progress(progress_offset, f"Обработка бинарной библиотеки {index} из {total_count}")
            self._log(f"Запуск глубокого анализа для: {library_path.name}")

            try:
                report_filename = f"{library_path.stem}_native_analysis_result.json"
                report_full_path = self.ghidra_report_directory / report_filename

                result_data = analyze_native_library(
                    lib_path=str(library_path),
                    output_json=str(report_full_path),
                    jvm_already_started=(index > 1)
                )

                architecture = self._get_architecture(library_path)
                self.native_data[library_path.name] = {
                    "architecture": architecture,
                    "file_path": str(library_path),
                    "analysis_report_path": str(report_full_path),
                    "analysis_results": result_data
                }

                for syscall_record in result_data.get("syscalls", []):
                    self.threats.append({
                        "source": "native_library",
                        "pattern": syscall_record["name"],
                        "risk": syscall_record["risk"],
                        "desc": f"Обнаружен системный вызов повышенной опасности: {syscall_record['name']} в библиотеке {library_path.name}",
                        "category": "Native_Syscall"
                    })

                for anti_debug_record in result_data.get("anti_debug", []):
                    self.threats.append({
                        "source": "native_library",
                        "pattern": anti_debug_record["indicator"],
                        "risk": anti_debug_record["risk"],
                        "desc": f"Выявлен механизм противодействия отладке: {anti_debug_record['indicator']} в библиотеке {library_path.name}",
                        "category": "Native_AntiDebug"
                    })

                for suspicious_record in result_data.get("suspicious_names", []):
                    self.threats.append({
                        "source": "native_library",
                        "pattern": suspicious_record["function"],
                        "risk": suspicious_record["risk"],
                        "desc": f"Функция с подозрительным наименованием: {suspicious_record['function']} в библиотеке {library_path.name}",
                        "category": "Native_Suspicious_Function"
                    })

            except Exception as analysis_exception:
                self._log(f"Процедура анализа завершилась ошибкой для библиотеки {library_path.name}: {str(analysis_exception)}")
                continue

        self._log("Завершение анализа собственных бинарных библиотек.")

    def _perform_signature_scan(self) -> bool:
        if not SIGNATURE_MODULES_AVAILABLE or not self.signature_scanner:
            self._log("Сигнатурные модули недоступны, пропускаем проверку")
            return False
        try:
            if self.signature_manager and self.signature_manager.needs_update():
                self._log("Обновление базы сигнатур...")
                try:
                    update_result = self.signature_manager.update_signatures()
                    self._log(f"Обновлено: {update_result.get('hashes_added', 0)} хешей, {update_result.get('rules_added', 0)} правил")
                except Exception as exception:
                    self._log(f"Ошибка обновления сигнатур: {exception}")
            
            self._log(f"Сигнатурное сканирование: {self.application_package_path.name}")
            self.signature_scan_result = self.signature_scanner.scan(str(self.application_package_path))
            
            if self.signature_scan_result.has_match:
                self._log(f"НАЙДЕНО СОВПАДЕНИЕ: {self.signature_scanner.get_scan_summary(self.signature_scan_result)}")
                self._add_signature_threats()
                if self.signature_scan_result.risk_level == "Critical":
                    return True
            else:
                self._log("Сигнатурных совпадений не найдено")
            return False
        except Exception as exception:
            self._log(f"Ошибка сигнатурного сканирования: {exception}")
            return False

    def _add_signature_threats(self):
        if not self.signature_scan_result:
            return
        if self.signature_scan_result.hash_match:
            self.threats.append({
                'source': 'signature_hash', 'pattern': self.signature_scan_result.hash_match['value'],
                'risk': 'Critical', 'desc': f"Известный вредоносный образец: {self.signature_scan_result.hash_match['threat_name']}",
                'category': 'Signature_Hash', 'confidence': self.signature_scan_result.hash_match['confidence'],
                'family': self.signature_scan_result.hash_match.get('family', 'Unknown')
            })
        for yara_match in self.signature_scan_result.yara_matches:
            self.threats.append({
                'source': 'signature_yara', 'pattern': yara_match['rule_name'], 'risk': 'High',
                'desc': f"Правило анализа: {yara_match['threat_name']}", 'category': 'Signature_YARA',
                'confidence': yara_match['confidence'], 'family': yara_match.get('family', 'Unknown')
            })
        if self.signature_scan_result.fuzzy_match:
            self.threats.append({
                'source': 'signature_fuzzy', 'pattern': self.signature_scan_result.fuzzy_match['value'], 'risk': 'Medium',
                'desc': f"Похожий образец: {self.signature_scan_result.fuzzy_match['threat_name']}",
                'category': 'Signature_Fuzzy', 'confidence': self.signature_scan_result.fuzzy_match['confidence'],
                'family': self.signature_scan_result.fuzzy_match.get('family', 'Unknown')
            })
        self.signature_info = {
            'scanned': True, 'has_match': self.signature_scan_result.has_match,
            'risk_level': self.signature_scan_result.risk_level,
            'hash_match': self.signature_scan_result.hash_match,
            'yara_matches': self.signature_scan_result.yara_matches,
            'fuzzy_match': self.signature_scan_result.fuzzy_match,
            'scan_errors': self.signature_scan_result.scan_errors
        }

    def _extract_package_structure(self):
        self._log("Распаковка пакета приложения...")
        with zipfile.ZipFile(self.application_package_path, 'r') as zip_reference:
            for member in zip_reference.namelist():
                if any(member.startswith(skip_directory) for skip_directory in self.SKIP_DIRS):
                    continue
                if self._is_important_file(member):
                    try:
                        zip_reference.extract(member, self.decompiled_directory)
                    except Exception:
                        pass
        stats = self._count_extracted_files()
        self._log(f"Извлечено: {stats['total']} файлов")
        if stats['so_files']:
            self._log(f"  Собственные библиотеки: {stats['so_files']}")
        if stats['dex_files']:
            self._log(f"  Файлы байт-кода: {stats['dex_files']}")

    def _is_important_file(self, filepath: str) -> bool:
        filepath_lower = filepath.lower()
        if any(filepath_lower.endswith(extension) for extension in ['.xml', '.dex', '.so', '.json', '.js', '.lua', '.py', '.txt', '.dat']):
            return True
        important_directories = ['assets/', 'lib/', 'META-INF/', 'res/values/', 'res/raw/', 'kotlin/']
        if any(filepath_lower.startswith(directory) for directory in important_directories):
            return True
        if filepath_lower == 'resources.arsc':
            return True
        return False

    def _count_extracted_files(self) -> Dict:
        return {
            'total': len(list(self.decompiled_directory.rglob('*'))),
            'so_files': len(list(self.decompiled_directory.rglob('*.so'))),
            'dex_files': len(list(self.decompiled_directory.rglob('*.dex'))),
            'assets': len(list((self.decompiled_directory / 'assets').rglob('*'))) if (self.decompiled_directory / 'assets').exists() else 0,
        }

    def _parse_manifest_fast(self):
        manifest_path = self.decompiled_directory / "AndroidManifest.xml"
        if not manifest_path.exists():
            manifest_path = self.decompiled_directory / "resources" / "AndroidManifest.xml"
        if not manifest_path.exists():
            for xml_path in self.decompiled_directory.rglob("AndroidManifest.xml"):
                if xml_path.is_file():
                    manifest_path = xml_path
                    break
        if not manifest_path.exists():
            self._log("Манифест приложения не найден в структуре декомпилированных файлов.")
            return
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                content = file_handle.read()
            if len(content) < 50:
                self._log("Файл манифеста оказался пустым или повреждённым.")
                return
            self.manifest_data = content
            self._parse_permissions_fast(content)
            self._parse_app_info_fast(content)
            self._parse_components_fast(content)
            self._log(f"Манифест: {len(self.permissions)} разрешений, пакет: {self.manifest_info.get('package', 'Не Доступно')}")
        except Exception as exception:
            self._log(f"Ошибка парсинга манифеста: {exception}")

    def _parse_permissions_fast(self, content: str):
        permissions_set = set()
        patterns = [
            r'(?:android:)?name="(android\.permission\.[^"]+)"',
            r'<uses-permission[^>]*(?:android:)?name="(android\.permission\.[^"]+)"'
        ]
        for pattern in patterns:
            found = re.findall(pattern, content, re.IGNORECASE)
            permissions_set.update(found)

        self.permissions = []
        for permission in sorted(permissions_set):
            if WhitelistFilter.is_legitimate_package(self.manifest_info.get('package', '')): 
                risk = 'Low'
            else:
                risk = self._assess_permission_risk(permission)
            category = self._get_permission_category(permission)
            self.permissions.append({"name": permission, "risk": risk, "category": category})
            if risk == "Critical":
                self.threats.append({"source": "manifest", "pattern": permission, "risk": "Critical",
                                      "desc": f"Опасное разрешение: {permission}", "category": "Permission"})

    def _parse_app_info_fast(self, content: str):
        self.manifest_info = {}
        if match := re.search(r'package="([^"]+)"', content):
            self.manifest_info['package'] = match.group(1)
        if match := re.search(r'versionName="([^"]+)"', content):
            self.manifest_info['version'] = match.group(1)
        if match := re.search(r'targetSdkVersion="(\d+)"', content):
            self.manifest_info['target_sdk'] = int(match.group(1))
        if 'android:debuggable="true"' in content:
            self.manifest_info['debuggable'] = True
            self.threats.append({"source": "manifest", "pattern": "debuggable=true", "risk": "High",
                                  "desc": "Приложение отлаживаемое", "category": "Debug"})
        else:
            self.manifest_info['debuggable'] = False

    def _parse_components_fast(self, content: str):
        self.manifest_info['components'] = {
            'activities': len(re.findall(r' <activity[^>]*>', content)),
            'services': len(re.findall(r' <service[^>]*>', content)),
            'receivers': len(re.findall(r' <receiver[^>]*>', content)),
            'providers': len(re.findall(r' <provider[^>]*>', content)),
        }
        exported = re.findall(r' <(activity|service|receiver|provider)[^>]*android:exported="true"', content)
        if len(exported) > 0:
            self.manifest_info['exported_components'] = len(exported)
            if len(exported) > 5:
                self.threats.append({"source": "manifest", "pattern": "exported_components", "risk": "Medium",
                                      "desc": f"Много экспортированных компонентов: {len(exported)}", "category": "Export"})

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
            'SMS': ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS'], 'CONTACTS': ['READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS'],
            'LOCATION': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'], 'CAMERA': ['CAMERA'], 'MICROPHONE': ['RECORD_AUDIO'],
            'PHONE': ['READ_PHONE_STATE', 'READ_CALL_LOG'], 'STORAGE': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'],
            'NETWORK': ['INTERNET', 'ACCESS_NETWORK_STATE'], 'SYSTEM': ['SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE'],
        }
        for category, keywords in categories.items():
            for keyword in keywords:
                if keyword in permission:
                    return category
        return 'OTHER'

    def _extract_open_source_intelligence_resources(self):
        self._log("Анализ ресурсов приложения...")
        strings_xml = self.decompiled_directory / "res" / "values" / "strings.xml"
        if strings_xml.exists():
            self._parse_strings_xml(strings_xml)
        assets_dir = self.decompiled_directory / "assets"
        if assets_dir.exists():
            self._scan_assets(assets_dir)
        raw_dir = self.decompiled_directory / "res" / "raw"
        if raw_dir.exists():
            self._scan_raw_resources(raw_dir)
        arsc_file = self.decompiled_directory / "resources.arsc"
        if arsc_file.exists():
            self._extract_strings_from_arsc(arsc_file)

    def _parse_strings_xml(self, filepath: Path):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file_handle:
                content = file_handle.read()
            strings = re.findall(r' <string[^>]*name="([^"]+)"[^>]*>([^<]+)</string>', content)
            for name, value in strings:
                for net_type, pattern in self.NETWORK_PATTERNS.items():
                    if matches := pattern.findall(value):
                        self.network_indicators[net_type].extend(matches)
                        self.osint_data.setdefault('urls', []).extend(matches)
                if self._looks_like_api_key(value):
                    self.osint_data.setdefault('api_keys', []).append({'name': name, 'value': value[:50] + '...' if len(value) > 50 else value})
        except Exception as exception:
            self._log(f"Ошибка парсинга строк: {exception}")

    def _scan_assets(self, assets_dir: Path):
        for filepath in assets_dir.rglob('*'):
            if filepath.is_file():
                try:
                    content = filepath.read_text(errors='ignore')
                    if filepath.suffix == '.json':
                        try:
                            config = json.loads(content)
                            self.osint_data.setdefault('configs', []).append({'file': str(filepath.relative_to(self.decompiled_directory)), 'keys': list(config.keys())[:10]})
                        except Exception:
                            pass
                    if filepath.suffix in ['.js', '.lua', '.py']:
                        self.osint_data.setdefault('scripts', []).append(str(filepath.relative_to(self.decompiled_directory)))
                    for net_type, pattern in self.NETWORK_PATTERNS.items():
                        if matches := pattern.findall(content):
                            self.network_indicators[net_type].extend(matches[:20])
                            self.osint_data.setdefault('urls', []).extend(matches[:20])
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
            self._log(f"Ошибка чтения бинарных ресурсов: {exception}")

    def _looks_like_api_key(self, value: str) -> bool:
        if len(value) < 20:
            return False
        key_patterns = [r'[A-Za-z0-9]{32,}', r'AIza[A-Za-z0-9_-]{35}', r'sk-[A-Za-z0-9]{48}', r'gh[pousr]_[A-Za-z0-9]{36}']
        return any(re.match(pattern, value) for pattern in key_patterns)

    def _analyze_bytecode_advanced(self):
        self._log("Расширенный анализ байт-кода и исходного кода...")
        java_files = list(self.decompiled_directory.rglob("*.java"))
        if not java_files:
            self._log("Исходные файлы отсутствуют. Пропускаем анализ.")
            return

        reflection_patterns = ['Class.forName', 'Method.invoke', 'getDeclaredMethod', 'getDeclaredField']
        webview_patterns = ['addJavascriptInterface', 'setJavaScriptEnabled', 'loadUrl']
        
        for file_path in java_files:
            if WhitelistFilter.is_legitimate_package(str(file_path)):
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    content = file_handle.read()
                
                for pattern in reflection_patterns:
                    if pattern in content:
                        self.threats.append({"file": str(file_path.relative_to(self.decompiled_directory)), "pattern": pattern, "risk": "Medium",
                                              "desc": f"Использование рефлексии: {pattern}", "category": "Reflection"})
                
                for dynamic_pattern in self.DYNAMIC_LOAD_PATTERNS:
                    if dynamic_pattern in content:
                        self.dynamic_load_calls.append({"file": str(file_path.relative_to(self.decompiled_directory)), "pattern": dynamic_pattern, "risk": "High"})
                        self.threats.append({"file": str(file_path.relative_to(self.decompiled_directory)), "pattern": dynamic_pattern, "risk": "High",
                                              "desc": f"Динамическая загрузка кода: {dynamic_pattern}", "category": "DynamicLoading"})
                
                if any(wp in content for wp in webview_patterns):
                    self.threats.append({"file": str(file_path.relative_to(self.decompiled_directory)), "pattern": "WebView_JS_Interface", "risk": "High",
                                          "desc": "Использование компонента отображения веб-страниц с интерфейсом сценариев", "category": "WebView"})
                
                for behavior, patterns in self.BEHAVIOR_PATTERNS.items():
                    if any(p in content for p in patterns):
                        self.threats.append({"file": str(file_path.relative_to(self.decompiled_directory)), "pattern": behavior, "risk": "High",
                                              "desc": f"Паттерн поведения: {behavior}", "category": f"Behavior_{behavior}"})
            except Exception:
                continue
        self._log(f"Анализ исходных файлов завершён. Найдено угроз: {len(self.threats)}")

    def _analyze_cryptography(self):
        self._log("Анализ криптографических реализаций...")
        java_files = list(self.decompiled_directory.rglob("*.java"))
        weak_found = 0
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    content = file_handle.read()
                
                cipher_match = self.CRYPTO_PATTERNS['cipher_init'].findall(content)
                for algorithm in cipher_match:
                    if algorithm.upper() in [a.upper() for a in self.WEAK_CRYPTO_ALGORITHMS]:
                        self.crypto_findings.append({"type": "weak_algorithm", "value": algorithm, "risk": "Critical", "file": str(file_path.name)})
                        weak_found += 1
                    self.crypto_findings.append({"type": "cipher_usage", "value": algorithm, "risk": "Medium", "file": str(file_path.name)})
                
                iv_match = self.CRYPTO_PATTERNS['iv_param'].findall(content)
                if iv_match:
                    self.crypto_findings.append({"type": "static_initialization_vector", "value": "Обнаружен статический вектор инициализации", "risk": "High", "file": str(file_path.name)})
                
                key_match = self.CRYPTO_PATTERNS['static_key'].findall(content)
                if key_match:
                    self.crypto_findings.append({"type": "hardcoded_key", "value": "Обнаружен жёстко закодированный ключ шифрования", "risk": "Critical", "file": str(file_path.name)})
            except Exception:
                continue
        self._log(f"Криптоанализ завершён. Найдено слабых алгоритмов: {weak_found}")

    def _analyze_anti_analysis(self):
        self._log("Анализ защит от анализа...")
        java_files = list(self.decompiled_directory.rglob("*.java"))
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    content = file_handle.read()
                
                for category, patterns in self.ANTI_ANALYSIS_PATTERNS.items():
                    for pattern in patterns:
                        if pattern in content:
                            self.anti_analysis_findings.append({"category": category, "pattern": pattern, "file": str(file_path.name)})
                            self.threats.append({"file": str(file_path.relative_to(self.decompiled_directory)), "pattern": pattern, "risk": "High",
                                                  "desc": f"Признак защиты от анализа ({category}): {pattern}", "category": f"Anti_{category}"})
            except Exception:
                continue
        self._log(f"Анализ защит завершён. Обнаружено индикаторов: {len(self.anti_analysis_findings)}")

    def _extract_network_indicators(self):
        self._log("Поиск сетевых индикаторов...")
        for filepath in self.decompiled_directory.rglob('*'):
            if not filepath.is_file(): continue
            if filepath.suffix in ['.png', '.jpg', '.gif', '.webp', '.so', '.dex']: continue
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

    def _analyze_network_intelligence(self):
        self._log("Углублённая сетевая разведка...")
        flags = {"hardcoded_ip": False, "non_https": False, "self_signed_tls": False, "suspicious_tld": False, "tor_or_bulletproof": False}
        
        ips = self.network_indicators.get('ip', [])
        private_prefixes = ('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.')
        for ip_address in ips:
            if not ip_address.startswith(private_prefixes):
                flags["hardcoded_ip"] = True
                self.threats.append({"source": "network", "pattern": f"hardcoded_ip:{ip_address}", "risk": "High", "desc": f"Жёстко закодированный внешний адрес: {ip_address}", "category": "Network_Exfiltration"})

        urls = self.network_indicators.get('url', [])
        for url in urls:
            if url.startswith("http://") and "https://" not in url:
                flags["non_https"] = True
                break
        
        suspicious_tlds = ['.xyz', '.top', '.info', '.cc', '.tk', '.pw', '.ga', '.cf', '.gq', '.ml']
        domains = self.network_indicators.get('domain', [])
        for domain in domains:
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                flags["suspicious_tld"] = True
                self.threats.append({"source": "network", "pattern": f"suspicious_tld:{domain}", "risk": "Medium", "desc": f"Подозрительная доменная зона: {domain}", "category": "Network_Exfiltration"})
                break

        java_files = list(self.decompiled_directory.rglob("*.java"))
        for file_path in java_files:
            try:
                content = file_path.read_text(errors='ignore')
                if "X509TrustManager" in content and ("TrustAllCerts" in content or "checkClientTrusted" in content):
                    flags["self_signed_tls"] = True
                    self.threats.append({"source": "network", "pattern": "bypass_ssl_check", "risk": "High", "desc": "Обход проверки защищённого соединения", "category": "Network_Exfiltration"})
                    break
            except Exception:
                continue

        self.osint_data['network_flags'] = flags
        self._log(f"Сетевые флаги: {flags}")

    def _perform_taint_analysis(self):
        self._log("Статический анализ потоков данных...")
        java_files = list(self.decompiled_directory.rglob("*.java"))
        found_flows = 0
        
        for file_path in java_files:
            if WhitelistFilter.is_legitimate_package(str(file_path)): continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    content = file_handle.read()
                
                sources_found = [source for source in self.TAINT_SOURCES if source in content]
                sinks_found = [sink for sink in self.TAINT_SINKS if sink in content]
                
                if sources_found and sinks_found:
                    for src in sources_found:
                        for sink in sinks_found:
                            self.taint_flows.append({"file": str(file_path.relative_to(self.decompiled_directory)), "source": src, "sink": sink, "risk": "High"})
                            self.threats.append({"file": str(file_path.relative_to(self.decompiled_directory)), "pattern": f"DataFlow:{src}->{sink}", "risk": "High",
                                                  "desc": f"Обнаружен поток данных: {src} -> {sink}", "category": "Data_Exfiltration"})
                    found_flows += 1

                for pattern in self.CRITICAL_FLOW_PATTERNS:
                    if re.search(pattern, content, re.I | re.S):
                        self.threats.append({"file": str(file_path.relative_to(self.decompiled_directory)), "pattern": "CriticalChain", "risk": "Critical",
                                              "desc": f"Критическая цепочка утечки данных", "category": "Malware_Signature"})
                        found_flows += 1
            except Exception:
                continue
        self._log(f"Анализ потоков завершён. Найдено потоков: {found_flows}")

    def _analyze_entropy(self):
        high_entropy_files = []
        for filepath in self.decompiled_directory.rglob('*'):
            if filepath.is_file() and filepath.suffix in ['.dex', '.so', '.bin']:
                try:
                    with open(filepath, 'rb') as file_handle:
                        data = file_handle.read(1024 * 1024)
                    entropy = EntropyCalculator.calculate(data)
                    if EntropyCalculator.is_packed(entropy):
                        high_entropy_files.append({'file': str(filepath.relative_to(self.decompiled_directory)), 'entropy': round(entropy, 2)})
                except Exception:
                    pass
        self.entropy_info['high_entropy_files'] = high_entropy_files
        if len(high_entropy_files) > 0:
            self.threats.append({'source': 'entropy', 'pattern': 'high_entropy', 'risk': 'Medium',
                                 'desc': f"Обнаружено {len(high_entropy_files)} файлов с высокой энтропией (возможная упаковка)", 'category': 'Packing'})

    def _analyze_certificate(self):
        cert_analyzer = CertificateAnalyzer(self.application_package_path)
        self.certificate_info = cert_analyzer.analyze()
        if self.certificate_info.get('risk') == 'High':
            self.threats.append({'source': 'certificate', 'pattern': 'unsigned', 'risk': 'High', 'desc': 'Приложение не подписано', 'category': 'Certificate'})
        elif self.certificate_info.get('debug_cert'):
            self.threats.append({'source': 'certificate', 'pattern': 'debug_certificate', 'risk': 'Medium', 'desc': 'Использован отладочный сертификат', 'category': 'Certificate'})

    def _build_call_graph(self):
        self.call_graph = self.get_call_graph_data()

    def _detect_behavioral_chains(self):
        self._log("Поиск поведенческих цепочек...")
        chains_found = []
        threat_categories = set(t["category"] for t in self.threats)
        
        if "Native_JNI" in threat_categories and any("cipher" in t["pattern"].lower() for t in self.threats) and "DynamicLoading" in threat_categories:
            chains_found.append({"chain": "JNI_Decrypt_Load_Exec", "risk": "Critical", "desc": "Классическая цепочка вредоносного программного обеспечения: собственный код расшифровывает и загружает нагрузку"})
        
        if "Data_Collection" in threat_categories and "Data_Exfiltration" in threat_categories:
            chains_found.append({"chain": "Collect_Exfiltrate", "risk": "High", "desc": "Сбор данных с последующей отправкой по сети"})
            
        if "DynamicLoading" in threat_categories and "Code_Execution" in threat_categories:
            chains_found.append({"chain": "Load_Execute", "risk": "High", "desc": "Динамическая загрузка кода с последующим выполнением"})

        self.behavioral_chains = chains_found
        for chain in chains_found:
            self.threats.append({"source": "behavioral_chain", "pattern": chain["chain"], "risk": chain["risk"],
                                  "desc": chain["desc"], "category": "Behavioral_Chain"})
        self._log(f"Найдено поведенческих цепочек: {len(chains_found)}")

    def _correlate_threats(self):
        for url in self.network_indicators.get('url', []):
            if any(keyword in url.lower() for keyword in ['malware', 'evil', 'hack', 'exploit']):
                self.threats.append({"source": "network_indicator", "pattern": url, "risk": "High", "desc": f"Подозрительный адрес: {url}", "category": "Network"})
        for dynamic in self.dynamic_load_calls:
            self.threats.append({"source": dynamic["file"], "pattern": dynamic["pattern"], "risk": dynamic["risk"], "desc": f"Динамическая загрузка: {dynamic['pattern']}", "category": "Code_Injection"})
        
        unique, seen = [], set()
        for threat in self.threats:
            key = (threat.get("file", threat.get("source", " ")), threat["pattern"])
            if key not in seen:
                seen.add(key)
                unique.append(threat)
        self.threats = unique

    def _calculate_weighted_risk(self):
        self._log("Расчёт взвешенной оценки риска...")
        score = 0
        weights = {
            'execve': 30, 'network_exfiltration': 25, 'anti_debug': 20, 'anti_emulator': 20,
            'dynamic_loading': 15, 'hidden_payload': 15, 'obfuscation': 10, 'weak_crypto': 10,
            'hardcoded_ip': 5, 'non_https': 5, 'suspicious_tld': 5, 'self_signed_tls': 10,
            'behavioral_chain_critical': 35, 'behavioral_chain_high': 25, 'privacy_violation': 10
        }
        
        if any('ptrace' in t['pattern'].lower() or 'execve' in t['pattern'].lower() or 'exec' in t['pattern'].lower() for t in self.threats):
            score += weights['execve']
        
        if any(t['category'] == 'Data_Exfiltration' or t['pattern'].startswith('hardcoded_ip') for t in self.threats):
            score += weights['network_exfiltration']
            
        if any(t['category'] == 'Anti_debugger' for t in self.threats):
            score += weights['anti_debug']
        if any(t['category'] == 'Anti_emulator' for t in self.threats):
            score += weights['anti_emulator']
            
        if any(t['category'] == 'DynamicLoading' for t in self.threats):
            score += weights['dynamic_loading']
            
        if any(t['category'] == 'Hidden_Payload' for t in self.threats):
            score += weights['hidden_payload']
            
        if any('Class.forName' in t['pattern'] or 'Reflection' in t['category'] for t in self.threats):
            score += weights['obfuscation']

        if any(finding['risk'] == 'Critical' for finding in self.crypto_findings):
            score += weights['weak_crypto']

        flags = self.osint_data.get('network_flags', {})
        if flags.get('hardcoded_ip'): score += weights['hardcoded_ip']
        if flags.get('non_https'): score += weights['non_https']
        if flags.get('suspicious_tld'): score += weights['suspicious_tld']
        if flags.get('self_signed_tls'): score += weights['self_signed_tls']
        
        for chain in self.behavioral_chains:
            if chain['risk'] == 'Critical': score += weights['behavioral_chain_critical']
            elif chain['risk'] == 'High': score += weights['behavioral_chain_high']

        if len(self.privacy_violations) > 0:
            score += len(self.privacy_violations) * weights['privacy_violation']

        score += sum(1 for threat in self.threats if threat["risk"] == "Critical") * 2
        score += len(self.taint_flows) * 3

        self.risk_score = min(score, 100)
        self._log(f"Финальная оценка риска: {self.risk_score} из 100 (поведенческий + статический + сетевой)")

    def _print_summary(self):
        risk_counts = defaultdict(int)
        for threat in self.threats:
            risk_counts[threat["risk"]] += 1
        self._log(f"Файлов исходного кода: {len(list(self.decompiled_directory.rglob('*.java'))):,} ")
        self._log(f"Собственных библиотек: {len(list(self.decompiled_directory.rglob('*.so')))} ")
        self._log(f"Угроз всего: {len(self.threats):,} ")
        self._log(f"Критических: {risk_counts.get('Critical', 0)} ")
        self._log(f"Высоких: {risk_counts.get('High', 0)} ")
        self._log(f"Средних: {risk_counts.get('Medium', 0)} ")
        self._log(f"Низких: {risk_counts.get('Low', 0)} ")
        self._log(f"Разрешений: {len(self.permissions)} ")
        self._log(f"Сетевых адресов: {len(self.network_indicators.get('url', []))} ")
        self._log(f"Пакет: {self.manifest_info.get('package', 'Не Доступно')} ")
        self._log(f"Потоков данных: {len(self.taint_flows)} ")
        self._log(f"Поведенческих цепочек: {len(self.behavioral_chains)} ")
        self._log(f"Нарушений конфиденциальности: {len(self.privacy_violations)} ")
        if self.signature_info:
            self._log(f"Сигнатурное сканирование: совпадение найдено, если {self.signature_info.get('has_match')} ")

    def get_decompiled_files(self) -> List[Path]:
        return sorted(list(self.decompiled_directory.rglob("*.java"))) if self.decompiled_directory.exists() else []

    def get_statistics(self) -> Dict:
        return self.statistics

    def get_threats_by_category(self) -> Dict[str, List[Dict]]:
        result = defaultdict(list)
        for threat in self.threats:
            mitre_technique = MitreAttackMobileMapper.map_category_to_technique(threat.get("category", " "))
            threat_with_mitre = threat.copy()
            threat_with_mitre['mitre_technique_id'] = mitre_technique
            result[threat_with_mitre["category"]].append(threat_with_mitre)
        return dict(result)

    def get_network_indicators(self) -> Dict[str, List[str]]:
        return dict(self.network_indicators)

    def get_native_analysis_results(self) -> Dict:
        return self.native_data

    def get_osint_data(self) -> Dict:
        return self.osint_data

    def get_signature_info(self) -> Dict:
        return self.signature_info

    def get_certificate_info(self) -> Dict:
        return self.certificate_info

    def get_entropy_info(self) -> Dict:
        return self.entropy_info

    def get_risk_score(self) -> int:
        return self.risk_score

    def get_call_graph_data(self) -> Dict[str, List[str]]:
        graph_data = defaultdict(list)
        java_files = list(self.decompiled_directory.rglob("*.java"))
        if len(java_files) > 200:
            java_files = java_files[:200]
        known_classes = {file_path.stem for file_path in java_files}
        
        for file_path in java_files:
            source_class = file_path.stem
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                    content = file_handle.read()
                for target_class in known_classes:
                    if target_class != source_class and re.search(r'\b' + re.escape(target_class) + r'\b', content):
                        if target_class not in graph_data[source_class]:
                            graph_data[source_class].append(target_class)
                            if len(graph_data[source_class]) >= 10:
                                break
            except Exception:
                continue
        return dict(graph_data)

    def get_taint_flows(self) -> List[Dict]:
        return self.taint_flows

    def get_behavioral_chains(self) -> List[Dict]:
        return self.behavioral_chains

    def get_privacy_violations(self) -> List[Dict]:
        return self.privacy_violations

    def get_unpacking_indicators(self) -> List[Dict]:
        return self.unpacking_indicators

    def get_dynamic_analysis_config(self) -> Dict:
        return self.dynamic_analysis_config

    def extract_machine_learning_features(self) -> Dict[str, float]:
        """Извлечение числовых признаков для последующего обучения классификаторов"""
        features = {
            'manifest_permissions_count': float(len(self.permissions)),
            'critical_permissions_count': float(sum(1 for permission in self.permissions if permission.get('risk') == 'Critical')),
            'native_libraries_count': float(len(self.native_data)),
            'critical_native_imports': float(sum(1 for library in self.native_data.values() for import_entry in library.get('imports', []) if import_entry.get('risk') == 'Critical')),
            'entropy_high_files': float(len(self.entropy_info.get('high_entropy_files', []))),
            'network_indicators_total': float(sum(len(value_list) for value_list in self.network_indicators.values())),
            'taint_flows_count': float(len(self.taint_flows)),
            'behavioral_chains_count': float(len(self.behavioral_chains)),
            'dynamic_load_calls': float(len(self.dynamic_load_calls)),
            'anti_analysis_indicators': float(len(self.anti_analysis_findings)),
            'weak_crypto_instances': float(len(self.crypto_findings)),
            'privacy_violations_count': float(len(self.privacy_violations)),
            'risk_score': float(self.risk_score),
            'signature_match': 1.0 if self.signature_info.get('has_match') else 0.0,
            'unpacking_heuristics_count': float(len(self.unpacking_indicators))
        }
        self.ml_features = features
        return features

    def save_consolidated_report(self, filename_prefix: str) -> Path:
        threats_with_mitre = []
        for threat in self.threats:
            threat_copy = threat.copy()
            threat_copy['mitre_technique_id'] = MitreAttackMobileMapper.map_category_to_technique(threat.get("category", " "))
            threats_with_mitre.append(threat_copy)

        report_data = {
             "report_metadata": {"generated_at": datetime.now().isoformat(), "analyzer_version": "2.0.0", "analyzer_name": "Аналитический Движок Для Статического Анализа"},
             "summary": {"file_name": self.application_package_path.name if self.application_package_path else "Unknown", "file_hash": self.signature_info.get('hash_match', {}).get('value', 'Not Scanned'), "risk_score": self.risk_score, "verdict": "Malicious" if self.risk_score >= 70 else "Suspicious" if self.risk_score >= 30 else "Safe"},
             "application_info": {"package_name": self.manifest_info.get('package', 'N/A'), "version": self.manifest_info.get('version', 'N/A'), "target_sdk": self.manifest_info.get('target_sdk', 'N/A'), "debuggable": self.manifest_info.get('debuggable', False), "components": self.manifest_info.get('components', {})},
             "permissions_analysis": {"total_count": len(self.permissions), "dangerous_permissions": [permission for permission in self.permissions if permission["risk"] in ["Critical", "High"]], "all_permissions": self.permissions},
             "threats_detected": {"total_count": len(threats_with_mitre), "critical_count": len([t for t in threats_with_mitre if t["risk"] == "Critical"]), "threats_by_category": self.get_threats_by_category(), "detailed_threats": threats_with_mitre},
             "network_intelligence": {"urls": self.network_indicators.get('url', []), "ips": self.network_indicators.get('ip', []), "domains": self.network_indicators.get('domain', []), "osint_data": self.osint_data, "flags": self.osint_data.get('network_flags', {})},
             "taint_analysis": {"sources_sinks": len(self.taint_flows), "flows": self.taint_flows},
             "native_analysis": {"libraries_analyzed": len(self.native_data), "details": self.native_data},
             "signature_analysis": self.signature_info,
             "certificate_analysis": self.certificate_info,
             "entropy_analysis": self.entropy_info,
             "crypto_analysis": self.crypto_findings,
             "anti_analysis": self.anti_analysis_findings,
             "behavioral_chains": self.behavioral_chains,
             "unpacking_indicators": self.unpacking_indicators,
             "privacy_compliance": {"violations": self.privacy_violations, "data_minimization_score": "Pass" if len(self.privacy_violations) == 0 else "Fail"},
             "dynamic_analysis_preparation": self.dynamic_analysis_config,
             "machine_learning_features": self.ml_features,
             "call_graph": self.call_graph,
             "recommendations": self._generate_recommendations()
        }
        report_path = self.ghidra_report_directory / f"{filename_prefix}_full_report.json"
        with open(report_path, 'w', encoding='utf-8') as file_handle:
            json.dump(report_data, file_handle, indent=2, ensure_ascii=False)
        self._log(f"Отчет сохранен: {report_path}")
        return report_path

    def _generate_recommendations(self) -> List[str]:
        recommendations = []
        if self.risk_score >= 70:
            recommendations.append("Рекомендуется немедленное удаление приложения.")
            recommendations.append("Не предоставлять приложению никаких разрешений.")
        if self.certificate_info.get('debug_cert'):
            recommendations.append("Приложение подписано отладочным сертификатом. Не устанавливайте на основные устройства.")
        if self.entropy_info.get('high_entropy_files'):
            recommendations.append("Обнаружены признаки упаковки кода. Требуется дополнительный динамический анализ.")
        if len(self.get_threats_by_category().get('Data_Exfiltration', [])) > 0:
            recommendations.append("Обнаружена утечка данных. Проверьте сетевые запросы и цепочки потоков.")
        if len(self.behavioral_chains) > 0:
            recommendations.append("Найдены сигнатурные поведенческие цепочки. Высокая вероятность вредоносного программного обеспечения.")
        if len(self.privacy_violations) > 0:
            recommendations.append("Обнаружены нарушения принципов конфиденциальности. Избыточный сбор данных без явного согласия.")
        if not recommendations:
            recommendations.append("Специфических рекомендаций нет. Соблюдайте стандартные меры безопасности.")
        return recommendations