"""
Аналитический Движок Для Статического Анализа Файлов
Назначение: Координация Этапов Первого и Второго утверждённого алгоритма.
Выполняет декомпиляцию JADX, передачу данных в платформу Ghidra,
сканирование исходного кода, фильтрацию безопасных компонентов и
экспорт потенциально опасных файлов для последующей ручной оценки.
"""
import os
import sys
import subprocess
import shutil
import json
import re
import zipfile
import math
import gc
import logging
import hashlib
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
    logging.warning("Библиотека PYGHIDRA не установлена. Анализ нативных библиотек недоступен.")

try:
    from elftools.elf.elffile import ELFFile
    ELF_TOOLS_AVAILABLE = True
except ImportError:
    ELF_TOOLS_AVAILABLE = False
    logging.info("Библиотека pyelftools не установлена. Анализ заголовков ELF ограничен.")

try:
    from .signature_manager import SignatureManager
    from .signature_scanner import SignatureScanner, SignatureScanResult
    SIGNATURE_MODULES_AVAILABLE = True
except ImportError as exception:
    SIGNATURE_MODULES_AVAILABLE = False
    logging.warning(f"Не удалось импортировать сигнатурные модули: {exception}. Сигнатурный анализ отключён.")

try:
    from .native_analyzer import analyze_native_library
    NATIVE_ANALYZER_AVAILABLE = True
except ImportError:
    NATIVE_ANALYZER_AVAILABLE = False
    logging.warning("Модуль анализа нативных библиотек недоступен.")


class WhitelistFilter:
    """Фильтр ложных срабатываний для легитимных компонентов и фреймворков."""
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
        return any(package_name.startswith(prefix) for prefix in cls.LEGITIMATE_PACKAGES)

    @classmethod
    def is_legitimate_class(cls, class_name: str) -> bool:
        return any(legit in class_name for legit in cls.LEGITIMATE_CLASSES)


class CertificateAnalyzer:
    """Анализ сертификатов подписи пакета приложения."""
    def __init__(self, application_package_path: Path):
        self.application_package_path = application_package_path
        self.certificate_info: Dict = {}

    def analyze(self) -> Dict:
        try:
            with zipfile.ZipFile(self.application_package_path, 'r') as zip_reference:
                meta_inf_files = [
                    file_path for file_path in zip_reference.namelist()
                    if file_path.startswith('META-INF/') and
                    (file_path.endswith('.RSA') or file_path.endswith('.DSA') or file_path.endswith('.EC'))
                ]
                if not meta_inf_files:
                    self.certificate_info.update({'signed': False, 'risk': 'High', 'reason': 'Отсутствие цифровой подписи'})
                    return self.certificate_info

                self.certificate_info['signed'] = True
                certificate_name = meta_inf_files[0].split('/')[-1]
                if 'debug' in certificate_name.lower() or 'androiddebugkey' in certificate_name.lower():
                    self.certificate_info.update({'debug_cert': True, 'risk': 'Medium', 'reason': 'Использован отладочный сертификат'})
                else:
                    self.certificate_info.update({'debug_cert': False, 'risk': 'Low', 'reason': 'Стандартный сертификат разработчика'})
        except Exception as exception:
            self.certificate_info.update({'error': str(exception), 'risk': 'Unknown'})
        return self.certificate_info


class EntropyCalculator:
    """Вычисление энтропии Шеннона для обнаружения упаковки и шифрования."""
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
    """Сопоставление обнаруженных угроз с таксономией MITRE ATT&CK для мобильных систем."""
    TECHNIQUE_MAPPING = {
        'Data_Collection': 'T1415', 'Data_Exfiltration': 'T1416',
        'DynamicLoading': 'T1641', 'Native_AntiDebug': 'T1620',
        'Native_JNI': 'T1622', 'Code_Execution': 'T1414',
        'Permission': 'T1438', 'Certificate': 'T1550',
        'Behavioral_Chain': 'T1480', 'Hidden_Command': 'T1610',
        'Packing': 'T1513', 'Network_Exfiltration': 'T1416',
        'Cryptography': 'T1573', 'Anti_emulator': 'T1612',
        'Anti_debugger': 'T1620'
    }

    @classmethod
    def map_category_to_technique(cls, category: str) -> Optional[str]:
        return cls.TECHNIQUE_MAPPING.get(category)


class PrivacyComplianceAnalyzer:
    """Анализ соответствия принципам конфиденциальности и минимизации сбора данных."""
    SENSITIVE_SOURCES = {
        'getDeviceId', 'getImei', 'getLastKnownLocation', 'getContacts',
        'READ_SMS', 'RECORD_AUDIO'
    }

    @classmethod
    def analyze_data_minimization(cls, taint_flows: List[Dict], declared_permissions: List[Dict]) -> List[Dict]:
        violations = []
        declared_categories = {perm.get('category') for perm in declared_permissions if perm.get('category')}

        for flow in taint_flows:
            source = flow.get('source', '')
            sink = flow.get('sink', '')
            if source in cls.SENSITIVE_SOURCES and sink not in ['SharedPreferences', 'FileOutputStream']:
                source_category = next((p.get('category') for p in declared_permissions 
                                       if p.get('name', '').replace('android.permission.', '') == source or p.get('category') == source), None)
                if source_category and source_category not in declared_categories:
                    violations.append({
                        'type': 'undeclared_data_usage', 'source': source, 'sink': sink,
                        'description': f"Сбор данных из источника {source} без явного объявления в разрешении {source_category}",
                        'severity': 'High'
                    })
        return violations


class UnpackingHeuristicDetector:
    """Эвристическое обнаружение признаков упаковки и обфускации кода."""
    PACKER_SIGNATURES = [
        'DexClassLoader', 'loadClass', 'defineClass',
        'BaseDexClassLoader', 'InMemoryDexClassLoader'
    ]
    OBFUSCATION_PATTERNS = re.compile(r'(?:a|b|c|d|e|f|g)\d+\s*\(')

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
    """Подготовка конфигурации для последующего динамического анализа в эмулированной среде."""
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
            'frida_hooks': self.frida_hooks, 'target_endpoints': self.target_endpoints,
            'expected_syscalls': self.expected_syscalls, 'emulation_profile': 'malware_sandbox_heavy_monitoring'
        }


class AnalysisEngine:
    """
    Ядро статического анализа файлов. Реализует строго последовательный конвейер:
    Этап Первый: Первичная обработка (JADX + Ghidra)
    Этап Второй: Сбор потенциально опасных файлов (фильтрация и экспорт для LLM)
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
        'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.I),
        'ip': re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b'),
        'domain': re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?'),
        'websocket': re.compile(r'wss?://[^\s<>"{}|\\^`\[\]]+', re.I),
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
        'iv_param': re.compile(r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\]\s*\{([^}]*)\}', re.S),
        'static_key': re.compile(r'(?:byte\s*\[\]\s*\w+\s*=\s*new\s+byte\s*\[\]\s*\{([^}]*)\})', re.S)
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
        self.ghidra_input_directory = self.temporary_directory / "ghidra_input"
        self.ghidra_report_directory = self.temporary_directory / "ghidra_reports"
        self.application_package_path: Optional[Path] = None
        self.reports_directory = Path("reports")
        self.reports_directory.mkdir(parents=True, exist_ok=True)
        self.dangerous_files_export_directory = Path("exported_dangerous_files")
        
        # === ГАРАНТИРОВАННАЯ ИНИЦИАЛИЗАЦИЯ ВСЕХ АТРИБУТОВ ДЛЯ WORKER ===
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
        self.unpacking_indicators: List[Dict] = []
        self.privacy_violations: List[Dict] = []
        self.dynamic_analysis_config: Dict = {}
        self.ml_features: Dict[str, float] = {}

        self.progress_callback: Optional[Callable] = None
        self.log_callback: Optional[Callable] = None
        self.use_ghidra: bool = True
        self.resources_cleaned: bool = False
        
        if SIGNATURE_MODULES_AVAILABLE:
            self.signature_manager: Optional[SignatureManager] = SignatureManager()
            self.signature_scanner: Optional[SignatureScanner] = SignatureScanner(self.signature_manager)
        else:
            self.signature_manager = None
            self.signature_scanner = None

    def set_progress_callback(self, callback: Callable[[int, str], None]): self.progress_callback = callback
    def set_log_callback(self, callback: Callable[[str], None]): self.log_callback = callback

    def enable_ghidra(self, enabled: bool = True):
        """Включение или отключение модуля анализа машинного кода (Ghidra)."""
        self.use_ghidra = enabled
        self._log(f"Модуль анализа машинного кода включён при заданном параметре {enabled}")
        if enabled and not PYGHIDRA_AVAILABLE:
            self._log("Модуль анализа машинного кода не установлен. Необходимо выполнить установку пакета.")

    def _log(self, message: str):
        if self.log_callback: self.log_callback(message)
        logger.info(message)

    def _progress(self, value: int, message: str):
        if self.progress_callback: self.progress_callback(value, message)

    def _locate_jadx_executable(self) -> Optional[str]:
        """Надёжный поиск исполняемого файла JADX в системе."""
        jadx_path = shutil.which("jadx")
        if jadx_path: return jadx_path
        if os.name == 'nt':
            for ext in ['.bat', '.cmd', '.exe']:
                jadx_path = shutil.which(f"jadx{ext}")
                if jadx_path: return jadx_path
            user_profile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
            common_paths = [
                r"C:\Program Files\jadx\bin\jadx.bat",
                r"C:\jadx\bin\jadx.bat",
                os.path.join(user_profile, "jadx", "bin", "jadx.bat")
            ]
            for p in common_paths:
                if os.path.exists(p): return p
        return None

    def _decompile_with_jadx(self) -> bool:
        """Декомпиляция байт-кода приложения в читаемый исходный код на языке программирования Java."""
        jadx_executable = self._locate_jadx_executable()
        if not jadx_executable:
            self._log("❌ КРИТИЧЕСКАЯ ОШИБКА: JADX не найден в системном PATH.")
            self._log("💡 Решение: Добавьте путь к директории jadx/bin в переменную среды PATH или установите JADX в C:\\jadx")
            return False

        output_directory = self.decompiled_directory / "jadx_sources"
        if output_directory.exists(): shutil.rmtree(output_directory, ignore_errors=True)
        output_directory.mkdir(parents=True, exist_ok=True)

        command_line = [
            jadx_executable, "-d", str(output_directory.absolute()),
            "--deobf", "--show-bad-code", "--no-imports",
            "--no-debug-info", "--escape-unicode",
            str(self.application_package_path.absolute())
        ]

        self._log(f"Запуск внешней процедуры декомпиляции: {' '.join(command_line)}")
        try:
            process = subprocess.run(command_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1200, shell=False)
            output_text = ""
            try: output_text = process.stderr.decode('utf-8', errors='replace')
            except Exception: output_text = process.stderr.decode('cp1251', errors='replace')

            for line in output_text.splitlines():
                if line.strip(): self._log(f"[ДЕКОМПИЛЯТОР] {line.strip()}")

            generated_java_files = len(list(output_directory.rglob("*.java")))
            if process.returncode == 0:
                self._log(f"✅ Декомпиляция успешно завершена. Получено файлов: {generated_java_files}")
                return True
            elif generated_java_files > 0:
                self._log(f"⚠ Декомпиляция завершена с частичными ошибками (код: {process.returncode}).")
                self._log(f"✅ Успешно извлечено {generated_java_files} файлов. Анализ будет продолжен.")
                return True
            else:
                self._log(f"❌ Процедура декомпиляции завершилась неудачно. Исходные файлы не сгенерированы.")
                return False
        except subprocess.TimeoutExpired:
            self._log("⏱ Превышен допустимый лимит времени выполнения процедуры декомпиляции.")
            return False
        except Exception as execution_exception:
            self._log(f"❌ Непредвиденная ошибка при вызове внешнего инструмента: {execution_exception}")
            return False

    def analyze_application_package(self, application_package_path: str) -> Dict:
        """Основной метод запуска анализа. Строго следует утверждённому алгоритму."""
        try:
            self.application_package_path = Path(application_package_path)
            self._log("=" * 70)
            self._log("АНАЛИТИЧЕСКИЙ ДВИЖОК. ЗАПУСК КОНВЕЙЕРА")
            self._log("=" * 70)
            self._log(f"Целевой файл: {application_package_path}")
            self._log(f"Размер файла: {os.path.getsize(application_package_path) / 1024 / 1024:.2f} Мегабайт")
            self._log("=" * 70)

            for dir_path in [self.decompiled_directory, self.ghidra_input_directory, self.ghidra_report_directory, self.dangerous_files_export_directory]:
                if dir_path.exists(): shutil.rmtree(dir_path)
                dir_path.mkdir(parents=True, exist_ok=True)

            self._progress(5, "Этап первый: Первичная обработка...")
            jadx_success = self._decompile_with_jadx()
            if self.use_ghidra:
                if not PYGHIDRA_AVAILABLE:
                    self._log("Модуль анализа машинного кода не установлен. Пропуск анализа нативных библиотек.")
                else:
                    self._log("[ЭТАП 1] Передача данных в платформу Ghidra для углублённого статического анализа...")
                    self._analyze_native_libraries()
                    self._log("Платформа Ghidra: анализ структуры и содержимого завершён.")
            
            if not jadx_success or not self.decompiled_directory.exists():
                raise RuntimeError("Этап первый не завершён. Декомпилированные файлы отсутствуют.")

            self._progress(40, "Этап второй: Сбор потенциально опасных файлов...")
            self._execute_static_analysis_passes()
            
            dangerous_files_map = self._group_and_filter_dangerous_files()
            if not dangerous_files_map:
                self._log("Этап второй завершён. Потенциально опасные файлы не обнаружены.")
                return {"status": "clean", "message": "Потенциально опасные файлы не обнаружены."}

            self._progress(85, "Сохранение отобранных файлов для экспертной оценки...")
            export_manifest_path = self._export_files_for_llm_evaluation(dangerous_files_map)
            
            self._progress(100, "Анализ завершён. Файлы подготовлены.")
            self._log("=" * 70)
            self._log(f"КОНВЕЙЕР ЗАВЕРШЁН. Отсмотрено: {len(dangerous_files_map)} файлов.")
            self._log(f"Результаты сохранены: {export_manifest_path}")
            self._log("=" * 70)
            
            return {
                "status": "dangerous_files_exported",
                "manifest_path": str(export_manifest_path),
                "files_count": len(dangerous_files_map),
                "export_directory": str(self.dangerous_files_export_directory)
            }
        except Exception as exception:
            import traceback
            self._log(f"Критическая ошибка конвейера: {str(exception)}")
            self._log(f"Трассировка выполнения:\n{traceback.format_exc()}")
            return {"status": "error", "message": str(exception)}

    def _execute_static_analysis_passes(self) -> None:
        self._log("[ЭТАП 2] Запуск комплексного статического анализа...")
        self._progress(45, "Анализ манифеста...")
        self._parse_manifest_fast()
        self._progress(50, "Извлечение ресурсов и сетевых индикаторов...")
        self._extract_open_source_intelligence_resources()
        self._extract_network_indicators()
        self._analyze_network_intelligence()
        self._progress(60, "Анализ байт-кода и криптографии...")
        self._analyze_bytecode_advanced()
        self._analyze_cryptography()
        self._progress(70, "Анализ защит, энтропии и сертификатов...")
        self._analyze_anti_analysis()
        self._analyze_entropy()
        self.unpacking_indicators = UnpackingHeuristicDetector.detect_packer_indicators(
            list(self.decompiled_directory.rglob("*.java")), self.entropy_info
        )
        self._analyze_certificate()
        self._progress(75, "Анализ потоков данных...")
        self._perform_taint_analysis()
        self.privacy_violations = PrivacyComplianceAnalyzer.analyze_data_minimization(
            self.taint_flows, self.permissions
        )
        self._log("Статический анализ завершён.")

    def _group_and_filter_dangerous_files(self) -> Dict[str, Dict]:
        self._log("[ЭТАП 2] Фильтрация файлов и формирование перечня потенциально опасных компонентов...")
        dangerous_files: Dict[str, Dict] = defaultdict(lambda: {"findings": [], "risk_levels": set(), "absolute_path": ""})

        for threat in self.threats:
            file_path = threat.get("file") or threat.get("source")
            if not file_path or file_path in ["network_indicator", "behavioral_chain", "entropy"]: continue
            abs_path = str(self.decompiled_directory / file_path) if not Path(file_path).is_absolute() else file_path
            rel_path = str(Path(file_path).relative_to(self.decompiled_directory)) if Path(file_path).is_relative_to(self.decompiled_directory) else file_path
            if Path(abs_path).is_file():
                dangerous_files[rel_path]["absolute_path"] = abs_path
                dangerous_files[rel_path]["findings"].append({"category": threat.get("category", "Unknown"), "description": threat.get("desc", ""), "pattern": threat.get("pattern", "")})
                dangerous_files[rel_path]["risk_levels"].add(threat.get("risk", "Low"))

        valid_dangerous_files = {}
        for rel_path, data in dangerous_files.items():
            if Path(data["absolute_path"]).exists():
                data["risk_levels"] = list(data["risk_levels"])
                data["max_risk"] = self._determine_max_risk(data["risk_levels"])
                valid_dangerous_files[rel_path] = data
        safe_count = len(list(self.decompiled_directory.rglob("*.java"))) - len(valid_dangerous_files)
        self._log(f"Отфильтровано безопасных файлов: {safe_count}. Отобрано для экспертной оценки: {len(valid_dangerous_files)}.")
        return valid_dangerous_files

    def _export_files_for_llm_evaluation(self, dangerous_files_map: Dict[str, Dict]) -> Path:
        self._log("Формирование пакета файлов для последовательной экспертной оценки...")
        manifest_data = {"analysis_metadata": {}, "files": []}
        for rel_path, data in dangerous_files_map.items():
            src_path = Path(data["absolute_path"])
            dest_path = self.dangerous_files_export_directory / rel_path
            try:
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dest_path)
                content = src_path.read_text(encoding='utf-8', errors='ignore')
                file_hash = hashlib.sha256(content.encode()).hexdigest()
                manifest_data["files"].append({
                    "relative_path": rel_path, "absolute_path_in_export": str(dest_path.resolve()),
                    "sha256": file_hash, "size_bytes": len(content.encode('utf-8')),
                    "preliminary_findings": data["findings"], "max_risk_level": data["max_risk"],
                    "risk_factors": list(data["risk_levels"])
                })
            except Exception as copy_error:
                self._log(f"Ошибка копирования файла {rel_path}: {copy_error}")

        manifest_data["analysis_metadata"] = {
            "generated_at": datetime.now().isoformat(), "target_apk": str(self.application_package_path),
            "total_files_scanned": len(list(self.decompiled_directory.rglob("*.java"))),
            "dangerous_files_count": len(manifest_data["files"]), "stage": "Stage_Two_Completed_Ready_For_LLM"
        }
        manifest_path = self.dangerous_files_export_directory / "dangerous_files_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2, ensure_ascii=False)
        self._log(f"Пакет файлов сохранён. Манифест: {manifest_path}")
        return manifest_path

    def _determine_max_risk(self, risk_levels: List[str]) -> str:
        risk_hierarchy = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        max_score = max(risk_hierarchy.get(level, 0) for level in risk_levels)
        return next((k for k, v in risk_hierarchy.items() if v == max_score), "Low")

    # =========================================================================
    # МЕТОДЫ СТАТИЧЕСКОГО АНАЛИЗА
    # =========================================================================
    def _analyze_native_libraries(self) -> None:
        if not NATIVE_ANALYZER_AVAILABLE:
            self._log("Модуль анализа нативных библиотек недоступен.")
            return
        native_files = list(self.decompiled_directory.rglob("*.so"))
        if not native_files:
            self._log("Собственные бинарные библиотеки не обнаружены в структуре приложения.")
            return
        total_count = len(native_files)
        self._log(f"Начало анализа собственных бинарных библиотек. Количество файлов: {total_count}")
        for index, library_path in enumerate(native_files, 1):
            if library_path.name in self.SYSTEM_LIBS:
                self._log(f"Пропуск стандартной системной библиотеки: {library_path.name}")
                continue
            self._log(f"Запуск глубокого анализа для: {library_path.name}")
            try:
                report_filename = f"{library_path.stem}_native_analysis_result.json"
                report_full_path = self.ghidra_report_directory / report_filename
                result_data = analyze_native_library(library_path=str(library_path), output_json_path=str(report_full_path), jvm_already_started=(index > 1))
                architecture = self._get_architecture(library_path)
                self.native_data[library_path.name] = {"architecture": architecture, "file_path": str(library_path), "analysis_report_path": str(report_full_path), "analysis_results": result_data}
                for record in result_data.get("syscalls", []):
                    self.threats.append({"source": "native_library", "pattern": record["name"], "risk": record["risk"], "desc": f"Обнаружен системный вызов повышенной опасности: {record['name']} в библиотеке {library_path.name}", "category": "Native_Syscall"})
                for record in result_data.get("anti_debug", []):
                    self.threats.append({"source": "native_library", "pattern": record["indicator"], "risk": record["risk"], "desc": f"Выявлен механизм противодействия отладке: {record['indicator']} в библиотеке {library_path.name}", "category": "Native_AntiDebug"})
                for record in result_data.get("suspicious_names", []):
                    self.threats.append({"source": "native_library", "pattern": record["function"], "risk": record["risk"], "desc": f"Функция с подозрительным наименованием: {record['function']} в библиотеке {library_path.name}", "category": "Native_Suspicious_Function"})
            except Exception as analysis_exception:
                self._log(f"Процедура анализа завершилась ошибкой для библиотеки {library_path.name}: {str(analysis_exception)}")
                continue
        self._log("Завершение анализа собственных бинарных библиотек.")

    def _parse_manifest_fast(self):
        manifest_path = next((p for p in [self.decompiled_directory / "AndroidManifest.xml", self.decompiled_directory / "jadx_sources" / "AndroidManifest.xml"] if p.exists()), None)
        if not manifest_path:
            self._log("AndroidManifest.xml не найден.")
            return
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            if '<manifest' not in content:
                self._log("Содержимое манифеста невалидно.")
                return
            self.manifest_data = content
            permissions_set = set(re.findall(r'(?:android:)?name="(android\.[^"]+)"', content, re.I))
            self.permissions = []
            for perm in sorted(permissions_set):
                risk = "Critical" if any(k in perm for k in ['READ_SMS', 'BIND_ACCESSIBILITY']) else "High" if any(k in perm for k in ['ACCESS_FINE_LOCATION', 'RECORD_AUDIO']) else "Low"
                self.permissions.append({"name": perm, "risk": risk, "category": "System"})
                if risk == "Critical":
                    self.threats.append({"source": "manifest", "pattern": perm, "risk": "Critical", "desc": f"Опасное разрешение: {perm}", "category": "Permission"})
            pkg_match = re.search(r'(?:android:)?package="([^"]+)"', content)
            self.manifest_info['package'] = pkg_match.group(1) if pkg_match else "Unknown"
        except Exception as e:
            self._log(f"Ошибка парсинга манифеста: {e}")

    def _extract_open_source_intelligence_resources(self):
        self._log("Анализ ресурсов приложения...")
        strings_xml = self.decompiled_directory / "res" / "values" / "strings.xml"
        if strings_xml.exists(): self._parse_strings_xml(strings_xml)
        assets_dir = self.decompiled_directory / "assets"
        if assets_dir.exists(): self._scan_assets(assets_dir)

    def _parse_strings_xml(self, filepath: Path):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file_handle:
                content = file_handle.read()
            strings = re.findall(r'<string[^>]*name="([^"]+)"[^>]*>([^<]+)</string>', content)
            for name, value in strings:
                self.strings_data.append(f"{name}: {value}")
                for net_type, pattern in self.NETWORK_PATTERNS.items():
                    if matches := pattern.findall(value):
                        self.network_indicators[net_type].extend(matches)
                        self.osint_data.setdefault('urls', []).extend(matches)
        except Exception as exception:
            self._log(f"Ошибка парсинга строк: {exception}")

    def _scan_assets(self, assets_dir: Path):
        for filepath in assets_dir.rglob('*'):
            if filepath.is_file() and filepath.suffix in ['.json', '.js', '.lua', '.py']:
                try:
                    content = filepath.read_text(errors='ignore')
                    for net_type, pattern in self.NETWORK_PATTERNS.items():
                        if matches := pattern.findall(content):
                            self.network_indicators[net_type].extend(list(set(matches))[:10])
                except: continue

    def _extract_network_indicators(self):
        self._log("Поиск сетевых индикаторов...")
        for fp in self.decompiled_directory.rglob('*'):
            if fp.is_file() and fp.suffix not in ['.png', '.jpg', '.so', '.dex']:
                try:
                    content = fp.read_text(encoding='utf-8', errors='ignore')[:512*1024]
                    for net_type, pattern in self.NETWORK_PATTERNS.items():
                        if matches := pattern.findall(content):
                            self.network_indicators[net_type].extend(list(set(matches))[:10])
                except: continue

    def _analyze_network_intelligence(self):
        for ip in self.network_indicators.get('ip', []):
            if not any(ip.startswith(p) for p in ('10.', '172.16.', '192.168.')):
                self.threats.append({"source": "network", "pattern": f"hardcoded_ip:{ip}", "risk": "High", "desc": f"Жёстко закодированный внешний адрес: {ip}", "category": "Network_Exfiltration"})

    def _analyze_bytecode_advanced(self):
        java_files = list(self.decompiled_directory.rglob("*.java"))
        for file_path in java_files:
            if WhitelistFilter.is_legitimate_package(str(file_path)): continue
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                rel = str(file_path.relative_to(self.decompiled_directory))
                for p in self.DYNAMIC_LOAD_PATTERNS:
                    if p in content:
                        self.threats.append({"file": rel, "pattern": p, "risk": "High", "desc": f"Динамическая загрузка кода: {p}", "category": "DynamicLoading"})
                for beh, patterns in self.BEHAVIOR_PATTERNS.items():
                    if any(p in content for p in patterns):
                        self.threats.append({"file": rel, "pattern": beh, "risk": "High", "desc": f"Паттерн поведения: {beh}", "category": f"Behavior_{beh}"})
            except: continue

    def _analyze_cryptography(self):
        java_files = list(self.decompiled_directory.rglob("*.java"))
        for fp in java_files:
            try:
                content = fp.read_text(encoding='utf-8', errors='ignore')
                for algo in self.WEAK_CRYPTO_ALGORITHMS:
                    if algo.lower() in content.lower():
                        self.crypto_findings.append({"type": "weak_algorithm", "value": algo, "risk": "Critical", "file": fp.name})
            except: continue

    def _analyze_anti_analysis(self):
        java_files = list(self.decompiled_directory.rglob("*.java"))
        for fp in java_files:
            try:
                content = fp.read_text(encoding='utf-8', errors='ignore')
                rel = str(fp.relative_to(self.decompiled_directory))
                for cat, patterns in self.ANTI_ANALYSIS_PATTERNS.items():
                    for p in patterns:
                        if p in content:
                            self.threats.append({"file": rel, "pattern": p, "risk": "High", "desc": f"Признак защиты от анализа ({cat}): {p}", "category": f"Anti_{cat}"})
            except: continue

    def _analyze_entropy(self):
        high_entropy_files = []
        for fp in self.decompiled_directory.rglob('*'):
            if fp.is_file() and fp.suffix in ['.dex', '.so', '.bin']:
                try:
                    data = fp.read_bytes()[:1024*1024]
                    entropy = EntropyCalculator.calculate(data)
                    if EntropyCalculator.is_packed(entropy):
                        high_entropy_files.append({'file': str(fp.relative_to(self.decompiled_directory)), 'entropy': round(entropy, 2)})
                except: pass
        self.entropy_info['high_entropy_files'] = high_entropy_files

    def _analyze_certificate(self):
        cert_analyzer = CertificateAnalyzer(self.application_package_path)
        self.certificate_info = cert_analyzer.analyze()
        if self.certificate_info.get('risk') == 'High':
            self.threats.append({'source': 'certificate', 'pattern': 'unsigned', 'risk': 'High', 'desc': 'Приложение не подписано', 'category': 'Certificate'})

    def _perform_taint_analysis(self):
        java_files = list(self.decompiled_directory.rglob("*.java"))
        for file_path in java_files:
            if WhitelistFilter.is_legitimate_package(str(file_path)): continue
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                rel = str(file_path.relative_to(self.decompiled_directory))
                sources = [s for s in self.TAINT_SOURCES if s in content]
                sinks = [s for s in self.TAINT_SINKS if s in content]
                if sources and sinks:
                    for src in sources:
                        for sink in sinks:
                            self.taint_flows.append({"file": rel, "source": src, "sink": sink, "risk": "High"})
                            self.threats.append({"file": rel, "pattern": f"DataFlow:{src}->{sink}", "risk": "High", "desc": f"Обнаружен поток данных: {src} -> {sink}", "category": "Data_Exfiltration"})
            except: continue

    def cleanup_resources(self):
        if self.resources_cleaned: return
        for dir_path in [self.decompiled_directory, self.ghidra_input_directory]:
            if dir_path.exists():
                try: shutil.rmtree(dir_path); self._log(f"Удалена временная директория: {dir_path.name}")
                except: pass
        if PYGHIDRA_AVAILABLE and jpype.isJVMStarted():
            try: jpype.shutdownJVM(); self._log("Завершение виртуальной машины Java...")
            except: pass
        self.resources_cleaned = True

    def __del__(self): self.cleanup_resources()

    def _get_arch_from_path(self, path: Path) -> str:
        parts = path.as_posix().split("/")
        if len(parts) >= 2:
            parent = parts[-2]
            return {'arm64-v8a': 'aarch64', 'armeabi-v7a': 'arm', 'x86_64': 'x86_64', 'x86': 'x86'}.get(parent, parent)
        return "unknown"
    def _get_arch_from_elf(self, path: Path) -> str:
        if not ELF_TOOLS_AVAILABLE: return self._get_arch_from_path(path)
        try:
            with open(path, 'rb') as f:
                elf = ELFFile(f)
                return {'EM_X86_64': 'x86_64', 'EM_386': 'x86', 'EM_ARM': 'arm', 'EM_AARCH64': 'aarch64'}.get(elf.header['e_machine'], 'unknown')
        except: return self._get_arch_from_path(path)
    def _get_architecture(self, path: Path) -> str: return self._get_arch_from_elf(path)
    def _print_summary(self): pass
    def _correlate_threats(self): self.threats = list({(t.get("file", t.get("source", " ")), t["pattern"]): t for t in self.threats}.values())
    def _calculate_weighted_risk(self): self.risk_score = min(75, len(self.threats) * 2 + len(self.taint_flows) * 3)

    def get_statistics(self) -> Dict:
        """Возвращает сводную статистику анализа для отображения в интерфейсе."""
        return {
            "total_files": len(list(self.decompiled_directory.rglob("*.java"))) if self.decompiled_directory.exists() else 0,
            "total_threats": len(self.threats),
            "critical_threats": len([t for t in self.threats if t.get("risk") == "Critical"]),
            "high_threats": len([t for t in self.threats if t.get("risk") == "High"]),
            "permissions_count": len(self.permissions),
            "network_indicators": sum(len(v) for v in self.network_indicators.values()),
            "risk_score": self.risk_score,
            "manifest_package": self.manifest_info.get("package", "Unknown")
        }

    def get_decompiled_files(self) -> List[Path]:
        """Безопасный возврат списка декомпилированных Java-файлов."""
        if hasattr(self, 'decompiled_directory') and self.decompiled_directory.exists():
            return sorted(list(self.decompiled_directory.rglob("*.java")))
        return []

    def get_threats_by_category(self) -> Dict[str, List[Dict]]:
        result = defaultdict(list)
        for threat in self.threats:
            mitre_technique = MitreAttackMobileMapper.map_category_to_technique(threat.get("category", ""))
            threat_with_mitre = threat.copy()
            threat_with_mitre['mitre_technique_id'] = mitre_technique
            result[threat_with_mitre["category"]].append(threat_with_mitre)
        return dict(result)

    def get_network_indicators(self) -> Dict[str, List[str]]:
        return dict(self.network_indicators)
    def get_native_analysis_results(self) -> Dict: return self.native_data
    def get_osint_data(self) -> Dict: return self.osint_data
    def get_signature_info(self) -> Dict: return self.signature_info
    def get_certificate_info(self) -> Dict: return self.certificate_info
    def get_entropy_info(self) -> Dict: return self.entropy_info
    def get_risk_score(self) -> int: return self.risk_score
    def get_call_graph_data(self) -> Dict[str, List[str]]:
        graph_data = defaultdict(list)
        java_files = list(self.decompiled_directory.rglob("*.java"))
        if len(java_files) > 200: java_files = java_files[:200]
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
                            if len(graph_data[source_class]) >= 10: break
            except Exception: continue
        return dict(graph_data)

    def get_taint_flows(self) -> List[Dict]: return self.taint_flows
    def get_behavioral_chains(self) -> List[Dict]: return self.behavioral_chains
    def get_privacy_violations(self) -> List[Dict]: return self.privacy_violations
    def get_unpacking_indicators(self) -> List[Dict]: return self.unpacking_indicators
    def get_dynamic_analysis_config(self) -> Dict: return self.dynamic_analysis_config

    def extract_machine_learning_features(self) -> Dict[str, float]:
        features = {
            'manifest_permissions_count': float(len(self.permissions)),
            'critical_permissions_count': float(sum(1 for permission in self.permissions if permission.get('risk') == 'Critical')),
            'native_libraries_count': float(len(self.native_data)),
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
    
    def _calculate_verdict(self, risk_score: int) -> str:
        if risk_score is None: return "Unknown"
        if risk_score >= 70: return "Malicious"
        elif risk_score >= 30: return "Suspicious"
        return "Safe"
    
    def save_consolidated_report(self, filename_prefix: str) -> Path:
        def safe_get(obj, *keys, default=None):
            for key in keys:
                if obj is None: return default
                obj = obj.get(key, default) if isinstance(obj, dict) else default
            return obj if obj is not None else default

        threats_with_mitre = []
        for threat in self.threats:
            threat_copy = threat.copy() if threat else {}
            category = threat_copy.get("category", "") if threat_copy else ""
            threat_copy['mitre_technique_id'] = MitreAttackMobileMapper.map_category_to_technique(category)
            threats_with_mitre.append(threat_copy)

        file_name = "Unknown"
        if self.application_package_path is not None:
            try: file_name = self.application_package_path.name
            except Exception: file_name = "Unknown"
        file_hash = safe_get(self.signature_info, 'hash_match', 'value', default='Not Scanned')

        report_data = {
            "report_metadata": {"generated_at": datetime.now().isoformat(), "analyzer_version": "2.0.0", "analyzer_name": "Аналитический Движок Для Статического Анализа"},
            "summary": {"file_name": file_name, "file_hash": file_hash, "risk_score": self.risk_score if self.risk_score is not None else 0, "verdict": self._calculate_verdict(self.risk_score), "total_files": len(self.get_decompiled_files()), "total_threats": len(threats_with_mitre), "total_permissions": len(self.permissions)},
            "threats": threats_with_mitre, "permissions": self.permissions,
            "application_info": {"package_name": safe_get(self.manifest_info, 'package', default='N/A'), "version": safe_get(self.manifest_info, 'version', default='N/A'), "target_sdk": safe_get(self.manifest_info, 'target_sdk', default='N/A'), "debuggable": safe_get(self.manifest_info, 'debuggable', default=False), "components": self.manifest_info.get('components', {}) if self.manifest_info else {}},
            "permissions_analysis": {"total_count": len(self.permissions) if self.permissions else 0, "dangerous_permissions": [p for p in (self.permissions or []) if p.get("risk") in ["Critical", "High"]], "all_permissions": self.permissions or []},
            "threats_detected": {"total_count": len(threats_with_mitre), "critical_count": len([t for t in threats_with_mitre if t.get("risk") == "Critical"]), "threats_by_category": self.get_threats_by_category(), "detailed_threats": threats_with_mitre},
            "network_intelligence": {"urls": self.network_indicators.get('url', []) if self.network_indicators else [], "ips": self.network_indicators.get('ip', []) if self.network_indicators else [], "domains": self.network_indicators.get('domain', []) if self.network_indicators else [], "osint_data": self.osint_data or {}, "flags": safe_get(self.osint_data, 'network_flags', default={})},
            "taint_analysis": {"sources_sinks": len(self.taint_flows) if self.taint_flows else 0, "flows": self.taint_flows or []},
            "native_analysis": {"libraries_analyzed": len(self.native_data) if self.native_data else 0, "details": self.native_data or {}},
            "signature_analysis": self.signature_info or {}, "certificate_analysis": self.certificate_info or {},
            "entropy_analysis": self.entropy_info or {}, "crypto_analysis": self.crypto_findings or [],
            "anti_analysis": self.anti_analysis_findings or [], "behavioral_chains": self.behavioral_chains or [],
            "unpacking_indicators": self.unpacking_indicators or [],
            "privacy_compliance": {"violations": self.privacy_violations or [], "data_minimization_score": "Pass" if not self.privacy_violations else "Fail"},
            "dynamic_analysis_preparation": self.dynamic_analysis_config or {}, "machine_learning_features": self.ml_features or {},
            "call_graph": self.call_graph or {}, "recommendations": self._generate_recommendations()
        }
        try:
            self.ghidra_report_directory.mkdir(parents=True, exist_ok=True)
            report_path = self.reports_directory / f"{filename_prefix}_full_report.json"
            with open(report_path, 'w', encoding='utf-8') as file_handle:
                json.dump(report_data, file_handle, indent=2, ensure_ascii=False)
            self._log(f"✓ Отчёт сохранён: {report_path.resolve()}")
            return report_path
        except Exception as error:
            self._log(f"✗ Ошибка сохранения отчёта: {error}")
            return self.ghidra_report_directory / f"{filename_prefix}_full_report.json"

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