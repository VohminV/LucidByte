"""
Анализатор Нативных Библиотек Для Платформы PYGHIDRA
Назначение: Глубокое извлечение индикаторов компрометации, криптографических примитивов,
сигнатур интерфейса собственных методов и операций с памятью из бинарных библиотек формата ELF.
"""
import json
import re
import os
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

try:
    import pyghidra
    import jpype
    PYGHIDRA_AVAILABLE = True
except ImportError:
    PYGHIDRA_AVAILABLE = False
    logging.warning("Библиотека PYGHIDRA не установлена. Анализ нативных библиотек недоступен.")

logger = logging.getLogger(__name__)


class NativeIndicatorExtractor:
    """Извлечение индикаторов угроз из нативных библиотек посредством PYGHIDRA."""

    # Категории критических системных вызовов
    CRITICAL_SYSCALLS = {
        'process_control': ['execve', 'fork', 'clone', 'waitpid', 'ptrace'],
        'memory_management': ['mmap', 'mprotect', 'munmap', 'memfd_create'],
        'network_communication': ['socket', 'connect', 'sendto', 'recvfrom', 'bind', 'listen'],
        'file_system': ['open', 'read', 'write', 'close', 'unlink', 'rename'],
        'dynamic_loading': ['dlopen', 'dlsym', 'dlclose', 'android_dlopen_ext']
    }

    # Шаблоны антиотладочных механизмов
    ANTI_DEBUG_PATTERNS = [
        'ptrace', 'getppid', 'waitpid', 'sigaction', 'android_debuggable',
        'kill', 'raise', 'abort', 'tgkill'
    ]

    # Криптографические функции OpenSSL и BoringSSL
    CRYPTO_FUNCTIONS = [
        'AES_encrypt', 'AES_decrypt', 'AES_set_encrypt_key', 'AES_set_decrypt_key',
        'DES_encrypt', 'DES_decrypt', 'DES_set_key',
        'RSA_public_encrypt', 'RSA_private_decrypt', 'RSA_generate_key',
        'EVP_EncryptInit', 'EVP_DecryptInit', 'EVP_CipherInit',
        'SHA256_Init', 'MD5_Init', 'HMAC_Init',
        'BN_new', 'BN_generate_prime_ex', 'EC_KEY_new_by_curve_name'
    ]

    # Индикаторы упаковщиков и операций с памятью
    PACKING_INDICATORS = [
        'mmap', 'mprotect', 'memfd_create', 'dlopen', 'dlsym', 'dlclose',
        'munmap', 'mremap', 'mincore'
    ]

    def __init__(self, program: Any):
        self.program = program
        self.results: Dict[str, Any] = {
            "functions": [],
            "imports": [],
            "exports": [],
            "strings": [],
            "jni_functions": [],
            "suspicious_names": [],
            "syscalls": [],
            "crypto_usage": [],
            "anti_debug": [],
            "memory_operations": [],
            "jni_signatures": []
        }

    def extract_all(self) -> Dict[str, Any]:
        """Полное извлечение всех категорий индикаторов из нативной библиотеки."""
        self._extract_functions()
        self._extract_imports()
        self._extract_exports()
        self._extract_strings()
        self._detect_syscalls()
        self._detect_anti_debug()
        self._detect_crypto_usage()
        self._extract_jni_signatures()
        self.analyze_memory_operations()
        return self.results

    def _extract_functions(self) -> None:
        """Сбор информации о всех функциях в бинарном файле."""
        function_manager = self.program.getFunctionManager()
        if not function_manager:
            return

        for function in function_manager.getFunctions(True):
            function_name = function.getName()
            entry_point = str(function.getEntryPoint())

            # Определение функций интерфейса собственных методов Java
            if function_name.startswith("Java_") or function_name.startswith("JNI_"):
                self.results["jni_functions"].append({
                    "name": function_name,
                    "address": entry_point,
                    "signature": str(function.getSignature())
                })

            # Поиск подозрительных наименований функций
            suspicious_keywords = [
                "crypto", "encrypt", "decrypt", "key", "secret",
                "inject", "hook", "root", "su", "priv", "hide",
                "bypass", "obfuscate", "unpack", "payload"
            ]
            function_name_lower = function_name.lower()
            for keyword in suspicious_keywords:
                if keyword in function_name_lower:
                    self.results["suspicious_names"].append({
                        "function": function_name,
                        "address": entry_point,
                        "keyword": keyword,
                        "risk": "Высокий"
                    })
                    break

            self.results["functions"].append({
                "name": function_name,
                "address": entry_point
            })

    def _extract_imports(self) -> None:
        """Сбор внешних импортируемых символов."""
        symbol_table = self.program.getSymbolTable()
        if not symbol_table:
            return

        for symbol in symbol_table.getAllSymbols(True):
            if symbol.isExternalEntryPoint():
                symbol_name = symbol.getName()
                self.results["imports"].append({
                    "name": symbol_name,
                    "address": str(symbol.getAddress()),
                    "risk": self._assess_import_risk(symbol_name)
                })

    def _extract_exports(self) -> None:
        """Сбор экспортируемых символов и точек входа."""
        try:
            from ghidra.program.model.symbol import SourceType
        except ImportError:
            return

        symbol_table = self.program.getSymbolTable()
        if not symbol_table:
            return

        for symbol in symbol_table.getAllSymbols(True):
            if symbol.getSource() == SourceType.USER_DEFINED and symbol.isGlobal():
                symbol_name = symbol.getName()
                if symbol_name.startswith("Java_") or symbol_name.startswith("JNI_"):
                    self.results["exports"].append({
                        "name": symbol_name,
                        "address": str(symbol.getAddress())
                    })

    def _extract_strings(self) -> None:
        """Извлечение строк из сегментов памяти с фильтрацией по ключевым словам."""
        memory = self.program.getMemory()
        if not memory:
            return

        keywords = ['http', 'https', '.so', '.apk', '192.168', '10.', '172.',
                    'api', 'token', 'key', 'secret', 'config', 'payload']

        for block in memory.getBlocks():
            if not block.isInitialized() or not block.isRead():
                continue

            try:
                block_size = int(block.getSize())
                read_size = min(2 * 1024 * 1024, block_size)
                data = block.getBytes(block.getStart(), read_size)

                # Извлечение строк в кодировке ASCII
                ascii_pattern = rb'[\x20-\x7E]{8,}'
                ascii_matches = re.findall(ascii_pattern, data)
                ascii_count = 0
                for match in ascii_matches:
                    if ascii_count >= 50:
                        break
                    try:
                        decoded = match.decode('ascii')
                        if any(kw in decoded.lower() for kw in keywords):
                            self.results["strings"].append(decoded[:150])
                            ascii_count += 1
                    except UnicodeDecodeError:
                        continue

                # Извлечение строк в кодировке UTF-16LE
                unicode_pattern = rb'(?:[\x00][\x20-\x7E]){5,}'
                unicode_matches = re.findall(unicode_pattern, data)
                unicode_count = 0
                for match in unicode_matches:
                    if unicode_count >= 50:
                        break
                    try:
                        decoded = match.decode('utf-16-le', errors='ignore')
                        if any(kw in decoded.lower() for kw in keywords):
                            self.results["strings"].append(decoded[:150])
                            unicode_count += 1
                    except UnicodeDecodeError:
                        continue

            except Exception:
                continue

    def _detect_syscalls(self) -> None:
        """Обнаружение опасных системных вызовов на основе импортов."""
        import_names = [imp["name"].lower() for imp in self.results["imports"]]

        for category, syscalls in self.CRITICAL_SYSCALLS.items():
            for syscall in syscalls:
                for import_name in import_names:
                    if syscall in import_name:
                        self.results["syscalls"].append({
                            "name": import_name,
                            "type": category,
                            "specific_call": syscall,
                            "risk": "Критический"
                        })
                        break

    def _detect_anti_debug(self) -> None:
        """Обнаружение механизмов противодействия отладке и анализу."""
        import_names = [imp["name"].lower() for imp in self.results["imports"]]

        for pattern in self.ANTI_DEBUG_PATTERNS:
            for import_name in import_names:
                if pattern in import_name:
                    self.results["anti_debug"].append({
                        "indicator": import_name,
                        "pattern": pattern,
                        "risk": "Высокий",
                        "description": "Обнаружен индикатор противодействия отладке"
                    })
                    break

    def _detect_crypto_usage(self) -> None:
        """Обнаружение использования криптографических примитивов."""
        import_names = [imp["name"].lower() for imp in self.results["imports"]]

        for import_name in import_names:
            for crypto_func in self.CRYPTO_FUNCTIONS:
                if crypto_func.lower() in import_name:
                    risk_level = "Средний"
                    if any(weak in import_name for weak in ['des', 'md5', 'rc4', 'blowfish']):
                        risk_level = "Критический"
                    elif any(weak in import_name for weak in ['aes', 'rsa', 'sha256', 'sha512']):
                        risk_level = "Высокий"

                    self.results["crypto_usage"].append({
                        "function": import_name,
                        "algorithm_family": crypto_func.split('_')[0],
                        "risk": risk_level,
                        "description": "Использование криптографического алгоритма"
                    })
                    break

    def _extract_jni_signatures(self) -> None:
        """Анализ сигнатур методов интерфейса собственных методов Java."""
        for jni_func in self.results["jni_functions"]:
            function_name = jni_func["name"]

            # Извлечение класса и метода из сигнатуры JNI
            match = re.match(r'Java_(\w+)_(\w+)', function_name)
            if match:
                package_class = match.group(1)
                method_name = match.group(2)

                # Оценка риска на основе наименований
                risk_level = "Низкий"
                if any(kw in method_name.lower() for kw in ['encrypt', 'decrypt', 'crypt', 'key', 'secret']):
                    risk_level = "Высокий"
                elif any(kw in method_name.lower() for kw in ['init', 'check', 'verify', 'validate']):
                    risk_level = "Средний"

                self.results["jni_signatures"].append({
                    "function": function_name,
                    "class_reference": package_class,
                    "method_name": method_name,
                    "address": jni_func["address"],
                    "risk": risk_level
                })

    def analyze_memory_operations(self) -> None:
        """Анализ операций с памятью для выявления признаков упаковки и динамической загрузки."""
        import_names = [imp["name"].lower() for imp in self.results["imports"]]

        for import_name in import_names:
            for indicator in self.PACKING_INDICATORS:
                if indicator in import_name:
                    risk_level = "Высокий"
                    description = "Операция с памятью, характерная для упаковщиков"

                    if indicator in ['dlopen', 'dlsym', 'dlclose']:
                        description = "Динамическая загрузка библиотек, возможная подгрузка полезной нагрузки"
                    elif indicator in ['mmap', 'mprotect']:
                        description = "Изменение прав доступа к памяти, характерно для распаковки в памяти"
                    elif indicator == 'memfd_create':
                        description = "Создание безымянного файлового дескриптора в памяти, часто используется вредоносным программным обеспечением"

                    self.results["memory_operations"].append({
                        "function": import_name,
                        "type": indicator,
                        "risk": risk_level,
                        "description": description
                    })
                    break

    def _assess_import_risk(self, import_name: str) -> str:
        """Оценка уровня риска импортируемой функции."""
        critical_keywords = [
            'exec', 'system', 'popen', 'dlopen', 'dlsym', 'mmap',
            'ptrace', 'getuid', 'setuid', 'chmod', 'chown', 'kill', 'fork'
        ]
        high_keywords = [
            'socket', 'connect', 'send', 'recv', 'open', 'read', 'write',
            'close', 'ioctl', 'fcntl', 'getenv', 'putenv', 'AES', 'RSA', 'DES'
        ]

        name_lower = import_name.lower()
        for keyword in critical_keywords:
            if keyword in name_lower:
                return "Критический"
        for keyword in high_keywords:
            if keyword in name_lower:
                return "Высокий"
        return "Низкий"


def analyze_native_library(
    library_path: str,
    output_json_path: str,
    jvm_already_started: bool = False
) -> Dict[str, Any]:
    """
    Комплексный анализ одной нативной библиотеки посредством PYGHIDRA.
    
    Параметры:
        library_path: Полный путь к файлу библиотеки формата ELF
        output_json_path: Полный путь для сохранения результатов анализа
        jvm_already_started: Флаг, указывающий на наличие запущенной виртуальной машины Java

    Возвращает:
        Словарь, содержащий все извлечённые индикаторы и метаданные анализа
    """
    if not PYGHIDRA_AVAILABLE:
        raise ImportError("Библиотека PYGHIDRA не установлена. Необходимо выполнить установку пакета.")

    logger.info(f"Начало анализа: {library_path}")

    try:
        with pyghidra.open_program(library_path, analyze=False) as flat_api:
            program = flat_api.getCurrentProgram()

            logger.info("Запуск автоматического анализа бинарного файла...")
            pyghidra.analyze(program)

            extractor = NativeIndicatorExtractor(program)
            results = extractor.extract_all()

            results["metadata"] = {
                "library_name": os.path.basename(library_path),
                "library_path": library_path,
                "analysis_timestamp": datetime.now().isoformat(),
                "total_functions": len(results["functions"]),
                "total_imports": len(results["imports"]),
                "total_exports": len(results["exports"]),
                "critical_findings": sum(
                    1 for finding in results["syscalls"] + results["anti_debug"] + results["memory_operations"]
                    if finding.get("risk") == "Критический"
                )
            }

            with open(output_json_path, "w", encoding="utf-8") as output_file:
                json.dump(results, output_file, indent=2, ensure_ascii=False)

            logger.info(
                f"Анализ завершён успешно. Экспортировано: "
                f"{len(results['functions'])} функций, "
                f"{len(results['imports'])} импортов, "
                f"{len(results['jni_functions'])} методов интерфейса собственных методов, "
                f"{len(results['crypto_usage'])} криптографических вызовов."
            )

            return results

    except RuntimeError as runtime_error:
        if "Unable to start JVM" in str(runtime_error):
            logger.error("Ошибка: Не удалось запустить виртуальную машину Java. Проверьте установку JDK.")
        raise runtime_error
    except Exception as general_error:
        logger.error(f"Непредвиденная ошибка при анализе библиотеки {library_path}: {general_error}")
        raise general_error


if __name__ == "__main__":
    import sys
    import logging
    
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    if len(sys.argv) < 3:
        print("Использование: python native_analyzer.py <путь_к_библиотеке.so> <путь_к_файлу_отчёта.json>")
        sys.exit(1)

    input_library = sys.argv[1]
    output_report = sys.argv[2]

    if not os.path.exists(input_library):
        print(f"Ошибка: Файл библиотеки не найден по пути {input_library}")
        sys.exit(1)

    analyze_native_library(input_library, output_report)