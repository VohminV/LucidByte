"""
Модуль сигнатурного сканирования
Назначение: Непосредственная проверка файла приложения на соответствие известным сигнатурам
"""
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Проверка наличия yara-python
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("yara-python не установлен. YARA сканирование недоступно.")

# Проверка наличия ssdeep
try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False
    logging.warning("ssdeep не установлен. Нечёткое хеширование недоступно.")

from .signature_manager import SignatureManager

logger = logging.getLogger(__name__)


class SignatureScanResult:
    """Результат сигнатурного сканирования"""
    
    def __init__(self):
        self.hash_match: Optional[Dict] = None
        self.yara_matches: List[Dict] = []
        self.fuzzy_match: Optional[Dict] = None
        self.scan_errors: List[str] = []
    
    @property
    def has_match(self) -> bool:
        return bool(self.hash_match or self.yara_matches or self.fuzzy_match)
    
    @property
    def risk_level(self) -> str:
        if self.hash_match:
            return "Critical"
        elif self.yara_matches:
            return "High"
        elif self.fuzzy_match:
            return "Medium"
        return "None"
    
    def to_dict(self) -> Dict:
        return {
            'hash_match': self.hash_match,
            'yara_matches': self.yara_matches,
            'fuzzy_match': self.fuzzy_match,
            'has_match': self.has_match,
            'risk_level': self.risk_level,
            'scan_errors': self.scan_errors
        }


class SignatureScanner:
    """Сканер сигнатур для APK файлов"""
    
    def __init__(self, signature_manager: Optional[SignatureManager] = None):
        self.signature_manager = signature_manager or SignatureManager()
        self._compiled_yara_rules = None
        self._hash_database = None
    
    def _load_hash_database(self) -> List[str]:
        if self._hash_database is None:
            self._hash_database = self.signature_manager.get_hash_database()
        return self._hash_database
    
    def _compile_yara_rules(self) -> Optional[Any]:
        """Компиляция YARA правил с обработкой ошибок"""
        if not YARA_AVAILABLE:
            return None
        
        if self._compiled_yara_rules is not None:
            return self._compiled_yara_rules
        
        rule_paths = self.signature_manager.get_yara_rules_paths()
        if not rule_paths:
            return None
        
        try:
            # Попытка массовой компиляции
            self._compiled_yara_rules = yara.compile(filepaths={
                str(path): str(path) for path in rule_paths
            })
            logger.info(f"Скомпилировано {len(rule_paths)} YARA правил")
            return self._compiled_yara_rules
        except yara.Error as e:
            logger.warning(f"Ошибка массовой компиляции YARA: {e}. Попытка индивидуальной компиляции...")
            return self._compile_yara_rules_individual(rule_paths)
    
    def _compile_yara_rules_individual(self, rule_paths: List[Path]) -> Optional[Any]:
        """Индивидуальная компиляция для пропуска битых правил"""
        if not YARA_AVAILABLE:
            return None
        
        valid_rules = {}
        for rule_path in rule_paths:
            try:
                rules = yara.compile(str(rule_path))
                valid_rules[str(rule_path)] = str(rule_path)
                logger.debug(f"Правило {rule_path.name} успешно скомпилировано")
            except yara.Error as e:
                logger.warning(f"Правило {rule_path.name} некорректно и исключено: {e}")
                continue
        
        if valid_rules:
            return yara.compile(filepaths=valid_rules)
        return None
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest().lower()
        except Exception as e:
            logger.warning(f"Ошибка вычисления хеша {file_path}: {e}")
            return ""
    
    def _calculate_fuzzy_hash(self, file_path: Path) -> Optional[str]:
        if not SSDEEP_AVAILABLE:
            return None
        try:
            return ssdeep.hash_from_file(str(file_path))
        except Exception as e:
            logger.warning(f"Ошибка вычисления fuzzy hash: {e}")
            return None
    
    def scan(self, file_path: str) -> SignatureScanResult:
        result = SignatureScanResult()
        file_path = Path(file_path)
        
        if not file_path.exists():
            result.scan_errors.append(f"Файл не найден: {file_path}")
            return result
        
        # 1. Проверка по хеш-сумме
        if self.signature_manager.is_scan_enabled('sha256'):
            try:
                hash_result = self._scan_by_hash(file_path)
                result.hash_match = hash_result
            except Exception as e:
                result.scan_errors.append(f"Ошибка hash scan: {str(e)}")
        
        if result.hash_match:
            logger.info(f"Найдено совпадение по хешу для {file_path.name}")
            return result
        
        # 2. YARA сканирование
        if self.signature_manager.is_scan_enabled('yara') and YARA_AVAILABLE:
            try:
                yara_results = self._scan_by_yara(file_path)
                result.yara_matches = yara_results
            except Exception as e:
                result.scan_errors.append(f"Ошибка YARA scan: {str(e)}")
        
        # 3. Нечёткое хеширование
        if self.signature_manager.is_scan_enabled('ssdeep') and SSDEEP_AVAILABLE:
            try:
                fuzzy_result = self._scan_by_fuzzy_hash(file_path)
                result.fuzzy_match = fuzzy_result
            except Exception as e:
                result.scan_errors.append(f"Ошибка fuzzy hash scan: {str(e)}")
        
        return result
    
    def _scan_by_hash(self, file_path: Path) -> Optional[Dict]:
        file_hash = self._calculate_file_hash(file_path, 'sha256')
        if not file_hash:
            return None
        
        hash_database = self._load_hash_database()
        if file_hash in hash_database:
            return {
                'type': 'sha256',
                'value': file_hash,
                'source': 'hash_database',
                'confidence': 100,
                'threat_name': 'Known Malware (Hash Match)',
                'family': 'Unknown'
            }
        return None
    
    def _scan_by_yara(self, file_path: Path) -> List[Dict]:
        matches = []
        compiled_rules = self._compile_yara_rules()
        if not compiled_rules:
            return matches
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            yara_matches = compiled_rules.match(data=file_data)
            
            for match in yara_matches:
                matches.append({
                    'type': 'yara',
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'source': match.namespace or 'yara_rules',
                    'confidence': 95,
                    'threat_name': match.rule,
                    'family': match.rule.split('_')[0] if '_' in match.rule else 'Unknown',
                    'strings': [str(s) for s in match.strings]
                })
            
            if matches:
                logger.info(f"Найдено {len(matches)} YARA совпадений для {file_path.name}")
            
        except yara.Error as e:
            logger.warning(f"Ошибка YARA сканирования: {e}")
        except Exception as e:
            logger.warning(f"Ошибка чтения файла для YARA: {e}")
        
        return matches
    
    def _scan_by_fuzzy_hash(self, file_path: Path) -> Optional[Dict]:
        # Реализация сравнения fuzzy hash требует базы известных fuzzy hash
        # В текущей версии возвращаем None, так как база fuzzy hash не загружается автоматически
        return None
    
    def get_scan_summary(self, result: SignatureScanResult) -> str:
        if result.hash_match:
            return f"⚠️ КРИТИЧЕСКОЕ СОВПАДЕНИЕ: {result.hash_match['threat_name']}"
        elif result.yara_matches:
            rules = ', '.join([m['rule_name'] for m in result.yara_matches[:3]])
            return f"⚠️ YARA СОВПАДЕНИЯ: {rules}"
        elif result.fuzzy_match:
            return f"⚠️ НЕЧЁТКОЕ СОВПАДЕНИЕ: {result.fuzzy_match['threat_name']}"
        else:
            return "✅ Сигнатурных совпадений не найдено"