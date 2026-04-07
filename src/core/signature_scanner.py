"""
Модуль сигнатурного сканирования
Назначение: Непосредственная проверка файла приложения на соответствие известным сигнатурам
"""
import hashlib
import os
import pickle
import re
import json
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import logging

# Проверка наличия yara-python
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("Библиотека yara-python не установлена. Сканирование с использованием правил YARA недоступно.")

# Проверка наличия pefile (для анализа PE файлов)
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logging.info("Библиотека pefile не установлена. Анализ файлов формата PE недоступен.")

# Проверка наличия ssdeep для нечёткого хеширования
try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False
    logging.info("Библиотека ssdeep не установлена. Нечёткое хеширование недоступно.")

from .signature_manager import SignatureManager

logger = logging.getLogger(__name__)


class NetworkIoCExtractor:
    """Извлечение и классификация индикаторов компрометации из текстовых данных"""

    @staticmethod
    def extract_iocs(content: str) -> Dict[str, List[Dict]]:
        """Извлечение всех типов индикаторов компрометации из предоставленного текста"""
        iocs = {
            'urls': [],
            'ips': [],
            'domains': [],
            'emails': [],
            'file_hashes': [],
            'api_keys': []
        }

        # URL
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        for url in re.findall(url_pattern, content):
            iocs['urls'].append({
                'value': url,
                'risk': NetworkIoCExtractor.assess_url_risk(url),
                'type': 'url'
            })

        # IP адреса
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for ip in re.findall(ip_pattern, content):
            if not ip.startswith(('10.', '192.168.', '172.16.')):
                iocs['ips'].append({
                    'value': ip,
                    'risk': 'High',
                    'type': 'ip'
                })

        # Домены
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|xyz|top|info|ru|cn|tk)\b'
        for domain in re.findall(domain_pattern, content):
            iocs['domains'].append({
                'value': domain,
                'risk': NetworkIoCExtractor.assess_domain_risk(domain),
                'type': 'domain'
            })

        # File hashes
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }

        for hash_type, pattern in hash_patterns.items():
            for hash_val in re.findall(pattern, content):
                iocs['file_hashes'].append({
                    'value': hash_val.lower(),
                    'type': hash_type,
                    'risk': 'Critical'
                })

        return iocs

    @staticmethod
    def assess_url_risk(url: str) -> str:
        """Оценка уровня риска для указанного URL"""
        suspicious_tlds = ['.xyz', '.top', '.tk', '.pw', '.cc']
        if any(url.endswith(tld) for tld in suspicious_tlds):
            return 'High'
        if url.startswith('http://'):
            return 'Medium'
        return 'Low'

    @staticmethod
    def assess_domain_risk(domain: str) -> str:
        """Оценка уровня риска для указанного доменного имени"""
        suspicious_tlds = ['.xyz', '.top', '.tk', '.pw', '.cc', '.ga', '.cf']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return 'High'

        # Генерация доменов (DGA)
        if len(domain) > 20 and domain.count('.') == 1:
            subdomain = domain.split('.')[0]
            if len(subdomain) > 15 and subdomain.isalnum():
                return 'High'

        return 'Medium'


class SignatureScanResult:
    """Результат сигнатурного сканирования с расширенными полями данных"""
    def __init__(self):
        self.hash_match: Optional[Dict] = None
        self.yara_matches: List[Dict] = []
        self.fuzzy_match: Optional[Dict] = None
        self.ioc_matches: List[Dict] = []
        self.malware_family: Optional[str] = None
        self.threat_intel_data: Dict = {}
        self.scan_errors: List[str] = []
        self.scan_metadata: Dict = {
            'scan_time': None,
            'scan_duration_ms': 0,
            'file_size': 0,
            'file_type': 'unknown'
        }

    @property
    def has_match(self) -> bool:
        """Определение наличия совпадений по любому из типов сигнатур"""
        return bool(self.hash_match or self.yara_matches or
                    self.fuzzy_match or self.ioc_matches)

    @property
    def risk_level(self) -> str:
        """Определение итогового уровня риска на основе найденных совпадений"""
        if self.hash_match:
            return "Critical"
        elif self.yara_matches:
            max_confidence = max((m.get('confidence', 0) for m in self.yara_matches), default=0)
            if max_confidence >= 90:
                return "Critical"
            elif max_confidence >= 70:
                return "High"
            return "Medium"
        elif self.fuzzy_match:
            return "Medium"
        elif self.ioc_matches:
            high_risk_iocs = sum(1 for ioc in self.ioc_matches if ioc.get('risk') == 'High')
            if high_risk_iocs > 5:
                return "High"
            elif high_risk_iocs > 0:
                return "Medium"
        return "None"

    @property
    def confidence_score(self) -> int:
        """Расчёт общей уверенности в обнаружении угрозы"""
        score = 0

        if self.hash_match:
            score += 100
        elif self.yara_matches:
            score += sum(m.get('confidence', 0) for m in self.yara_matches) / max(len(self.yara_matches), 1)
        elif self.fuzzy_match:
            score += self.fuzzy_match.get('confidence', 0) * 0.7
        elif self.ioc_matches:
            score += min(len(self.ioc_matches) * 10, 80)

        return min(int(score), 100)

    def add_ioc_match(self, ioc_type: str, value: str, source: str,
                      confidence: int = 80):
        """Добавление нового индикатора компрометации в список результатов"""
        self.ioc_matches.append({
            'type': ioc_type,
            'value': value,
            'source': source,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        })

    def to_dict(self) -> Dict:
        """Сериализация результатов сканирования в словарь"""
        return {
            'hash_match': self.hash_match,
            'yara_matches': self.yara_matches,
            'fuzzy_match': self.fuzzy_match,
            'ioc_matches': self.ioc_matches,
            'malware_family': self.malware_family,
            'threat_intel_data': self.threat_intel_data,
            'has_match': self.has_match,
            'risk_level': self.risk_level,
            'confidence_score': self.confidence_score,
            'scan_errors': self.scan_errors,
            'scan_metadata': self.scan_metadata
        }

    def to_threat_report(self) -> Dict:
        """Генерация структурированного отчёта об угрозах для интеграции"""
        threats = []

        if self.hash_match:
            threats.append({
                'type': 'hash_match',
                'severity': 'Critical',
                'description': self.hash_match.get('threat_name', 'Неизвестная угроза'),
                'indicator': self.hash_match.get('value', ''),
                'confidence': 100
            })

        for yara in self.yara_matches:
            threats.append({
                'type': 'yara_rule',
                'severity': 'High',
                'description': yara.get('threat_name', 'Совпадение по правилу YARA'),
                'indicator': yara.get('rule_name', ''),
                'confidence': yara.get('confidence', 0)
            })

        for ioc in self.ioc_matches:
            threats.append({
                'type': f"ioc_{ioc['type']}",
                'severity': ioc.get('risk', 'Medium'),
                'description': f"Обнаружен индикатор: {ioc['type']}",
                'indicator': ioc.get('value', ''),
                'confidence': ioc.get('confidence', 0)
            })

        return {
            'scan_id': hashlib.md5(f"{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            'scan_timestamp': datetime.now().isoformat(),
            'threats': threats,
            'overall_risk': self.risk_level,
            'confidence': self.confidence_score,
            'malware_family': self.malware_family
        }


class SignatureScanner:
    """Сканер сигнатур для файлов приложений с расширенными возможностями анализа"""
    def __init__(self, signature_manager: Optional[SignatureManager] = None):
        self.signature_manager = signature_manager or SignatureManager()
        self._compiled_yara_rules = None
        self._hash_database = None
        self._fuzzy_hash_database = None
        self._yara_cache_file = Path("signatures/yara_rules.compiled")
        self._ioc_database: Dict[str, List[Dict]] = {}
        self._load_ioc_database()

    def _load_ioc_database(self):
        """Загрузка базы индикаторов компрометации из локального хранилища"""
        ioc_file = Path("signatures/ioc_database.json")
        if ioc_file.exists():
            try:
                with open(ioc_file, 'r', encoding='utf-8') as f:
                    self._ioc_database = json.load(f)
                logger.info(f"Загружена база индикаторов компрометации: {sum(len(v) for v in self._ioc_database.values())} записей")
            except Exception as e:
                logger.warning(f"Ошибка загрузки базы индикаторов компрометации: {e}")
                self._ioc_database = {}

    def _load_hash_database(self) -> List[str]:
        """Загрузка базы хешей в оперативную память"""
        if self._hash_database is None:
            self._hash_database = self.signature_manager.get_hash_database()
        return self._hash_database

    def _load_fuzzy_hash_database(self) -> List[Dict]:
        """Загрузка базы нечётких хешей в оперативную память"""
        if self._fuzzy_hash_database is None:
            fuzzy_db_file = Path("signatures/fuzzy_hashes.json")
            if fuzzy_db_file.exists():
                try:
                    with open(fuzzy_db_file, 'r', encoding='utf-8') as f:
                        self._fuzzy_hash_database = json.load(f)
                except Exception:
                    self._fuzzy_hash_database = []
            else:
                self._fuzzy_hash_database = []
        return self._fuzzy_hash_database

    def _compile_yara_rules(self) -> Optional[Any]:
        """Компиляция правил YARA с обработкой ошибок и кэшированием результатов"""
        if not YARA_AVAILABLE:
            return None

        if self._compiled_yara_rules is not None:
            return self._compiled_yara_rules

        # Попытка загрузки из кэша
        if self._yara_cache_file.exists():
            try:
                with open(self._yara_cache_file, 'rb') as f:
                    cached_rules = pickle.load(f)
                logger.info("Правила YARA успешно загружены из кэша")
                self._compiled_yara_rules = cached_rules
                return cached_rules
            except Exception:
                logger.warning("Не удалось загрузить кэш правил YARA")

        rule_paths = self.signature_manager.get_yara_rules_paths()
        if not rule_paths:
            return None

        try:
            self._compiled_yara_rules = yara.compile(filepaths={
                str(path): str(path) for path in rule_paths
            })
            logger.info(f"Скомпилировано {len(rule_paths)} правил YARA")

            # Сохранение в кэш
            try:
                self._yara_cache_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self._yara_cache_file, 'wb') as f:
                    pickle.dump(self._compiled_yara_rules, f)
            except Exception:
                pass

            return self._compiled_yara_rules
        except yara.Error as e:
            logger.warning(f"Ошибка массовой компиляции правил YARA: {e}. Попытка индивидуальной компиляции...")
            return self._compile_yara_rules_individual(rule_paths)

    def _compile_yara_rules_individual(self, rule_paths: List[Path]) -> Optional[Any]:
        """Индивидуальная компиляция правил для пропуска повреждённых файлов"""
        if not YARA_AVAILABLE:
            return None

        valid_rules = {}
        for rule_path in rule_paths:
            try:
                yara.compile(str(rule_path))
                valid_rules[str(rule_path)] = str(rule_path)
                logger.debug(f"Правило {rule_path.name} успешно скомпилировано")
            except yara.Error as e:
                logger.warning(f"Правило {rule_path.name} некорректно и исключено из анализа: {e}")
                continue

        if valid_rules:
            compiled = yara.compile(filepaths=valid_rules)
            # Сохранение в кэш
            try:
                with open(self._yara_cache_file, 'wb') as f:
                    pickle.dump(compiled, f)
            except Exception:
                pass
            return compiled
        return None

    def _calculate_file_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Вычисление криптографического хеша файла"""
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest().lower()
        except Exception as e:
            logger.warning(f"Ошибка вычисления хеша файла {file_path}: {e}")
            return ""

    def _calculate_fuzzy_hash(self, file_path: Path) -> Optional[str]:
        """Вычисление нечёткого хеша с использованием библиотеки ssdeep"""
        if not SSDEEP_AVAILABLE:
            return None
        try:
            return ssdeep.hash_file(str(file_path))
        except Exception as e:
            logger.warning(f"Ошибка вычисления нечёткого хеша: {e}")
            return None

    def _compare_fuzzy_hashes(self, hash1: str, hash2: str) -> int:
        """Сравнение двух нечётких хешей. Возвращает процент совпадения"""
        if not SSDEEP_AVAILABLE:
            return 0
        try:
            return ssdeep.compare(hash1, hash2)
        except Exception:
            return 0

    def _query_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """Запрос информации о хеше в платформе VirusTotal"""
        api_key = self.signature_manager.config.get('virustotal_api_key')
        if not api_key:
            return {'error': 'Ключ API не настроен'}

        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': api_key}
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return {
                    'detection_ratio': data['data']['attributes']['last_analysis_stats'],
                    'malware_names': self._extract_malware_names(data),
                    'first_seen': data['data']['attributes']['first_submission_date'],
                    'last_seen': data['data']['attributes']['last_analysis_date'],
                    'reputation': data['data']['attributes']['reputation'],
                    'tags': data['data']['attributes'].get('tags', []),
                    'family': self._detect_family_from_tags(data['data']['attributes'].get('tags', []))
                }
            return {'error': f'Код ответа сервера: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def _query_malwarebazaar(self, sha256: str) -> Dict[str, Any]:
        """Запрос информации в платформе MalwareBazaar"""
        api_key = self.signature_manager.config.get('malwarebazaar_api_key')
        if not api_key:
            return {'error': 'Ключ API не настроен'}

        try:
            url = 'https://bazaar.abuse.ch/api/v1/'
            headers = {
                'API-Key': api_key,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = f'query=get_info&hash={sha256}'
            response = requests.post(url, headers=headers, data=data, timeout=30)

            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {
                        'file_name': result['data'][0].get('file_name'),
                        'file_size': result['data'][0].get('file_size'),
                        'tags': result['data'][0].get('tags', []),
                        'vendor_intel': result['data'][0].get('vendor_intel', {}),
                        'signature': result['data'][0].get('signature'),
                        'family': result['data'][0].get('family')
                    }
            return {'error': 'Объект не найден или ошибка API'}
        except Exception as e:
            return {'error': str(e)}

    def _extract_malware_names(self, vt_data: Dict) -> List[str]:
        """Извлечение имён вредоносных программ из отчёта платформы VirusTotal"""
        names = []
        detections = vt_data['data']['attributes']['last_analysis_results']
        for vendor, result in detections.items():
            if result['category'] == 'malicious':
                names.append(f"{vendor}: {result['result']}")
        return names

    def _detect_family_from_tags(self, tags: List[str]) -> Optional[str]:
        """Определение семейства вредоносного программного обеспечения по тегам"""
        family_keywords = {
            'ransomware': ['ransomware', 'encrypt', 'lock'],
            'trojan': ['trojan', 'backdoor', 'rat'],
            'spyware': ['spy', 'keylog', 'stealer'],
            'banker': ['banker', 'bank', 'financial'],
            'adware': ['adware', 'ad'],
            'worm': ['worm', 'propagate']
        }

        tags_lower = [t.lower() for t in tags]
        for family, keywords in family_keywords.items():
            if any(kw in ' '.join(tags_lower) for kw in keywords):
                return family

        return None

    def _check_ioc_database(self, content: str) -> List[Dict]:
        """Проверка содержимого на наличие известных индикаторов компрометации"""
        matches = []

        # Проверка URL
        for ioc in self._ioc_database.get('urls', []):
            if ioc['value'] in content:
                matches.append({
                    'type': 'url',
                    'value': ioc['value'],
                    'source': ioc.get('source', 'ioc_database'),
                    'confidence': ioc.get('confidence', 80),
                    'risk': ioc.get('risk', 'High')
                })

        # Проверка доменов
        for ioc in self._ioc_database.get('domains', []):
            if ioc['value'] in content:
                matches.append({
                    'type': 'domain',
                    'value': ioc['value'],
                    'source': ioc.get('source', 'ioc_database'),
                    'confidence': ioc.get('confidence', 80),
                    'risk': ioc.get('risk', 'High')
                })

        return matches

    def scan(self, file_path: str) -> SignatureScanResult:
        """Основной метод сканирования файла с расширенными проверками"""
        start_time = datetime.now()
        result = SignatureScanResult()
        file_path = Path(file_path)

        # Обновление метаданных
        result.scan_metadata['scan_time'] = start_time.isoformat()

        if not file_path.exists():
            result.scan_errors.append(f"Файл не найден: {file_path}")
            return result

        # Получение размера файла
        try:
            result.scan_metadata['file_size'] = file_path.stat().st_size
        except Exception:
            pass

        # Определение типа файла
        if file_path.suffix.lower() == '.apk':
            result.scan_metadata['file_type'] = 'android_apk'
        elif file_path.suffix.lower() == '.dex':
            result.scan_metadata['file_type'] = 'android_dex'
        elif file_path.suffix.lower() == '.so':
            result.scan_metadata['file_type'] = 'native_library'

        # 1. Проверка по хеш-сумме
        if self.signature_manager.is_scan_enabled('sha256'):
            try:
                hash_result = self._scan_by_hash(file_path)
                result.hash_match = hash_result

                # Если найдено совпадение по хешу, запросить внешние источники
                if hash_result:
                    file_hash = hash_result['value']
                    vt_result = self._query_virustotal(file_hash)
                    if 'error' not in vt_result:
                        result.threat_intel_data['virustotal'] = vt_result
                        if vt_result.get('family'):
                            result.malware_family = vt_result['family']

                    mb_result = self._query_malwarebazaar(file_hash)
                    if 'error' not in mb_result:
                        result.threat_intel_data['malwarebazaar'] = mb_result
                        if mb_result.get('family'):
                            result.malware_family = mb_result['family']
            except Exception as e:
                result.scan_errors.append(f"Ошибка при сканировании по хешу: {str(e)}")

        if result.hash_match:
            logger.info(f"Найдено совпадение по хешу для файла {file_path.name}")
            result.scan_metadata['scan_duration_ms'] = (datetime.now() - start_time).total_seconds() * 1000
            return result

        # 2. Сканирование с использованием правил YARA
        if self.signature_manager.is_scan_enabled('yara') and YARA_AVAILABLE:
            try:
                yara_results = self._scan_by_yara(file_path)
                result.yara_matches = yara_results

                # Определение семейства по правилам YARA
                if yara_results:
                    families = set()
                    for match in yara_results:
                        if 'family' in match and match['family'] != 'Unknown':
                            families.add(match['family'])
                    if families:
                        result.malware_family = ', '.join(families)
            except Exception as e:
                result.scan_errors.append(f"Ошибка при сканировании YARA: {str(e)}")

        if result.yara_matches:
            logger.info(f"Найдено {len(result.yara_matches)} совпадений по правилам YARA для файла {file_path.name}")
            result.scan_metadata['scan_duration_ms'] = (datetime.now() - start_time).total_seconds() * 1000
            return result

        # 3. Нечёткое хеширование (если включено)
        if self.signature_manager.is_scan_enabled('fuzzy') and SSDEEP_AVAILABLE:
            try:
                fuzzy_result = self._scan_by_fuzzy_hash(file_path)
                result.fuzzy_match = fuzzy_result
            except Exception as e:
                result.scan_errors.append(f"Ошибка при нечётком сканировании: {str(e)}")

        # 4. Проверка индикаторов компрометации в содержимом файла
        try:
            ioc_results = self._scan_for_iocs(file_path)
            result.ioc_matches = ioc_results
        except Exception as e:
            result.scan_errors.append(f"Ошибка при сканировании индикаторов компрометации: {str(e)}")

        result.scan_metadata['scan_duration_ms'] = (datetime.now() - start_time).total_seconds() * 1000
        return result

    def _scan_by_hash(self, file_path: Path) -> Optional[Dict]:
        """Проверка по базе криптографических хешей"""
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
                'threat_name': 'Известная Вредоносная Программа (Совпадение По Хешу)',
                'family': 'Unknown'
            }
        return None

    def _scan_by_fuzzy_hash(self, file_path: Path) -> Optional[Dict]:
        """Проверка по базе нечётких хешей"""
        if not SSDEEP_AVAILABLE:
            return None

        file_fuzzy = self._calculate_fuzzy_hash(file_path)
        if not file_fuzzy:
            return None

        fuzzy_database = self._load_fuzzy_hash_database()
        best_match = None
        best_score = 0

        for entry in fuzzy_database:
            score = self._compare_fuzzy_hashes(file_fuzzy, entry.get('hash', ''))
            if score > best_score and score >= 70:  # Порог совпадения 70%
                best_score = score
                best_match = entry

        if best_match:
            return {
                'type': 'ssdeep',
                'value': file_fuzzy,
                'matched_hash': best_match.get('hash'),
                'similarity_score': best_score,
                'source': 'fuzzy_database',
                'confidence': best_score,
                'threat_name': best_match.get('threat_name', 'Похожий образец'),
                'family': best_match.get('family', 'Unknown')
            }

        logger.debug(f"Нечёткий хеш для файла {file_path.name}: {file_fuzzy} (совпадений не обнаружено)")
        return None

    def _scan_by_yara(self, file_path: Path) -> List[Dict]:
        """Сканирование файла с использованием скомпилированных правил YARA"""
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
                    'strings': [str(s) for s in match.strings],
                    'tags': match.tags if hasattr(match, 'tags') else []
                })

            if matches:
                logger.info(f"Найдено {len(matches)} совпадений по правилам YARA для файла {file_path.name}")

        except yara.Error as e:
            logger.warning(f"Ошибка сканирования с использованием правил YARA: {e}")
        except Exception as e:
            logger.warning(f"Ошибка чтения файла для сканирования YARA: {e}")

        return matches

    def _scan_for_iocs(self, file_path: Path) -> List[Dict]:
        """Сканирование файла на наличие индикаторов компрометации"""
        iocs = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10 * 1024 * 1024)  # Первые 10 мегабайт

            # Извлечение индикаторов компрометации из содержимого
            extracted_iocs = NetworkIoCExtractor.extract_iocs(content)

            # Добавление URL
            for url in extracted_iocs.get('urls', []):
                if url['risk'] in ['High', 'Critical']:
                    iocs.append({
                        'type': 'url',
                        'value': url['value'],
                        'source': 'content_analysis',
                        'confidence': 75,
                        'risk': url['risk']
                    })

            # Добавление IP
            for ip in extracted_iocs.get('ips', []):
                iocs.append({
                    'type': 'ip',
                    'value': ip['value'],
                    'source': 'content_analysis',
                    'confidence': 70,
                    'risk': ip['risk']
                })

            # Добавление доменов
            for domain in extracted_iocs.get('domains', []):
                if domain['risk'] in ['High', 'Critical']:
                    iocs.append({
                        'type': 'domain',
                        'value': domain['value'],
                        'source': 'content_analysis',
                        'confidence': 75,
                        'risk': domain['risk']
                    })

            # Добавление хешей файлов
            for file_hash in extracted_iocs.get('file_hashes', []):
                iocs.append({
                    'type': f"hash_{file_hash['type']}",
                    'value': file_hash['value'],
                    'source': 'content_analysis',
                    'confidence': 85,
                    'risk': file_hash['risk']
                })

            # Проверка по базе известных индикаторов компрометации
            db_matches = self._check_ioc_database(content)
            iocs.extend(db_matches)

        except Exception as e:
            logger.warning(f"Ошибка сканирования индикаторов компрометации: {e}")

        return iocs

    def get_scan_summary(self, result: SignatureScanResult) -> str:
        """Получение краткой сводки результатов сканирования"""
        if result.hash_match:
            return f"⚠️ КРИТИЧЕСКОЕ СОВПАДЕНИЕ: {result.hash_match['threat_name']}"
        elif result.yara_matches:
            rules = ', '.join([m['rule_name'] for m in result.yara_matches[:3]])
            return f"⚠️ СОВПАДЕНИЯ ПО ПРАВИЛАМ YARA: {rules}"
        elif result.fuzzy_match:
            return f"⚠️ НЕЧЁТКОЕ СОВПАДЕНИЕ: {result.fuzzy_match['threat_name']} (совпадение: {result.fuzzy_match.get('similarity_score', 0)}%)"
        elif result.ioc_matches:
            return f"⚠️ ИНДИКАТОРЫ КОМПРОМЕТАЦИИ ОБНАРУЖЕНЫ: {len(result.ioc_matches)} записей"
        else:
            return "✅ Сигнатурных совпадений не найдено"

    def export_ioc_report(self, result: SignatureScanResult, output_path: Path) -> Path:
        """Экспорт отчёта с индикаторами компрометации в формате, совместимом с STIX"""
        report = {
            'report_id': hashlib.md5(f"{datetime.now().isoformat()}".encode()).hexdigest()[:32],
            'generated_at': datetime.now().isoformat(),
            'scanner_version': '2.0.0',
            'file_info': {
                'path': 'Недоступно',
                'size': result.scan_metadata.get('file_size', 0),
                'type': result.scan_metadata.get('file_type', 'unknown'),
                'hash_sha256': result.hash_match['value'] if result.hash_match else None
            },
            'threat_assessment': {
                'risk_level': result.risk_level,
                'confidence': result.confidence_score,
                'malware_family': result.malware_family
            },
            'indicators': {
                'hashes': [],
                'yara_rules': [],
                'network': [],
                'file_system': [],
                'behavioral': []
            },
            'threat_intelligence': result.threat_intel_data,
            'recommendations': self._generate_ioc_recommendations(result)
        }

        # Добавление хешей
        if result.hash_match:
            report['indicators']['hashes'].append({
                'type': 'sha256',
                'value': result.hash_match['value'],
                'confidence': 100
            })

        # Добавление правил YARA
        for yara in result.yara_matches:
            report['indicators']['yara_rules'].append({
                'rule_name': yara['rule_name'],
                'confidence': yara.get('confidence', 0)
            })

        # Добавление сетевых индикаторов компрометации
        for ioc in result.ioc_matches:
            if ioc['type'] in ['url', 'ip', 'domain']:
                report['indicators']['network'].append({
                    'type': ioc['type'],
                    'value': ioc['value'],
                    'risk': ioc.get('risk', 'Medium'),
                    'confidence': ioc.get('confidence', 0)
                })

        # Сохранение отчёта
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"Отчёт с индикаторами компрометации сохранён: {output_path}")
        return output_path

    def _generate_ioc_recommendations(self, result: SignatureScanResult) -> List[str]:
        """Генерация рекомендаций на основе обнаруженных индикаторов компрометации"""
        recommendations = []

        if result.hash_match:
            recommendations.append("Немедленно удалить файл - обнаружено точное совпадение с известной угрозой")
            recommendations.append("Заблокировать хеш в системах контроля целостности")

        if result.yara_matches:
            recommendations.append("Провести дополнительный динамический анализ")
            recommendations.append("Проверить систему на наличие других файлов с аналогичными сигнатурами")

        if result.ioc_matches:
            url_count = sum(1 for ioc in result.ioc_matches if ioc['type'] == 'url')
            ip_count = sum(1 for ioc in result.ioc_matches if ioc['type'] == 'ip')
            domain_count = sum(1 for ioc in result.ioc_matches if ioc['type'] == 'domain')

            if url_count > 0:
                recommendations.append(f"Заблокировать {url_count} подозрительных URL на уровне сети")
            if ip_count > 0:
                recommendations.append(f"Добавить {ip_count} IP-адресов в чёрный список межсетевого экрана")
            if domain_count > 0:
                recommendations.append(f"Заблокировать {domain_count} доменов в фильтре DNS")

        if result.threat_intel_data.get('virustotal'):
            vt_data = result.threat_intel_data['virustotal']
            detection_ratio = vt_data.get('detection_ratio', {})
            malicious = detection_ratio.get('malicious', 0)
            if malicious > 10:
                recommendations.append(f"Угроза подтверждена {malicious}/60 антивирусными движками платформы VirusTotal")

        if not recommendations:
            recommendations.append("Специфических рекомендаций нет. Продолжить мониторинг.")

        return recommendations

    def update_ioc_database(self, new_iocs: List[Dict]) -> int:
        """Обновление базы индикаторов компрометации"""
        added_count = 0

        for ioc in new_iocs:
            ioc_type = ioc.get('type', '')
            ioc_value = ioc.get('value', '')

            if not ioc_type or not ioc_value:
                continue

            if ioc_type not in self._ioc_database:
                self._ioc_database[ioc_type] = []

            # Проверка на дубликаты
            exists = any(existing.get('value') == ioc_value
                         for existing in self._ioc_database[ioc_type])

            if not exists:
                self._ioc_database[ioc_type].append({
                    'value': ioc_value,
                    'source': ioc.get('source', 'manual'),
                    'risk': ioc.get('risk', 'Medium'),
                    'confidence': ioc.get('confidence', 80),
                    'added_at': datetime.now().isoformat()
                })
                added_count += 1

        # Сохранение обновлённой базы
        ioc_file = Path("signatures/ioc_database.json")
        try:
            ioc_file.parent.mkdir(parents=True, exist_ok=True)
            with open(ioc_file, 'w', encoding='utf-8') as f:
                json.dump(self._ioc_database, f, indent=2, ensure_ascii=False)
            logger.info(f"База индикаторов компрометации обновлена: добавлено {added_count} новых записей")
        except Exception as e:
            logger.warning(f"Ошибка сохранения базы индикаторов компрометации: {e}")

        return added_count