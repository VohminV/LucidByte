"""
Модуль управления базой сигнатур
Назначение: Автоматизированная загрузка, обновление и хранение сигнатур из открытых источников,
интеграция с платформами разведки угроз, управление индикаторами компрометации и нечёткими хешами.
"""
import os
import json
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import logging
import time

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logging.warning("Библиотека pyyaml не установлена. Конфигурация в формате YAML недоступна.")

logger = logging.getLogger(__name__)


class SignatureManager:
    """Управление базой сигнатур для анализа угроз."""

    DEFAULT_SOURCES = {
        'yara_rules': [
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware_index.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT1.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT28.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/Banker_QakBot.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RAT_Remcos.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/Android_Malware.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/anti_av/Android_AntiAnalysis.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/anti_vm/VM_General.yar',
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/android_malware.yar',
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/malware_microsoft_office.yar',
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_apt29.yar',
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_lazarus.yar',
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/espionage_general.yar',
            'https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Gosar.yar',
            'https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Ransomware_Luna.yar',
            'https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Win_Trojan_Remcos.yar',
            'https://raw.githubusercontent.com/advanced-threat-research/Yara-Rules/master/Android/Android_Malware.yar',
            'https://raw.githubusercontent.com/stratosphereips/yara-rules/master/malware/android/android_malware.yar',
        ],
        'hash_lists': []
    }

    def __init__(self, signatures_dir: str = "signatures", config_path: str = "config.yaml"):
        self.signatures_dir = Path(signatures_dir)
        self.config_path = Path(config_path)
        self.rules_dir = self.signatures_dir / "rules"
        self.hashes_dir = self.signatures_dir / "hashes"
        self.ioc_dir = self.signatures_dir / "ioc"
        self.fuzzy_dir = self.signatures_dir / "fuzzy"
        self.metadata_file = self.signatures_dir / "metadata.json"
        
        self.config = self._load_config()
        self._initialize_directories()
        self._api_rate_limit_delay = 1.0
        self._ioc_database: Dict[str, List[Dict]] = {}
        self._fuzzy_database: List[Dict] = []
        self._load_ioc_database()
        self._load_fuzzy_database()

    def _load_config(self) -> Dict:
        """Загрузка конфигурации из файла с поддержкой форматов YAML и JSON."""
        default_config = {
            'sources': self.DEFAULT_SOURCES,
            'update_interval_hours': 24,
            'enable_sha256_scan': True,
            'enable_yara_scan': True,
            'enable_fuzzy_scan': False,
            'http_proxy': None,
            'https_proxy': None,
            'virustotal_api_key': None,
            'malwarebazaar_api_key': None,
            'misp_url': None,
            'misp_api_key': None
        }
        
        if not self.config_path.exists():
            logger.warning(f"Файл конфигурации {self.config_path} не найден. Используются значения по умолчанию.")
            return default_config
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as config_file:
                if self.config_path.suffix in ['.yaml', '.yml']:
                    if YAML_AVAILABLE:
                        loaded_config = yaml.safe_load(config_file) or {}
                    else:
                        logger.error("Библиотека pyyaml не установлена. Невозможно прочитать конфигурацию в формате YAML.")
                        return default_config
                else:
                    loaded_config = json.load(config_file)
            
            if 'signatures' in loaded_config:
                default_config.update(loaded_config['signatures'])
            default_config.update({key: value for key, value in loaded_config.items() if key != 'signatures'})
            
        except Exception as configuration_error:
            logger.error(f"Ошибка загрузки конфигурации: {configuration_error}")
        
        return default_config

    def _initialize_directories(self) -> None:
        """Инициализация директорий для хранения сигнатур и индикаторов."""
        self.signatures_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.hashes_dir.mkdir(parents=True, exist_ok=True)
        self.ioc_dir.mkdir(parents=True, exist_ok=True)
        self.fuzzy_dir.mkdir(parents=True, exist_ok=True)

    def _get_metadata(self) -> Dict:
        """Получение метаданных последнего обновления базы сигнатур."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as metadata_file:
                    return json.load(metadata_file)
            except Exception:
                pass
        
        return {
            'last_update': None,
            'sources_updated': [],
            'total_hashes': 0,
            'total_rules': 0,
            'total_iocs': 0,
            'last_attempt': None,
            'sources_failed': 0
        }

    def _save_metadata(self, metadata: Dict) -> None:
        """Сохранение метаданных обновления базы сигнатур."""
        with open(self.metadata_file, 'w', encoding='utf-8') as metadata_file:
            json.dump(metadata, metadata_file, indent=2, ensure_ascii=False)

    def needs_update(self) -> bool:
        """Проверка необходимости обновления базы сигнатур согласно установленному интервалу."""
        metadata = self._get_metadata()
        last_update = metadata.get('last_update')
        
        if not last_update:
            return True
        
        try:
            last_update_datetime = datetime.fromisoformat(last_update)
            update_interval = timedelta(hours=self.config.get('update_interval_hours', 24))
            return datetime.now() - last_update_datetime > update_interval
        except Exception:
            return True

    def validate_api_keys(self) -> Dict[str, bool]:
        """Проверка работоспособности ключей внешних платформ разведки угроз."""
        validation_results = {
            'malwarebazaar': False,
            'virustotal': False,
            'misp': False
        }
        
        malwarebazaar_api_key = self.config.get('malwarebazaar_api_key')
        if malwarebazaar_api_key:
            try:
                request_url = 'https://bazaar.abuse.ch/api/v1/'
                request_headers = {
                    'API-Key': malwarebazaar_api_key,
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'LucidByte-Analyzer/1.0'
                }
                request_data = 'query=get_tags'
                response = requests.post(request_url, headers=request_headers, data=request_data, timeout=10)
                if response.status_code == 200:
                    response_json = response.json()
                    if response_json.get('query_status') == 'ok':
                        validation_results['malwarebazaar'] = True
            except Exception as validation_error:
                logger.warning(f"Ошибка валидации MalwareBazaar API: {validation_error}")
        
        virustotal_api_key = self.config.get('virustotal_api_key')
        if virustotal_api_key:
            try:
                request_url = 'https://www.virustotal.com/api/v3/files/search?query=1'
                request_headers = {'x-apikey': virustotal_api_key, 'Accept': 'application/json'}
                response = requests.get(request_url, headers=request_headers, timeout=10)
                if response.status_code in [200, 404]:
                    validation_results['virustotal'] = True
            except Exception as validation_error:
                logger.warning(f"Ошибка валидации VirusTotal API: {validation_error}")
        
        misp_url = self.config.get('misp_url')
        misp_api_key = self.config.get('misp_api_key')
        if misp_url and misp_api_key:
            try:
                request_url = f"{misp_url}/attributes/describeTypes.json"
                request_headers = {'Authorization': misp_api_key, 'Accept': 'application/json'}
                response = requests.get(request_url, headers=request_headers, timeout=10, verify=False)
                if response.status_code == 200:
                    validation_results['misp'] = True
            except Exception as validation_error:
                logger.warning(f"Ошибка валидации MISP API: {validation_error}")
        
        return validation_results

    def update_signatures(self, force: bool = False) -> Dict[str, Any]:
        """Обновление базы сигнатур из всех конфигурируемых источников."""
        update_results = {
            'success': True,
            'sources_updated': [],
            'errors': [],
            'hashes_added': 0,
            'rules_added': 0,
            'iocs_added': 0, 
            'sources_attempted': 0, 
            'sources_failed': 0,
            'sources_skipped': 0
        }
        
        if not force and not self.needs_update():
            logger.info("База сигнатур актуальна. Обновление не требуется.")
            update_results['skipped'] = True
            return update_results
        
        logger.info("Начало обновления базы сигнатур и индикаторов компрометации...")
        
        if self.config.get('enable_sha256_scan', True):
            try:
                hash_count = self._update_hash_database()
                update_results['hashes_added'] = hash_count
                if hash_count > 0:
                    update_results['sources_updated'].append('hash_database')
                else:
                    update_results['sources_skipped'] += 1
                    logger.info("Хеш-база: отсутствуют доступные источники без ключа API.")
            except Exception as update_error:
                logger.warning(f"Ошибка обновления хеш-базы: {update_error}")
                update_results['errors'].append(f"hash_database: {str(update_error)}")
                update_results['sources_failed'] += 1
                update_results['success'] = False
        
        if self.config.get('enable_yara_scan', True):
            try:
                rule_count = self._update_yara_rules()
                update_results['rules_added'] = rule_count
                if rule_count > 0:
                    update_results['sources_updated'].append('yara_rules')
                else:
                    update_results['sources_skipped'] += 1
            except Exception as update_error:
                logger.warning(f"Ошибка обновления правил YARA: {update_error}")
                update_results['errors'].append(f"yara_rules: {str(update_error)}")
                update_results['sources_failed'] += 1
                update_results['success'] = False
        
        if self.config.get('misp_url') and self.config.get('misp_api_key'):
            try:
                ioc_count = self._update_ioc_from_misp()
                update_results['iocs_added'] = ioc_count
                if ioc_count > 0:
                    update_results['sources_updated'].append('misp_iocs')
            except Exception as update_error:
                logger.warning(f"Ошибка обновления индикаторов компрометации из MISP: {update_error}")
                update_results['errors'].append(f"misp_iocs: {str(update_error)}")
                update_results['sources_failed'] += 1
        
        metadata = self._get_metadata()
        metadata['last_update'] = datetime.now().isoformat()
        metadata['sources_updated'] = update_results['sources_updated']
        metadata['total_hashes'] = update_results['hashes_added']
        metadata['total_rules'] = update_results['rules_added']
        metadata['total_iocs'] = sum(len(indicators) for indicators in self._ioc_database.values())
        metadata['last_attempt'] = datetime.now().isoformat()
        metadata['sources_failed'] = update_results['sources_failed']
        self._save_metadata(metadata)
        
        logger.info(f"Обновление завершено: {update_results['hashes_added']} хешей, {update_results['rules_added']} правил, {update_results['iocs_added']} индикаторов.")
        if update_results['sources_failed'] > 0:
            logger.warning(f"Не удалось загрузить данные из {update_results['sources_failed']} источников.")
        
        return update_results

    def _update_hash_database(self) -> int:
        """Обновление базы хеш-сумм из доступных внешних источников."""
        total_hashes = 0
        
        malwarebazaar_api_key = self.config.get('malwarebazaar_api_key')
        if malwarebazaar_api_key:
            try:
                malwarebazaar_hashes = self._fetch_malwarebazaar_hashes(malwarebazaar_api_key)
                if malwarebazaar_hashes:
                    hash_file = self.hashes_dir / f"malwarebazaar_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(hash_file, 'w', encoding='utf-8') as output_file:
                        for hash_value in malwarebazaar_hashes:
                            output_file.write(f"{hash_value}\n")
                    total_hashes += len(malwarebazaar_hashes)
                    logger.info(f"Загружено {len(malwarebazaar_hashes)} хешей из MalwareBazaar API.")
            except Exception as fetch_error:
                logger.warning(f"Ошибка запроса к MalwareBazaar API: {fetch_error}")
        
        virustotal_api_key = self.config.get('virustotal_api_key')
        if virustotal_api_key:
            try:
                virustotal_hashes = self._fetch_virustotal_hashes(virustotal_api_key)
                if virustotal_hashes:
                    hash_file = self.hashes_dir / f"virustotal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(hash_file, 'w', encoding='utf-8') as output_file:
                        for hash_value in virustotal_hashes:
                            output_file.write(f"{hash_value}\n")
                    total_hashes += len(virustotal_hashes)
                    logger.info(f"Загружено {len(virustotal_hashes)} хешей из VirusTotal API.")
            except Exception as fetch_error:
                logger.warning(f"Ошибка запроса к VirusTotal API: {fetch_error}")
        
        if total_hashes == 0:
            placeholder_file = self.hashes_dir / "placeholder_hashes.txt"
            if not placeholder_file.exists():
                with open(placeholder_file, 'w', encoding='utf-8') as output_file:
                    output_file.write("# Placeholder - добавьте ключи API для загрузки хешей\n")
                    output_file.write("# Источники: MalwareBazaar, VirusTotal\n")
                logger.info("Создан файл-заглушка для хешей. Требуется настройка ключей API.")
        
        return total_hashes

    def _fetch_malwarebazaar_hashes(self, api_key: str, limit: int = 1000) -> List[str]:
        """Получение хеш-сумм из MalwareBazaar API."""
        hashes = []
        try:
            request_url = 'https://bazaar.abuse.ch/api/v1/'
            request_headers = {
                'API-Key': api_key,
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'LucidByte-Analyzer/1.0'
            }
            request_data = 'query=get_recent&selector=files'
            response = requests.post(request_url, headers=request_headers, data=request_data, timeout=30)
            
            if response.status_code == 200:
                response_json = response.json()
                if response_json.get('query_status') == 'ok':
                    files = response_json.get('data', [])
                    for file_information in files[:limit]:
                        sha256_hash = file_information.get('sha256')
                        if sha256_hash:
                            hashes.append(sha256_hash.lower())
                    time.sleep(self._api_rate_limit_delay)
        except Exception as fetch_error:
            logger.warning(f"Ошибка получения данных из MalwareBazaar API: {fetch_error}")
        return hashes

    def _fetch_virustotal_hashes(self, api_key: str, limit: int = 1000) -> List[str]:
        """Получение хеш-сумм из VirusTotal API с поддержкой пагинации."""
        hashes = []
        cursor = None
        fetched_count = 0
        
        try:
            while fetched_count < limit:
                request_url = 'https://www.virustotal.com/api/v3/files?limit=100'
                if cursor:
                    request_url += f'&cursor={cursor}'
                
                request_headers = {'x-apikey': api_key, 'Accept': 'application/json'}
                response = requests.get(request_url, headers=request_headers, timeout=30)
                 
                if response.status_code == 200:
                    response_data = response.json()
                    for item in response_data.get('data', []):
                        sha256_hash = item.get('attributes', {}).get('sha256')
                        if sha256_hash:
                            analysis_stats = item.get('attributes', {}).get('last_analysis_stats', {})
                            if analysis_stats.get('malicious', 0) > 5:
                                hashes.append(sha256_hash.lower())
                                fetched_count += 1
                    
                    meta_information = response_data.get('meta', {})
                    cursor = meta_information.get('cursor')
                    if not cursor:
                        break
                    
                    time.sleep(self._api_rate_limit_delay)
                else:
                    logger.warning(f"Ошибка запроса к VirusTotal API. Код ответа: {response.status_code}")
                    break
        except Exception as fetch_error:
            logger.warning(f"Ошибка получения данных из VirusTotal API: {fetch_error}")
        
        return hashes[:limit]

    def _update_yara_rules(self) -> int:
        """Обновление базы правил YARA из открытых репозиториев."""
        total_rules = 0
        sources = self.config.get('sources', {}).get('yara_rules', self.DEFAULT_SOURCES['yara_rules'])
        
        if isinstance(sources, str):
            sources = [sources]
        
        successful_downloads = 0
        failed_downloads = 0
        skipped_downloads = 0
        
        for source_url in sources:
            if not source_url.strip().endswith('.yar'):
                logger.debug(f"Пропуск источника (не файл с расширением .yar): {source_url}")
                skipped_downloads += 1
                continue
                
            try:
                proxies = {}
                if self.config.get('http_proxy'):
                    proxies['http'] = self.config['http_proxy']
                if self.config.get('https_proxy'):
                    proxies['https'] = self.config['https_proxy']
                
                headers = {
                    'User-Agent': 'LucidByte-Analyzer/1.0', 
                    'Accept': 'text/plain,*/*'
                }
                
                logger.info(f"Загрузка правила YARA: {source_url}")
                response = requests.get(source_url, timeout=30, proxies=proxies, headers=headers)
                
                if response.status_code == 200 and len(response.text) > 100:
                    if 'rule' in response.text or 'import' in response.text or 'include' in response.text:
                        rule_filename = source_url.split('/')[-1]
                        if not rule_filename.endswith('.yar'):
                            rule_filename = f"rules_{hashlib.md5(source_url.encode()).hexdigest()[:8]}.yar"
                        
                        rule_file = self.rules_dir / rule_filename
                        with open(rule_file, 'w', encoding='utf-8') as file_handle:
                            file_handle.write(response.text)
                        
                        rule_count = response.text.count('rule')
                        total_rules += rule_count
                        successful_downloads += 1
                        logger.info(f"Загружено {rule_count} правил из источника: {source_url}")
                    else:
                        logger.warning(f"Файл не содержит правил YARA: {source_url}")
                        skipped_downloads += 1
                elif response.status_code == 404:
                    logger.warning(f"Файл не найден (код 404): {source_url}")
                    failed_downloads += 1
                elif response.status_code == 403:
                    logger.warning(f"Доступ запрещён (код 403): {source_url}")
                    skipped_downloads += 1
                elif response.status_code == 400:
                    logger.warning(f"Некорректный запрос (код 400). Проверьте ссылку: {source_url}")
                    skipped_downloads += 1
                else:
                    logger.warning(f"Ошибка загрузки (код {response.status_code}): {source_url}")
                    failed_downloads += 1
                
                time.sleep(0.5)
                
            except requests.exceptions.Timeout:
                logger.warning(f"Таймаут соединения: {source_url}")
                failed_downloads += 1
            except requests.exceptions.ConnectionError:
                logger.warning(f"Ошибка соединения: {source_url}")
                failed_downloads += 1
            except requests.exceptions.RequestException as exception:
                logger.warning(f"Сетевая ошибка при обращении к {source_url}: {exception}")
                failed_downloads += 1
            except Exception as exception:
                logger.warning(f"Ошибка обработки файла {source_url}: {exception}")
                failed_downloads += 1
        
        logger.info(f"Статистика обновления правил YARA: {successful_downloads} успешно, {failed_downloads} неудачно, {skipped_downloads} пропущено.")
        return total_rules

    def query_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """Запрос подробной информации о файле в платформе VirusTotal."""
        virustotal_api_key = self.config.get('virustotal_api_key')
        if not virustotal_api_key:
            return {'error': 'Ключ API VirusTotal не настроен в конфигурации.'}
        
        try:
            request_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            request_headers = {'x-apikey': virustotal_api_key}
            response = requests.get(request_url, headers=request_headers, timeout=30)
            
            if response.status_code == 200:
                response_data = response.json()
                attributes = response_data.get('data', {}).get('attributes', {})
                
                return {
                    'detection_ratio': attributes.get('last_analysis_stats', {}),
                    'malware_names': self._extract_malware_names_from_vt(response_data),
                    'first_seen': attributes.get('first_submission_date'),
                    'last_seen': attributes.get('last_analysis_date'),
                    'reputation': attributes.get('reputation', 0),
                    'tags': attributes.get('tags', []),
                    'family': self._detect_family_from_tags(attributes.get('tags', [])),
                    'type_description': attributes.get('type_description', 'Unknown'),
                    'size': attributes.get('size', 0),
                    'names': attributes.get('names', [])
                }
            elif response.status_code == 404:
                return {'error': 'Файл не найден в базе данных VirusTotal.'}
            else:
                return {'error': f'Ошибка API. Код состояния: {response.status_code}'}
        except Exception as query_error:
            return {'error': f'Исключение при выполнении запроса: {str(query_error)}'}

    def query_malwarebazaar(self, sha256: str) -> Dict[str, Any]:
        """Запрос информации о файле в платформе MalwareBazaar."""
        malwarebazaar_api_key = self.config.get('malwarebazaar_api_key')
        if not malwarebazaar_api_key:
            return {'error': 'Ключ API MalwareBazaar не настроен в конфигурации.'}
        
        try:
            request_url = 'https://bazaar.abuse.ch/api/v1/'
            request_headers = {
                'API-Key': malwarebazaar_api_key,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            request_data = f'query=get_info&hash={sha256}'
            response = requests.post(request_url, headers=request_headers, data=request_data, timeout=30)
            
            if response.status_code == 200:
                response_json = response.json()
                if response_json.get('query_status') == 'ok':
                    file_data = response_json['data'][0]
                    return {
                        'file_name': file_data.get('file_name'),
                        'file_size': file_data.get('file_size'),
                        'file_type': file_data.get('file_type'),
                        'mime_type': file_data.get('mime_type'),
                        'tags': file_data.get('tags', []),
                        'vendor_intel': file_data.get('vendor_intel', {}),
                        'signature': file_data.get('signature'),
                        'family': file_data.get('family'),
                        'first_seen': file_data.get('first_seen'),
                        'last_seen': file_data.get('last_seen'),
                        'delivery_method': file_data.get('delivery_method'),
                        'imphash': file_data.get('imphash'),
                        'tlsh': file_data.get('tlsh'),
                        'ssdeep': file_data.get('ssdeep')
                    }
            return {'error': 'Файл не найден или произошла ошибка API.'}
        except Exception as query_error:
            return {'error': f'Исключение при выполнении запроса: {str(query_error)}'}

    def query_misp(self, indicators: Dict[str, List[str]]) -> List[Dict]:
        """Сравнение индикаторов с базой данных платформы MISP."""
        misp_url = self.config.get('misp_url')
        misp_api_key = self.config.get('misp_api_key')
        
        if not misp_url or not misp_api_key:
            logger.warning("Интеграция с MISP отключена: отсутствуют адрес сервера или ключ API.")
            return []
        
        matches = []
        try:
            search_attributes = []
            for indicator_type, values in indicators.items():
                for value in values[:50]:
                    search_attributes.append({
                        'type': indicator_type,
                        'value': value,
                        'to_ids': True
                    })
            
            if not search_attributes:
                return matches
            
            request_url = f"{misp_url}/attributes/restSearch"
            request_headers = {
                'Authorization': misp_api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            request_payload = json.dumps({'request': {'Attribute': search_attributes}})
            
            response = requests.post(request_url, headers=request_headers, data=request_payload, timeout=30, verify=False)
            
            if response.status_code == 200:
                response_data = response.json()
                attributes = response_data.get('response', {}).get('Attribute', [])
                
                for attribute in attributes:
                    matches.append({
                        'uuid': attribute.get('uuid'),
                        'type': attribute.get('type'),
                        'value': attribute.get('value'),
                        'category': attribute.get('category'),
                        'to_ids': attribute.get('to_ids'),
                        'timestamp': attribute.get('timestamp'),
                        'event_id': attribute.get('event_id'),
                        'threat_level': attribute.get('event', {}).get('threat_level_id'),
                        'info': attribute.get('event', {}).get('info')
                    })
                    
                logger.info(f"MISP: найдено {len(matches)} совпадений для запрошенных индикаторов.")
            else:
                logger.warning(f"MISP API ошибка. Код состояния: {response.status_code}")
                
        except Exception as query_error:
            logger.warning(f"Ошибка выполнения запроса к MISP: {query_error}")
        
        return matches

    def _update_ioc_from_misp(self) -> int:
        """Обновление локальной базы индикаторов компрометации из платформы MISP."""
        misp_url = self.config.get('misp_url')
        misp_api_key = self.config.get('misp_api_key')
        
        if not misp_url or not misp_api_key:
            return 0
        
        new_iocs_count = 0
        try:
            request_url = f"{misp_url}/attributes/restSearch"
            request_headers = {
                'Authorization': misp_api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            request_payload = json.dumps({
                'request': {
                    'to_ids': True,
                    'limit': 500,
                    'page': 1,
                    'sort': ['timestamp', 'desc']
                }
            })
            
            response = requests.post(request_url, headers=request_headers, data=request_payload, timeout=60, verify=False)
            
            if response.status_code == 200:
                response_data = response.json()
                attributes = response_data.get('response', {}).get('Attribute', [])
                
                for attribute in attributes:
                    ioc_type = attribute.get('type')
                    ioc_value = attribute.get('value')
                    
                    if ioc_type and ioc_value and ioc_type in ['ip-dst', 'domain', 'url', 'md5', 'sha1', 'sha256']:
                        normalized_type = ioc_type.replace('-', '_')
                        if normalized_type not in self._ioc_database:
                            self._ioc_database[normalized_type] = []
                        
                        exists = any(existing.get('value') == ioc_value for existing in self._ioc_database[normalized_type])
                        if not exists:
                            self._ioc_database[normalized_type].append({
                                'value': ioc_value,
                                'source': 'misp',
                                'risk': 'High',
                                'confidence': 90,
                                'category': attribute.get('category'),
                                'added_at': datetime.now().isoformat()
                            })
                            new_iocs_count += 1
                
                self._save_ioc_database()
                logger.info(f"MISP: обновлено {new_iocs_count} новых индикаторов.")
            else:
                logger.warning(f"Обновление базы MISP не выполнено. Код состояния: {response.status_code}")
                
        except Exception as update_error:
            logger.warning(f"Ошибка обновления индикаторов из MISP: {update_error}")
        
        return new_iocs_count

    def _extract_malware_names_from_vt(self, vt_data: Dict) -> List[str]:
        """Извлечение имён вредоносных программ из отчёта платформы VirusTotal."""
        names = []
        detections = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
        for vendor, result in detections.items():
            if result.get('category') == 'malicious':
                names.append(f"{vendor}: {result.get('result', 'Unknown')}")
        return names

    def _detect_family_from_tags(self, tags: List[str]) -> Optional[str]:
        """Определение семейства вредоносного программного обеспечения по тегам."""
        family_keywords = {
            'ransomware': ['ransomware', 'encrypt', 'lock', 'cryptolocker'],
            'trojan': ['trojan', 'backdoor', 'rat', 'remote_access'],
            'spyware': ['spy', 'keylog', 'stealer', 'infostealer'],
            'banker': ['banker', 'bank', 'financial', 'fakeapp'],
            'adware': ['adware', 'ad', 'popup'],
            'worm': ['worm', 'propagate', 'self_replicating'],
            'rootkit': ['rootkit', 'kernel', 'hide']
        }
        
        tags_lower = [tag.lower() for tag in tags]
        
        for family, keywords in family_keywords.items():
            if any(keyword in ' '.join(tags_lower) for keyword in keywords):
                return family
        
        return None

    def _load_ioc_database(self) -> None:
        """Загрузка базы индикаторов компрометации из файловой системы."""
        ioc_file = self.ioc_dir / "ioc_database.json"
        if ioc_file.exists():
            try:
                with open(ioc_file, 'r', encoding='utf-8') as database_file:
                    self._ioc_database = json.load(database_file)
                logger.info(f"Загружена база индикаторов компрометации: {sum(len(indicators) for indicators in self._ioc_database.values())} записей.")
            except Exception as load_error:
                logger.warning(f"Ошибка загрузки базы индикаторов: {load_error}")
                self._ioc_database = {}

    def _save_ioc_database(self) -> None:
        """Сохранение базы индикаторов компрометации в файловую систему."""
        ioc_file = self.ioc_dir / "ioc_database.json"
        try:
            with open(ioc_file, 'w', encoding='utf-8') as database_file:
                json.dump(self._ioc_database, database_file, indent=2, ensure_ascii=False)
        except Exception as save_error:
            logger.warning(f"Ошибка сохранения базы индикаторов: {save_error}")

    def search_ioc(self, value: str) -> List[Dict]:
        """Поиск индикатора в локальной базе данных."""
        matches = []
        for indicator_type, indicators in self._ioc_database.items():
            for indicator in indicators:
                if indicator.get('value') == value:
                    matches.append({
                        'type': indicator_type,
                        'value': indicator['value'],
                        'source': indicator.get('source'),
                        'risk': indicator.get('risk'),
                        'confidence': indicator.get('confidence'),
                        'added_at': indicator.get('added_at')
                    })
        return matches

    def add_ioc(self, ioc_type: str, value: str, source: str = "manual", risk: str = "Medium", confidence: int = 80) -> bool:
        """Добавление нового индикатора в базу данных."""
        if not ioc_type or not value:
            return False
        
        if ioc_type not in self._ioc_database:
            self._ioc_database[ioc_type] = []
        
        exists = any(existing.get('value') == value for existing in self._ioc_database[ioc_type])
        if not exists:
            self._ioc_database[ioc_type].append({
                'value': value,
                'source': source,
                'risk': risk,
                'confidence': confidence,
                'added_at': datetime.now().isoformat()
            })
            self._save_ioc_database()
            return True
        return False

    def _load_fuzzy_database(self) -> None:
        """Загрузка базы нечётких хешей из файловой системы."""
        fuzzy_file = self.fuzzy_dir / "fuzzy_hashes.json"
        if fuzzy_file.exists():
            try:
                with open(fuzzy_file, 'r', encoding='utf-8') as database_file:
                    self._fuzzy_database = json.load(database_file)
                logger.info(f"Загружена база нечётких хешей: {len(self._fuzzy_database)} записей.")
            except Exception as load_error:
                logger.warning(f"Ошибка загрузки базы нечётких хешей: {load_error}")
                self._fuzzy_database = []

    def _save_fuzzy_database(self) -> None:
        """Сохранение базы нечётких хешей в файловую систему."""
        fuzzy_file = self.fuzzy_dir / "fuzzy_hashes.json"
        try:
            with open(fuzzy_file, 'w', encoding='utf-8') as database_file:
                json.dump(self._fuzzy_database, database_file, indent=2, ensure_ascii=False)
        except Exception as save_error:
            logger.warning(f"Ошибка сохранения базы нечётких хешей: {save_error}")

    def get_fuzzy_hash_record(self, hash_value: str) -> Optional[Dict]:
        """Получение записи нечёткого хеша по значению."""
        for record in self._fuzzy_database:
            if record.get('hash') == hash_value:
                return record
        return None

    def add_fuzzy_hash(self, hash_value: str, threat_name: str, family: str = "Unknown", metadata: Optional[Dict] = None) -> bool:
        """Добавление записи нечёткого хеша в базу данных."""
        if not hash_value:
            return False
        
        exists = any(record.get('hash') == hash_value for record in self._fuzzy_database)
        if not exists:
            self._fuzzy_database.append({
                'hash': hash_value,
                'threat_name': threat_name,
                'family': family,
                'metadata': metadata or {},
                'added_at': datetime.now().isoformat()
            })
            self._save_fuzzy_database()
            return True
        return False

    def get_hash_database(self) -> List[str]:
        """Получение списка хешей из локальной базы данных."""
        hashes = []
        for hash_file in self.hashes_dir.glob("*.txt"):
            try:
                with open(hash_file, 'r', encoding='utf-8') as file_handle:
                    for line in file_handle:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if len(line) in [32, 64]:
                                hashes.append(line.lower())
            except Exception as read_error:
                logger.warning(f"Ошибка чтения файла хешей {hash_file}: {read_error}")
        return list(set(hashes))

    def get_yara_rules_paths(self) -> List[Path]:
        """Получение путей ко всем загруженным правилам YARA."""
        return list(self.rules_dir.glob("*.yar"))

    def is_scan_enabled(self, scan_type: str) -> bool:
        """Проверка активации конкретного типа сканирования в конфигурации."""
        return self.config.get(f'enable_{scan_type}_scan', True)

    def get_status(self) -> Dict[str, Any]:
        """Получение текущего статуса менеджера сигнатур."""
        metadata = self._get_metadata()
        return {
            'last_update': metadata.get('last_update'),
            'total_hashes': len(self.get_hash_database()),
            'total_rules': len(self.get_yara_rules_paths()),
            'total_iocs': sum(len(indicators) for indicators in self._ioc_database.values()),
            'total_fuzzy_hashes': len(self._fuzzy_database),
            'needs_update': self.needs_update(),
            'scan_enabled': {
                'sha256': self.is_scan_enabled('sha256'),
                'yara': self.is_scan_enabled('yara'),
                'fuzzy': self.is_scan_enabled('fuzzy')
            },
            'api_keys_valid': self.validate_api_keys()
        }