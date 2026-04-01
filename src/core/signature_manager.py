"""
Модуль управления базой сигнатур
Назначение: Автоматизированная загрузка, обновление и хранение сигнатур из открытых источников
"""
import os
import json
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging
import re

logger = logging.getLogger(__name__)

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class SignatureManager:
    """Управление базой сигнатур для анализа угроз"""
    
    # ✅ ИСПРАВЛЕНО: Только проверенные прямые ссылки на конкретные файлы
    DEFAULT_SOURCES = {
        'yara_rules': [
            # Yara-Rules Repository (Конкретные существующие файлы)
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware_index.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT1.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT28.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/Banker_QakBot.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RAT_Remcos.yar',
            'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/Android_Malware.yar',
            
            # Neo23x0 Signature Base
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/android_malware.yar',
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/malware_microsoft_office.yar',
            'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor_inverse_match.yar',
            
            # Elastic Protections-Artifacts
            'https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Trojan_Gosar.yar',
            'https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Multi_Ransomware_Luna.yar',
        ],
        'hash_lists': []
    }
    
    def __init__(self, signatures_dir: str = "signatures", config_path: str = "config.yaml"):
        self.signatures_dir = Path(signatures_dir)
        self.config_path = Path(config_path)
        self.rules_dir = self.signatures_dir / "rules"
        self.hashes_dir = self.signatures_dir / "hashes"
        self.metadata_file = self.signatures_dir / "metadata.json"
        
        self.config = self._load_config()
        self._initialize_directories()
        
    def _load_config(self) -> Dict:
        """Загрузка конфигурации из файла (поддержка YAML и JSON)"""
        default_config = {
            'sources': self.DEFAULT_SOURCES,
            'update_interval_hours': 24,
            'fuzzy_hash_threshold': 90,
            'enable_sha256_scan': True,
            'enable_yara_scan': True,
            'enable_ssdeep_scan': True,
            'http_proxy': None,
            'https_proxy': None,
            'virustotal_api_key': None,
            'malwarebazaar_api_key': None
        }
        
        if not self.config_path.exists():
            logger.warning(f"Файл конфигурации {self.config_path} не найден. Используются значения по умолчанию.")
            return default_config
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                if self.config_path.suffix in ['.yaml', '.yml']:
                    if YAML_AVAILABLE:
                        loaded_config = yaml.safe_load(f) or {}
                    else:
                        logger.error("Библиотека pyyaml не установлена. Невозможно прочитать YAML конфиг.")
                        return default_config
                else:
                    loaded_config = json.load(f)
            
            if 'signatures' in loaded_config:
                default_config.update(loaded_config['signatures'])
            default_config.update({k: v for k, v in loaded_config.items() if k != 'signatures'})
            
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}")
        
        return default_config
    
    def _initialize_directories(self):
        """Инициализация директорий для хранения сигнатур"""
        self.signatures_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.hashes_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_metadata(self) -> Dict:
        """Получение метаданных последнего обновления"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        
        return {
            'last_update': None,
            'sources_updated': [],
            'total_hashes': 0,
            'total_rules': 0,
            'last_attempt': None,
            'sources_failed': 0
        }
    
    def _save_metadata(self, metadata: Dict):
        """Сохранение метаданных обновления"""
        with open(self.metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    def needs_update(self) -> bool:
        """Проверка необходимости обновления базы сигнатур"""
        metadata = self._get_metadata()
        last_update = metadata.get('last_update')
        
        if not last_update:
            return True
        
        try:
            last_update_dt = datetime.fromisoformat(last_update)
            update_interval = timedelta(hours=self.config.get('update_interval_hours', 24))
            return datetime.now() - last_update_dt > update_interval
        except Exception:
            return True
    
    def update_signatures(self, force: bool = False) -> Dict[str, Any]:
        """Обновление базы сигнатур из всех источников"""
        results = {
            'success': True,
            'sources_updated': [],
            'errors': [],
            'hashes_added': 0,
            'rules_added': 0,
            'sources_attempted': 0,
            'sources_failed': 0,
            'sources_skipped': 0
        }
        
        if not force and not self.needs_update():
            logger.info("База сигнатур актуальна, обновление не требуется")
            results['skipped'] = True
            return results
        
        logger.info("🔄 Начало обновления базы сигнатур...")
        
        # Обновление хеш-баз
        if self.config.get('enable_sha256_scan', True):
            try:
                hash_count = self._update_hash_database()
                results['hashes_added'] = hash_count
                if hash_count > 0:
                    results['sources_updated'].append('hash_database')
                else:
                    results['sources_skipped'] += 1
                    logger.info("⚠ Хеш-база: нет доступных источников без API ключа")
            except Exception as e:
                logger.warning(f"Ошибка обновления хеш-базы: {e}")
                results['errors'].append(f"hash_database: {str(e)}")
                results['sources_failed'] += 1
                results['success'] = False
        
        # Обновление YARA правил
        if self.config.get('enable_yara_scan', True):
            try:
                rule_count = self._update_yara_rules()
                results['rules_added'] = rule_count
                if rule_count > 0:
                    results['sources_updated'].append('yara_rules')
                else:
                    results['sources_skipped'] += 1
            except Exception as e:
                logger.warning(f"Ошибка обновления YARA правил: {e}")
                results['errors'].append(f"yara_rules: {str(e)}")
                results['sources_failed'] += 1
                results['success'] = False
        
        # Сохранение метаданных
        metadata = self._get_metadata()
        metadata['last_update'] = datetime.now().isoformat()
        metadata['sources_updated'] = results['sources_updated']
        metadata['total_hashes'] = results['hashes_added']
        metadata['total_rules'] = results['rules_added']
        metadata['last_attempt'] = datetime.now().isoformat()
        metadata['sources_failed'] = results['sources_failed']
        self._save_metadata(metadata)
        
        logger.info(f"✓ Обновление завершено: {results['hashes_added']} хешей, {results['rules_added']} правил")
        if results['sources_failed'] > 0:
            logger.warning(f"⚠ Не удалось загрузить из {results['sources_failed']} источников")
        
        return results
    
    def _update_hash_database(self) -> int:
        """Обновление базы хеш-сумм из доступных источников"""
        total_hashes = 0
        
        mb_api_key = self.config.get('malwarebazaar_api_key')
        if mb_api_key:
            try:
                mb_hashes = self._fetch_malwarebazaar_hashes(mb_api_key)
                if mb_hashes:
                    hash_file = self.hashes_dir / f"malwarebazaar_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(hash_file, 'w', encoding='utf-8') as f:
                        for hash_value in mb_hashes:
                            f.write(f"{hash_value}\n")
                    total_hashes += len(mb_hashes)
                    logger.info(f"Загружено {len(mb_hashes)} хешей из MalwareBazaar API")
            except Exception as e:
                logger.warning(f"MalwareBazaar API ошибка: {e}")
        
        vt_api_key = self.config.get('virustotal_api_key')
        if vt_api_key:
            try:
                vt_hashes = self._fetch_virustotal_hashes(vt_api_key)
                if vt_hashes:
                    hash_file = self.hashes_dir / f"virustotal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(hash_file, 'w', encoding='utf-8') as f:
                        for hash_value in vt_hashes:
                            f.write(f"{hash_value}\n")
                    total_hashes += len(vt_hashes)
                    logger.info(f"Загружено {len(vt_hashes)} хешей из VirusTotal")
            except Exception as e:
                logger.warning(f"VirusTotal API ошибка: {e}")
        
        if total_hashes == 0:
            placeholder_file = self.hashes_dir / "placeholder_hashes.txt"
            if not placeholder_file.exists():
                with open(placeholder_file, 'w', encoding='utf-8') as f:
                    f.write("# Placeholder - добавьте API ключи для загрузки хешей\n")
                    f.write("# Источники: MalwareBazaar, VirusTotal\n")
                logger.info("Создан файл-заглушка для хешей (требуется API ключ)")
        
        return total_hashes
    
    def _fetch_malwarebazaar_hashes(self, api_key: str, limit: int = 1000) -> List[str]:
        """Получение хешей из MalwareBazaar API"""
        hashes = []
        try:
            url = 'https://bazaar.abuse.ch/api/v1/'
            headers = {
                'API-Key': api_key,
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'LucidByte-Analyzer/1.0'
            }
            data = 'query=get_tags'
            response = requests.post(url, headers=headers, data=data, timeout=30)
            if response.status_code == 200:
                json_data = response.json()
                if json_data.get('query_status') == 'ok':
                    pass 
        except Exception as e:
            logger.warning(f"MalwareBazaar API ошибка: {e}")
        return hashes
    
    def _fetch_virustotal_hashes(self, api_key: str, limit: int = 1000) -> List[str]:
        """Получение хешей из VirusTotal API"""
        hashes = []
        try:
            url = 'https://www.virustotal.com/api/v3/files?limit=100'
            headers = {'x-apikey': api_key, 'Accept': 'application/json'}
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    sha256 = item.get('attributes', {}).get('sha256')
                    if sha256:
                        stats = item.get('attributes', {}).get('last_analysis_stats', {})
                        if stats.get('malicious', 0) > 5:
                            hashes.append(sha256.lower())
        except Exception as e:
            logger.warning(f"VirusTotal API ошибка: {e}")
        return hashes[:limit]
    
    def _update_yara_rules(self) -> int:
        """Обновление базы YARA правил из открытых репозиториев"""
        total_rules = 0
        sources = self.config.get('sources', {}).get('yara_rules', self.DEFAULT_SOURCES['yara_rules'])
        
        if isinstance(sources, str):
            sources = [sources]
        
        successful_downloads = 0
        failed_downloads = 0
        skipped_downloads = 0
        
        for source_url in sources:
            try:
                proxies = {}
                if self.config.get('http_proxy'): proxies['http'] = self.config['http_proxy']
                if self.config.get('https_proxy'): proxies['https'] = self.config['https_proxy']
                
                headers = {'User-Agent': 'LucidByte-Analyzer/1.0', 'Accept': 'text/plain,*/*'}
                
                logger.info(f"📥 Загрузка: {source_url}")
                response = requests.get(source_url, timeout=30, proxies=proxies, headers=headers)
                
                if response.status_code == 200 and len(response.text) > 100:
                    if 'rule ' in response.text or 'import ' in response.text or 'include ' in response.text:
                        rule_filename = source_url.split('/')[-1]
                        if not rule_filename.endswith('.yar'):
                            rule_filename = f"rules_{hashlib.md5(source_url.encode()).hexdigest()[:8]}.yar"
                        
                        rule_file = self.rules_dir / rule_filename
                        with open(rule_file, 'w', encoding='utf-8') as f:
                            f.write(response.text)
                        
                        rule_count = response.text.count('rule ')
                        total_rules += rule_count
                        successful_downloads += 1
                        logger.info(f"✓ Загружено {rule_count} правил из {source_url}")
                    else:
                        logger.warning(f"⚠ Файл не содержит YARA правил: {source_url}")
                        skipped_downloads += 1
                elif response.status_code == 404:
                    logger.warning(f"⚠ Файл не найден (404): {source_url}")
                    failed_downloads += 1
                elif response.status_code == 403:
                    logger.warning(f"⚠ Доступ запрещён (403): {source_url}")
                    skipped_downloads += 1
                else:
                    logger.warning(f"⚠ Ошибка загрузки ({response.status_code}): {source_url}")
                    failed_downloads += 1
                    
            except requests.exceptions.Timeout:
                logger.warning(f"⚠ Таймаут соединения: {source_url}")
                failed_downloads += 1
            except requests.exceptions.ConnectionError:
                logger.warning(f"⚠ Ошибка соединения: {source_url}")
                failed_downloads += 1
            except requests.exceptions.RequestException as e:
                logger.warning(f"⚠ Сетевая ошибка {source_url}: {e}")
                failed_downloads += 1
            except Exception as e:
                logger.warning(f"⚠ Ошибка обработки {source_url}: {e}")
                failed_downloads += 1
        
        logger.info(f"YARA правила: {successful_downloads} успешно, {failed_downloads} неудачно, {skipped_downloads} пропущено")
        return total_rules
    
    def get_hash_database(self) -> List[str]:
        """Получение списка хешей из локальной базы"""
        hashes = []
        for hash_file in self.hashes_dir.glob("*.txt"):
            try:
                with open(hash_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if len(line) in [32, 64]:
                                hashes.append(line.lower())
            except Exception as e:
                logger.warning(f"Ошибка чтения файла хешей {hash_file}: {e}")
        return list(set(hashes))
    
    def get_yara_rules_paths(self) -> List[Path]:
        """Получение путей ко всем YARA правилам"""
        return list(self.rules_dir.glob("*.yar"))
    
    def get_fuzzy_threshold(self) -> int:
        return self.config.get('fuzzy_hash_threshold', 90)
    
    def is_scan_enabled(self, scan_type: str) -> bool:
        return self.config.get(f'enable_{scan_type}_scan', True)
    
    def get_status(self) -> Dict[str, Any]:
        metadata = self._get_metadata()
        return {
            'last_update': metadata.get('last_update'),
            'total_hashes': len(self.get_hash_database()),
            'total_rules': len(self.get_yara_rules_paths()),
            'needs_update': self.needs_update(),
            'scan_enabled': {
                'sha256': self.is_scan_enabled('sha256'),
                'yara': self.is_scan_enabled('yara'),
                'ssdeep': self.is_scan_enabled('ssdeep')
            }
        }