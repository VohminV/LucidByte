"""
Класс управления конфигурацией приложения
"""
import os
import yaml
from pathlib import Path
from typing import Any, Dict


class Configuration:
    """Управление конфигурацией приложения с поддержкой YAML"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.configuration_path = Path(config_path)
        self.settings: Dict[str, Any] = self.load_configuration()
    
    def load_configuration(self) -> Dict[str, Any]:
        """
        Загрузка конфигурации из YAML файла
        Возвращает словарь с настройками
        """
        if not self.configuration_path.exists():
            # Если файл не найден, создаём конфигурацию по умолчанию
            default_config = self.get_default_config()
            self.save_configuration(default_config)
            return default_config
        
        try:
            with open(self.configuration_path, "r", encoding="utf-8") as file_handle:
                data = yaml.safe_load(file_handle)
            
            if data is None:
                return self.get_default_config()
            
            return data
        except yaml.YAMLError as exception:
            raise ValueError(f"Ошибка парсинга YAML файла конфигурации: {exception}")
    
    def save_configuration(self, config: Dict[str, Any]) -> None:
        """Сохранение конфигурации в YAML файл"""
        with open(self.configuration_path, "w", encoding="utf-8") as file_handle:
            yaml.dump(config, file_handle, default_flow_style=False, allow_unicode=True)
    
    def get_default_config(self) -> Dict[str, Any]:
        """Возвращает конфигурацию по умолчанию"""
        return {
            "application": {
                "name": "LucidByte",
                "version": "2.0.0",
                "theme": "dark"
            },
            "analysis": {
                "decompiler_path": "",
                "temp_directory": "temp",
                "enable_ghidra": True,
                "enable_signature_scan": True
            },
            "security": {
                "suspicious_permissions": [
                    "READ_SMS",
                    "SEND_SMS",
                    "READ_CONTACTS",
                    "ACCESS_FINE_LOCATION"
                ],
                "dangerous_api_calls": [
                    "Runtime.exec",
                    "DexClassLoader",
                    "ProcessBuilder"
                ],
                "risk_threshold": 70
            },
            "signatures": {
                "sources": {
                    "malwarebazaar": "https://bazaar.abuse.ch/export/",
                    "yara_rules": [
                        "https://raw.githubusercontent.com/Yara-Rules/rules/master/",
                        "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara-rules/",
                        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/"
                    ]
                },
                "update_interval_hours": 24,
                "fuzzy_hash_threshold": 90,
                "enable_sha256_scan": True,
                "enable_yara_scan": True,
                "enable_ssdeep_scan": True,
                "virustotal_api_key": null
            },
            "language_model": {
                "base_url": "http://localhost:11434",
                "model_name": "llama2"
            }
        }
    
    def get_application_name(self) -> str:
        return self.settings.get("application", {}).get("name", "Unknown")
    
    def get_application_version(self) -> str:
        return self.settings.get("application", {}).get("version", "0.0.0")
    
    def get_language_model_url(self) -> str:
        return self.settings.get("language_model", {}).get("base_url", "")
    
    def get_language_model_name(self) -> str:
        return self.settings.get("language_model", {}).get("model_name", "")
    
    def get_decompiler_path(self) -> str:
        return self.settings.get("analysis", {}).get("decompiler_path", "")
    
    def get_temp_directory(self) -> str:
        return self.settings.get("analysis", {}).get("temp_directory", "temp")
    
    def get_theme(self) -> str:
        return self.settings.get("application", {}).get("theme", "dark")
    
    def get_suspicious_permissions(self) -> list:
        return self.settings.get("security", {}).get("suspicious_permissions", [])
    
    def get_dangerous_api_calls(self) -> list:
        return self.settings.get("security", {}).get("dangerous_api_calls", [])
    
    def get_risk_threshold(self) -> int:
        return self.settings.get("security", {}).get("risk_threshold", 70)
    
    def get_signature_settings(self) -> Dict[str, Any]:
        """Получение настроек сигнатурного анализа"""
        return self.settings.get("signatures", {})