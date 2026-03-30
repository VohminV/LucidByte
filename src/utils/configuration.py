import os
import yaml
from pathlib import Path

class Configuration:
    def __init__(self, config_path: str = "config.yaml"):
        self.configuration_path = Path(config_path)
        self.settings = self.load_configuration()

    def load_configuration(self) -> dict:
        if not self.configuration_path.exists():
            raise FileNotFoundError("Файл конфигурации не найден")
        
        with open(self.configuration_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
        
        return data

    def get_application_name(self) -> str:
        return self.settings["application"]["name"]

    def get_application_version(self) -> str:
        return self.settings["application"]["version"]

    def get_language_model_url(self) -> str:
        return self.settings["language_model"]["base_url"]

    def get_language_model_name(self) -> str:
        return self.settings["language_model"]["model_name"]

    def get_decompiler_path(self) -> str:
        return self.settings["analysis"]["decompiler_path"]

    def get_temp_directory(self) -> str:
        return self.settings["analysis"]["temp_directory"]

    def get_theme(self) -> str:
        return self.settings["application"]["theme"]

    def get_suspicious_permissions(self) -> list:
        return self.settings["security"]["suspicious_permissions"]

    def get_dangerous_api_calls(self) -> list:
        return self.settings["security"]["dangerous_api_calls"]

    def get_risk_threshold(self) -> int:
        return self.settings["security"]["risk_threshold"]