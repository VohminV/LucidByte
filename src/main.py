import sys
import os
from pathlib import Path

# Добавление корневой директории проекта в путь поиска модулей
current_file = Path(__file__).resolve()
project_root = current_file.parent.parent
sys.path.insert(0, str(project_root))

from PySide6.QtWidgets import QApplication
from src.utils.configuration import Configuration
from src.gui.main_window import MainWindow
from src.core.apk_loader import ApkLoader
from src.core.decompiler import Decompiler
from src.core.permission_analyzer import PermissionAnalyzer
from src.core.api_call_scanner import ApiCallScanner
from src.core.malware_signatures import MalwareSignatureDatabase
from src.core.native_code_analyzer import NativeCodeAnalyzer
from src.core.packer_detector import PackerDetector
from src.core.deobfuscator import Deobfuscator
from src.core.dynamic_analyzer import DynamicAnalyzer
from src.network.traffic_capture import TrafficCapture
from src.ai_engine.language_model_manager import LanguageModelManager
from src.ai_engine.threat_analyzer import ThreatAnalyzer

class Application:
    def __init__(self):
        self.configuration = None
        self.main_window = None
        self.apk_loader = None
        self.decompiler = None
        self.permission_analyzer = None
        self.api_scanner = None
        self.signature_database = None
        self.native_analyzer = None
        self.packer_detector = None
        self.deobfuscator = None
        self.dynamic_analyzer = None
        self.traffic_capture = None
        self.language_model = None
        self.threat_analyzer = None

    def initialize(self):
        try:
            self.configuration = Configuration("config.yaml")
            print(f"Конфигурация загружена: {self.configuration.get_application_name()}")
        except FileNotFoundError as error:
            print(f"Критическая ошибка: {error}")
            return False

        self.apk_loader = ApkLoader(
            temp_directory=self.configuration.get_temp_directory()
        )
        
        self.decompiler = Decompiler(
            decompiler_command=self.configuration.get_decompiler_path()
        )
        
        self.permission_analyzer = PermissionAnalyzer(
            suspicious_permissions=self.configuration.get_suspicious_permissions()
        )
        
        self.api_scanner = ApiCallScanner(
            dangerous_api_calls=self.configuration.get_dangerous_api_calls()
        )
        
        self.signature_database = MalwareSignatureDatabase()
        
        self.native_analyzer = NativeCodeAnalyzer(
            ghidra_path=self.configuration.settings.get("native_analysis", {}).get("ghidra_path", "ghidra"),
            enable_capstone=self.configuration.settings.get("native_analysis", {}).get("enable_capstone", True)
        )
        
        self.packer_detector = PackerDetector()
        
        self.language_model = LanguageModelManager(
            base_url=self.configuration.get_language_model_url(),
            model_name=self.configuration.get_language_model_name()
        )
        
        self.deobfuscator = Deobfuscator(
            language_model_manager=self.language_model
        )
        
        self.dynamic_analyzer = DynamicAnalyzer(
            emulator_port=self.configuration.settings.get("sandbox", {}).get("emulator_port", "5554"),
            frida_port=self.configuration.settings.get("sandbox", {}).get("frida_server_port", 27042)
        )
        
        self.traffic_capture = TrafficCapture(
            proxy_port=self.configuration.settings.get("sandbox", {}).get("mitmproxy_port", 8080)
        )
        
        self.threat_analyzer = ThreatAnalyzer(
            language_model=self.language_model,
            permission_analyzer=self.permission_analyzer,
            api_scanner=self.api_scanner,
            signature_database=self.signature_database,
            native_analyzer=self.native_analyzer,
            packer_detector=self.packer_detector,
            deobfuscator=self.deobfuscator,
            dynamic_analyzer=self.dynamic_analyzer,
            traffic_capture=self.traffic_capture
        )
        
        return True

    def run(self):
        application = QApplication(sys.argv)
        
        self.main_window = MainWindow()
        self.main_window.show()
        
        print("Приложение LucidByte запущено")
        print(f"Версия: {self.configuration.get_application_version()}")
        print(f"Модель: {self.configuration.get_language_model_name()}")
        print("Режим: Полноценный Реверс-Инженеринг Android")
        
        return application.exec()

def main():
    application = Application()
    
    if not application.initialize():
        print("Не удалось инициализировать приложение")
        sys.exit(1)
    
    sys.exit(application.run())

if __name__ == "__main__":
    main()