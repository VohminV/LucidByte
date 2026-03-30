from typing import Dict, List, Optional
from src.ai_engine.language_model_manager import LanguageModelManager
from src.core.permission_analyzer import PermissionAnalyzer
from src.core.api_call_scanner import ApiCallScanner
from src.core.malware_signatures import MalwareSignatureDatabase
from src.core.native_code_analyzer import NativeCodeAnalyzer
from src.core.packer_detector import PackerDetector
from src.core.deobfuscator import Deobfuscator
from src.core.dynamic_analyzer import DynamicAnalyzer
from src.network.traffic_capture import TrafficCapture

class ThreatAnalyzer:
    def __init__(
        self, 
        language_model: LanguageModelManager,
        permission_analyzer: PermissionAnalyzer,
        api_scanner: ApiCallScanner,
        signature_database: MalwareSignatureDatabase,
        native_analyzer: Optional[NativeCodeAnalyzer] = None,
        packer_detector: Optional[PackerDetector] = None,
        deobfuscator: Optional[Deobfuscator] = None,
        dynamic_analyzer: Optional[DynamicAnalyzer] = None,
        traffic_capture: Optional[TrafficCapture] = None
    ):
        self.language_model = language_model
        self.permission_analyzer = permission_analyzer
        self.api_scanner = api_scanner
        self.signature_database = signature_database
        self.native_analyzer = native_analyzer
        self.packer_detector = packer_detector
        self.deobfuscator = deobfuscator
        self.dynamic_analyzer = dynamic_analyzer
        self.traffic_capture = traffic_capture
        self.analysis_results: Dict = {}

    def perform_full_analysis(self, source_code: str, enable_dynamic: bool = False) -> Dict:
        permissions = self.permission_analyzer.get_all_permissions()
        suspicious_permissions = self.permission_analyzer.get_suspicious_permissions()
        api_calls = self.api_scanner.get_all_dangerous_calls()
        
        detected_signatures = self.signature_database.check_signature(
            permissions, 
            api_calls
        )
        
        permission_risk = self.permission_analyzer.get_risk_score()
        api_risk = self.api_scanner.get_risk_score()
        signature_risk = max([sig.risk_level for sig in detected_signatures], default=0)
        
        packer_risk = 0
        if self.packer_detector:
            packer_risk = self.packer_detector.get_total_risk_score()
        
        native_risk = 0
        if self.native_analyzer:
            native_risk = len(self.native_analyzer.get_dangerous_native_functions()) * 2
            native_risk = min(native_risk, 10)
        
        dynamic_risk = 0
        if self.dynamic_analyzer and enable_dynamic:
            dynamic_risk = self.dynamic_analyzer.get_total_risk_score()
        
        network_risk = 0
        if self.traffic_capture:
            network_risk = self.traffic_capture.get_risk_score()
        
        overall_risk = min(
            (permission_risk + api_risk + signature_risk + packer_risk + native_risk + dynamic_risk + network_risk) // 4,
            10
        )
        
        llm_analysis = ""
        if source_code and len(source_code) < 50000:
            llm_analysis = self.language_model.analyze_malware_threat(
                code_snippet=source_code[:10000],
                permissions=suspicious_permissions,
                api_calls={k: len(v) for k, v in api_calls.items()}
            )
        
        self.analysis_results = {
            "overall_risk": overall_risk,
            "permission_risk": permission_risk,
            "api_risk": api_risk,
            "signature_risk": signature_risk,
            "packer_risk": packer_risk,
            "native_risk": native_risk,
            "dynamic_risk": dynamic_risk,
            "network_risk": network_risk,
            "permissions": permissions,
            "suspicious_permissions": suspicious_permissions,
            "dangerous_api_calls": api_calls,
            "detected_signatures": [
                {
                    "name": sig.name,
                    "category": sig.category,
                    "risk_level": sig.risk_level,
                    "description": sig.description
                }
                for sig in detected_signatures
            ],
            "detected_packers": [
                {
                    "name": p.name,
                    "description": p.description,
                    "risk_level": p.risk_level
                }
                for p in (self.packer_detector.detected_packers if self.packer_detector else [])
            ],
            "native_functions": [
                {
                    "name": f.name,
                    "address": f.address,
                    "is_dangerous": f.is_dangerous,
                    "description": f.description
                }
                for f in (self.native_analyzer.get_dangerous_native_functions() if self.native_analyzer else [])
            ],
            "deobfuscation_summary": self.deobfuscator.get_deobfuscation_summary() if self.deobfuscator else "",
            "dynamic_summary": self.dynamic_analyzer.get_behavior_summary() if self.dynamic_analyzer and enable_dynamic else "",
            "network_summary": self.traffic_capture.get_traffic_summary() if self.traffic_capture else "",
            "llm_analysis": llm_analysis
        }
        
        return self.analysis_results

    def get_risk_level_name(self, risk_score: int) -> str:
        if risk_score <= 2:
            return "Низкий"
        elif risk_score <= 4:
            return "Средний"
        elif risk_score <= 6:
            return "Повышенный"
        elif risk_score <= 8:
            return "Высокий"
        else:
            return "Критический"

    def generate_comprehensive_report(self) -> str:
        report = "=" * 60 + "\n"
        report += "ОТЧЕТ ОБ АНАЛИЗЕ БЕЗОПАСНОСТИ ANDROID ПРИЛОЖЕНИЯ\n"
        report += "LucidByte v3.0.0\n"
        report += "=" * 60 + "\n\n"
        
        risk_score = self.analysis_results.get("overall_risk", 0)
        risk_name = self.get_risk_level_name(risk_score)
        
        report += f"ОБЩИЙ УРОВЕНЬ РИСКА: {risk_score}/10 ({risk_name})\n\n"
        
        report += "-" * 60 + "\n"
        report += "1. СТАТИЧЕСКИЙ АНАЛИЗ\n"
        report += "-" * 60 + "\n"
        report += f"Разрешений всего: {len(self.analysis_results.get('permissions', []))}\n"
        report += f"Подозрительных разрешений: {len(self.analysis_results.get('suspicious_permissions', []))}\n"
        report += f"Опасных вызовов API: {len(self.analysis_results.get('dangerous_api_calls', {}))}\n\n"
        
        report += "-" * 60 + "\n"
        report += "2. ОБНАРУЖЕННЫЕ УГРОЗЫ\n"
        report += "-" * 60 + "\n"
        detected = self.analysis_results.get("detected_signatures", [])
        if detected:
            for sig in detected:
                report += f"  - {sig['name']} ({sig['category']}): {sig['description']}\n"
        else:
            report += "Известные сигнатуры не обнаружены\n"
        report += "\n"
        
        report += "-" * 60 + "\n"
        report += "3. УПАКОВЩИКИ И ОБФУСКАЦИЯ\n"
        report += "-" * 60 + "\n"
        packers = self.analysis_results.get("detected_packers", [])
        if packers:
            for packer in packers:
                report += f"  - {packer['name']}: {packer['description']} (Риск: {packer['risk_level']})\n"
        else:
            report += "Упаковщики не обнаружены\n"
        report += "\n"
        
        report += "-" * 60 + "\n"
        report += "4. НАТИВНЫЙ КОД\n"
        report += "-" * 60 + "\n"
        native = self.analysis_results.get("native_functions", [])
        if native:
            for func in native[:5]:
                report += f"  - {func['name']} @ {func['address']}: {func['description']}\n"
        else:
            report += "Опасные нативные функции не обнаружены\n"
        report += "\n"
        
        report += "-" * 60 + "\n"
        report += "5. ДИНАМИЧЕСКИЙ АНАЛИЗ\n"
        report += "-" * 60 + "\n"
        report += self.analysis_results.get("dynamic_summary", "Не проводился\n")
        report += "\n"
        
        report += "-" * 60 + "\n"
        report += "6. СЕТЕВОЙ ТРАФИК\n"
        report += "-" * 60 + "\n"
        report += self.analysis_results.get("network_summary", "Не захвачен\n")
        report += "\n"
        
        report += "-" * 60 + "\n"
        report += "7. АНАЛИЗ LARGE LANGUAGE MODEL\n"
        report += "-" * 60 + "\n"
        report += self.analysis_results.get("llm_analysis", "Не проводился\n")
        report += "\n"
        
        report += "=" * 60 + "\n"
        report += "КОНЕЦ ОТЧЕТА\n"
        report += "=" * 60 + "\n"
        
        return report