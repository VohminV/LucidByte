import os
import subprocess
import threading
from pathlib import Path
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

@dataclass
class NetworkRequest:
    timestamp: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    response_code: Optional[int]
    response_body: Optional[str]
    is_suspicious: bool
    risk_reason: str

class TrafficCapture:
    def __init__(self, proxy_port: int = 8080):
        self.proxy_port = proxy_port
        self.is_capturing = False
        self.captured_requests: List[NetworkRequest] = []
        self.suspicious_domains = [
            ".ru", ".cn", ".tk", ".top", ".xyz",
            "pastebin", "githubusercontent", "dropbox"
        ]
        self.suspicious_paths = [
            "/upload", "/exfil", "/data", "/config",
            "/key", "/token", "/password", "/sms"
        ]

    def start_mitmproxy(self) -> bool:
        try:
            script_path = "scripts/mitm_capture.py"
            
            command_list = [
                "mitmproxy",
                "-p", str(self.proxy_port),
                "--mode", "regular",
                "-s", script_path,
                "--set", "upstream_cert=false"
            ]
            
            self.proxy_process = subprocess.Popen(
                command_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.is_capturing = True
            print(f"Mitmproxy запущен на порту {self.proxy_port}")
            return True
            
        except Exception as exception:
            print(f"Ошибка запуска Mitmproxy: {exception}")
            return False

    def configure_android_proxy(self, emulator_port: str = "5554") -> bool:
        try:
            command_list = [
                "adb", "-s", f"emulator-{emulator_port}",
                "shell", "settings", "put", "global", "http_proxy",
                f"10.0.2.2:{self.proxy_port}"
            ]
            
            result = subprocess.run(
                command_list,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("Прокси настроен на Android устройстве")
                return True
            else:
                print(f"Ошибка настройки прокси: {result.stderr}")
                return False
                
        except Exception as exception:
            print(f"Ошибка настройки прокси: {exception}")
            return False

    def install_ca_certificate(self, emulator_port: str = "5554") -> bool:
        try:
            cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
            
            if not cert_path.exists():
                print("Сертификат Mitmproxy не найден")
                return False
            
            push_command = [
                "adb", "-s", f"emulator-{emulator_port}",
                "push", str(cert_path), "/sdcard/mitmproxy-ca-cert.cer"
            ]
            
            subprocess.run(push_command)
            
            install_command = [
                "adb", "-s", f"emulator-{emulator_port}",
                "shell", "su", "-c", "cp /sdcard/mitmproxy-ca-cert.cer /system/etc/security/cacerts/"
            ]
            
            subprocess.run(install_command)
            
            print("Сертификат установлен")
            return True
            
        except Exception as exception:
            print(f"Ошибка установки сертификата: {exception}")
            return False

    def analyze_request(self, request: NetworkRequest) -> NetworkRequest:
        is_suspicious = False
        risk_reason = ""
        
        for domain in self.suspicious_domains:
            if domain in request.url:
                is_suspicious = True
                risk_reason = f"Подозрительный домен: {domain}"
                break
        
        for path in self.suspicious_paths:
            if path in request.url.lower():
                is_suspicious = True
                risk_reason = f"Подозрительный путь: {path}"
                break
        
        if request.method == "POST" and request.body:
            if any(keyword in request.body.lower() for keyword in ["password", "token", "key", "sms"]):
                is_suspicious = True
                risk_reason = "Передача чувствительных данных"
        
        request.is_suspicious = is_suspicious
        request.risk_reason = risk_reason
        
        return request

    def stop_capture(self):
        if hasattr(self, 'proxy_process') and self.proxy_process:
            self.proxy_process.terminate()
            self.is_capturing = False
        
        print("Захват трафика остановлен")

    def get_traffic_summary(self) -> str:
        summary = "=== Анализ Сетевого Трафика ===\n\n"
        summary += f"Всего запросов: {len(self.captured_requests)}\n"
        
        suspicious_requests = [r for r in self.captured_requests if r.is_suspicious]
        summary += f"Подозрительных запросов: {len(suspicious_requests)}\n\n"
        
        if suspicious_requests:
            summary += "Подозрительные соединения:\n"
            for request in suspicious_requests[:10]:
                summary += f"  [{request.method}] {request.url}\n"
                summary += f"    Причина: {request.risk_reason}\n\n"
        
        return summary

    def get_risk_score(self) -> int:
        suspicious_count = len([r for r in self.captured_requests if r.is_suspicious])
        
        if suspicious_count == 0:
            return 0
        elif suspicious_count <= 2:
            return 3
        elif suspicious_count <= 5:
            return 5
        elif suspicious_count <= 10:
            return 7
        else:
            return 10