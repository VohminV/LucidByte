import os
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

@dataclass
class BehaviorEvent:
    timestamp: str
    event_type: str
    description: str
    risk_level: int
    details: Dict

class DynamicAnalyzer:
    def __init__(self, emulator_port: str = "5554", frida_port: int = 27042):
        self.emulator_port = emulator_port
        self.frida_port = frida_port
        self.is_emulator_running = False
        self.is_frida_running = False
        self.captured_events: List[BehaviorEvent] = []
        self.package_name = ""
        
        self.monitored_apis = [
            "android.telephony.SmsManager.sendTextMessage",
            "android.accounts.AccountManager.getAccounts",
            "android.location.LocationManager.getLastKnownLocation",
            "android.media.AudioRecord.startRecording",
            "android.hardware.Camera.open",
            "java.lang.Runtime.exec",
            "java.net.URLConnection.connect",
            "javax.crypto.Cipher.doFinal",
            "dalvik.system.DexClassLoader.loadClass"
        ]

    def start_emulator(self, emulator_path: str = "emulator") -> bool:
        try:
            command_list = [
                emulator_path,
                "-avd", "Pixel_4_API_30",
                "-port", self.emulator_port,
                "-no-snapshot",
                "-wipe-data"
            ]
            
            self.emulator_process = subprocess.Popen(
                command_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(30)
            self.is_emulator_running = True
            print("Эмулятор запущен")
            return True
            
        except Exception as exception:
            print(f"Ошибка запуска эмулятора: {exception}")
            return False

    def install_apk(self, apk_path: str) -> bool:
        try:
            command_list = [
                "adb", "-s", f"emulator-{self.emulator_port}",
                "install", "-r", apk_path
            ]
            
            result = subprocess.run(
                command_list,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                print(f"APK установлен: {apk_path}")
                return True
            else:
                print(f"Ошибка установки: {result.stderr}")
                return False
                
        except Exception as exception:
            print(f"Ошибка установки APK: {exception}")
            return False

    def start_frida_server(self) -> bool:
        try:
            command_list = [
                "adb", "-s", f"emulator-{self.emulator_port}",
                "shell", "su", "-c", "/data/local/tmp/frida-server"
            ]
            
            self.frida_process = subprocess.Popen(
                command_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(5)
            self.is_frida_running = True
            print("Frida сервер запущен")
            return True
            
        except Exception as exception:
            print(f"Ошибка запуска Frida: {exception}")
            return False

    def inject_frida_script(self, package_name: str, script_content: str) -> bool:
        try:
            import frida
            
            device = frida.get_device_manager().add_remote_device(f"localhost:{self.frida_port}")
            session = device.attach(package_name)
            script = session.create_script(script_content)
            script.load()
            
            print(f"Скрипт Frida внедрен в {package_name}")
            return True
            
        except Exception as exception:
            print(f"Ошибка внедрения скрипта: {exception}")
            return False

    def get_frida_hook_script(self) -> str:
        script = """
        Java.perform(function() {
            var monitoredApis = [
                'android.telephony.SmsManager.sendTextMessage',
                'android.accounts.AccountManager.getAccounts',
                'android.location.LocationManager.getLastKnownLocation',
                'java.lang.Runtime.exec',
                'java.net.URLConnection.connect',
                'javax.crypto.Cipher.doFinal'
            ];
            
            monitoredApis.forEach(function(apiName) {
                try {
                    var parts = apiName.split('.');
                    var className = parts.slice(0, -1).join('.');
                    var methodName = parts[parts.length - 1];
                    
                    var targetClass = Java.use(className);
                    
                    targetClass[methodName].implementation = function() {
                        send({
                            type: 'api_call',
                            api: apiName,
                            arguments: JSON.stringify(arguments),
                            timestamp: new Date().toISOString()
                        });
                        
                        return this[methodName].apply(this, arguments);
                    };
                } catch(e) {
                    console.log('Не удалось установить хук для: ' + apiName);
                }
            });
        });
        """
        return script

    def capture_network_traffic(self, duration_seconds: int = 60) -> List[Dict]:
        traffic_data = []
        
        try:
            command_list = [
                "adb", "-s", f"emulator-{self.emulator_port}",
                "shell", "tcpdump", "-i", "any", "-s", "0", "-w", "/sdcard/capture.pcap",
                "-G", str(duration_seconds), "-W", "1"
            ]
            
            subprocess.run(command_list, timeout=duration_seconds + 10)
            
            pull_command = [
                "adb", "-s", f"emulator-{self.emulator_port}",
                "pull", "/sdcard/capture.pcap", "temp/network_capture.pcap"
            ]
            
            subprocess.run(pull_command)
            
            traffic_data.append({
                "file": "temp/network_capture.pcap",
                "duration": duration_seconds,
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as exception:
            print(f"Ошибка захвата трафика: {exception}")
        
        return traffic_data

    def record_behavior_event(self, event_type: str, description: str, risk_level: int, details: Dict):
        event = BehaviorEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            description=description,
            risk_level=risk_level,
            details=details
        )
        self.captured_events.append(event)

    def stop_analysis(self):
        if hasattr(self, 'frida_process') and self.frida_process:
            self.frida_process.terminate()
            self.is_frida_running = False
        
        if hasattr(self, 'emulator_process') and self.emulator_process:
            self.emulator_process.terminate()
            self.is_emulator_running = False
        
        print("Динамический анализ завершен")

    def get_behavior_summary(self) -> str:
        summary = "=== Динамический Анализ Поведения ===\n\n"
        summary += f"Захвачено событий: {len(self.captured_events)}\n\n"
        
        high_risk_events = [e for e in self.captured_events if e.risk_level >= 7]
        
        if high_risk_events:
            summary += "События высокого риска:\n"
            for event in high_risk_events[:10]:
                summary += f"  [{event.timestamp}] {event.event_type}: {event.description}\n"
        
        return summary

    def get_total_risk_score(self) -> int:
        if not self.captured_events:
            return 0
        
        total_risk = sum(event.risk_level for event in self.captured_events)
        return min(total_risk // 5, 10)