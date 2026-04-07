"""
Модуль подготовки конфигурации для динамического анализа
"""
import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

class FridaHookGenerator:
    """Генерация Frida хуков для динамического анализа"""
    
    HOOK_TEMPLATES = {
        'crypto': '''
        Java.perform(function() {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.doFinal.overload('[B').implementation = function(data) {
                console.log('[CRYPTO] Cipher.doFinal called');
                console.log('[CRYPTO] Data length: ' + data.length);
                return this.doFinal(data);
            };
        });
        ''',
        
        'network': '''
        Java.perform(function() {
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            HttpURLConnection.getOutputStream.implementation = function() {
                console.log('[NETWORK] HTTP request to: ' + this.getURL());
                return this.getOutputStream();
            };
        });
        ''',
        
        'file_operations': '''
        Java.perform(function() {
            var FileOutputStream = Java.use('java.io.FileOutputStream');
            FileOutputStream.write.overload('[B').implementation = function(data) {
                console.log('[FILE] Writing ' + data.length + ' bytes');
                return this.write(data);
            };
        });
        ''',
        
        'anti_debug': '''
        Java.perform(function() {
            var Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function() {
                console.log('[ANTI_DEBUG] isDebuggerConnected called');
                return false;
            };
        });
        '''
    }
    
    @classmethod
    def generate_hooks(cls, threats: List[Dict]) -> List[str]:
        """Генерация хуков на основе обнаруженных угроз"""
        hooks = []
        threat_categories = {t.get('category', '') for t in threats}
        
        if any('crypto' in cat.lower() for cat in threat_categories):
            hooks.append(cls.HOOK_TEMPLATES['crypto'])
        
        if any('network' in cat.lower() or 'exfiltration' in cat.lower() 
               for cat in threat_categories):
            hooks.append(cls.HOOK_TEMPLATES['network'])
        
        if any('file' in cat.lower() for cat in threat_categories):
            hooks.append(cls.HOOK_TEMPLATES['file_operations'])
        
        if any('anti_debug' in cat.lower() for cat in threat_categories):
            hooks.append(cls.HOOK_TEMPLATES['anti_debug'])
        
        return hooks


class EmulatorConfigGenerator:
    """Генерация конфигурации для эмулятора"""
    
    @classmethod
    def generate_config(cls, app_info: Dict, threats: List[Dict]) -> Dict[str, Any]:
        """Генерация конфигурации эмулятора"""
        
        # Определение профиля на основе угроз
        profile = 'standard'
        if any(t.get('risk') == 'Critical' for t in threats):
            profile = 'malware_heavy_monitoring'
        elif len(threats) > 10:
            profile = 'suspicious_monitoring'
        
        config = {
            'emulator': {
                'avd_name': 'malware_analysis_avd',
                'api_level': 30,
                'device': 'pixel',
                'ram': 4096,
                'storage': 2048,
                'profile': profile
            },
            'monitoring': {
                'enable_network': True,
                'enable_file_system': True,
                'enable_process': True,
                'enable_crypto': any('crypto' in str(t).lower() for t in threats),
                'enable_ui': True
            },
            'frida': {
                'enabled': True,
                'scripts': FridaHookGenerator.generate_hooks(threats),
                'spawn_mode': True
            },
            'timeout': {
                'analysis_duration': 300,
                'idle_timeout': 60
            },
            'app': {
                'package': app_info.get('package', ''),
                'main_activity': app_info.get('main_activity', ''),
                'permissions': app_info.get('permissions', [])
            }
        }
        
        return config


class DynamicAnalysisPreparer:
    """Подготовка полного комплекта для динамического анализа"""
    
    def __init__(self):
        self.frida_hooks: List[str] = []
        self.emulator_config: Dict = {}
        self.monitoring_rules: List[Dict] = []
    
    def prepare_full_config(self, threats: List[Dict], 
                           app_info: Dict,
                           network_indicators: Dict) -> Dict[str, Any]:
        """Подготовка полной конфигурации"""
        
        config = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': '1.0',
                'purpose': 'malware_analysis'
            },
            'emulator_config': EmulatorConfigGenerator.generate_config(
                app_info, threats
            ),
            'frida_hooks': FridaHookGenerator.generate_hooks(threats),
            'monitoring_targets': self._prepare_monitoring_targets(
                threats, network_indicators
            ),
            'evasion_countermeasures': self._prepare_evasion_countermeasures(threats),
            'data_collection': self._prepare_data_collection_plan(threats)
        }
        
        return config
    
    def _prepare_monitoring_targets(self, threats: List[Dict], 
                                   network_indicators: Dict) -> List[Dict]:
        """Подготовка целей для мониторинга"""
        targets = []
        
        # Сетевые цели
        for url in network_indicators.get('url', []):
            targets.append({
                'type': 'network',
                'target': url,
                'action': 'log_and_capture'
            })
        
        # Поведенческие цели
        for threat in threats:
            if threat.get('category') == 'Data_Exfiltration':
                targets.append({
                    'type': 'data_flow',
                    'target': threat.get('pattern', ''),
                    'action': 'capture_and_alert'
                })
        
        return targets
    
    def _prepare_evasion_countermeasures(self, threats: List[Dict]) -> List[str]:
        """Подготовка контрмер против уклонения"""
        countermeasures = []
        
        has_anti_emulator = any('anti_emulator' in t.get('category', '').lower() 
                               for t in threats)
        has_anti_debug = any('anti_debug' in t.get('category', '').lower() 
                            for t in threats)
        
        if has_anti_emulator:
            countermeasures.extend([
                'hide_emulator_indicators',
                'randomize_device_info',
                'disable_emulator_detection_checks'
            ])
        
        if has_anti_debug:
            countermeasures.extend([
                'hide_debugger',
                'disable_ptrace_checks',
                'randomize_timing'
            ])
        
        return countermeasures
    
    def _prepare_data_collection_plan(self, threats: List[Dict]) -> Dict[str, Any]:
        """План сбора данных"""
        plan = {
            'network': {
                'capture_pcap': True,
                'capture_ssl': True,
                'log_dns': True
            },
            'file_system': {
                'monitor_directories': [
                    '/data/data/',
                    '/sdcard/',
                    '/storage/emulated/0/'
                ],
                'capture_new_files': True
            },
            'memory': {
                'dump_on_suspicious': True,
                'scan_for_strings': True
            },
            'behavioral': {
                'track_api_calls': True,
                'track_syscalls': True,
                'track_permissions': True
            }
        }
        
        return plan
    
    def save_config(self, output_path: Path, config: Dict[str, Any]):
        """Сохранение конфигурации"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)