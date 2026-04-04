"""
Рабочий поток для анализа пакета приложения
Назначение: Асинхронное выполнение анализа в отдельном потоке
"""
from PySide6.QtCore import QThread, Signal
from typing import List, Dict, Optional
from pathlib import Path
import traceback
from src.core.analysis_engine import AnalysisEngine

class AnalysisWorker(QThread):
    """
    Рабочий поток для анализа пакетов приложений
    Режим: Полноценный Реверс-Инженеринг Мобильных Систем
    """
    # ==================== СИГНАЛЫ ПРОГРЕССА ====================
    progress = Signal(int, str)
    log_signal = Signal(str)
    finished = Signal(bool)

    # ==================== СИГНАЛЫ ДАННЫХ ====================
    manifest_ready = Signal(str, dict)
    strings_ready = Signal(list)
    permissions_ready = Signal(list)
    threats_ready = Signal(list)
    files_ready = Signal(list)
    stats_ready = Signal(dict)

    # Сигналы расширенных модулей
    graph_ready = Signal(dict, list)
    report_ready = Signal(str)
    network_ready = Signal(dict)
    signature_ready = Signal(dict)
    osint_ready = Signal(dict)
    native_ready = Signal(dict)
    risk_ready = Signal(int)
    
    # Новые сигналы для расширенного анализа
    taint_ready = Signal(list)
    behavioral_chains_ready = Signal(list)
    crypto_ready = Signal(list)
    anti_analysis_ready = Signal(list)
    structure_ready = Signal(list)
    
    # Сигналы новых модулей
    privacy_ready = Signal(list)
    unpacking_ready = Signal(list)
    dynamic_config_ready = Signal(dict)
    ml_features_ready = Signal(dict)

    def __init__(self, application_package_path: str):
        """
        Инициализация рабочего потока
        Аргументы:
            application_package_path: Путь к пакету приложения для анализа
        """
        super().__init__()
        self.application_package_path = application_package_path
        self.engine = AnalysisEngine()
        self.engine.enable_ghidra(True)
        self.engine.set_progress_callback(self._on_progress)
        self.engine.set_log_callback(self._on_log)

    def _on_progress(self, value: int, message: str):
        self.progress.emit(value, message)

    def _on_log(self, message: str):
        self.log_signal.emit(message)

    def run(self):
        try:
            self._log("Запуск рабочего потока анализа...")
            success = self.engine.analyze_application_package(self.application_package_path)
            
            if success:
                self._log("Анализ завершён")
                self.manifest_ready.emit(self.engine.manifest_data, self.engine.manifest_info)
                self.strings_ready.emit(self.engine.strings_data)
                self.permissions_ready.emit(self.engine.permissions)
                self.threats_ready.emit(self.engine.threats)
                self.files_ready.emit([str(file_path) for file_path in self.engine.get_decompiled_files()])
                self.stats_ready.emit(self.engine.get_statistics())
                
                try:
                    graph_data = self.engine.get_call_graph_data()
                    self.graph_ready.emit(graph_data, self.engine.threats)
                except Exception as error:
                    self.graph_ready.emit({}, [])
                
                try:
                    self.network_ready.emit(self.engine.get_network_indicators())
                except Exception:
                    self.network_ready.emit({})
                
                try:
                    self.signature_ready.emit(self.engine.get_signature_info())
                except Exception:
                    self.signature_ready.emit({})
                
                try:
                    self.osint_ready.emit(self.engine.get_osint_data())
                except Exception:
                    self.osint_ready.emit({})
                
                try:
                    self.native_ready.emit(self.engine.get_native_analysis_results())
                except Exception:
                    self.native_ready.emit({})
                
                try:
                    self.risk_ready.emit(self.engine.get_risk_score())
                except Exception:
                    self.risk_ready.emit(0)
                    
                try:
                    self.taint_ready.emit(self.engine.get_taint_flows())
                except Exception:
                    self.taint_ready.emit([])
                    
                try:
                    self.behavioral_chains_ready.emit(self.engine.get_behavioral_chains())
                except Exception:
                    self.behavioral_chains_ready.emit([])

                try:
                    self.privacy_ready.emit(self.engine.get_privacy_violations())
                except Exception:
                    self.privacy_ready.emit([])
                    
                try:
                    self.unpacking_ready.emit(self.engine.get_unpacking_indicators())
                except Exception:
                    self.unpacking_ready.emit([])
                    
                try:
                    self.dynamic_config_ready.emit(self.engine.get_dynamic_analysis_config())
                except Exception:
                    self.dynamic_config_ready.emit({})
                    
                try:
                    self.ml_features_ready.emit(self.engine.ml_features)
                except Exception:
                    self.ml_features_ready.emit({})

                try:
                    report_path = self.engine.save_consolidated_report("analysis_results")
                    self.report_ready.emit(str(report_path))
                except Exception as error:
                    self._log(f"Не удалось сохранить отчёт: {error}")
                
                self._log("=" * 70)
                self._log("РЕЗУЛЬТАТЫ")
                critical_count = len([threat for threat in self.engine.threats if threat.get('risk') == 'Critical'])
                high_count = len([threat for threat in self.engine.threats if threat.get('risk') == 'High'])
                self._log(f"Критических: {critical_count}")
                self._log(f"Высоких: {high_count}")
                self._log(f"Риск: {self.engine.get_risk_score()}/100")
                self._log(f"Признаков машинного обучения: {len(self.engine.ml_features)}")
                self._log("=" * 70)
            
            self.finished.emit(success)
            
        except Exception as exception:
            error_trace = traceback.format_exc()
            self.log_signal.emit(f"Ошибка: {str(exception)}")
            self.log_signal.emit(f"Трассировка:\n{error_trace}")
            self.finished.emit(False)

    def _log(self, message: str):
        self.log_signal.emit(message)

    def stop_analysis(self):
        if self.isRunning():
            self._log("Остановка...")
            self.terminate()
            self.wait(5000)