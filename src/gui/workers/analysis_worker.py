"""
Рабочий поток для анализа пакета приложения
Назначение: Асинхронное выполнение анализа в отдельном потоке,
интеграция с расширенными модулями AnalysisEngine и управление жизненным циклом ресурсов.
"""
from PySide6.QtCore import QThread, Signal
from typing import List, Dict, Optional
import traceback
import logging

try:
    from src.core.analysis_engine import AnalysisEngine
except ImportError:
    try:
        from analysis_engine import AnalysisEngine
    except ImportError:
        print("Ошибка: Не удалось импортировать AnalysisEngine. Проверьте пути.")
        AnalysisEngine = None

logger = logging.getLogger(__name__)

class AnalysisWorker(QThread):
    """Рабочий поток для анализа пакетов приложений"""
    progress = Signal(int, str)
    log_signal = Signal(str)
    finished = Signal(bool)

    manifest_ready = Signal(str, dict)
    strings_ready = Signal(list)
    permissions_ready = Signal(list)
    threats_ready = Signal(list)
    files_ready = Signal(list)
    stats_ready = Signal(dict)
    graph_ready = Signal(dict, list)
    report_ready = Signal(str)
    network_ready = Signal(dict)
    signature_ready = Signal(dict)
    osint_ready = Signal(dict)
    native_ready = Signal(dict)
    risk_ready = Signal(int)

    taint_ready = Signal(list)
    behavioral_chains_ready = Signal(list)
    crypto_ready = Signal(list)
    anti_analysis_ready = Signal(list)
    structure_ready = Signal(list)
    privacy_ready = Signal(list) 
    unpacking_ready = Signal(list)
    dynamic_config_ready = Signal(dict)
    ml_features_ready = Signal(dict)

    def __init__(self, application_package_path: str):
        super().__init__()
        self.application_package_path = application_package_path
        if AnalysisEngine:
            self.engine = AnalysisEngine()
            self.engine.enable_ghidra(True)
            self.engine.set_progress_callback(self._on_progress)
            self.engine.set_log_callback(self._on_log)
        else:
            self.engine = None
            self._on_log("КРИТИЧЕСКАЯ ОШИБКА: Движок анализа не загружен.")

    def _on_progress(self, value: int, message: str):
        try: self.progress.emit(value, message)
        except Exception: pass

    def _on_log(self, message: str):
        try: self.log_signal.emit(message)
        except Exception: pass

    def run(self):
        if not self.engine:
            self.finished.emit(False)
            return

        try:
            self._log("Запуск рабочего потока анализа...")
            success = self.engine.analyze_application_package(self.application_package_path)
            
            if success:
                self._log("Анализ завершён. Сбор и передача данных...")
                
                try: self.manifest_ready.emit(self.engine.manifest_data, self.engine.manifest_info)
                except Exception: pass
                try: self.strings_ready.emit(self.engine.strings_data)
                except Exception: pass
                try: self.permissions_ready.emit(self.engine.permissions)
                except Exception: pass
                try: self.threats_ready.emit(self.engine.threats)
                except Exception: pass
                try: self.files_ready.emit([str(file_path) for file_path in self.engine.get_decompiled_files()])
                except Exception: pass
                try: self.stats_ready.emit(self.engine.get_statistics())
                except Exception: pass

                try:
                    graph_data = self.engine.get_call_graph_data()
                    self.graph_ready.emit(graph_data, self.engine.threats)
                except Exception: self.graph_ready.emit({}, [])

                try: self.network_ready.emit(self.engine.get_network_indicators())
                except Exception: pass
                try: self.osint_ready.emit(self.engine.get_osint_data())
                except Exception: pass
                try: self.signature_ready.emit(self.engine.get_signature_info())
                except Exception: pass
                try: self.native_ready.emit(self.engine.get_native_analysis_results())
                except Exception: pass
                try: self.risk_ready.emit(self.engine.get_risk_score())
                except Exception: pass

                try: self.taint_ready.emit(self.engine.get_taint_flows())
                except Exception: pass
                try: self.behavioral_chains_ready.emit(self.engine.get_behavioral_chains())
                except Exception: pass
                try: self.crypto_ready.emit(self.engine.crypto_findings)
                except Exception: pass
                try: self.anti_analysis_ready.emit(self.engine.anti_analysis_findings)
                except Exception: pass
                try: self.structure_ready.emit(self.engine.structure_findings)
                except Exception: pass
                try: self.privacy_ready.emit(self.engine.get_privacy_violations())
                except Exception: pass
                try: self.unpacking_ready.emit(self.engine.get_unpacking_indicators())
                except Exception: pass
                try: self.dynamic_config_ready.emit(self.engine.get_dynamic_analysis_config())
                except Exception: pass
                try: self.ml_features_ready.emit(self.engine.ml_features)
                except Exception: pass

                # Сохранение итогового отчёта и отправка в историю
                try:
                    report_path = self.engine.save_consolidated_report("analysis_results")
                    self.report_ready.emit(str(report_path))
                    self._log(f"✅ Итоговый отчёт сохранён и передан в интерфейс.")
                except Exception as error:
                    self._log(f"Не удалось сохранить консолидированный отчёт: {error}")
                
                self._log("=" * 70)
                self._log("РЕЗУЛЬТАТЫ")
                self._log(f"Риск: {self.engine.get_risk_score()}/100")
                self._log("=" * 70)
            
            self.finished.emit(success)
            
        except Exception as exception:
            error_trace = traceback.format_exc()
            self._log(f"КРИТИЧЕСКАЯ ОШИБКА ПОТОКА: {str(exception)}")
            self._log(f"Трассировка:\n{error_trace}")
            self.finished.emit(False)
        finally:
            self.cleanup_resources()

    def cleanup_resources(self):
        if hasattr(self, 'engine') and self.engine:
            try:
                self._log("Освобождение ресурсов (Temp files, Ghidra sessions)...")
                self.engine.cleanup_resources()
            except Exception as e:
                logger.warning(f"Ошибка при очистке ресурсов: {e}")

    def stop_analysis(self):
        if not self.isRunning(): return
        self._log("🛑 Запрос остановки анализа...")
        if hasattr(self.engine, '_stop_flag'): self.engine._stop_flag = True
        self.terminate()
        if not self.wait(5000): self._log("⚠ Предупреждение: поток не завершился вовремя")
        try:
            if hasattr(self, 'engine') and self.engine: self.engine.cleanup_resources()
        except Exception as e: self._log(f"⚠ Ошибка при очистке ресурсов: {e}")
        self._log("✅ Анализ остановлен, ресурсы освобождены")

    def __del__(self): self.cleanup_resources()
    def _log(self, message: str): self.log_signal.emit(message)