from PySide6.QtCore import QThread, Signal
from src.core.analysis_engine import AnalysisEngine
from typing import List, Dict, Optional
from pathlib import Path

class AnalysisWorker(QThread):
    """
    Рабочий поток для анализа APK
    """
    # Сигналы прогресса
    progress = Signal(int, str)
    log_signal = Signal(str)
    finished = Signal(bool)

    # Сигналы данных
    manifest_ready = Signal(str)
    strings_ready = Signal(list)
    permissions_ready = Signal(list)
    threats_ready = Signal(list)
    files_ready = Signal(list)
    stats_ready = Signal(dict)

    # ✅ НОВОЕ: Сигнал графа вызовов
    graph_ready = Signal(dict, list)

    # ✅ НОВОЕ: Сигнал отчёта
    report_ready = Signal(str)

    def __init__(self, apk_path: str):
        super().__init__()
        self.apk_path = apk_path
        self.engine = AnalysisEngine()
        
        # Активация Ghidra
        self.engine.enable_ghidra(True)
        
        # Колбэки
        self.engine.set_progress_callback(self._on_progress)
        self.engine.set_log_callback(self._on_log)

    def _on_progress(self, value: int, message: str):
        self.progress.emit(value, message)

    def _on_log(self, message: str):
        self.log_signal.emit(message)

    def run(self):
        """Основной метод анализа"""
        try:
            self._log("🚀 Запуск AnalysisWorker...")
            
            # Запуск анализа
            success = self.engine.analyze_apk(self.apk_path)
            
            if success:
                self._log("✅ Анализ завершён")
                
                # Эмит данных
                self.manifest_ready.emit(self.engine.manifest_data)
                self.strings_ready.emit(self.engine.strings_data)
                self.permissions_ready.emit(self.engine.permissions)
                self.threats_ready.emit(self.engine.threats)
                
                files = [str(f) for f in self.engine.get_decompiled_files()]
                self.files_ready.emit(files)
                self.stats_ready.emit(self.engine.get_statistics())
                
                # ✅ ЭМИТ ГРАФА ВЫЗОВОВ
                try:
                    graph_data = self.engine.get_call_graph_data()
                    self.graph_ready.emit(graph_data, self.engine.threats)
                    self._log(f"🕸 Граф отправлен: {len(graph_data)} узлов")
                except AttributeError as e:
                    self._log(f"⚠ Ошибка графа: {e}")
                    self.graph_ready.emit({}, [])
                
                # ✅ СОХРАНЕНИЕ ОТЧЁТА
                try:
                    report_path = self.engine.save_consolidated_report("analysis_results")
                    self.report_ready.emit(str(report_path))
                    self._log(f"📄 Отчёт: {report_path}")
                except AttributeError as e:
                    self._log(f"⚠ Не удалось сохранить отчёт: {e}")
                
                # Логирование
                self._log("=" * 70)
                self._log("📊 РЕЗУЛЬТАТЫ")
                self._log(f"🔴 Critical: {len([t for t in self.engine.threats if t.get('risk') == 'Critical'])}")
                self._log(f"🎯 Риск: {self.engine.get_risk_score()}/100")
                self._log("=" * 70)
            
            self.finished.emit(success)
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            self.log_signal.emit(f"❌ Ошибка: {str(e)}")
            self.log_signal.emit(f"📋 Трассировка:\n{error_trace}")
            self.finished.emit(False)

    def _log(self, message: str):
        self.log_signal.emit(message)

    def stop_analysis(self):
        if self.isRunning():
            self._log("⏹ Остановка...")
            self.terminate()
            self.wait(5000)