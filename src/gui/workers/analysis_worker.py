from PySide6.QtCore import QThread, Signal
from src.core.analysis_engine import AnalysisEngine

class AnalysisWorker(QThread):
    progress = Signal(int, str)
    log_signal = Signal(str)
    finished = Signal(bool)
    manifest_ready = Signal(str)
    strings_ready = Signal(list)
    permissions_ready = Signal(list)
    threats_ready = Signal(list)
    files_ready = Signal(list)
    stats_ready = Signal(dict)

    def __init__(self, apk_path: str):
        super().__init__()
        self.apk_path = apk_path
        self.engine = AnalysisEngine()
        
        # Активация оптимизированного Ghidra
        self.engine.enable_ghidra(True)
        
        self.engine.set_progress_callback(self._on_progress)
        self.engine.set_log_callback(self._on_log)

    def _on_progress(self, value: int, message: str):
        self.progress.emit(value, message)

    def _on_log(self, message: str):
        self.log_signal.emit(message)

    def run(self):
        try:
            success = self.engine.analyze_apk(self.apk_path)
            
            if success:
                self.manifest_ready.emit(self.engine.manifest_data)
                self.strings_ready.emit(self.engine.strings_data)
                self.permissions_ready.emit(self.engine.permissions)
                self.threats_ready.emit(self.engine.threats)
                
                files = [str(f) for f in self.engine.get_decompiled_files()]
                self.files_ready.emit(files)
                self.stats_ready.emit(self.engine.get_statistics())
            
            self.finished.emit(success)
            
        except Exception as e:
            self.log_signal.emit(f"Критическая ошибка: {str(e)}")
            self.finished.emit(False)