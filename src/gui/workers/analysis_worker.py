"""
Рабочий поток для анализа пакета приложения (STABLE VERSION)
- Полностью JSON-safe сигналы
- Защита от dict/object → Qt crash
- Стабильный lifecycle cleanup
"""

from PySide6.QtCore import QThread, Signal
import traceback
import logging
import json

try:
    from src.core.analysis_engine import AnalysisEngine
except ImportError:
    AnalysisEngine = None
    print("❌ AnalysisEngine не найден")

logger = logging.getLogger(__name__)


class AnalysisWorker(QThread):
    """Асинхронный поток анализа APK"""

    # =========================
    # CORE SIGNALS
    # =========================
    progress = Signal(int, str)
    log_signal = Signal(str)
    finished = Signal(bool)

    # =========================
    # DATA SIGNALS (ALL JSON-STR)
    # =========================
    manifest_ready = Signal(str, str)
    strings_ready = Signal(str)
    permissions_ready = Signal(str)
    threats_ready = Signal(str)
    files_ready = Signal(str)
    stats_ready = Signal(str)
    graph_ready = Signal(str, str)

    report_ready = Signal(str)
    network_ready = Signal(str)
    osint_ready = Signal(str)
    signature_ready = Signal(str)
    native_ready = Signal(str)

    risk_ready = Signal(int)

    # =========================
    # ADVANCED MODULES
    # =========================
    taint_ready = Signal(str)
    behavioral_chains_ready = Signal(str)
    crypto_ready = Signal(str)
    anti_analysis_ready = Signal(str)
    structure_ready = Signal(str)
    privacy_ready = Signal(str)
    unpacking_ready = Signal(str)
    dynamic_config_ready = Signal(str)
    ml_features_ready = Signal(str)

    # =========================
    # INIT
    # =========================
    def __init__(self, application_package_path: str):
        super().__init__()
        self.application_package_path = application_package_path
        self.engine = None

        if AnalysisEngine:
            self.engine = AnalysisEngine()
            self.engine.enable_ghidra(True)
            self.engine.set_progress_callback(self._on_progress)
            self.engine.set_log_callback(self._on_log)
        else:
            self._log("❌ CRITICAL: AnalysisEngine not loaded")

    # =========================
    # SAFE HELPERS
    # =========================
    def _safe_json(self, data):
        """Безопасная JSON сериализация"""
        try:
            return json.dumps(data, ensure_ascii=False, default=str)
        except Exception:
            return "{}"

    def _on_progress(self, value: int, message: str):
        try:
            self.progress.emit(value, message)
        except Exception:
            pass

    def _on_log(self, message: str):
        self._log(message)

    def _log(self, msg: str):
        try:
            self.log_signal.emit(str(msg))
        except Exception:
            pass

    # =========================
    # MAIN THREAD
    # =========================
    def run(self):
        if not self.engine:
            self.finished.emit(False)
            return

        try:
            self._log("🚀 Запуск анализа APK...")

            success = self.engine.analyze_application_package(
                self.application_package_path
            )

            if not success:
                self.finished.emit(False)
                return

            self._log("📦 Сбор результатов...")

            # =========================
            # 1. MANIFEST
            # =========================
            try:
                self.manifest_ready.emit(
                    self._safe_json(self.engine.manifest_data),
                    self._safe_json(self.engine.manifest_info),
                )
            except Exception:
                pass

            # =========================
            # 2. STRINGS
            # =========================
            try:
                self.strings_ready.emit(
                    self._safe_json(self.engine.strings_data)
                )
            except Exception:
                pass

            # =========================
            # 3. PERMISSIONS
            # =========================
            try:
                self.permissions_ready.emit(
                    self._safe_json(self.engine.permissions)
                )
            except Exception:
                pass

            # =========================
            # 4. THREATS
            # =========================
            try:
                self.threats_ready.emit(
                    self._safe_json(self.engine.threats)
                )
            except Exception:
                pass

            # =========================
            # 5. FILES
            # =========================
            try:
                files = [str(f) for f in self.engine.get_decompiled_files()]
                self.files_ready.emit(self._safe_json(files))
            except Exception:
                pass

            # =========================
            # 6. STATS
            # =========================
            try:
                self.stats_ready.emit(
                    self._safe_json(self.engine.get_statistics())
                )
            except Exception:
                pass

            # =========================
            # 7. GRAPH
            # =========================
            try:
                graph = self.engine.get_call_graph_data()
                threats = self.engine.threats

                self.graph_ready.emit(
                    self._safe_json(graph),
                    self._safe_json(threats),
                )
            except Exception:
                self.graph_ready.emit("{}", "[]")

            # =========================
            # 8. NETWORK / OSINT
            # =========================
            try:
                self.network_ready.emit(
                    self._safe_json(self.engine.get_network_indicators())
                )
            except Exception:
                pass

            try:
                self.osint_ready.emit(
                    self._safe_json(self.engine.get_osint_data())
                )
            except Exception:
                pass

            try:
                self.signature_ready.emit(
                    self._safe_json(self.engine.get_signature_info())
                )
            except Exception:
                pass

            # =========================
            # 9. NATIVE
            # =========================
            try:
                self.native_ready.emit(
                    self._safe_json(self.engine.get_native_analysis_results())
                )
            except Exception:
                pass

            # =========================
            # 10. RISK (INT SAFE)
            # =========================
            try:
                self.risk_ready.emit(int(self.engine.get_risk_score()))
            except Exception:
                pass

            # =========================
            # 11. ADVANCED MODULES
            # =========================
            modules = [
                (self.taint_ready, lambda: self.engine.get_taint_flows()),
                (self.behavioral_chains_ready, lambda: self.engine.get_behavioral_chains()),
                (self.crypto_ready, lambda: self.engine.crypto_findings),
                (self.anti_analysis_ready, lambda: self.engine.anti_analysis_findings),
                (self.structure_ready, lambda: self.engine.structure_findings),
                (self.privacy_ready, lambda: self.engine.get_privacy_violations()),
                (self.unpacking_ready, lambda: self.engine.get_unpacking_indicators()),
                (self.dynamic_config_ready, lambda: self.engine.get_dynamic_analysis_config()),
                (self.ml_features_ready, lambda: self.engine.ml_features),
            ]

            for signal, getter in modules:
                try:
                    signal.emit(self._safe_json(getter()))
                except Exception:
                    pass

            # =========================
            # 12. REPORT
            # =========================
            try:
                report_path = self.engine.save_consolidated_report()
                self.report_ready.emit(str(report_path))
                self._log(f"📄 Report saved: {report_path}")
            except Exception as e:
                self._log(f"⚠ Report error: {e}")

            self._log("=" * 60)
            self._log(f"🎯 RISK: {self.engine.get_risk_score()}/100")
            self._log("=" * 60)

            self.finished.emit(True)

        except Exception as e:
            self._log(f"❌ CRITICAL ERROR: {e}")
            self._log(traceback.format_exc())
            self.finished.emit(False)

        finally:
            self.cleanup_resources()

    # =========================
    # CLEANUP
    # =========================
    def cleanup_resources(self):
        if self.engine:
            try:
                self._log("🧹 Cleaning resources...")
                self.engine.cleanup_resources()
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")

    def stop_analysis(self):
        if not self.isRunning():
            return

        self._log("🛑 Stopping analysis...")

        try:
            if hasattr(self.engine, "_stop_flag"):
                self.engine._stop_flag = True
        except Exception:
            pass

        self.terminate()

        if not self.wait(5000):
            self._log("⚠ Thread stop timeout")

        try:
            self.cleanup_resources()
        except Exception:
            pass

    def __del__(self):
        self.cleanup_resources()