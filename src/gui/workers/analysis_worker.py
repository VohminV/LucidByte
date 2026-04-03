"""
Рабочий поток для анализа APK
Назначение: Асинхронное выполнение анализа в отдельном потоке
"""
from PySide6.QtCore import QThread, Signal
from src.core.analysis_engine import AnalysisEngine
from typing import List, Dict, Optional
from pathlib import Path
import traceback


class AnalysisWorker(QThread):
    """
    Рабочий поток для анализа APK файлов
    Режим: Полноценный Реверс-Инженеринг Android
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
    
    # ✅ НОВОЕ: Сигнал графа вызовов
    graph_ready = Signal(dict, list)
    
    # ✅ НОВОЕ: Сигнал отчёта
    report_ready = Signal(str)
    
    # ✅ НОВОЕ: Сигнал сетевых индикаторов
    network_ready = Signal(dict)
    
    # ✅ НОВОЕ: Сигнал сигнатурного анализа
    signature_ready = Signal(dict)
    
    # ✅ НОВОЕ: Сигнал OSINT данных
    osint_ready = Signal(dict)
    
    # ✅ НОВОЕ: Сигнал native анализа
    native_ready = Signal(dict)
    
    # ✅ НОВОЕ: Сигнал оценки риска
    risk_ready = Signal(int)
    
    def __init__(self, apk_path: str):
        """
        Инициализация рабочего потока
        
        Аргументы:
            apk_path: Путь к APK файлу для анализа
        """
        super().__init__()
        self.apk_path = apk_path
        self.engine = AnalysisEngine()
        
        # Активация Ghidra
        self.engine.enable_ghidra(True)
        
        # Колбэки
        self.engine.set_progress_callback(self._on_progress)
        self.engine.set_log_callback(self._on_log)
    
    def _on_progress(self, value: int, message: str):
        """
        Обработка прогресса от движка анализа
        
        Аргументы:
            value: Значение прогресса (0-100)
            message: Сообщение о текущем этапе
        """
        self.progress.emit(value, message)
    
    def _on_log(self, message: str):
        """
        Обработка логов от движка анализа
        
        Аргументы:
            message: Сообщение лога
        """
        self.log_signal.emit(message)
    
    def run(self):
        """
        Основной метод анализа
        Выполняется в отдельном потоке
        """
        try:
            self._log("🚀 Запуск AnalysisWorker...")
            
            # Запуск анализа
            success = self.engine.analyze_apk(self.apk_path)
            
            if success:
                self._log("✅ Анализ завершён")
                
                # Эмит данных манифеста
                self.manifest_ready.emit(
                    self.engine.manifest_data,
                    self.engine.manifest_info
                )
                
                # Эмит строк
                self.strings_ready.emit(self.engine.strings_data)
                
                # Эмит разрешений
                self.permissions_ready.emit(self.engine.permissions)
                
                # Эмит угроз
                self.threats_ready.emit(self.engine.threats)
                
                # Эмит файлов
                files = [str(f) for f in self.engine.get_decompiled_files()]
                self.files_ready.emit(files)
                
                # Эмит статистики
                self.stats_ready.emit(self.engine.get_statistics())
                
                # ✅ ЭМИТ ГРАФА ВЫЗОВОВ
                try:
                    graph_data = self.engine.get_call_graph_data()
                    self.graph_ready.emit(graph_data, self.engine.threats)
                    self._log(f"🕸 Граф отправлен: {len(graph_data)} узлов")
                except AttributeError as error:
                    self._log(f"⚠ Ошибка графа: {error}")
                    self.graph_ready.emit({}, [])
                except Exception as error:
                    self._log(f"⚠ Ошибка графа: {error}")
                    self.graph_ready.emit({}, [])
                
                # ✅ ЭМИТ СЕТЕВЫХ ИНДИКАТОРОВ
                try:
                    network_indicators = self.engine.get_network_indicators()
                    self.network_ready.emit(network_indicators)
                    total_count = sum(len(v) for v in network_indicators.values())
                    self._log(f"🌐 Сетевые индикаторы: {total_count}")
                except AttributeError as error:
                    self._log(f"⚠ Ошибка сетевых индикаторов: {error}")
                    self.network_ready.emit({})
                except Exception as error:
                    self._log(f"⚠ Ошибка сетевых индикаторов: {error}")
                    self.network_ready.emit({})
                
                # ✅ ЭМИТ СИГНАТУРНОГО АНАЛИЗА
                try:
                    signature_info = self.engine.get_signature_info()
                    self.signature_ready.emit(signature_info)
                    if signature_info.get('has_match'):
                        self._log(f"⚠️ Сигнатурное совпадение: {signature_info.get('risk_level')}")
                    else:
                        self._log("✅ Сигнатурных совпадений не найдено")
                except AttributeError as error:
                    self._log(f"⚠ Ошибка сигнатурного анализа: {error}")
                    self.signature_ready.emit({})
                except Exception as error:
                    self._log(f"⚠ Ошибка сигнатурного анализа: {error}")
                    self.signature_ready.emit({})
                
                # ✅ ЭМИТ OSINT ДАННЫХ
                try:
                    osint_data = self.engine.get_osint_data()
                    self.osint_ready.emit(osint_data)
                    self._log(f"🔍 OSINT данные: {len(osint_data)} категорий")
                except AttributeError as error:
                    self._log(f"⚠ Ошибка OSINT: {error}")
                    self.osint_ready.emit({})
                except Exception as error:
                    self._log(f"⚠ Ошибка OSINT: {error}")
                    self.osint_ready.emit({})
                
                # ✅ ЭМИТ NATIVE АНАЛИЗА
                try:
                    native_data = self.engine.get_native_analysis_results()
                    self.native_ready.emit(native_data)
                    self._log(f"📦 Native анализ: {len(native_data)} библиотек")
                except AttributeError as error:
                    self._log(f"⚠ Ошибка native анализа: {error}")
                    self.native_ready.emit({})
                except Exception as error:
                    self._log(f"⚠ Ошибка native анализа: {error}")
                    self.native_ready.emit({})
                
                # ✅ ЭМИТ ОЦЕНКИ РИСКА
                try:
                    risk_score = self.engine.get_risk_score()
                    self.risk_ready.emit(risk_score)
                    self._log(f"🎯 Оценка риска: {risk_score}/100")
                except AttributeError as error:
                    self._log(f"⚠ Ошибка оценки риска: {error}")
                    self.risk_ready.emit(0)
                except Exception as error:
                    self._log(f"⚠ Ошибка оценки риска: {error}")
                    self.risk_ready.emit(0)
                
                # ✅ СОХРАНЕНИЕ ОТЧЁТА
                try:
                    report_path = self.engine.save_consolidated_report("analysis_results")
                    self.report_ready.emit(str(report_path))
                    self._log(f"📄 Отчёт: {report_path}")
                except AttributeError as error:
                    self._log(f"⚠ Не удалось сохранить отчёт: {error}")
                except Exception as error:
                    self._log(f"⚠ Не удалось сохранить отчёт: {error}")
                
                # Логирование результатов
                self._log("=" * 70)
                self._log("📊 РЕЗУЛЬТАТЫ")
                critical_count = len([threat for threat in self.engine.threats if threat.get('risk') == 'Critical'])
                high_count = len([threat for threat in self.engine.threats if threat.get('risk') == 'High'])
                medium_count = len([threat for threat in self.engine.threats if threat.get('risk') == 'Medium'])
                self._log(f"🔴 Critical: {critical_count}")
                self._log(f"🟠 High: {high_count}")
                self._log(f"🟡 Medium: {medium_count}")
                self._log(f"🎯 Риск: {self.engine.get_risk_score()}/100")
                self._log("=" * 70)
            
            self.finished.emit(success)
            
        except Exception as exception:
            error_trace = traceback.format_exc()
            self.log_signal.emit(f"❌ Ошибка: {str(exception)}")
            self.log_signal.emit(f"📋 Трассировка:\n{error_trace}")
            self.finished.emit(False)
    
    def _log(self, message: str):
        """
        Внутренний метод логирования
        
        Аргументы:
            message: Сообщение лога
        """
        self.log_signal.emit(message)
    
    def stop_analysis(self):
        """
        Остановка анализа
        Принудительно завершает выполнение потока
        """
        if self.isRunning():
            self._log("⏹ Остановка...")
            self.terminate()
            self.wait(5000)