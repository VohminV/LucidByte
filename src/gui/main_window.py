"""
Главное Окно Приложения LucidByte
Назначение: Координация пользовательского интерфейса, управление жизненным циклом анализа,
визуализация результатов, интеграция с большой языковой моделью и экспорт отчётов.
"""
import os
import sys
import math
import json
import shutil
import traceback
import time
from datetime import datetime
from typing import Optional, List, Dict
from pathlib import Path

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QFileDialog, QStatusBar, QProgressBar,
    QLabel, QTabWidget, QTextEdit, QDockWidget,
    QMessageBox, QTreeWidget, QTreeWidgetItem, QListWidget,
    QPushButton, QToolBar, QGraphicsItem, QApplication, QGraphicsView,
    QGraphicsScene
)
from PySide6.QtGui import (
    QAction, QFont, QPen, QBrush, QColor, QIcon,
    QPainter, QLinearGradient, QPainterPath, QPolygonF
)
from PySide6.QtCore import Qt, QThread, Signal, QRectF, QPointF
import qdarkstyle

from src.gui.widgets.code_editor import CodeEditor
from src.gui.widgets.permission_tree import PermissionTree
from src.gui.widgets.threat_list import ThreatList
from src.gui.widgets.ai_chat import AiChatWidget
from src.gui.workers.analysis_worker import AnalysisWorker
from src.ai_engine.language_model_manager import LanguageModelManager
from src.ai_engine.prompts import ThreatAnalysisPrompts
from src.core.ip_validator import IPValidator

# ==============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==============================================================================
def extract_critical_sections(report_data: dict, max_indicators: int = 150) -> dict:
    network_indicators = report_data.get("network_indicators", {})
    validated_network = {}
    for key, value_list in network_indicators.items():
        if isinstance(value_list, list):
            if 'ip' in key.lower():
                validated_network[key] = [ip for ip in value_list if IPValidator.is_valid_ip(ip)][:50]
            else:
                validated_network[key] = value_list[:50]
        else:
            validated_network[key] = value_list
    return {
        "verdict": report_data.get("summary", {}).get("verdict"),
        "risk_score": report_data.get("summary", {}).get("risk_score", 0),
        "threats_detected": report_data.get("threats_detected", {}).get("detailed_threats", [])[:max_indicators],
        "network_indicators": validated_network,
        "permissions_analysis": report_data.get("permissions_analysis", {}).get("dangerous_permissions", [])[:50]
    }

# ==============================================================================
# ГРАФИЧЕСКИЕ ЭЛЕМЕНТЫ (ГРАФЫ)
# ==============================================================================
class GraphNodeItem(QGraphicsItem):
    """Элемент узла графа"""
    def __init__(self, text: str, node_type: str = "method", parent=None):
        super().__init__(parent)
        self.text = text
        self.node_type = node_type
        self.setFlag(QGraphicsItem.ItemIsMovable)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setAcceptHoverEvents(True)
        self.width = 140
        self.height = 50
        self.setPos(0, 0)

    def boundingRect(self):
        return QRectF(0, 0, self.width, self.height)

    def paint(self, painter, option, widget):
        gradient = QLinearGradient(0, 0, 0, self.height)
        if self.node_type == "threat":
            gradient.setColorAt(0, QColor("#FF416C"))
            gradient.setColorAt(1, QColor("#FF4B2B"))
        elif self.node_type == "class":
            gradient.setColorAt(0, QColor("#4A90D9"))
            gradient.setColorAt(1, QColor("#2C3E50"))
        else:
            gradient.setColorAt(0, QColor("#2ECC71"))
            gradient.setColorAt(1, QColor("#27AE60"))

        painter.setPen(QPen(QColor("#FFFFFF"), 3 if self.isSelected() else 1))
        painter.setBrush(QBrush(gradient))
        painter.setRenderHint(QPainter.Antialiasing)

        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width, self.height, 10, 10)
        painter.drawPath(path)

        painter.setPen(QColor("#FFFFFF"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        painter.drawText(self.boundingRect(), Qt.AlignCenter, self.text[:18])

class GraphEdgeItem(QGraphicsItem):
    """Элемент связи графа со стрелкой"""
    def __init__(self, start_item, end_item, parent=None):
        super().__init__(parent)
        self.start_item = start_item
        self.end_item = end_item
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setZValue(-1)

    def boundingRect(self):
        if not self.start_item or not self.end_item: return QRectF()
        return QRectF(self.start_item.pos(), self.end_item.pos()).normalized().adjusted(-10, -10, 10, 10)

    def paint(self, painter, option, widget):
        if not self.start_item or not self.end_item: return

        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor("#888888"), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))

        start_pos = self.start_item.pos() + QPointF(self.start_item.width / 2, self.start_item.height / 2)
        end_pos = self.end_item.pos() + QPointF(self.end_item.width / 2, self.end_item.height / 2)
        painter.drawLine(start_pos, end_pos)

        angle = math.atan2(end_pos.y() - start_pos.y(), end_pos.x() - start_pos.x())
        arrow_size = 10
        painter.setBrush(QColor("#888888"))
        arrow_point1 = QPointF(end_pos.x() - arrow_size * math.cos(angle - math.pi / 6), end_pos.y() - arrow_size * math.sin(angle - math.pi / 6))
        arrow_point2 = QPointF(end_pos.x() - arrow_size * math.cos(angle + math.pi / 6), end_pos.y() - arrow_size * math.sin(angle + math.pi / 6))
        painter.drawPolygon(QPolygonF([end_pos, arrow_point1, arrow_point2]))

class CallGraphView(QGraphicsView):
    """Визуализатор графа вызовов функций"""
    def __init__(self):
        super().__init__()
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setRenderHint(QPainter.Antialiasing)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setStyleSheet("QGraphicsView { background: #1e1e1e; border: 1px solid #333333; border-radius: 4px; }")
        self.zoom_level = 1.0
        self.nodes = {}
        self.setMinimumSize(400, 300)

    def wheelEvent(self, event):
        factor = 1.15
        if event.angleDelta().y() > 0: self.scale(factor, factor); self.zoom_level *= factor
        else: self.scale(1 / factor, 1 / factor); self.zoom_level /= factor
        event.accept()

    def draw_graph(self, graph_data: dict, threats: list = []):
        self.scene.clear()
        self.nodes = {}
        spacing_x, spacing_y = 180, 120
        for i, class_name in enumerate(graph_data.keys()):
            node = GraphNodeItem(class_name, "class")
            node.setPos((i % 6) * spacing_x, (i // 6) * spacing_y)
            self.scene.addItem(node)
            self.nodes[class_name] = node

        for src, targets in graph_data.items():
            if src in self.nodes:
                for dst in targets:
                    if dst in self.nodes:
                        self.scene.addItem(GraphEdgeItem(self.nodes[src], self.nodes[dst]))

    def clear_graph(self):
        self.scene.clear()
        self.nodes = {}

# ==============================================================================
# ГЛАВНОЕ ОКНО
# ==============================================================================
class MainWindow(QMainWindow):
    """Главное окно платформы анализа вредоносного программного обеспечения LucidByte."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LucidByte - Android Malware Analysis Platform")
        self.setMinimumSize(1600, 1000)
        
        self.current_apk_path = None
        self.analysis_worker: Optional[AnalysisWorker] = None
        self.decompiled_files: List[str] = []
        self.current_graph_data: Dict = {}
        self.current_threats: List = []
        self.current_permissions: List = []
        self.current_report_index: Optional[int] = None
        self.current_report_data: Optional[Dict] = None
        self.llm_manager: Optional[LanguageModelManager] = None
        self.history_file = "lucidbyte_report_history.json"
        self.report_history: List[Dict] = []

        self.setup_menu()
        self.setup_toolbar()
        self.setup_interface()
        self.setup_docks()
        self.setup_status_bar()
        self.apply_style()
        self.load_history()

    def setup_menu(self):
        menu = self.menuBar()
        file_menu = menu.addMenu("📁 Файл")
        file_menu.addAction("📂 Открыть APK (Ctrl+O)", self.open_apk_file)
        file_menu.addSeparator()
        file_menu.addAction("📤 Экспорт отчёта (Ctrl+E)", self.export_report)
        file_menu.addSeparator()
        file_menu.addAction("❌ Выход (Ctrl+Q)", self.close)

        analysis_menu = menu.addMenu("🔍 Анализ")
        analysis_menu.addAction("▶ Запустить анализ (F5)", self.start_analysis)
        analysis_menu.addSeparator()
        analysis_menu.addAction("🗑 Очистить результаты", self.clear_results)

        menu.addMenu("🛠 Инструменты").addAction("🔧 Проверить JADX", self.check_jadx)
        menu.addMenu("❓ Помощь").addAction("ℹ️ О программе", self.show_about)

    def setup_toolbar(self):
        tb = QToolBar("Основная панель")
        tb.setMovable(False)
        self.addToolBar(tb)
        
        tb.addAction("📂 Открыть", self.open_apk_file)
        tb.addSeparator()
        tb.addAction("▶ Этапы 1-2", self.start_analysis)
        tb.addSeparator()
        llm_btn = tb.addAction("🤖 Этапы 3-4 (LLM)", self.analyze_selected_report_with_ai)
        llm_btn.setToolTip("Запустить экспертную оценку LLM для выбранного отчёта")
        tb.addSeparator()
        tb.addAction("📤 Экспорт", self.export_report)

    def setup_interface(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self.ai_summary = QLabel("🤖 Ожидание загрузки APK файла...")
        self.ai_summary.setStyleSheet("background: #2d2d2d; color: #4A90D9; padding: 8px; border-radius: 4px; font-weight: bold;")
        layout.addWidget(self.ai_summary)

        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("<b style='color:#4A90D9'>🔐 Разрешения</b>"))
        self.permission_tree = PermissionTree()
        left_layout.addWidget(self.permission_tree)
        left_layout.addWidget(QLabel("<b style='color:#4A90D9'>⚠️ Угрозы</b>"))
        self.threat_list = ThreatList()
        left_layout.addWidget(self.threat_list)
        splitter.addWidget(left)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane { border: 1px solid #333; } QTabBar::tab { background: #2d2d2d; color: #fff; padding: 6px 12px; border: 1px solid #444; border-bottom: none; border-radius: 4px 4px 0 0; } QTabBar::tab:selected { background: #4A90D9; }")
        self.code_editor = CodeEditor()
        self.manifest_view = QTextEdit(); self.manifest_view.setReadOnly(True)
        self.strings_view = QTextEdit(); self.strings_view.setReadOnly(True)
        self.tabs.addTab(self.code_editor, "📄 Исходный код")
        self.tabs.addTab(self.manifest_view, "📋 Manifest")
        self.tabs.addTab(self.strings_view, "💬 Строки")
        splitter.addWidget(self.tabs)

        self.ai_chat = AiChatWidget()
        splitter.addWidget(self.ai_chat)
        splitter.setSizes([300, 900, 350])
        layout.addWidget(splitter, 1)

    def setup_docks(self):
        # Журнал
        self.log_dock = QDockWidget("📋 Журнал событий", self)
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setStyleSheet("QTextEdit { background: #0d0d0d; color: #00FF00; font-family: Consolas, monospace; font-size: 11px; border: none; }")
        self.log_dock.setWidget(self.log_widget)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.log_dock)

        # Граф вызовов (ИСПРАВЛЕНО: принудительная видимость и размер)
        self.graph_dock = QDockWidget("🕸 Call Graph", self)
        self.graph_view = CallGraphView()
        self.graph_dock.setWidget(self.graph_view)
        self.addDockWidget(Qt.RightDockWidgetArea, self.graph_dock)
        self.graph_dock.show()
        self.graph_dock.raise_()

        # История
        self.history_dock = QDockWidget("📜 История отчётов", self)
        hist_w = QWidget()
        hist_l = QVBoxLayout(hist_w)
        hist_l.setContentsMargins(4, 4, 4, 4)
        self.history_list = QListWidget()
        self.history_list.setStyleSheet("QListWidget { background: #1e1e1e; color: #fff; border: 1px solid #333; border-radius: 4px; } QListWidget::item:selected { background: #4A90D9; }")
        self.history_list.itemSelectionChanged.connect(self.on_history_selection_changed)
        self.analyze_history_btn = QPushButton("🤖 Анализировать выбранный отчёт")
        self.analyze_history_btn.setStyleSheet("QPushButton { background: #27AE60; color: white; padding: 6px; border: none; border-radius: 4px; font-weight: bold; } QPushButton:hover { background: #2ECC71; } QPushButton:disabled { background: #555; }")
        self.analyze_history_btn.clicked.connect(self.analyze_selected_report_with_ai)
        self.analyze_history_btn.setEnabled(False)
        hist_l.addWidget(self.history_list)
        hist_l.addWidget(self.analyze_history_btn)
        self.history_dock.setWidget(hist_w)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.history_dock)

    def setup_status_bar(self):
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setFixedWidth(200)
        self.progress.setStyleSheet("QProgressBar { border: 1px solid #333; background: #2d2d2d; } QProgressBar::chunk { background: #4A90D9; }")
        self.status.addPermanentWidget(self.progress)
        self.status_label = QLabel("Готово")
        self.status_label.setStyleSheet("color: #888888; margin-right: 10px;")
        self.status.addWidget(self.status_label, 1)

    def apply_style(self):
        self.setStyleSheet(qdarkstyle.load_stylesheet())
        self.setFont(QFont("Segoe UI", 10))

    def load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f: self.report_history = json.load(f)
                for e in self.report_history: self.history_list.addItem(f"{e.get('timestamp', '-')} | {e.get('filename', '-')} | Риск: {e.get('risk_score', 0)}")
            except Exception as e: self.log(f"⚠️ Ошибка загрузки истории: {e}")

    def save_history(self):
        try:
            with open(self.history_file, "w", encoding="utf-8") as f: json.dump(self.report_history, f, indent=2, ensure_ascii=False)
        except Exception as e: self.log(f"⚠️ Ошибка сохранения истории: {e}")

    def add_report_to_history(self, report_path: str, metadata: Dict):
        src = Path(report_path)
        dest = Path("reports") / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.exists(): shutil.copy2(src, dest)
        entry = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "filename": dest.name, "path": str(dest.resolve()), "risk_score": metadata.get("risk_score", 0), "threat_count": metadata.get("threat_count", 0)}
        self.report_history.append(entry)
        self.save_history()
        self.history_list.addItem(f"{entry['timestamp']} | {entry['filename']} | Риск: {entry['risk_score']}")
        self.history_list.scrollToBottom()

    def on_history_selection_changed(self):
        items = self.history_list.selectedItems()
        if not items: self.current_report_index = None; self.current_report_data = None; self.analyze_history_btn.setEnabled(False); return
        idx = self.history_list.row(items[0])
        self.current_report_index = idx
        self.analyze_history_btn.setEnabled(True)
        p = Path(self.report_history[idx].get("path", ""))
        found = next((x.resolve() for x in [p, Path("reports")/p.name] if x.exists() and x.is_file()), None)
        if not found: self.log(f"⚠️ Файл отчёта не найден: {p.name}"); self.current_report_data = None; return
        try:
            with open(found, "r", encoding="utf-8") as f: self.current_report_data = json.load(f)
            self._update_ui_from_report(self.current_report_data)
            self.log(f"📄 Отчёт загружен: {p.name}")
        except Exception as e: self.log(f"✗ Ошибка загрузки: {e}"); self.current_report_data = None

    def _update_ui_from_report(self, data: dict):
        if not data: return
        self.threat_list.clear()
        threats = data.get("threats_detected", {}).get("detailed_threats", data.get("threats", []))
        if threats: self.threat_list.add_threats(threats)
        self.permission_tree.clear()
        perms = data.get("permissions_analysis", {}).get("all_permissions", data.get("permissions", []))
        if perms: self.permission_tree.add_permissions(perms)
        manifest = data.get("application_info", {})
        if manifest: self.manifest_view.setText(json.dumps(manifest, indent=2, ensure_ascii=False))
        s = data.get("summary", {})
        self.ai_summary.setText(f"Отчёт: {s.get('file_name', '-')} | Файлов: {s.get('total_files', 0)} | Угроз: {s.get('total_threats', 0)} | Риск: {s.get('risk_score', 0)}/100")

    def analyze_selected_report_with_ai(self):
        if not self.current_report_data:
            self.log("⚠️ Выберите отчёт из истории или запустите анализ APK")
            return
        critical = extract_critical_sections(self.current_report_data)
        payload = json.dumps(critical, ensure_ascii=False, separators=(',', ':'))
        if not self.llm_manager: self.llm_manager = LanguageModelManager(base_url="http://localhost:11434", model_name="qwen2.5-coder:14b")
        self.ai_chat.set_typing_indicator(True)
        QApplication.processEvents()
        try:
            ioc = self.llm_manager.send_request(prompt=ThreatAnalysisPrompts.IOC_EXTRACTION_PROMPT.format(analysis_data=payload), system_instruction=ThreatAnalysisPrompts.SYSTEM_IOC_EXTRACTION)
            if not ioc: raise RuntimeError("Нет ответа IoC")
            verdict = self.llm_manager.send_request(prompt=ThreatAnalysisPrompts.VERDICT_PROMPT.format(ioc_data=ioc), system_instruction=ThreatAnalysisPrompts.SYSTEM_VERDICT)
            if verdict:
                self.ai_chat.add_ai_response(f"## 🔍 IoC Extraction\n\n{ioc}\n\n---\n\n## ⚖️ Verdict\n\n{verdict}")
                self.log("✅ Анализ завершён")
            else: self.log("✗ Ошибка вердикта")
        except Exception as e: self.log(f"✗ Ошибка LLM: {e}")
        finally: self.ai_chat.set_typing_indicator(False)

    def open_apk_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите APK", "", "APK (*.apk)")
        if path:
            self.current_apk_path = path
            self.status_label.setText(f"📱 {os.path.basename(path)}")
            self.log(f"✓ Загружен: {path}")
            self.start_analysis()

    def start_analysis(self):
        if not self.current_apk_path: QMessageBox.warning(self, "Ошибка", "Сначала выберите APK"); return
        if self.analysis_worker and self.analysis_worker.isRunning(): return
        self.progress.setVisible(True); self.progress.setValue(0); self.status_label.setText("🔄 Анализ...")
        if self.analysis_worker: self.analysis_worker.stop_analysis(); self.analysis_worker.wait(2000)
        self.analysis_worker = AnalysisWorker(self.current_apk_path)
        for s, sl in [('progress', self.on_analysis_progress), ('log_signal', self.log), ('finished', self.on_analysis_finished),
                      ('manifest_ready', self.on_manifest_ready), ('strings_ready', self.on_strings_ready),
                      ('permissions_ready', self.on_permissions_ready), ('threats_ready', self.on_threats_ready),
                      ('files_ready', self.on_files_ready), ('graph_ready', self.on_graph_ready),
                      ('report_ready', self.on_report_ready), ('risk_ready', self.on_risk_ready)]:
            try: getattr(self.analysis_worker, s).connect(sl)
            except: pass
        self.analysis_worker.start()

    def on_analysis_progress(self, v, m): self.progress.setValue(v); self.status_label.setText(f"🔄 {m}")
    def on_analysis_finished(self, ok):
        self.progress.setVisible(False)
        if ok: self.status_label.setText("✅ Завершено"); self.log("✅ Этапы 1-2 выполнены.")
        else: self.status_label.setText("❌ Ошибка"); QMessageBox.critical(self, "Ошибка", "Не удалось завершить анализ.")

    def on_manifest_ready(self, c, i=None): self.manifest_view.setText(c)
    def on_strings_ready(self, s): self.strings_view.setText("\n".join(s[:1000]))
    def on_permissions_ready(self, p):
        self.permission_tree.clear()
        for x in p:
            it = QTreeWidgetItem([x.get("name", ""), x.get("risk", "")])
            self.permission_tree.addTopLevelItem(it)
    def on_threats_ready(self, t): self.threat_list.clear(); [self.threat_list.addTopLevelItem(QTreeWidgetItem([x.get("risk",""), x.get("desc",""), x.get("file","")])) for x in t]
    def on_files_ready(self, f):
        self.decompiled_files = f
        js = [x for x in f if x.endswith('.java')]
        if js: self.code_editor.load_file(js[0])
    def on_graph_ready(self, g, t):
        self.current_graph_data = g
        if g: self.graph_view.draw_graph(g, t); self.log(f"🕸 Граф построен: {len(g)} узлов")
        else: self.log("⚠️ Граф пуст")
    def on_report_ready(self, p): self.add_report_to_history(p, {"risk_score": getattr(self, 'current_risk_score', 0), "threat_count": self.threat_list.topLevelItemCount()}); self.log(f"✅ Отчёт: {p}")
    def on_risk_ready(self, r): setattr(self, 'current_risk_score', r); self.log(f"🎯 Риск: {r}/100")

    def log(self, t): self.log_widget.append(f"[{QThread.currentThread().objectName() or 'Main'}] {t}"); self.log_widget.verticalScrollBar().setValue(self.log_widget.verticalScrollBar().maximum())
    def set_ai_summary(self, t): self.ai_summary.setText(f"🤖 {t}")
    def clear_results(self):
        if QMessageBox.question(self, "Подтверждение", "Очистить всё?", QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            self.threat_list.clear(); self.permission_tree.clear(); self.code_editor.clear(); self.manifest_view.clear(); self.strings_view.clear()
            self.decompiled_files = []; self.current_graph_data = {}; self.set_ai_summary("🤖 Очищено.")
            self.log("🗑 Очищено")

    def export_report(self):
        if self.current_report_index is not None:
            p = self.report_history[self.current_report_index].get("path")
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f: data = json.load(f)
            else: QMessageBox.warning(self, "Ошибка", "Файл не найден"); return
        elif not self.decompiled_files: QMessageBox.warning(self, "Ошибка", "Нет данных"); return
        else: data = {"summary": {"risk_score": getattr(self, 'current_risk_score', 0)}}
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить", "report.json", "JSON (*.json)")
        if path:
            with open(path, 'w', encoding='utf-8') as f: json.dump(data, f, indent=2, ensure_ascii=False)
            self.log(f"✓ Экспортировано: {path}")

    def check_jadx(self):
        import shutil, subprocess
        p = shutil.which("jadx")
        if p: QMessageBox.information(self, "JADX", f"✓ Найден: {p}")
        else: QMessageBox.warning(self, "JADX", "✗ Не в PATH")

    def show_about(self): QMessageBox.about(self, "О программе", "<h2>LucidByte</h2><p>v4.0</p>")

    def closeEvent(self, event):
        if self.analysis_worker and self.analysis_worker.isRunning():
            if QMessageBox.question(self, "Выход", "Завершить анализ?", QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes: event.ignore(); return
            self.analysis_worker.stop_analysis()
        try: import jpype; jpype.shutdownJVM() if jpype.isJVMStarted() else None
        except: pass
        event.accept()