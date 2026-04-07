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
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QFileDialog,
    QStatusBar, QProgressBar, QLabel, QTabWidget, QTextEdit, QDockWidget,
    QMessageBox, QTreeWidget, QTreeWidgetItem, QListWidget, QPushButton, QToolBar, 
    QGraphicsItem, QGraphicsView, QApplication, QGraphicsScene
)
from PySide6.QtGui import QAction, QFont, QPen, QBrush, QColor, QPainter, QLinearGradient, QPainterPath, QPolygonF
from PySide6.QtCore import Qt, QThread, Signal, QRectF, QPointF
import qdarkstyle

# Импорт виджетов и компонентов
from src.gui.widgets.code_editor import CodeEditor
from src.gui.widgets.permission_tree import PermissionTree
from src.gui.widgets.threat_list import ThreatList
from src.gui.widgets.ai_chat import AiChatWidget
from src.gui.workers.analysis_worker import AnalysisWorker
from src.ai_engine.language_model_manager import LanguageModelManager
from src.ai_engine.prompts import ThreatAnalysisPrompts
from src.core.ip_validator import IPValidator

# ==============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И КЛАССЫ ГРАФА
# ==============================================================================
def extract_critical_sections(report_data: dict, max_indicators: int = 150) -> dict:
    """Извлекает и валидирует критические данные для LLM."""
    network = report_data.get("network_indicators", {})
    validated = {}
    for k, v in network.items():
        if isinstance(v, list):
            if 'ip' in k.lower():
                validated[k] = [ip for ip in v if IPValidator.is_valid_ip(ip)][:50]
            else: validated[k] = v[:50]
        else: validated[k] = v
    return {
        "verdict": report_data.get("summary", {}).get("verdict"),
        "risk_score": report_data.get("summary", {}).get("risk_score", 0),
        "threats_detected": report_data.get("threats_detected", {}).get("detailed_threats", [])[:max_indicators],
        "network_indicators": validated,
        "permissions_analysis": report_data.get("permissions_analysis", {}).get("dangerous_permissions", [])[:50]
    }

class GraphNodeItem(QGraphicsItem):
    def __init__(self, text: str, node_type: str = "method", parent=None):
        super().__init__(parent)
        self.text = text
        self.node_type = node_type
        self.setFlag(QGraphicsItem.ItemIsMovable)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setAcceptHoverEvents(True)
        self.width, self.height = 140, 50

    def boundingRect(self): return QRectF(0, 0, self.width, self.height)

    def paint(self, painter, option, widget):
        grad = QLinearGradient(0, 0, 0, self.height)
        if self.node_type == "threat": grad.setColorAt(0, QColor("#FF416C")); grad.setColorAt(1, QColor("#FF4B2B"))
        elif self.node_type == "class": grad.setColorAt(0, QColor("#4A90D9")); grad.setColorAt(1, QColor("#2C3E50"))
        else: grad.setColorAt(0, QColor("#2ECC71")); grad.setColorAt(1, QColor("#27AE60"))
        
        painter.setPen(QPen(QColor("#FFFFFF"), 3 if self.isSelected() else 1))
        painter.setBrush(QBrush(grad))
        painter.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width, self.height, 10, 10)
        painter.drawPath(path)
        painter.setPen(QColor("#FFFFFF"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        painter.drawText(self.boundingRect(), Qt.AlignCenter, self.text[:18])

class GraphEdgeItem(QGraphicsItem):
    def __init__(self, start, end, parent=None):
        super().__init__(parent)
        self.start_item = start
        self.end_item = end
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setZValue(-1)

    def boundingRect(self):
        if not self.start_item or not self.end_item: return QRectF()
        return QRectF(self.start_item.pos(), self.end_item.pos()).normalized().adjusted(-10, -10, 10, 10)

    def paint(self, painter, option, widget):
        if not self.start_item or not self.end_item: return
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor("#888888"), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p1 = self.start_item.pos() + QPointF(self.start_item.width/2, self.start_item.height/2)
        p2 = self.end_item.pos() + QPointF(self.end_item.width/2, self.end_item.height/2)
        painter.drawLine(p1, p2)
        angle = math.atan2(p2.y()-p1.y(), p2.x()-p1.x())
        poly = QPolygonF([p2, QPointF(p2.x()-10*math.cos(angle-math.pi/6), p2.y()-10*math.sin(angle-math.pi/6)),
                          QPointF(p2.x()-10*math.cos(angle+math.pi/6), p2.y()-10*math.sin(angle+math.pi/6))])
        painter.setBrush(QColor("#888888"))
        painter.drawPolygon(poly)

class CallGraphView(QGraphicsView):
    def __init__(self):
        super().__init__()
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setRenderHint(QPainter.Antialiasing)
        self.setStyleSheet("QGraphicsView { background: #1e1e1e; border: 1px solid #333333; border-radius: 4px; }")
        self.nodes = {}

    def draw_graph(self, graph_data: dict, threats: list = []):
        self.scene.clear()
        self.nodes = {}
        for i, name in enumerate(graph_data.keys()):
            n = GraphNodeItem(name, "class")
            n.setPos((i % 6) * 180, (i // 6) * 120)
            self.scene.addItem(n)
            self.nodes[name] = n
        for src, dsts in graph_data.items():
            if src in self.nodes:
                for dst in dsts:
                    if dst in self.nodes: self.scene.addItem(GraphEdgeItem(self.nodes[src], self.nodes[dst]))

    def clear_graph(self): self.scene.clear(); self.nodes = {}

# ==============================================================================
# ГЛАВНОЕ ОКНО
# ==============================================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LucidByte - Android Malware Analysis Platform")
        self.setMinimumSize(1600, 1000)

        self.current_apk_path = None
        self.analysis_worker: Optional[AnalysisWorker] = None
        self.decompiled_files: List[str] = []
        self.current_report_data: Optional[Dict] = None
        self.current_report_index: Optional[int] = None
        self.llm_manager: Optional[LanguageModelManager] = None
        
        self.report_history: List[Dict] = []
        self.history_file = "lucidbyte_report_history.json"

        self.setup_ui()
        self.load_history()

    def setup_ui(self):
        self.setup_menu()
        self.setup_toolbar()
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        self.ai_summary = QLabel("🤖 Ожидание анализа APK...")
        self.ai_summary.setStyleSheet("background: #2d2d2d; color: #4A90D9; padding: 10px; border-radius: 6px; font-weight: bold;")
        layout.addWidget(self.ai_summary)
        
        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0,0,0,0) 
        left_layout.addWidget(QLabel(" <b style='color:#4A90D9'>🔐 Разрешения</b> "))
        self.permission_tree = PermissionTree()
        left_layout.addWidget(self.permission_tree)
        left_layout.addWidget(QLabel(" <b style='color:#4A90D9'>⚠️ Угрозы</b> "))
        self.threat_list = ThreatList()
        left_layout.addWidget(self.threat_list)
        splitter.addWidget(left)
        
        self.tabs = QTabWidget()
        self.code_editor = CodeEditor()
        self.manifest_view = QTextEdit()
        self.manifest_view.setReadOnly(True)
        self.strings_view = QTextEdit()
        self.strings_view.setReadOnly(True)
        self.tabs.addTab(self.code_editor, "📄 Код")
        self.tabs.addTab(self.manifest_view, "📋 Manifest")
        self.tabs.addTab(self.strings_view, "💬 Строки")
        splitter.addWidget(self.tabs)
        
        self.ai_chat = AiChatWidget()
        splitter.addWidget(self.ai_chat)
        splitter.setSizes([300, 900, 350])
        layout.addWidget(splitter, 1)
        
        self.setup_docks()
        self.setup_status_bar()
        self.setStyleSheet(qdarkstyle.load_stylesheet())
        self.setFont(QFont("Segoe UI", 10))

    def setup_menu(self):
        m = self.menuBar()
        f = m.addMenu("📁 Файл")
        f.addAction("📂 Открыть (Ctrl+O)", self.open_apk_file).setShortcut("Ctrl+O")
        f.addSeparator()
        f.addAction("📤 Экспорт (Ctrl+E)", self.export_report).setShortcut("Ctrl+E")
        f.addSeparator()
        f.addAction("❌ Выход (Ctrl+Q)", self.close).setShortcut("Ctrl+Q")
        
        a = m.addMenu("🔍 Анализ")
        a.addAction("▶ Этапы 1-2 (F5)", self.start_analysis).setShortcut("F5")
        a.addAction("🗑 Очистить", self.clear_results)
        
        m.addMenu("🛠 Инструменты").addAction("🔧 Проверить JADX", self.check_jadx)
        m.addMenu("❓ Помощь").addAction("ℹ️ О программе", lambda: QMessageBox.about(self, "LucidByte", " <h2>LucidByte v4.0</h2> <p>© 2026</p> "))

    def setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        open_btn = QPushButton("📂 Открыть")
        open_btn.clicked.connect(self.open_apk_file)
        toolbar.addWidget(open_btn)
        toolbar.addSeparator()
        
        analyze_btn = QPushButton("▶ Этапы 1-2")
        analyze_btn.clicked.connect(self.start_analysis)
        toolbar.addWidget(analyze_btn)
        toolbar.addSeparator()
        
        btn_llm = QPushButton("🤖 Этапы 3-4 (LLM)")
        btn_llm.setStyleSheet("background: #27AE60; color: white; font-weight: bold; padding: 4px 10px; border: none; border-radius: 3px;")
        # Исправлено: привязка к существующему методу
        btn_llm.clicked.connect(self.analyze_selected_report_with_ai)
        toolbar.addWidget(btn_llm)
        toolbar.addSeparator()
        
        export_btn = QPushButton("📤 Экспорт")
        export_btn.clicked.connect(self.export_report)
        toolbar.addWidget(export_btn)

    def setup_docks(self):
        self.log_dock = QDockWidget("📋 Журнал", self)
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setStyleSheet("QTextEdit { background: #0d0d0d; color: #00FF00; font-family: Consolas, monospace; border: none; }")
        self.log_dock.setWidget(self.log_widget)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.log_dock)
        
        self.graph_dock = QDockWidget("🕸 Call Graph", self)
        self.graph_view = CallGraphView()
        self.graph_dock.setWidget(self.graph_view)
        self.addDockWidget(Qt.RightDockWidgetArea, self.graph_dock)
        self.graph_dock.show()
        
        self.history_dock = QDockWidget("📜 История", self)
        hw = QWidget()
        hl = QVBoxLayout(hw)
        hl.setContentsMargins(4,4,4,4)
        self.history_list = QListWidget()
        self.history_list.setStyleSheet("QListWidget { background: #1e1e1e; color: white; border: 1px solid #333; border-radius: 4px; } QListWidget::item:selected { background: #4A90D9; }")
        self.history_list.itemSelectionChanged.connect(self.on_history_selection_changed)
        self.analyze_history_btn = QPushButton("🤖 Анализировать отчёт")
        self.analyze_history_btn.clicked.connect(self.analyze_selected_report_with_ai)
        self.analyze_history_btn.setEnabled(False)
        hl.addWidget(self.history_list)
        hl.addWidget(self.analyze_history_btn)
        self.history_dock.setWidget(hw)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.history_dock)

    def setup_status_bar(self):
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setRange(0,100)
        self.progress.setFixedWidth(200)
        self.status.addPermanentWidget(self.progress, 1)
        self.status_label = QLabel("Готово")
        self.status_label.setStyleSheet("color: #888; margin-right: 10px;")
        self.status.addWidget(self.status_label, 1)

    def log(self, text: str):
        ts = QThread.currentThread().objectName() or "Main"
        self.log_widget.append(f"[{ts}] {text}")
        self.log_widget.verticalScrollBar().setValue(self.log_widget.verticalScrollBar().maximum())

    # ============================================================================== 
    # ЛОГИКА АНАЛИЗА
    # ==============================================================================
    def start_analysis(self):
        if not self.current_apk_path:
            QMessageBox.warning(self, "Ошибка", "Сначала выберите APK файл.")
            return
        if self.analysis_worker and self.analysis_worker.isRunning():
            QMessageBox.warning(self, "Внимание", "Анализ уже выполняется.")
            return
            
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.status_label.setText("🔄 Анализ...")
        if self.analysis_worker: self.analysis_worker.stop_analysis(); self.analysis_worker.wait(2000)
            
        self.analysis_worker = AnalysisWorker(self.current_apk_path)
        signals_map = {
            'progress': self.on_progress, 'log_signal': self.log, 'finished': self.on_finished,
            'manifest_ready': self.on_manifest, 'strings_ready': self.on_strings, 'permissions_ready': self.on_permissions,
            'threats_ready': self.on_threats, 'files_ready': self.on_files, 'graph_ready': self.on_graph,
            'report_ready': self.on_report, 'risk_ready': self.on_risk, 'network_ready': self.on_network,
            'osint_ready': self.on_osint, 'signature_ready': self.on_signature, 'native_ready': self.on_native,
            'taint_ready': self.on_taint, 'behavioral_chains_ready': self.on_chains,
            'crypto_ready': self.on_crypto, 'anti_analysis_ready': self.on_anti,
            'privacy_ready': self.on_privacy, 'unpacking_ready': self.on_unpack, 'dynamic_config_ready': self.on_dynamic,
            'ml_features_ready': self.on_ml
        }
        for s, sl in signals_map.items():
            try: getattr(self.analysis_worker, s).connect(sl)
            except AttributeError: pass
                
        self.analysis_worker.start()
        self.log("⏳ Запущен анализ в фоне...")

    def on_progress(self, v, m): self.progress.setValue(v); self.status_label.setText(f"🔄 {m}")
    def on_finished(self, ok):
        self.progress.setVisible(False)
        if ok: self.status_label.setText("✅ Готово"); self.log("✅ Этапы 1-2 завершены.")
        else: self.status_label.setText("❌ Ошибка"); QMessageBox.critical(self, "Ошибка", "Анализ прерван. Проверьте лог.")

    # Слоты с десериализацией JSON
    def on_manifest(self, manifest_str: str, info_str: str): 
        self.manifest_view.setText(manifest_str)

    def on_strings(self, s: str):
        try: self.strings_view.setText("\n".join(json.loads(s)[:1000]))
        except json.JSONDecodeError: self.strings_view.setText("")

    def on_permissions(self, p: str):
        try:
            perms = json.loads(p)
            self.permission_tree.clear()
            for x in perms:
                it = QTreeWidgetItem([x.get("name", " "), x.get("risk", " ")])
                c = {"Critical": "#ff0000", "High": "#ff6b6b", "Medium": "#ffa500", "Low": "#90ee90"}.get(x.get("risk", "Low"), "#fff")
                it.setForeground(1, QColor(c))
                self.permission_tree.addTopLevelItem(it)
        except json.JSONDecodeError: pass

    def on_threats(self, t: str):
        try:
            threats = json.loads(t)
            self.threat_list.clear()
            for x in threats:
                fp = x.get("file", "Unknown")
                if len(fp) > 60: fp = "..." + fp[-57:]
                it = QTreeWidgetItem([x.get("risk", " "), x.get("desc", " "), fp])
                self.threat_list.addTopLevelItem(it)
        except json.JSONDecodeError: pass

    def on_files(self, f: str):
        try:
            self.decompiled_files = json.loads(f)
            js = [x for x in self.decompiled_files if x.endswith('.java')]
            if js: self.code_editor.load_file(js[0])
        except json.JSONDecodeError: pass

    def on_graph(self, g: str, t: str):
        try:
            graph = json.loads(g)
            threats = json.loads(t)
            self.graph_view.clear_graph()
            if graph: self.graph_view.draw_graph(graph, threats); self.log(f"🕸 Граф: {len(graph)} узлов")
        except json.JSONDecodeError: pass

    def on_risk(self, r: int): self.log(f"🎯 Риск: {r}/100")

    def on_network(self, d: str):
        try:
            data = json.loads(d)
            count = sum(len(v) for v in data.values()) if isinstance(data, dict) else 0
            self.log(f"🌐 Сеть: {count} индикаторов")
        except json.JSONDecodeError: pass

    def on_osint(self, d: str):
        try:
            data = json.loads(d)
            self.log(f"🔍 OSINT: {len(data.get('urls',[]))} URL")
        except json.JSONDecodeError: pass

    def on_signature(self, d: str): self.log("✅ Сигнатуры проверены")

    def on_native(self, d: str):
        try:
            data = json.loads(d)
            self.log(f"📦 Native: {len(data)} библиотек")
        except json.JSONDecodeError: pass

    def on_taint(self, f: str):
        try:
            data = json.loads(f)
            self.log(f"🌊 Taint: {len(data)} потоков")
        except json.JSONDecodeError: pass

    def on_chains(self, c: str):
        try:
            data = json.loads(c)
            self.log(f"🔗 Цепочки: {len(data)}")
        except json.JSONDecodeError: pass

    def on_crypto(self, f: str):
        try:
            data = json.loads(f)
            self.log(f"🔐 Crypto: {len(data)} проблем")
        except json.JSONDecodeError: pass

    def on_anti(self, f: str):
        try:
            data = json.loads(f)
            self.log(f"🛡 Anti-Analysis: {len(data)} защит")
        except json.JSONDecodeError: pass

    def on_privacy(self, v: str):
        try:
            data = json.loads(v)
            self.log(f"🔒 Privacy: {len(data)} нарушений")
        except json.JSONDecodeError: pass

    def on_unpack(self, i: str):
        try:
            data = json.loads(i)
            self.log(f"📦 Unpacking: {len(data)} признаков")
        except json.JSONDecodeError: pass

    def on_dynamic(self, c: str): self.log("⚙️ Dynamic Config готов")

    def on_ml(self, f: str):
        try:
            data = json.loads(f)
            self.log(f"🤖 ML Features: {len(data)}")
        except json.JSONDecodeError: pass

    def on_report(self, p):
        self.log(f"✅ Отчёт сохранён: {p}")
        self.add_report_to_history(p, {"risk_score": getattr(self, 'current_risk', 0), "threat_count": self.threat_list.topLevelItemCount()})

    def clear_results(self):
        if QMessageBox.question(self, "Подтверждение", "Очистить всё?", QMessageBox.Yes|QMessageBox.No) == QMessageBox.Yes:
            self.threat_list.clear()
            self.permission_tree.clear()
            self.code_editor.clear()
            self.manifest_view.clear()
            self.strings_view.clear()
            self.decompiled_files = []
            self.log("🗑 Очищено")

    def open_apk_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите APK", "", "APK (*.apk)")
        if path:
            self.current_apk_path = path
            self.status_label.setText(f"📱 {os.path.basename(path)}")
            self.log(f"✓ Загружен: {path}")
            self.start_analysis()

    def add_report_to_history(self, path: str, meta: Dict):
        src = Path(path).resolve()
        dst = Path("reports") / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.exists() and src != dst:
            try: shutil.copy2(src, dst); self.log(f"📁 Скопирован: {dst.name}")
            except: dst = src
        else: dst = src
        entry = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"), "filename": dst.name, "path": str(dst), **meta}
        self.report_history.append(entry)
        self.save_history()
        self.history_list.addItem(f"{entry['timestamp']} | {entry['filename']} | Риск: {entry.get('risk_score', 0)}")

    def save_history(self):
        try:
            with open(self.history_file, "w", encoding="utf-8") as f: json.dump(self.report_history, f, indent=2, ensure_ascii=False)
        except Exception as e: self.log(f"⚠️ Ошибка истории: {e}")

    def load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f: self.report_history = json.load(f)
                for e in self.report_history: self.history_list.addItem(f"{e.get('timestamp','-')} | {e.get('filename','-')} | Риск: {e.get('risk_score',0)}")
            except: pass

    def on_history_selection_changed(self):
        items = self.history_list.selectedItems()
        if not items: 
            self.current_report_index = None
            self.current_report_data = None
            self.analyze_history_btn.setEnabled(False)
            return
        self.current_report_index = self.history_list.row(items[0])
        self.analyze_history_btn.setEnabled(True)
        info = self.report_history[self.current_report_index]
        p = Path(info.get("path", ""))
        found = next((x.resolve() for x in [p, Path("reports")/p.name] if x.exists()), None)
        if not found: self.current_report_data = None; return
        try:
            with open(found, "r", encoding="utf-8") as f: self.current_report_data = json.load(f)
            self.log(f"📄 Отчёт загружен: {info.get('filename')}")
        except: self.current_report_data = None

    # ==============================================================================
    # ЭТАПЫ 3 & 4 (LLM ANALYSIS)
    # ==============================================================================
    def analyze_selected_report_with_ai(self):
        """Запуск LLM анализа выбранного отчёта (Строго Этапы 3 и 4)"""
        if self.current_report_index is None or not self.current_report_data:
            self.log("⚠️ Выберите отчёт из истории или запустите анализ.")
            return

        critical = extract_critical_sections(self.current_report_data, max_indicators=150)
        payload = json.dumps(critical, ensure_ascii=False, separators=(',', ': '))
        self.log(f"📦 Подготовка данных для LLM ({len(payload)} символов)")

        if not self.llm_manager:
            self.llm_manager = LanguageModelManager(base_url="http://localhost:11434", model_name="qwen2.5-coder:14b")
            self.log("ℹ️ LLM менеджер инициализирован.")

        self.ai_chat.set_typing_indicator(True)
        QApplication.processEvents()
        try:
            self.log("🧠 Этап 3: Извлечение IoC...")
            ioc_resp = self.llm_manager.send_request(
                prompt=ThreatAnalysisPrompts.IOC_EXTRACTION_PROMPT.format(analysis_data=payload),
                system_instruction=ThreatAnalysisPrompts.SYSTEM_IOC_EXTRACTION
            )
            if not ioc_resp: raise RuntimeError("Нет ответа IoC")
            
            self.log("⚖️ Этап 4: Вердикт...")
            verdict = self.llm_manager.send_request(
                prompt=ThreatAnalysisPrompts.VERDICT_PROMPT.format(ioc_data=ioc_resp),
                system_instruction=ThreatAnalysisPrompts.SYSTEM_VERDICT
            )
            
            final = f"## 🔍 IoC Extraction\n\n{ioc_resp}\n\n---\n\n## ⚖️ Verdict\n\n{verdict}"
            self.ai_chat.add_ai_response(final)
            self.log("✅ Полный анализ завершён. Выведен в чат.")
        except Exception as e:
            self.log(f"✗ Ошибка LLM: {e}")
            self.ai_chat.add_ai_response(f"⚠️ Ошибка анализа: {str(e)}")
        finally:
            self.ai_chat.set_typing_indicator(False)

    def export_report(self):
        src = None
        if self.current_report_index is not None:
            p = self.report_history[self.current_report_index].get("path")
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f: src = json.load(f)
            else: return
        elif not self.decompiled_files: return
        else: src = {"risk": getattr(self, 'current_risk', 0), "files": self.decompiled_files}
        
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт", "report.json", "JSON (*.json)")
        if path:
            with open(path, 'w', encoding='utf-8') as f: json.dump(src, f, indent=2, ensure_ascii=False)
            self.log(f"✓ Экспорт: {path}")

    def check_jadx(self):
        import shutil, subprocess
        p = shutil.which("jadx")
        if p: QMessageBox.information(self, "JADX", f"✓ Найден: {p}")
        else: QMessageBox.warning(self, "JADX", "✗ Не найден в PATH")

    def closeEvent(self, event):
        if self.analysis_worker and self.analysis_worker.isRunning():
            if QMessageBox.question(self, "Выход", "Анализ выполняется. Выйти?", QMessageBox.Yes|QMessageBox.No) != QMessageBox.Yes:
                event.ignore(); return
            self.analysis_worker.stop_analysis()
        try: import jpype; jpype.shutdownJVM() if jpype.isJVMStarted() else None
        except: pass
        import gc; gc.collect()
        event.accept()