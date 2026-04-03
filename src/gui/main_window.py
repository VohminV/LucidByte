import os
import sys
import math
import json
from datetime import datetime
from typing import Optional, List, Dict
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QFileDialog, QStatusBar, QProgressBar,
    QLabel, QTabWidget, QTextEdit, QDockWidget,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem,
    QMessageBox, QTreeWidget, QTreeWidgetItem, QListWidget,
    QPushButton, QToolBar, QGraphicsItem
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


class GraphNodeItem(QGraphicsItem):
    """Элемент узла графа с улучшенной отрисовкой"""
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

        if self.isSelected():
            painter.setPen(QPen(QColor("#FFFFFF"), 3))
        else:
            painter.setPen(QPen(QColor("#FFFFFF"), 1))

        painter.setBrush(QBrush(gradient))
        painter.setRenderHint(QPainter.Antialiasing)

        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width, self.height, 10, 10)
        painter.drawPath(path)

        painter.setPen(QColor("#FFFFFF"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        painter.drawText(self.boundingRect(), Qt.AlignCenter, self.text[:18])

    def hoverEnterEvent(self, event):
        self.update()
        super().hoverEnterEvent(event) 

    def hoverLeaveEvent(self, event):
        self.update()
        super().hoverLeaveEvent(event)


class GraphEdgeItem(QGraphicsItem):
    """Элемент связи графа со стрелкой"""
    def __init__(self, start_item, end_item, parent=None):
        super().__init__(parent)
        self.start_item = start_item
        self.end_item = end_item
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setZValue(-1)

    def boundingRect(self):
        if not self.start_item or not self.end_item:
            return QRectF()
        return QRectF(self.start_item.pos(), self.end_item.pos()).normalized().adjusted(-10, -10, 10, 10)

    def paint(self, painter, option, widget):
        if not self.start_item or not self.end_item:
            return

        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor("#888888"), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))

        start_pos = self.start_item.pos() + QPointF(self.start_item.width / 2, self.start_item.height / 2)
        end_pos = self.end_item.pos() + QPointF(self.end_item.width / 2, self.end_item.height / 2)

        painter.drawLine(start_pos, end_pos)

        angle = 0.0
        dx = end_pos.x() - start_pos.x()
        dy = end_pos.y() - start_pos.y()
        if dx != 0 or dy != 0:
            angle = math.atan2(dy, dx)

        arrow_size = 10
        painter.setBrush(QColor("#888888"))

        arrow_point1 = QPointF(
            end_pos.x() - arrow_size * math.cos(angle - math.pi / 6),
            end_pos.y() - arrow_size * math.sin(angle - math.pi / 6)
        )
        arrow_point2 = QPointF(
            end_pos.x() - arrow_size * math.cos(angle + math.pi / 6),
            end_pos.y() - arrow_size * math.sin(angle + math.pi / 6)
        )

        arrow_polygon = QPolygonF([end_pos, arrow_point1, arrow_point2])
        painter.drawPolygon(arrow_polygon)


class CallGraphView(QGraphicsView):
    """Вьюер графа вызовов функций"""
    def __init__(self):
        super().__init__()
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setRenderHint(QPainter.Antialiasing)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setStyleSheet("""
            QGraphicsView {
                background: #1e1e1e;
                border: 1px solid #333333;
                border-radius: 4px;
            }
        """)
        self.zoom_level = 1.0
        self.nodes = {}

    def wheelEvent(self, event):
        factor = 1.15
        if event.angleDelta().y() > 0:
            self.scale(factor, factor)
            self.zoom_level *= factor
        else:
            self.scale(1 / factor, 1 / factor)
            self.zoom_level /= factor
        event.accept()

    def draw_graph(self, graph_data: dict, threats: list = []):
        self.scene.clear()
        self.nodes = {}
        spacing_x = 180
        spacing_y = 120

        for i, class_name in enumerate(graph_data.keys()):
            x = (i % 6) * spacing_x
            y = (i // 6) * spacing_y
            node_item = GraphNodeItem(class_name, "class")
            node_item.setPos(x, y)
            self.scene.addItem(node_item)
            self.nodes[class_name] = node_item

        for src, targets in graph_data.items():
            if src not in self.nodes:
                continue
            for dst in targets:
                if dst in self.nodes:
                    edge = GraphEdgeItem(self.nodes[src], self.nodes[dst])
                    self.scene.addItem(edge)

        if threats:
            self._highlight_threats(threats)

    def _highlight_threats(self, threats: list):
        threat_count = len([t for t in threats if t.get('risk') == 'Critical'])
        if threat_count > 0:
            threat_node = GraphNodeItem(f"⚠️ УГРОЗЫ: {threat_count}", "threat")
            threat_node.setPos(50, 50)
            self.scene.addItem(threat_node)

    def clear_graph(self):
        self.scene.clear()
        self.nodes = {}


class MainWindow(QMainWindow):
    """Главное окно приложения LucidByte"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LucidByte - Android Malware Analysis Platform")
        self.setMinimumSize(1600, 1000)
        
        self.current_apk_path = None
        self.analysis_worker: Optional[AnalysisWorker] = None
        self.decompiled_files: List[str] = []
        self.current_file_index = 0
        self.current_graph_data: Dict = {}
        self.current_threats: List = []
        self.current_permissions: List = []
        self.current_network_indicators: Dict = {}
        self.current_signature_info: Dict = {}
        self.current_risk_score: int = 0
        self.current_manifest_info: Dict = {}
        self.current_osint_data: Dict = {}
        self.current_native_data: Dict = {}

        # Инициализация компонентов истории отчетов
        self.history_file = "lucidbyte_report_history.json"
        self.report_history: List[Dict] = []
        self.current_report_index: Optional[int] = None
        self.current_report_data: Optional[Dict] = None
        self.llm_manager: Optional[LanguageModelManager] = None

        self.setup_menu()
        self.setup_toolbar()
        self.setup_interface()
        self.setup_docks()
        self.setup_history_dock()
        self.setup_status_bar()
        self.apply_style()

    def setup_menu(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("Файл")
        open_action = QAction("📂 Открыть APK", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_apk_file)
        file_menu.addAction(open_action)
        file_menu.addSeparator()
        export_action = QAction("📤 Экспорт отчёта", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        exit_action = QAction("❌ Выход", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        analysis_menu = menu_bar.addMenu("Анализ")
        run_action = QAction("▶ Запустить анализ", self)
        run_action.setShortcut("F5")
        run_action.triggered.connect(self.start_analysis)
        analysis_menu.addAction(run_action)
        analysis_menu.addSeparator()
        clear_action = QAction("🗑 Очистить результаты", self)
        clear_action.triggered.connect(self.clear_results)
        analysis_menu.addAction(clear_action)

        tools_menu = menu_bar.addMenu("Инструменты")
        jadx_action = QAction("🔧 Проверить JADX", self)
        jadx_action.triggered.connect(self.check_jadx)
        tools_menu.addAction(jadx_action)

        help_menu = menu_bar.addMenu("Помощь")
        about_action = QAction("ℹ О программе", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        open_btn = QPushButton("📂 Открыть")
        open_btn.clicked.connect(self.open_apk_file)
        toolbar.addWidget(open_btn)
        toolbar.addSeparator()
        analyze_btn = QPushButton("▶ Анализ")
        analyze_btn.clicked.connect(self.start_analysis)
        toolbar.addWidget(analyze_btn)
        toolbar.addSeparator()
        export_btn = QPushButton("📤 Экспорт")
        export_btn.clicked.connect(self.export_report)
        toolbar.addWidget(export_btn)

    def setup_interface(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        self.ai_summary = QLabel("🤖 AI Summary: Ожидается анализ APK файла...")
        self.ai_summary.setStyleSheet("""
            QLabel {
                background: #2d2d2d;
                color: #4A90D9;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.ai_summary)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("<b style='color:#4A90D9'>🔐 Permissions</b>"))
        self.permission_tree = PermissionTree()
        self.permission_tree.setMinimumHeight(200)
        left_layout.addWidget(self.permission_tree)
        left_layout.addWidget(QLabel("<b style='color:#4A90D9'>⚠ Threats</b>"))
        self.threat_list = ThreatList()
        self.threat_list.setMinimumHeight(200)
        left_layout.addWidget(self.threat_list)
        splitter.addWidget(left)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #333333; border-radius: 4px; }
            QTabBar::tab { background: #2d2d2d; color: #ffffff; padding: 8px 16px; border: 1px solid #333333; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; }
            QTabBar::tab:selected { background: #4A90D9; }
        """)
        self.code_editor = CodeEditor()
        self.manifest_view = QTextEdit()
        self.manifest_view.setReadOnly(True)
        self.smali_view = QTextEdit()
        self.smali_view.setReadOnly(True)
        self.strings_view = QTextEdit()
        self.strings_view.setReadOnly(True)
        self.resources_view = QTextEdit()
        self.resources_view.setReadOnly(True)
        self.tabs.addTab(self.code_editor, "📄 Code")
        self.tabs.addTab(self.manifest_view, "📋 Manifest")
        self.tabs.addTab(self.smali_view, "⚙ Smali")
        self.tabs.addTab(self.strings_view, "💬 Strings")
        self.tabs.addTab(self.resources_view, "📦 Resources")
        splitter.addWidget(self.tabs)

        self.ai_chat = AiChatWidget()
        splitter.addWidget(self.ai_chat)
        splitter.setSizes([350, 900, 350])

    def setup_docks(self):
        self.log_dock = QDockWidget("📋 Logs", self)
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setStyleSheet("""
            QTextEdit { background: #0d0d0d; color: #00FF00; font-family: 'Consolas', 'Courier New', monospace; font-size: 10px; border: 1px solid #333333; }
        """)
        self.log_dock.setWidget(self.log_widget)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.log_dock)

        self.graph_dock = QDockWidget("🕸 Call Graph", self)
        self.graph_view = CallGraphView()
        self.graph_dock.setWidget(self.graph_view)
        self.addDockWidget(Qt.RightDockWidgetArea, self.graph_dock)

    def setup_history_dock(self):
        """Настройка панели истории отчетов"""
        self.history_dock = QDockWidget("📜 История отчетов", self)
        self.history_dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        
        history_widget = QWidget()
        history_layout = QVBoxLayout(history_widget)
        history_layout.setContentsMargins(5, 5, 5, 5)
        
        self.history_list = QListWidget()
        self.history_list.setStyleSheet("""
            QListWidget {
                background: #1e1e1e;
                color: #ffffff;
                border: 1px solid #333333;
                border-radius: 4px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #2d2d2d;
            }
            QListWidget::item:selected {
                background: #4A90D9;
                color: #ffffff;
            }
        """)
        self.history_list.itemSelectionChanged.connect(self.on_history_selection_changed)
        
        self.analyze_history_btn = QPushButton("🤖 Анализировать выбранный отчет")
        self.analyze_history_btn.setStyleSheet("""
            QPushButton {
                background: #27AE60;
                color: #ffffff;
                padding: 8px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover { background: #2ECC71; }
            QPushButton:disabled { background: #555555; color: #888888; }
        """)
        self.analyze_history_btn.clicked.connect(self.analyze_selected_report_with_ai)
        self.analyze_history_btn.setEnabled(False)
        
        history_layout.addWidget(self.history_list)
        history_layout.addWidget(self.analyze_history_btn)
        self.history_dock.setWidget(history_widget)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.history_dock)
        
        self.load_history()

    def setup_status_bar(self):
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setFormat("%p%")
        self.progress.setStyleSheet("""
            QProgressBar { background: #2d2d2d; border: 1px solid #333333; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background: #4A90D9; border-radius: 4px; }
        """)
        self.status.addPermanentWidget(self.progress, 1)
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888888;")
        self.status.addWidget(self.status_label, 1)

    def apply_style(self):
        self.setStyleSheet(qdarkstyle.load_stylesheet())
        self.setFont(QFont("Segoe UI", 10))

    # ==================== История отчетов ====================
    def load_history(self):
        """Загрузка истории отчетов из файла"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as file:
                    self.report_history = json.load(file)
                for entry in self.report_history:
                    item_text = f"{entry.get('timestamp', 'Неизвестно')} | {entry.get('filename', 'Без имени')} | Риск: {entry.get('risk_score', 0)}"
                    self.history_list.addItem(item_text)
            except Exception as error:
                self.log(f"⚠️ Ошибка загрузки истории: {error}")

    def save_history(self):
        """Сохранение истории отчетов в файл"""
        try:
            with open(self.history_file, "w", encoding="utf-8") as file:
                json.dump(self.report_history, file, indent=2, ensure_ascii=False)
        except Exception as error:
            self.log(f"⚠️ Ошибка сохранения истории: {error}")

    def add_report_to_history(self, report_path: str, metadata: Dict):
        """Добавление нового отчета в историю"""
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": os.path.basename(report_path),
            "path": report_path,
            "risk_score": metadata.get("risk_score", 0),
            "threat_count": metadata.get("threat_count", 0)
        }
        self.report_history.append(entry)
        self.save_history()
        self.history_list.addItem(f"{entry['timestamp']} | {entry['filename']} | Риск: {entry['risk_score']}")
        self.history_list.scrollToBottom()

    def populate_ui_from_report(self, report_data: dict):
        """Синхронизация элементов интерфейса с данными загруженного отчёта"""
        if not report_data:
            self.log("⚠️ Структура отчёта пуста. Интерфейс не обновлён.")
            return

        # 1. Заполнение списка угроз
        threats_list = report_data.get("threats", [])
        self.threat_list.clear()
        if isinstance(threats_list, list) and threats_list:
            self.threat_list.add_threats(threats_list)
            self.log(f"✓ ThreatList обновлён: {len(threats_list)} записей")
        else:
            self.log("⚠️ Поле 'threats' в отчёте отсутствует или пустое")

        # 2. Заполнение дерева разрешений
        permissions_list = report_data.get("permissions", [])
        self.permission_tree.clear()
        if isinstance(permissions_list, list) and permissions_list:
            self.permission_tree.add_permissions(permissions_list)
            self.log(f"✓ PermissionTree обновлён: {len(permissions_list)} записей")
        else:
            self.log("⚠️ Поле 'permissions' в отчёте отсутствует или пустое")

        # 3. Построение графа вызовов
        graph_data = report_data.get("call_graph") or report_data.get("graph", {})
        self.graph_view.clear_graph()
        if isinstance(graph_data, dict) and graph_data:
            self.graph_view.draw_graph(graph_data, threats_list)
            self.log(f"✓ CallGraphView перестроен: {len(graph_data)} узлов")
        else:
            self.log("⚠️ Данные графа вызовов отсутствуют в отчёте")

        # 4. Обновление информации о манифесте
        manifest_data = report_data.get("application_info", {})
        if manifest_data:
            self.manifest_view.setText(json.dumps(manifest_data, indent=2, ensure_ascii=False))

        # 5. Обновление сводной панели
        summary = report_data.get("summary", {})
        self.set_ai_summary(
            f"Отчёт загружен | Файлов: {summary.get('total_files', 0)} | "
            f"Угроз: {summary.get('total_threats', 0)} | "
            f"Риск: {summary.get('risk_score', 0)}/100"
        )

    def on_history_selection_changed(self):
        """Обработка изменения выбранной записи в журнале истории"""
        selected_items = self.history_list.selectedItems()
        
        if not selected_items:
            self.current_report_index = None
            self.current_report_data = None
            self.analyze_history_btn.setEnabled(False)
            return

        self.current_report_index = self.history_list.row(selected_items[0])
        self.analyze_history_btn.setEnabled(True)

        report_info = self.report_history[self.current_report_index]
        report_path = report_info.get("path")

        if not report_path or not os.path.exists(report_path):
            self.log(f"⚠️ Файл отчёта не найден на диске: {report_path}")
            self.current_report_data = None
            return

        try:
            with open(report_path, "r", encoding="utf-8") as file:
                self.current_report_data = json.load(file)
            
            # Непосредственное заполнение виджетов данными
            self.populate_ui_from_report(self.current_report_data)
            self.log(f"📄 Отчёт успешно загружен: {report_info.get('filename', 'Без имени')}")
            
        except json.JSONDecodeError as json_err:
            self.log(f"✗ Ошибка парсинга JSON: {json_err}")
            self.current_report_data = None
        except Exception as err:
            self.log(f"✗ Критическая ошибка загрузки отчёта: {err}")
            self.current_report_data = None

    def analyze_selected_report_with_ai(self):
        """Загрузка отчета и отправка на анализ ИИ"""
        if self.current_report_index is None:
            return
        
        # Если данные еще не загружены в память, инициируем загрузку
        if not self.current_report_data:
            report_info = self.report_history[self.current_report_index]
            report_path = report_info.get("path")
            
            if not os.path.exists(report_path):
                QMessageBox.warning(self, "Ошибка", "Файл отчета не найден на диске.")
                return
            
            try:
                with open(report_path, "r", encoding="utf-8") as file:
                    self.current_report_data = json.load(file)
                # Заполняем интерфейс перед анализом
                self.populate_ui_from_report(self.current_report_data)
            except Exception as error:
                QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать отчет:\n{error}")
                return

        prompt_template = ThreatAnalysisPrompts.THREAT_REPORT_PROMPT
        formatted_prompt = prompt_template.format(
            analysis_data=json.dumps(self.current_report_data, ensure_ascii=False, indent=2)
        )
        
        if self.llm_manager:
            self.ai_chat.set_typing_indicator(True)
            response = self.llm_manager.send_request(
                prompt=formatted_prompt, 
                system_instruction=ThreatAnalysisPrompts.SYSTEM_INSTRUCTION
            )
            self.ai_chat.set_typing_indicator(False)
            if response:
                self.ai_chat.add_ai_response(response)
            else:
                self.ai_chat.add_ai_response("Ошибка подключения к языковой модели. Проверьте настройки сервера.")
        else:
            self.ai_chat.add_ai_response("Менеджер языковой модели не инициализирован. Анализ невозможен.")

    # ==================== Основной функционал ====================
    def open_apk_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите APK файл", "", "APK Files (*.apk);;All Files (*)")
        if path:
            self.current_apk_path = path
            filename = os.path.basename(path)
            self.status_label.setText(f"📱 {filename}")
            self.log("=" * 60)
            self.log(f"✓ APK загружен: {path}")
            self.log(f"📊 Размер: {os.path.getsize(path) / 1024 / 1024:.2f} Мегабайт")
            self.log("=" * 60)
            self.start_analysis()

    def start_analysis(self):
        if not self.current_apk_path:
            QMessageBox.warning(self, "Ошибка", "Сначала выберите APK файл через меню Файл → Открыть APK")
            return
        if self.analysis_worker and self.analysis_worker.isRunning():
            QMessageBox.warning(self, "Внимание", "Анализ уже выполняется. Дождитесь завершения.")
            return

        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.status_label.setText("🔄 Анализ...")
        self.log("=" * 60)
        self.log("🚀 Запуск анализа...")
        self.log(f"📁 Файл: {self.current_apk_path}")
        self.log("=" * 60)

        self.analysis_worker = AnalysisWorker(self.current_apk_path)
        
        self.analysis_worker.progress.connect(self.on_analysis_progress)
        self.analysis_worker.log_signal.connect(self.log)
        self.analysis_worker.finished.connect(self.on_analysis_finished)
        self.analysis_worker.manifest_ready.connect(self.on_manifest_ready)
        self.analysis_worker.strings_ready.connect(self.on_strings_ready)
        self.analysis_worker.permissions_ready.connect(self.on_permissions_ready)
        self.analysis_worker.threats_ready.connect(self.on_threats_ready)
        self.analysis_worker.files_ready.connect(self.on_files_ready)
        self.analysis_worker.graph_ready.connect(self.on_graph_ready)
        self.analysis_worker.report_ready.connect(self.on_report_ready)
        self.analysis_worker.osint_ready.connect(self.on_osint_ready)
        self.analysis_worker.signature_ready.connect(self.on_signature_ready)
        self.analysis_worker.native_ready.connect(self.on_native_ready)
        self.analysis_worker.risk_ready.connect(self.on_risk_ready)
        self.analysis_worker.network_ready.connect(self.on_network_ready)
        
        self.analysis_worker.start()
        self.log("⏳ Анализ выполняется в фоновом режиме...")

    def on_analysis_progress(self, value: int, message: str):
        self.progress.setValue(value)
        self.status_label.setText(f"🔄 {message}")

    def on_analysis_finished(self, success: bool):
        self.progress.setVisible(False)
        if success:
            self.status_label.setText("✓ Анализ завершен")
            self.log("=" * 60)
            self.log("✓ Анализ завершен успешно")
            threat_count = self.threat_list.topLevelItemCount()
            perm_count = self.permission_tree.topLevelItemCount()
            file_count = len(self.decompiled_files)
            self.set_ai_summary(f"Анализ завершен | Файлов: {file_count} | Угроз: {threat_count} | Разрешений: {perm_count}")
            critical = self.threat_list.get_critical_count()
            if critical > 0:
                self.log(f"⚠️ ВНИМАНИЕ: Найдено {critical} критических угроз!")
            self.log("=" * 60)
        else:
            self.status_label.setText("✗ Анализ не удался")
            self.log("✗ Анализ завершен с ошибками")
            QMessageBox.critical(self, "Ошибка", "Не удалось завершить анализ. Проверьте логи для деталей.")

    def on_manifest_ready(self, content: str, info: dict = None):
        self.manifest_view.setText(content)
        if info:
            self.current_manifest_info = info
        self.log(f"✓ Манифест загружен ({len(content):,} байт)")

    def on_strings_ready(self, strings: list):
        self.strings_view.setText("\n".join(strings[:1000]))
        self.log(f"✓ Строки извлечены: {len(strings)}")

    def on_permissions_ready(self, permissions: list):
        self.current_permissions = permissions
        self.permission_tree.clear()
        for perm in permissions:
            item = QTreeWidgetItem([perm.get("name", "Unknown"), perm.get("risk", "Low")])
            colors = {"Critical": QColor("#ff0000"), "High": QColor("#ff6b6b"), "Medium": QColor("#ffa500"), "Low": QColor("#90ee90")}
            risk = perm.get("risk", "Low")
            if risk in colors:
                item.setForeground(0, colors[risk])
                item.setForeground(1, colors[risk])
            self.permission_tree.addTopLevelItem(item)
        self.permission_tree.resizeColumnToContents(1)
        self.log(f"✓ Разрешения: {len(permissions)}")

    def on_threats_ready(self, threats: list):
        self.current_threats = threats
        self.threat_list.clear()
        for threat in threats:
            file_path = threat.get("file", "Unknown")
            if len(file_path) > 60:
                file_path = "..." + file_path[-57:]
            item = QTreeWidgetItem([threat.get("risk", "Low"), threat.get("desc", "Unknown"), file_path])
            colors = {"Critical": QColor("#ff0000"), "High": QColor("#ff6b6b"), "Medium": QColor("#ffa500"), "Low": QColor("#90ee90")}
            risk = threat.get("risk", "Low")
            if risk in colors:
                item.setForeground(0, colors[risk])
            self.threat_list.addTopLevelItem(item)
        self.threat_list.resizeColumnToContents(0)
        self.log(f"✓ Угрозы: {len(threats)}")

    def on_files_ready(self, files: list):
        self.decompiled_files = files
        java_files = [f for f in files if f.endswith('.java')]
        if java_files:
            self.code_editor.load_file(java_files[0])
            self.log(f"✓ Загружен файл: {os.path.basename(java_files[0])}")
            self.log(f"✓ Всего Java файлов: {len(java_files)}")
        else:
            self.code_editor.setPlainText("Java файлы не найдены")
        self.log(f"✓ Файлов декомпилировано: {len(files)}")

    def on_graph_ready(self, graph_data: dict, threats: list):
        self.current_graph_data = graph_data
        self.current_threats = threats
        if graph_data:
            self.graph_view.draw_graph(graph_data, threats)
            self.log(f"🕸 Граф вызовов построен: {len(graph_data)} узлов")
        else:
            self.log("⚠ Граф вызовов пуст")

    def on_report_ready(self, report_path: str):
        """Обработка сигнала о готовности отчёта после анализа"""
        self.log(f"✅ Отчёт сохранён: {report_path}")
        
        # Автоматическое добавление отчёта в историю
        metadata = {
            "risk_score": self.current_risk_score,
            "threat_count": self.threat_list.topLevelItemCount()
        }
        self.add_report_to_history(report_path, metadata)
        self.log("📜 Отчёт автоматически добавлен в историю")

    def on_osint_ready(self, osint_data: dict):
        self.current_osint_data = osint_data
        url_count = len(osint_data.get('urls', []))
        api_key_count = len(osint_data.get('api_keys', []))
        self.log(f"🔍 OSINT данные: {url_count} URL, {api_key_count} API Ключей")

    def on_signature_ready(self, signature_info: dict):
        self.current_signature_info = signature_info
        if signature_info.get('has_match'):
            self.log(f"⚠️ Сигнатурное совпадение: {signature_info.get('risk_level')}")
        else:
            self.log("✅ Сигнатурных совпадений не найдено")

    def on_native_ready(self, native_data: dict):
        self.current_native_data = native_data
        self.log(f"📦 Native анализ: {len(native_data)} библиотек")

    def on_risk_ready(self, risk_score: int):
        self.current_risk_score = risk_score
        self.log(f"🎯 Оценка риска: {risk_score}/100")

    def on_network_ready(self, network_indicators: dict):
        self.current_network_indicators = network_indicators
        total_indicators = sum(len(value_list) for value_list in network_indicators.values())
        self.log(f"🌐 Сетевые индикаторы: {total_indicators}")

    def log(self, text: str):
        timestamp = QThread.currentThread().objectName() or "Main"
        self.log_widget.append(f"[{timestamp}] {text}")
        scrollbar = self.log_widget.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def set_ai_summary(self, text: str):
        self.ai_summary.setText(f"🤖 {text}")

    def clear_results(self):
        reply = QMessageBox.question(self, "Подтверждение", "Очистить все результаты анализа?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.threat_list.clear()
            self.permission_tree.clear()
            self.code_editor.clear()
            self.manifest_view.clear()
            self.strings_view.clear()
            self.decompiled_files = []
            self.current_graph_data = {}
            self.current_threats = []
            self.current_permissions = []
            self.current_network_indicators = {}
            self.current_signature_info = {}
            self.current_risk_score = 0
            self.current_manifest_info = {}
            self.current_osint_data = {}
            self.current_native_data = {}
            self.set_ai_summary("🤖 Результаты очищены. Ожидается новый анализ...")
            self.log("🗑 Результаты анализа очищены")

    def export_report(self):
        """Диалог выбора формата и определение источника данных для экспорта"""
        source_data: Optional[Dict] = None
        
        # Проверяем, выбран ли отчет из истории
        if self.current_report_index is not None:
            report_info = self.report_history[self.current_report_index]
            report_path = report_info.get("path")
            
            if os.path.exists(report_path):
                try:
                    with open(report_path, "r", encoding="utf-8") as file:
                        source_data = json.load(file)
                    self.log(f"📤 Подготовка к экспорту отчета из истории: {report_info['filename']}")
                except Exception as error:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить отчет из истории:\n{error}")
                    return
            else:
                QMessageBox.warning(self, "Ошибка", "Файл отчета не найден на диске. Экспорт невозможен.")
                return
        else:
            # Используем данные текущего анализа
            if not self.decompiled_files and not self.current_threats:
                QMessageBox.warning(self, "Ошибка", "Нет результатов анализа для экспорта")
                return
            source_data = self._generate_json_report()
            self.log("📤 Подготовка к экспорту текущего результата анализа")

        # Диалог выбора формата
        format_dialog = QMessageBox()
        format_dialog.setWindowTitle("Выбор формата экспорта")
        format_dialog.setText("Выберите формат отчёта:")
        format_dialog.addButton("HTML (Веб-страница)", QMessageBox.AcceptRole)
        format_dialog.addButton("JSON (Данные)", QMessageBox.AcceptRole)
        format_dialog.addButton("TXT (Текст)", QMessageBox.AcceptRole)
        format_dialog.addButton("Отмена", QMessageBox.RejectRole)
        format_dialog.exec()
        
        chosen_button = format_dialog.clickedButton()
        
        if chosen_button.text() == "Отмена":
            return
        elif chosen_button.text() == "HTML (Веб-страница)":
            self._export_html_report(source_data)
        elif chosen_button.text() == "JSON (Данные)":
            self._export_json_report(source_data)
        elif chosen_button.text() == "TXT (Текст)":
            self._export_txt_report(source_data)

    def _export_html_report(self, data: Dict):
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт HTML", "lucidbyte_report.html", "HTML Files (*.html);;All Files (*)")
        if path:
            try:
                html_content = self._generate_html_report(data)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                self.log(f"✓ Отчёт экспортирован: {path}")
                QMessageBox.information(self, "Успех", f"Отчёт успешно сохранён:\n{path}")
            except Exception as error:
                self.log(f"✗ Ошибка экспорта: {error}")
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить отчёт:\n{error}")

    def _export_json_report(self, data: Dict):
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт JSON", "lucidbyte_report.json", "JSON Files (*.json);;All Files (*)")
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                # Если это экспорт текущего анализа, добавляем в историю
                if self.current_report_index is None:
                    metadata = {
                        "risk_score": data["summary"]["risk_score"],
                        "threat_count": data["summary"]["total_threats"]
                    }
                    self.add_report_to_history(path, metadata)
                    
                self.log(f"✓ Отчёт экспортирован: {path}")
                QMessageBox.information(self, "Успех", f"Отчёт успешно сохранён:\n{path}")
            except Exception as error:
                self.log(f"✗ Ошибка экспорта: {error}")
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить отчёт:\n{error}")

    def _export_txt_report(self, data: Dict):
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт TXT", "lucidbyte_report.txt", "Text Files (*.txt);;All Files (*)")
        if path:
            try:
                txt_content = self._generate_txt_report(data)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(txt_content) 
                self.log(f"✓ Отчёт экспортирован: {path}")
                QMessageBox.information(self, "Успех", f"Отчёт успешно сохранён:\n{path}")
            except Exception as error:
                self.log(f"✗ Ошибка экспорта: {error}")
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить отчёт:\n{error}")

    def _generate_html_report(self, data: Dict) -> str:
        """Генерация HTML отчета на основе переданных данных"""
        meta = data.get("report_metadata", {})
        summary = data.get("summary", {})
        threats = data.get("threats", [])
        signature_info = data.get("signature_analysis", {})
        
        filename = meta.get("file_name", "Unknown")
        timestamp = meta.get("generated_at", datetime.now().isoformat())
        
        file_count = summary.get("total_files", 0)
        threat_count = summary.get("total_threats", 0)
        perm_count = summary.get("total_permissions", 0)
        
        threats_html = ""
        for threat in threats:
            risk_color = self._get_risk_color(threat.get("risk", "Low"))
            threats_html += f"<tr><td style='color: {risk_color}; font-weight: bold;'>{threat.get('risk', 'Low')}</td><td>{threat.get('desc', 'Unknown')}</td><td style='font-family: monospace; font-size: 11px;'>{threat.get('file', 'Unknown')}</td></tr>"
        
        signature_html = ""
        if signature_info:
            if signature_info.get('has_match'):
                signature_html = f"<div class='alert alert-danger'><strong>⚠️ ОБНАРУЖЕНО СИГНАТУРНОЕ СОВПАДЕНИЕ</strong><br>Уровень риска: {signature_info.get('risk_level', 'Unknown')}</div>"
            else:
                signature_html = "<div class='alert alert-success'><strong>✅ СИГНАТУРНЫХ СОВПАДЕНИЙ НЕ НАЙДЕНО</strong></div>"
        
        html = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>LucidByte Analysis Report - {filename}</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1e1e1e; color: #ffffff; padding: 20px; }}
                .container {{ max-width: 1400px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #4A90D9 0%, #2C3E50 100%); padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
                .header h1 {{ color: #ffffff; margin-bottom: 10px; }}
                .stat {{ display: inline-block; margin: 10px; padding: 15px; background: #2d2d2d; border-radius: 8px; }}
                .stat .value {{ font-size: 24px; font-weight: bold; color: #4A90D9; }}
                .stat .label {{ color: #888888; font-size: 12px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #333333; padding: 10px; text-align: left; }}
                th {{ background: #2d2d2d; color: #4A90D9; }}
                tr:nth-child(even) {{ background: #252525; }}
                .alert {{ padding: 15px; border-radius: 6px; margin: 15px 0; }}
                .alert-danger {{ background: rgba(255, 68, 68, 0.1); border: 1px solid #ff4444; color: #ff4444; }}
                .alert-success {{ background: rgba(68, 255, 68, 0.1); border: 1px solid #44ff44; color: #44ff44; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 LucidByte Analysis Report</h1>
                    <p><strong>Файл:</strong> {filename}</p>
                    <p><strong>Дата анализа:</strong> {timestamp}</p>
                </div>
                <div class="stat"><div class="value">{file_count}</div><div class="label">Файлов</div></div>
                <div class="stat"><div class="value">{threat_count}</div><div class="label">Угроз</div></div>
                <div class="stat"><div class="value">{perm_count}</div><div class="label">Разрешений</div></div>
                {signature_html}
                <h2>⚠️ Угрозы</h2>
                <table><tr><th>Риск</th><th>Описание</th><th>Файл</th></tr>{threats_html}</table>
            </div>
        </body>
        </html>
        """
        return html

    def _generate_json_report(self, data: Optional[Dict] = None) -> Dict:
        """Генерация или возврат JSON структуры отчета"""
        if data is not None:
            return data
            
        return {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "analyzer_name": "LucidByte Analysis Platform",
                "analyzer_version": "1.0.0",
                "file_path": self.current_apk_path,
                "file_name": os.path.basename(self.current_apk_path) if self.current_apk_path else "Unknown"
            },
            "summary": {
                "risk_score": self.current_risk_score,
                "total_files": len(self.decompiled_files),
                "total_threats": self.threat_list.topLevelItemCount(),
                "total_permissions": self.permission_tree.topLevelItemCount()
            },
            "application_info": self.current_manifest_info,
            "threats": self.current_threats,
            "permissions": self.current_permissions,
            "network_indicators": self.current_network_indicators,
            "signature_analysis": self.current_signature_info,
            "osint_data": self.current_osint_data,
            "native_analysis": self.current_native_data
        }

    def _generate_txt_report(self, data: Dict) -> str:
        """Генерация текстового отчета на основе переданных данных"""
        meta = data.get("report_metadata", {})
        summary = data.get("summary", {})
        threats = data.get("threats", [])
        
        filename = meta.get("file_name", "Unknown")
        timestamp = meta.get("generated_at", datetime.now().isoformat())
        risk_score = summary.get("risk_score", 0)
        
        file_count = summary.get("total_files", 0)
        threat_count = summary.get("total_threats", 0)
        perm_count = summary.get("total_permissions", 0)
        
        txt = f"""
    ================================================================================
    LUCIDBYTE ANALYSIS REPORT
    Файл: {filename}
    Дата анализа: {timestamp}
    Оценка риска: {risk_score}/100
    ================================================================================
    СТАТИСТИКА
    Файлов: {file_count}
    Угроз: {threat_count}
    Разрешений: {perm_count}
    ================================================================================
    УГРОЗЫ
        """
        for threat in threats:
            txt += f"[{threat.get('risk', 'Low')}] {threat.get('desc', 'Unknown')}\n    Файл: {threat.get('file', 'Unknown')}\n\n"
            
        txt += "================================================================================\nLucidByte Android Malware Analysis Platform\n"
        return txt

    def _get_risk_color(self, risk: str) -> str:
        colors = {"Critical": "#ff0000", "High": "#ff6b6b", "Medium": "#ffa500", "Low": "#90ee90"}
        return colors.get(risk, "#ffffff")

    def check_jadx(self):
        import subprocess, shutil
        jadx_path = shutil.which("jadx")
        if jadx_path:
            try:
                result = subprocess.run([jadx_path, "--version"], capture_output=True, text=True, timeout=10)
                QMessageBox.information(self, "JADX Status", f"✓ JADX найден:\n{jadx_path}\n\n{result.stdout}")
            except Exception as e:
                QMessageBox.warning(self, "JADX Status", f"⚠ JADX найден, но ошибка при проверке:\n{e}")
        else:
            QMessageBox.warning(self, "JADX Status", "✗ JADX не найден в PATH\n\nУстановите JADX и добавьте путь к bin в переменную PATH:\nhttps://github.com/skylot/jadx/releases")

    def show_about(self):
        QMessageBox.about(self, "О программе", "<h2>LucidByte</h2><p>Android Malware Analysis Platform</p><p>Режим: Полноценный Реверс-Инженеринг Android</p><p>© 2026 Все права защищены</p>")

    def closeEvent(self, event):
        if self.analysis_worker and self.analysis_worker.isRunning():
            reply = QMessageBox.question(self, "Подтверждение", "Анализ выполняется. Завершить и выйти?", QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.analysis_worker.terminate()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()