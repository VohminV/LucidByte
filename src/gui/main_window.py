import os
import sys
import math
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
from typing import Optional, List, Dict


# ==================== GRAPH NODE ITEM ====================
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


# ==================== GRAPH EDGE ITEM ====================
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


# ==================== CALL GRAPH VIEW ====================
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
    
    # ✅ ИСПРАВЛЕНО: Добавлено двоеточие в аннотации типа
    def draw_graph(self, graph_data: dict, threats: list = []):
        """Отрисовка графа вызовов"""
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


# ==================== MAIN WINDOW ====================
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

        self.setup_menu()
        self.setup_toolbar()
        self.setup_interface()
        self.setup_docks()
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
        export_action = QAction("📤 Экспорт отчета", self)
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

    def open_apk_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите APK файл", "", "APK Files (*.apk);;All Files (*)")
        if path:
            self.current_apk_path = path
            filename = os.path.basename(path)
            self.status_label.setText(f"📱 {filename}")
            self.log("=" * 60)
            self.log(f"✓ APK загружен: {path}")
            self.log(f"📊 Размер: {os.path.getsize(path) / 1024 / 1024:.2f} MB")
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
        
        # ✅ Подключение сигнала графа вызовов
        self.analysis_worker.graph_ready.connect(self.on_graph_ready)
        # ✅ Подключение сигнала отчёта
        self.analysis_worker.report_ready.connect(self.on_report_ready)
        
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

    def on_manifest_ready(self, content: str):
        self.manifest_view.setText(content)
        self.log(f"✓ Манифест загружен ({len(content):,} байт)")

    def on_strings_ready(self, strings: list):
        self.strings_view.setText("\n".join(strings[:1000]))
        self.log(f"✓ Строки извлечены: {len(strings)}")

    def on_permissions_ready(self, permissions: list):
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

    # ✅ НОВЫЙ МЕТОД: Обработка графа вызовов
    def on_graph_ready(self, graph_data: dict, threats: list):
        """Обработка данных графа вызовов"""
        self.current_graph_data = graph_data
        self.current_threats = threats
        if graph_data:
            self.graph_view.draw_graph(graph_data, threats)
            self.log(f"🕸 Граф вызовов построен: {len(graph_data)} узлов")
        else:
            self.log("⚠ Граф вызовов пуст")

    # ✅ НОВЫЙ МЕТОД: Обработка отчёта
    def on_report_ready(self, report_path: str):
        """Обработка пути к сохранённому отчёту"""
        self.log(f"✅ Отчёт сохранён: {report_path}")

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
            self.set_ai_summary("🤖 Результаты очищены. Ожидается новый анализ...")
            self.log("🗑 Результаты анализа очищены")

    def export_report(self):
        if not self.decompiled_files:
            QMessageBox.warning(self, "Ошибка", "Нет результатов анализа для экспорта")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчет", "report.html", "HTML Files (*.html);;All Files (*)")
        if path:
            try:
                html_content = self.generate_html_report()
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                self.log(f"✓ Отчет экспортирован: {path}")
                QMessageBox.information(self, "Успех", f"Отчет успешно сохранен:\n{path}")
            except Exception as e:
                self.log(f"✗ Ошибка экспорта: {e}")
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить отчет:\n{e}")

    def generate_html_report(self) -> str:
        threat_count = self.threat_list.topLevelItemCount()
        perm_count = self.permission_tree.topLevelItemCount()
        file_count = len(self.decompiled_files)
        threats_html = ""
        for i in range(threat_count):
            item = self.threat_list.topLevelItem(i)
            if item:
                threats_html += f"<tr><td style='color: {self.get_risk_color(item.text(0))}'>{item.text(0)}</td><td>{item.text(1)}</td><td>{item.text(2)}</td></tr>"
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>LucidByte Analysis Report</title><style>body {{ font-family: Arial, sans-serif; background: #1e1e1e; color: #fff; padding: 20px; }} h1 {{ color: #4A90D9; }} table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }} th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }} th {{ background: #2d2d2d; }} .stat {{ display: inline-block; margin: 10px; padding: 15px; background: #2d2d2d; border-radius: 8px; }}</style></head><body><h1>🔍 LucidByte Analysis Report</h1><p>File: {self.current_apk_path}</p><div class="stat">📁 Files: {file_count}</div><div class="stat">⚠ Threats: {threat_count}</div><div class="stat">🔐 Permissions: {perm_count}</div><h2>Threats</h2><table><tr><th>Risk</th><th>Description</th><th>File</th></tr>{threats_html}</table></body></html>"""
        return html

    def get_risk_color(self, risk: str) -> str:
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