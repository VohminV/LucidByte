from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QFileDialog, QStatusBar, QProgressBar,
    QLabel, QTabWidget, QTextEdit, QDockWidget,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem
)
from PySide6.QtGui import QAction, QFont, QPen, QBrush
from PySide6.QtCore import Qt
import qdarkstyle

from src.gui.widgets.code_editor import CodeEditor
from src.gui.widgets.permission_tree import PermissionTree
from src.gui.widgets.threat_list import ThreatList
from src.gui.widgets.ai_chat import AiChatWidget


# ================= CALL GRAPH VIEW =================
class CallGraphView(QGraphicsView):
    def __init__(self):
        super().__init__()
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setRenderHint(self.renderHints())

    def draw_graph(self, graph_data):
        self.scene.clear()

        positions = {}
        radius = 20
        spacing = 120

        # Position nodes
        for i, node in enumerate(graph_data.keys()):
            x = (i % 5) * spacing
            y = (i // 5) * spacing
            positions[node] = (x, y)

        # Draw nodes
        for node, (x, y) in positions.items():
            circle = QGraphicsEllipseItem(x, y, radius, radius)
            circle.setBrush(QBrush(Qt.blue))
            circle.setToolTip(node)
            self.scene.addItem(circle)

        # Draw edges
        pen = QPen(Qt.white)
        for src, targets in graph_data.items():
            for dst in targets:
                if dst in positions:
                    x1, y1 = positions[src]
                    x2, y2 = positions[dst]
                    line = QGraphicsLineItem(
                        x1 + radius/2, y1 + radius/2,
                        x2 + radius/2, y2 + radius/2
                    )
                    line.setPen(pen)
                    self.scene.addItem(line)


# ================= MAIN WINDOW =================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LucidByte - Android Malware Analysis Platform")
        self.setMinimumSize(1600, 1000)

        self.setup_menu()
        self.setup_interface()
        self.setup_docks()
        self.setup_status_bar()
        self.apply_style()

    def setup_menu(self):
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("Файл")
        open_action = QAction("Открыть APK", self)
        open_action.triggered.connect(self.open_apk_file)
        file_menu.addAction(open_action)

        file_menu.addSeparator()
        file_menu.addAction("Выход", self.close)

        analysis_menu = menu_bar.addMenu("Анализ")
        analysis_menu.addAction("Запустить анализ", self.start_analysis)

    def setup_interface(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # ===== AI SUMMARY =====
        self.ai_summary = QLabel("AI Summary: ожидается анализ...")
        self.ai_summary.setStyleSheet("background:#1e1e1e; padding:8px; border-radius:6px;")
        layout.addWidget(self.ai_summary)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        # ===== LEFT PANEL =====
        left = QWidget()
        left_layout = QVBoxLayout(left)

        self.permission_tree = PermissionTree()
        self.threat_list = ThreatList()

        left_layout.addWidget(QLabel("Permissions"))
        left_layout.addWidget(self.permission_tree)
        left_layout.addWidget(QLabel("Threats"))
        left_layout.addWidget(self.threat_list)

        splitter.addWidget(left)

        # ===== CENTER TABS =====
        self.tabs = QTabWidget()

        self.code_editor = CodeEditor()
        self.manifest_view = QTextEdit()
        self.smali_view = QTextEdit()
        self.strings_view = QTextEdit()
        self.resources_view = QTextEdit()

        self.tabs.addTab(self.code_editor, "Code")
        self.tabs.addTab(self.manifest_view, "Manifest")
        self.tabs.addTab(self.smali_view, "Smali")
        self.tabs.addTab(self.strings_view, "Strings")
        self.tabs.addTab(self.resources_view, "Resources")

        splitter.addWidget(self.tabs)

        # ===== RIGHT PANEL =====
        self.ai_chat = AiChatWidget()
        splitter.addWidget(self.ai_chat)

        splitter.setSizes([300, 900, 400])

    def setup_docks(self):
        # ===== LOG PANEL =====
        self.log_dock = QDockWidget("Logs", self)
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_dock.setWidget(self.log_widget)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.log_dock)

        # ===== CALL GRAPH =====
        self.graph_dock = QDockWidget("Call Graph", self)
        self.graph_view = CallGraphView()
        self.graph_dock.setWidget(self.graph_view)
        self.addDockWidget(Qt.RightDockWidgetArea, self.graph_dock)

    def setup_status_bar(self):
        self.status = QStatusBar()
        self.setStatusBar(self.status)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.status.addPermanentWidget(self.progress)

        self.status_label = QLabel("Ready")
        self.status.addWidget(self.status_label)

    def apply_style(self):
        self.setStyleSheet(qdarkstyle.load_stylesheet())
        self.setFont(QFont("JetBrains Mono", 10))

    def open_apk_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open APK")
        if path:
            self.status_label.setText(f"Loaded: {path}")
            self.log(f"APK loaded: {path}")
            self.load_demo_graph()

    def start_analysis(self):
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.status_label.setText("Analyzing...")
        self.log("Analysis started")

    def log(self, text):
        self.log_widget.append(text)

    def set_ai_summary(self, text):
        self.ai_summary.setText(f"AI Summary: {text}")

    def update_threat_level(self, item, level):
        colors = {
            "Critical": "#ff0000",
            "High": "#ff6b6b",
            "Medium": "#ffa500",
            "Low": "#90ee90"
        }
        item.setForeground(0, colors.get(level, "white"))

    # ===== DEMO GRAPH =====
    def load_demo_graph(self):
        graph = {
            "MainActivity.onCreate": ["initUI", "loadData"],
            "initUI": ["setupButtons"],
            "loadData": ["fetchFromServer"],
            "fetchFromServer": [],
            "setupButtons": []
        }
        self.graph_view.draw_graph(graph)
