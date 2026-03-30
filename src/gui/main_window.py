from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QMenuBar, QMenu, QFileDialog,
    QStatusBar, QProgressBar, QLabel, QGroupBox
)
from PySide6.QtGui import QAction, QFont
from PySide6.QtCore import Qt
import qdarkstyle

from src.gui.widgets.code_editor import CodeEditor
from src.gui.widgets.permission_tree import PermissionTree
from src.gui.widgets.threat_list import ThreatList
from src.gui.widgets.ai_chat import AiChatWidget


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LucidByte - Android Malware Analysis Platform")
        self.setMinimumSize(1600, 1000)

        self.setup_menu()
        self.setup_interface()
        self.setup_status_bar()
        self.apply_style()

    def setup_menu(self):
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("Файл")

        open_action = QAction("Открыть APK файл", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_apk_file)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        exit_action = QAction("Выход", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        analysis_menu = menu_bar.addMenu("Анализ")

        start_analysis_action = QAction("Запустить полный анализ", self)
        start_analysis_action.setShortcut("F5")
        start_analysis_action.triggered.connect(self.start_analysis)
        analysis_menu.addAction(start_analysis_action)

        help_menu = menu_bar.addMenu("Помощь")

        about_action = QAction("О программе", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def setup_interface(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # ===== TOP INFO PANEL =====
        info_widget = QWidget()
        info_widget.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                border: 1px solid #3c3c3c;
                border-radius: 6px;
                padding: 6px;
            }
        """)

        info_layout = QHBoxLayout()
        info_widget.setLayout(info_layout)

        self.file_label = QLabel("Файл не загружен")
        self.file_label.setFont(QFont("Arial", 10))

        self.risk_label = QLabel("Уровень риска: Не определен")
        self.risk_label.setFont(QFont("Arial", 10, QFont.Bold))

        info_layout.addWidget(self.file_label)
        info_layout.addStretch()
        info_layout.addWidget(self.risk_label)

        main_layout.addWidget(info_widget)

        # ===== MAIN SPLITTER =====
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # ===== LEFT PANEL =====
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)

        self.permission_tree = PermissionTree()
        self.threat_list = ThreatList()

        permission_group = QGroupBox("Разрешения Android")
        perm_layout = QVBoxLayout()
        perm_layout.addWidget(self.permission_tree)
        permission_group.setLayout(perm_layout)

        threat_group = QGroupBox("Обнаруженные угрозы")
        threat_layout = QVBoxLayout()
        threat_layout.addWidget(self.threat_list)
        threat_group.setLayout(threat_layout)

        left_layout.addWidget(permission_group)
        left_layout.addWidget(threat_group)

        splitter.addWidget(left_panel)

        # ===== CENTER PANEL =====
        center_panel = QWidget()
        center_layout = QVBoxLayout()
        center_panel.setLayout(center_layout)

        self.code_editor = CodeEditor()

        code_group = QGroupBox("Декомпилированный код / Smali / Java")
        code_layout = QVBoxLayout()
        code_layout.addWidget(self.code_editor)
        code_group.setLayout(code_layout)

        center_layout.addWidget(code_group)

        splitter.addWidget(center_panel)

        # ===== RIGHT PANEL =====
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)

        self.ai_chat = AiChatWidget()
        self.ai_chat.message_sent.connect(self.handle_ai_message)

        ai_group = QGroupBox("AI Анализатор")
        ai_layout = QVBoxLayout()
        ai_layout.addWidget(self.ai_chat)
        ai_group.setLayout(ai_layout)

        right_layout.addWidget(ai_group)

        splitter.addWidget(right_panel)

        splitter.setSizes([400, 800, 400])

        main_layout.addWidget(splitter)

    def setup_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        self.status_label = QLabel("Готов к работе")
        self.status_bar.addWidget(self.status_label)

    def apply_style(self):
        self.setStyleSheet(qdarkstyle.load_stylesheet() + """
            QSplitter::handle {
                background-color: #444;
                width: 3px;
            }
            QSplitter::handle:hover {
                background-color: #00aaff;
            }
            QProgressBar {
                border: 1px solid #3c3c3c;
                border-radius: 5px;
                text-align: center;
                height: 12px;
            }
            QProgressBar::chunk {
                background-color: #00aaff;
                border-radius: 5px;
            }
        """)

        app_font = QFont("JetBrains Mono", 10)
        self.setFont(app_font)
        self.code_editor.setFont(QFont("JetBrains Mono", 11))

    def open_apk_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите APK файл",
            "",
            "APK файлы (*.apk);;JAR файлы (*.jar);;Все файлы (*.*)"
        )

        if file_path:
            self.file_label.setText(f"Файл: {file_path}")
            self.status_label.setText(f"Загружен файл: {file_path}")

    def start_analysis(self):
        self.status_label.setText("Запуск анализа...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

    def handle_ai_message(self, message: str):
        self.status_label.setText("AI обрабатывает запрос...")

    def show_about(self):
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.about(
            self,
            "О программе LucidByte",
            "LucidByte\n\n"
            "Инструмент анализа вредоносного ПО Android\n"
            "Статический и AI анализ APK файлов."
        )

    def update_risk_display(self, risk_score: int):
        if risk_score >= 8:
            color = "#ff0000"
        elif risk_score >= 6:
            color = "#ff6b6b"
        elif risk_score >= 4:
            color = "#ffa500"
        else:
            color = "#90ee90"

        self.risk_label.setText(f"Уровень риска: {risk_score}/10")
        self.risk_label.setStyleSheet(f"""
            QLabel {{
                color: white;
                background-color: {color};
                padding: 4px 12px;
                border-radius: 8px;
                font-weight: bold;
            }}
        """)

    def set_analysis_complete(self):
        self.progress_bar.setVisible(False)
        self.status_label.setText("Анализ завершен")