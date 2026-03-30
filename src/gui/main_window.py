from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTextEdit, QSplitter, QMenuBar, QMenu,
    QFileDialog, QStatusBar, QProgressBar, QLabel
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
        self.setWindowTitle("LucidByte - Анализ Вредоносного Программного Обеспечения Android")
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
        
        info_panel = QHBoxLayout()
        
        self.file_label = QLabel("Файл не загружен")
        self.file_label.setFont(QFont("Arial", 10))
        info_panel.addWidget(self.file_label)
        
        self.risk_label = QLabel("Уровень риска: Не определен")
        self.risk_label.setFont(QFont("Arial", 10, QFont.Bold))
        info_panel.addWidget(self.risk_label)
        
        main_layout.addLayout(info_panel)
        
        splitter = QSplitter(Qt.Horizontal)
        
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        
        self.permission_tree = PermissionTree()
        left_layout.addWidget(self.permission_tree)
        
        self.threat_list = ThreatList()
        left_layout.addWidget(self.threat_list)
        
        splitter.addWidget(left_panel)
        
        center_panel = QWidget()
        center_layout = QVBoxLayout()
        center_panel.setLayout(center_layout)
        
        self.code_editor = CodeEditor()
        center_layout.addWidget(self.code_editor)
        
        splitter.addWidget(center_panel)
        
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        
        self.ai_chat = AiChatWidget()
        self.ai_chat.message_sent.connect(self.handle_ai_message)
        right_layout.addWidget(self.ai_chat)
        
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
        self.setStyleSheet(qdarkstyle.load_stylesheet())

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
        self.status_label.setText("Обработка запроса...")

    def show_about(self):
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.about(
            self,
            "О программе LucidByte",
            "LucidByte v3.0.0\n\n"
            "Инструмент анализа вредоносного программного обеспечения Android\n"
            "с использованием Крупной Языковой Модели.\n\n"
            "Разработано для Хозяина"
        )

    def update_risk_display(self, risk_score: int):
        risk_colors = {
            0: "#90ee90",
            3: "#90ee90",
            5: "#ffa500",
            7: "#ff6b6b",
            10: "#ff0000"
        }
        
        color = "#ff6b6b"
        for threshold, threshold_color in risk_colors.items():
            if risk_score >= threshold:
                color = threshold_color
        
        self.risk_label.setText(f"Уровень риска: {risk_score}/10")
        self.risk_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def set_analysis_complete(self):
        self.progress_bar.setVisible(False)
        self.status_label.setText("Анализ завершен")