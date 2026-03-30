from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, 
    QPushButton, QLabel, QScrollArea
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

class AiChatWidget(QWidget):
    """Виджет чата с ИИ-ассистентом"""
    
    message_sent = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Заголовок
        header = QLabel("🤖 AI Assistant")
        header.setStyleSheet("""
            QLabel {
                background: #2d2d2d;
                color: #4A90D9;
                padding: 8px;
                font-weight: bold;
                border-radius: 4px;
            }
        """)
        layout.addWidget(header)
        
        # Область сообщений
        self.messages_area = QScrollArea()
        self.messages_area.setWidgetResizable(True)
        self.messages_content = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_content)
        self.messages_area.setWidget(self.messages_content)
        self.messages_area.setStyleSheet("""
            QScrollArea {
                background: #1e1e1e;
                border: 1px solid #333333;
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.messages_area, 1)
        
        # Поле ввода
        self.input_field = QTextEdit()
        self.input_field.setPlaceholderText("Задайте вопрос об анализе...")
        self.input_field.setMaximumHeight(80)
        self.input_field.setStyleSheet("""
            QTextEdit {
                background: #2d2d2d;
                color: #ffffff;
                border: 1px solid #333333;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        layout.addWidget(self.input_field)
        
        # Кнопка отправки
        self.send_button = QPushButton("Отправить")
        self.send_button.setStyleSheet("""
            QPushButton {
                background: #4A90D9;
                color: #ffffff;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #5A9FE9;
            }
            QPushButton:pressed {
                background: #3A80C9;
            }
        """)
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)
    
    def send_message(self):
        """Отправка сообщения"""
        text = self.input_field.toPlainText().strip()
        if text:
            self.message_sent.emit(text)
            self.add_message(text, is_user=True)
            self.input_field.clear()
    
    def add_message(self, text: str, is_user: bool = False):
        """Добавление сообщения в чат"""
        msg_label = QLabel(text)
        msg_label.setWordWrap(True)
        msg_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        
        if is_user:
            msg_label.setStyleSheet("""
                QLabel {
                    background: #2d4a2d;
                    color: #ffffff;
                    padding: 8px;
                    border-radius: 4px;
                    margin: 4px;
                }
            """)
            msg_label.setAlignment(Qt.AlignRight)
        else:
            msg_label.setStyleSheet("""
                QLabel {
                    background: #2d2d4a;
                    color: #ffffff;
                    padding: 8px;
                    border-radius: 4px;
                    margin: 4px;
                }
            """)
            msg_label.setAlignment(Qt.AlignLeft)
        
        self.messages_layout.addWidget(msg_label)
    
    def add_ai_response(self, text: str):
        """Добавление ответа ИИ"""
        self.add_message(text, is_user=False)
    
    def clear_chat(self):
        """Очистка чата"""
        while self.messages_layout.count():
            item = self.messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def set_typing_indicator(self, is_typing: bool):
        """Индикатор набора текста"""
        if is_typing:
            self.add_message("ИИ печатает...", is_user=False)