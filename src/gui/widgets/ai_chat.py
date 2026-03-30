from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton
from PySide6.QtCore import Signal

class AiChatWidget(QWidget):
    message_sent = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.setup_interface()

    def setup_interface(self):
        layout = QVBoxLayout()
        
        # Область отображения сообщений
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setPlaceholderText("Здесь появятся ответы эксперта по безопасности на основе Large Language Model")
        layout.addWidget(self.chat_display)
        
        # Поле ввода вопроса
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Задайте вопрос об анализе кода...")
        self.input_field.returnPressed.connect(self.send_message)
        layout.addWidget(self.input_field)
        
        # Кнопка отправки
        self.send_button = QPushButton("Отправить запрос")
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)
        
        self.setLayout(layout)

    def send_message(self):
        message = self.input_field.text().strip()
        if message:
            self.message_sent.emit(message)
            self.add_message("Вы", message)
            self.input_field.clear()

    def add_message(self, sender: str, message: str):
        self.chat_display.append(f"<b>{sender}:</b><br>{message}<br>")

    def add_ai_response(self, response: str):
        self.add_message("Large Language Model", response)

    def clear_chat(self):
        self.chat_display.clear()