from PySide6.QtWidgets import QTextEdit, QWidget, QVBoxLayout, QLabel
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat

class CodeEditor(QTextEdit):
    """Редактор кода с подсветкой синтаксиса"""
    
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("JetBrains Mono", 10))
        self.current_file = None
        
        self.setStyleSheet("""
            QTextEdit {
                background: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #333333;
                border-radius: 4px;
                padding: 8px;
            }
            QTextEdit:focus {
                border: 1px solid #4A90D9;
            }
        """)
        
        # Включаем нумерацию строк (через виджет-обертку)
        self.line_numbers = []
    
    def load_file(self, file_path: str):
        """Загрузка файла в редактор"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.setPlainText(content)
            self.current_file = file_path
            
            # Обновление заголовка (если есть родительский виджет с label)
            parent = self.parent()
            if parent and hasattr(parent, 'setWindowTitle'):
                import os
                parent.setWindowTitle(f"Code - {os.path.basename(file_path)}")
                
        except Exception as e:
            self.setPlainText(f"Ошибка загрузки файла:\n{str(e)}")
            self.current_file = None
    
    def load_content(self, content: str, title: str = "Code"):
        """Загрузка содержимого из строки"""
        self.setPlainText(content)
        self.current_file = title
    
    def clear_content(self):
        """Очистка редактора"""
        self.clear()
        self.current_file = None
    
    def highlight_line(self, line_number: int, color: str = "#ffff00"):
        """Подсветка строки кода"""
        # Реализация подсветки (упрощенная)
        cursor = self.textCursor()
        cursor.movePosition(cursor.Start)
        for _ in range(line_number - 1):
            cursor.movePosition(cursor.NextBlock)
        cursor.select(cursor.BlockUnderCursor)
        
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(color))
        cursor.setCharFormat(fmt)
    
    def search_text(self, text: str):
        """Поиск текста в редакторе"""
        cursor = self.document().find(text)
        if cursor:
            self.setTextCursor(cursor)
            return True
        return False
    
    def get_current_file(self):
        """Получение пути текущего файла"""
        return self.current_file