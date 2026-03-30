from PySide6.QtWidgets import QTextEdit
from PySide6.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtCore import QRegularExpression

class JavaSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super().__init__(parent)
        
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor("#cc7832"))
        self.keyword_format.setFontWeight(700)
        
        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor("#6a8759"))
        
        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("#808080"))
        
        self.dangerous_format = QTextCharFormat()
        self.dangerous_format.setForeground(QColor("#ff6b6b"))
        self.dangerous_format.setFontWeight(700)
        
        self.highlighting_rules = []
        
        # Ключевые слова Java
        keywords = [
            "public", "private", "protected", "class", "interface", "extends",
            "implements", "import", "package", "void", "int", "String", "boolean",
            "if", "else", "for", "while", "return", "new", "this", "super",
            "try", "catch", "finally", "throw", "throws", "static", "final"
        ]
        
        for keyword in keywords:
            pattern = QRegularExpression(f"\\b{keyword}\\b")
            self.highlighting_rules.append((pattern, self.keyword_format))
        
        # Строки
        string_pattern = QRegularExpression("\".*?\"")
        self.highlighting_rules.append((string_pattern, self.string_format))
        
        # Комментарии
        comment_pattern = QRegularExpression("//[^\n]*")
        self.highlighting_rules.append((comment_pattern, self.comment_format))

    def highlightBlock(self, text):
        for pattern, format_style in self.highlighting_rules:
            match_iterator = pattern.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format_style)

class CodeEditor(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFontFamily("Consolas")
        self.setFontPointSize(11)
        self.setLineWrapMode(QTextEdit.NoWrap)
        
        self.highlighter = JavaSyntaxHighlighter(self.document())
    
    def set_code(self, code_content: str):
        self.setText(code_content)
    
    def highlight_dangerous_lines(self, dangerous_keywords: list):
        # Подсветка опасных строк кода
        content = self.toPlainText()
        lines = content.split("\n")
        
        highlighted_content = []
        for line in lines:
            is_dangerous = False
            for keyword in dangerous_keywords:
                if keyword in line:
                    is_dangerous = True
                    break
            
            if is_dangerous:
                highlighted_content.append(f"<span style='background-color: #ff6b6b40'>{line}</span>")
            else:
                highlighted_content.append(line)
        
        self.setHtml("\n".join(highlighted_content))