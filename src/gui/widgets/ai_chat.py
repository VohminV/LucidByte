"""
src/gui/widgets/ai_chat.py
Виджет чата с ИИ-ассистентом с интеллектуальным форматированием ответов и экспортом
Версия: 3.2.0
"""
import json
import re
import html
import os
from datetime import datetime
from typing import Any, List, Dict, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit, QPushButton,
    QLabel, QScrollArea, QTextBrowser, QSizePolicy,
    QMenu, QApplication, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QClipboard, QAction


class AiChatWidget(QWidget):
    """Виджет чата с ИИ-ассистентом с интеллектуальным форматированием ответов"""
    message_sent = Signal(str)

    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.messages: List[Dict[str, str]] = []
        self.typing_label: Optional[QLabel] = None

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        header = QLabel("🤖 AI Assistant")
        header.setStyleSheet("""
            QLabel { background: #2d2d2d; color: #4A90D9; padding: 8px; 
                     font-weight: bold; border-radius: 4px; font-size: 14px; }
        """)
        layout.addWidget(header)

        self.messages_area = QScrollArea()
        self.messages_area.setWidgetResizable(True)
        self.messages_content = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_content)
        self.messages_layout.setContentsMargins(5, 5, 5, 5)
        self.messages_layout.setSpacing(8)
        self.messages_area.setWidget(self.messages_content)
        self.messages_area.setStyleSheet("""
            QScrollArea { background: #1e1e1e; border: 1px solid #333333; border-radius: 4px; }
        """)
        layout.addWidget(self.messages_area, 1)

        self.input_field = QTextEdit()
        self.input_field.setPlaceholderText("Задайте вопрос об анализе...")
        self.input_field.setMaximumHeight(80)
        self.input_field.setStyleSheet("""
            QTextEdit { background: #2d2d2d; color: #ffffff; border: 1px solid #333333; 
                        border-radius: 4px; padding: 8px; font-family: 'Segoe UI', sans-serif; }
        """)
        layout.addWidget(self.input_field)

        self.send_button = QPushButton("Отправить")
        self.send_button.setStyleSheet("""
            QPushButton { background: #4A90D9; color: #ffffff; padding: 8px 16px; 
                          border: none; border-radius: 4px; font-weight: bold; font-size: 13px; }
            QPushButton:hover { background: #5A9FE9; }
            QPushButton:pressed { background: #3A80C9; }
        """)
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)

        self.export_button = QPushButton("📤 Экспорт переписки в HTML")
        self.export_button.setStyleSheet("""
            QPushButton { background: #27AE60; color: #ffffff; padding: 8px 16px; 
                          border: none; border-radius: 4px; font-weight: bold; font-size: 13px; }
            QPushButton:hover { background: #2ECC71; }
        """)
        self.export_button.clicked.connect(self.export_full_conversation_to_html)
        layout.addWidget(self.export_button)

    def send_message(self):
        text = self.input_field.toPlainText().strip()
        if text:
            self.message_sent.emit(text)
            self.add_message(text, is_user=True)
            self.messages.append({"role": "user", "content": text})
            self.input_field.clear()

    def _json_to_html(self, data: Any, depth: int = 0) -> str:
        """Рекурсивное преобразование структуры JSON в читаемый HTML"""
        if depth > 10:
            return html.escape(str(data))
            
        margin = depth * 12
        result = []

        if isinstance(data, dict):
            for key, value in data.items():
                key_display = key.replace("_", " ").title()
                if isinstance(value, (dict, list)):
                    result.append(f'<div style="margin-bottom:8px; padding-left:{margin}px; border-left:2px solid #4A90D9;">')
                    result.append(f'<strong style="color:#4A90D9; font-size:13px; display:block; margin:6px 0 2px;">{key_display}</strong>')
                    result.append(self._json_to_html(value, depth + 1))
                    result.append('</div>')
                else:
                    val_str = html.escape(str(value))
                    result.append(f'<div style="display:flex; padding-left:{margin}px; margin:3px 0;">')
                    result.append(f'<span style="color:#9cdcfe; min-width:140px; font-size:12px;">{key_display}: </span>')
                    result.append(f'<span style="color:#d4d4d4; font-size:12px;">{val_str}</span>')
                    result.append('</div>')
                    
        elif isinstance(data, list):
            if not data:
                return '<span style="color:#6a9955; font-size:12px;">[]</span>'
                
            if all(isinstance(item, dict) for item in data):
                headers = list(data[0].keys())
                result.append('<table style="width:100%; border-collapse:collapse; margin:8px 0; font-size:12px;">')
                result.append('<tr>')
                for h in headers:
                    result.append(f'<th style="background:#2d2d4a; color:#4A90D9; padding:6px; border:1px solid #333; text-align:left;">{h.replace("_", " ").title()}</th>')
                result.append('</tr>')
                for row in data:
                    result.append('<tr>')
                    for h in headers:
                        val = html.escape(str(row.get(h, "")))
                        result.append(f'<td style="padding:6px; border:1px solid #333; color:#d4d4d4;">{val}</td>')
                    result.append('</tr>')
                result.append('</table>')
            else:
                result.append('<ul style="margin:4px 0; padding-left:20px; list-style-type:disc;">')
                for item in data:
                    item_str = html.escape(str(item))
                    result.append(f'<li style="color:#d4d4d4; font-size:12px; margin:2px 0;">{item_str}</li>')
                result.append('</ul>')
        else:
            return html.escape(str(data))
            
        return '\n'.join(result)

    def _format_response(self, text: str) -> str:
        """Основной метод форматирования: детекция JSON или обработка Markdown"""
        cleaned = text.strip()
        
        if cleaned.startswith('{') or cleaned.startswith('['):
            try:
                parsed_data = json.loads(cleaned)
                return self._json_to_html(parsed_data)
            except json.JSONDecodeError:
                pass

        safe_text = html.escape(text)
        
        # Блоки кода
        safe_text = re.sub(r'```(\w*)\n(.*?)```', 
                           r'<pre style="background:#1a1a1a; color:#d4d4d4; padding:10px; border-radius:6px; '
                           r'overflow-x:auto; font-family:Consolas, monospace; font-size:12px;">\2</pre>', 
                           safe_text, flags=re.DOTALL)
                           
        # Заголовки
        safe_text = re.sub(r'^###\s+(.+)$', r'<h3 style="color:#4A90D9; margin:12px 0 6px;">\1</h3>', safe_text, flags=re.MULTILINE)
        safe_text = re.sub(r'^##\s+(.+)$', r'<h2 style="color:#4A90D9; margin:14px 0 8px; border-bottom:1px solid #333; padding-bottom:4px;">\1</h2>', safe_text, flags=re.MULTILINE)
        
        # Жирный и курсив
        safe_text = re.sub(r'\*\*(.+?)\*\*', r'<strong style="color:#ffffff;">\1</strong>', safe_text)
        safe_text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', safe_text)
        
        # Списки
        safe_text = re.sub(r'^-\s+(.+)$', r'<li style="margin-left:18px;">\1</li>', safe_text, flags=re.MULTILINE)
        safe_text = re.sub(r'((?:<li>.*?</li>\n?)+)', r'<ul style="list-style-type:disc; padding-left:16px; margin:8px 0;">\1</ul>', safe_text, flags=re.DOTALL)
        
        # Переносы строк
        safe_text = re.sub(r'\n{2,}', '<br><br>', safe_text)
        safe_text = re.sub(r'(?<!<br>)\n(?!<)', '<br>', safe_text)

        return safe_text

    def _create_context_menu(self, text: str, is_ai: bool = False) -> QMenu:
        """Создание контекстного меню для сообщения"""
        menu = QMenu(self)
        
        copy_action = QAction("📋 Копировать текст", self)
        copy_action.triggered.connect(lambda: self._copy_to_clipboard(text))
        menu.addAction(copy_action)
        
        if is_ai:
            export_action = QAction("📤 Экспортировать в HTML", self)
            export_action.triggered.connect(lambda: self._export_message_to_html(text))
            menu.addAction(export_action)
            
        menu.addSeparator()
         
        clear_action = QAction("🗑 Очистить чат", self)
        clear_action.triggered.connect(self.clear_chat)
        menu.addAction(clear_action)
        
        return menu

    def _copy_to_clipboard(self, text: str):
        """Копирование текста в системный буфер обмена"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self._show_temp_notification("Текст скопирован в буфер обмена")

    def _show_temp_notification(self, message: str):
        """Временное уведомление о действии"""
        notification = QLabel(message)
        notification.setStyleSheet("""
            QLabel { 
                background: #27AE60; color: #ffffff; padding: 8px; 
                border-radius: 4px; font-weight: bold; font-size: 12px;
            }
        """)
        notification.setAlignment(Qt.AlignCenter)
        self.layout().insertWidget(1, notification)
        QTimer.singleShot(2000, notification.deleteLater)

    def _export_message_to_html(self, text: str):
        """Экспорт отдельного сообщения в файл HTML"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить ответ в HTML",
            f"ai_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html);;All Files (*)"
        )
        
        if file_path:
            try:
                html_content = self._generate_single_message_html(text)
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(html_content)
                self._show_temp_notification(f"Файл сохранён: {os.path.basename(file_path)}")
            except Exception as error:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл:\n{error}")

    def _generate_single_message_html(self, text: str) -> str:
        """Генерация HTML для одного сообщения"""
        formatted_content = self._format_response(text)
        
        return f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>LucidByte AI Response - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: #1e1e1e; color: #ffffff; padding: 40px; margin: 0; line-height: 1.6;
                }}
                .container {{
                    max-width: 900px; margin: 0 auto; background: #2d2d2d; border-radius: 8px; padding: 30px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
                }}
                .header {{ border-bottom: 2px solid #4A90D9; padding-bottom: 15px; margin-bottom: 25px; }}
                .header h1 {{ color: #4A90D9; margin: 0; font-size: 24px; }}
                .header p {{ color: #888888; margin: 5px 0 0; font-size: 12px; }}
                .content {{ background: #2d2d4a; border-radius: 6px; padding: 20px; margin: 20px 0; }}
                pre {{ background: #1a1a1a; color: #d4d4d4; padding: 15px; border-radius: 6px; overflow-x:auto; font-family: 'Consolas', monospace; font-size: 13px; border: 1px solid #333333; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
                th, td {{ border: 1px solid #333333; padding: 10px; text-align: left; }}
                th {{ background: #2d2d4a; color: #4A90D9; }}
                td {{ background: #252525; color: #d4d4d4; }}
                .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #333333; color: #888888; font-size: 11px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🤖 LucidByte AI Analysis Response</h1>
                    <p>Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Платформа: LucidByte v3.0.0</p>
                </div>
                <div class="content">{formatted_content}</div>
                <div class="footer">Сгенерировано системой анализа вредоносного программного обеспечения LucidByte<br>© 2026 Все права защищены</div>
            </div>
        </body>
        </html>
        """

    def _generate_full_conversation_html(self) -> str:
        """Генерация HTML для всей переписки"""
        messages_html = ""
        
        for msg in self.messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            is_ai = role == "assistant"
            
            bg_color = "#2d4a2d" if not is_ai else "#2d2d4a"
            align = "right" if not is_ai else "left"
            formatted_content = self._format_response(content)
            
            messages_html += f"""
            <div style="background:{bg_color}; color:#ffffff; border-radius:8px; padding:15px 20px; margin:10px 0; 
                      text-align:{align}; font-family:'Segoe UI', sans-serif; line-height: 1.5;">
                <div style="font-size:11px; color:#888888; margin-bottom:8px;">
                    {'🤖 AI Assistant' if is_ai else '👤 Пользователь'}
                </div>
                {formatted_content}
            </div>
            """
        
        return f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>LucidByte AI Conversation - {datetime.now().strftime('%Y%m%d_%H%M%S')}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e1e; color: #ffffff; padding: 40px; margin: 0; line-height: 1.6; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: #2d2d2d; border-radius: 8px; padding: 30px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3); }}
                .header {{ border-bottom: 2px solid #4A90D9; padding-bottom: 15px; margin-bottom: 25px; }}
                .header h1 {{ color: #4A90D9; margin: 0; font-size: 24px; }}
                .header p {{ color: #888888; margin: 5px 0 0; font-size: 12px; }}
                pre {{ background: #1a1a1a; color: #d4d4d4; padding: 15px; border-radius: 6px; overflow-x:auto; font-family: 'Consolas', monospace; font-size: 13px; border: 1px solid #333333; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
                th, td {{ border: 1px solid #333333; padding: 10px; text-align: left; }}
                th {{ background: #2d2d4a; color: #4A90D9; }}
                td {{ background: #252525; color: #d4d4d4; }}
                .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #333333; color: #888888; font-size: 11px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🤖 LucidByte AI Conversation Log</h1>
                    <p>Дата экспорта: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Платформа: LucidByte v3.0.0 | Всего сообщений: {len(self.messages)}</p>
                </div>
                {messages_html}
                <div class="footer">Сгенерировано системой анализа вредоносного программного обеспечения LucidByte<br>© 2026 Все права защищены</div>
            </div>
        </body>
        </html>
        """

    def export_full_conversation_to_html(self):
        """Экспорт всей переписки в файл HTML"""
        if not self.messages:
            QMessageBox.information(self, "Информация", "Переписка пуста. Нечего экспортировать.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить переписку в HTML",
            f"lucidbyte_conversation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html);;All Files (*)"
        )
        
        if file_path:
            try:
                html_content = self._generate_full_conversation_html()
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(html_content)
                self._show_temp_notification(f"Переписка сохранена: {os.path.basename(file_path)}")
            except Exception as error:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл:\n{error}")

    def add_message(self, text: str, is_user: bool = False):
        msg_browser = QTextBrowser()
        msg_browser.setReadOnly(True)
        msg_browser.setOpenExternalLinks(True)
        msg_browser.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        msg_browser.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        msg_browser.setStyleSheet("border: none; background: transparent; color: #e0e0e0; font-size: 13px;")

        bg_color = "#2d4a2d" if is_user else "#2d2d4a"
        align = "right" if is_user else "left"
        formatted_content = self._format_response(text)
        
        message_widget = QWidget()
        message_layout = QVBoxLayout(message_widget)
        message_layout.setContentsMargins(0, 0, 0, 0)
        
        final_html = f"""
        <div style="background:{bg_color}; color:#ffffff; border-radius:8px; padding:10px 14px; margin:4px 2px; 
                  text-align:{align}; font-family:'Segoe UI', sans-serif; line-height:1.5;">
            {formatted_content}
        </div>
        """
        msg_browser.setHtml(final_html)
        
        doc = msg_browser.document()
        doc.adjustSize()
        msg_browser.setMinimumHeight(int(doc.size().height()) + 10)
        
        msg_browser.setContextMenuPolicy(Qt.CustomContextMenu)
        msg_browser.customContextMenuRequested.connect(
            lambda pos: self._show_context_menu_at(msg_browser, text, not is_user, pos)
        )
        
        message_layout.addWidget(msg_browser)
        self.messages_layout.addWidget(message_widget)
        self.messages_area.verticalScrollBar().setValue(self.messages_area.verticalScrollBar().maximum())

    def _show_context_menu_at(self, browser: QTextBrowser, text: str, is_ai: bool, pos):
        """Показ контекстного меню в позиции курсора"""
        menu = self._create_context_menu(text, is_ai)
        menu.exec(browser.viewport().mapToGlobal(pos))

    def add_ai_response(self, text: str):
        """Добавление ответа ассистента в чат"""
        self.add_message(text, is_user=False)
        self.messages.append({"role": "assistant", "content": text})

    def set_typing_indicator(self, is_typing: bool):
        """Индикатор набора текста ИИ"""
        if is_typing:
            if self.typing_label and self.typing_label.parent():
                self.typing_label.deleteLater()
            
            self.typing_label = QLabel("🤖 ИИ формирует ответ...")
            self.typing_label.setStyleSheet("""
                QLabel { background: #2d2d4a; color: #4A90D9; padding: 8px; border-radius: 4px; font-style: italic; font-size: 12px; }
            """)
            self.messages_layout.addWidget(self.typing_label)
            self.messages_area.verticalScrollBar().setValue(self.messages_area.verticalScrollBar().maximum())
        else:
            if self.typing_label and self.typing_label.parent():
                self.typing_label.deleteLater()
                self.typing_label = None

    def clear_chat(self):
        """Очистка истории сообщений"""
        reply = QMessageBox.question(
            self, "Подтверждение", "Очистить всю историю переписки?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            while self.messages_layout.count():
                item = self.messages_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            self.messages.clear()
            if self.typing_label and self.typing_label.parent():
                self.typing_label.deleteLater()
                self.typing_label = None
            self._show_temp_notification("Чат очищен")