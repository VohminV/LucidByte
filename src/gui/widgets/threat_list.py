from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

class ThreatList(QTreeWidget):
    """Список обнаруженных угроз безопасности"""
    
    def __init__(self):
        super().__init__()
        self.setHeaderLabels(["Risk", "Description", "File"])
        self.setColumnWidth(0, 80)
        self.setColumnWidth(1, 300)
        self.setColumnWidth(2, 400)
        self.setAlternatingRowColors(True)
        self.setStyleSheet("""
            QTreeWidget {
                background: #1e1e1e;
                color: #ffffff;
                border: 1px solid #333333;
                border-radius: 4px;
            }
            QTreeWidget::item {
                padding: 4px;
            }
            QTreeWidget::item:hover {
                background: #2d2d2d;
            }
            QTreeWidget::item:selected {
                background: #4A90D9;
            }
            QHeaderView::section {
                background: #2d2d2d;
                color: #ffffff;
                padding: 4px;
                border: 1px solid #333333;
            }
        """)
    
    def add_threat(self, risk: str, description: str, file_path: str):
        """Добавление одной угрозы"""
        item = QTreeWidgetItem([risk, description, file_path])
        
        # Цветовая кодировка по уровню риска
        colors = {
            "Critical": QColor("#ff0000"),
            "High": QColor("#ff6b6b"),
            "Medium": QColor("#ffa500"),
            "Low": QColor("#90ee90")
        }
        
        if risk in colors:
            item.setForeground(0, colors[risk])
        
        self.addTopLevelItem(item)
    
    def add_threats(self, threats: list):
        """Добавление списка угроз"""
        self.clear()
        for threat in threats:
            self.add_threat(
                threat.get("risk", "Low"),
                threat.get("desc", "Unknown"),
                threat.get("file", "Unknown")
            )
        self.resizeColumnToContents(0)
    
    def get_threat_count(self):
        """Получение количества угроз"""
        return self.topLevelItemCount()
    
    def get_critical_count(self):
        """Получение количества критических угроз"""
        count = 0
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item and item.text(0) == "Critical":
                count += 1
        return count