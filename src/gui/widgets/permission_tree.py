from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

class PermissionTree(QTreeWidget):
    """Дерево разрешений Android приложения"""
    
    def __init__(self):
        super().__init__()
        self.setHeaderLabels(["Permission", "Risk Level"])
        self.setColumnWidth(0, 400)
        self.setColumnWidth(1, 100)
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
    
    def add_permission(self, name: str, risk: str):
        """Добавление одного разрешения"""
        item = QTreeWidgetItem([name, risk])
        
        colors = {
            "Critical": QColor("#ff0000"),
            "High": QColor("#ff6b6b"),
            "Medium": QColor("#ffa500"),
            "Low": QColor("#90ee90")
        }
        
        if risk in colors:
            item.setForeground(0, colors[risk])
            item.setForeground(1, colors[risk])
        
        self.addTopLevelItem(item)
    
    def add_permissions(self, permissions: list):
        """Добавление списка разрешений"""
        self.clear()
        for perm in permissions:
            self.add_permission(
                perm.get("name", "Unknown"),
                perm.get("risk", "Low")
            )
        self.resizeColumnToContents(1)
    
    def get_permission_count(self):
        """Получение количества разрешений"""
        return self.topLevelItemCount()
    
    def get_dangerous_count(self):
        """Получение количества опасных разрешений"""
        count = 0
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item and item.text(1) in ["Critical", "High"]:
                count += 1
        return count