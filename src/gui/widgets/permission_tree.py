from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem, QMenu
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QAction

class PermissionTree(QTreeWidget):
    """Дерево разрешений Android приложения с категориями"""
    
    def __init__(self):
        super().__init__()
        self.setHeaderLabels(["Permission", "Risk", "Category"])
        self.setColumnWidth(0, 350)
        self.setColumnWidth(1, 80)
        self.setColumnWidth(2, 120)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        
        self.all_permissions = []
        
        self.setStyleSheet("""
            QTreeWidget {
                background: #1e1e1e;
                color: #ffffff;
                border: 1px solid #333333;
                border-radius: 4px;
                gridline-color: #333333;
            }
            QTreeWidget::item {
                padding: 4px;
                border: none;
            }
            QTreeWidget::item:hover {
                background: #2d2d2d;
            }
            QTreeWidget::item:selected {
                background: #4A90D9;
            }
            QHeaderView::section {
                background: #2d2d2d;
                color: #4A90D9;
                padding: 6px;
                border: 1px solid #333333;
                font-weight: bold;
            }
        """)
        
        # Контекстное меню
        self.context_menu = QMenu(self)
        filter_dangerous = QAction("⚠️ Показать только опасные", self)
        filter_dangerous.triggered.connect(lambda: self.filter_by_risk(["Critical", "High"]))
        self.context_menu.addAction(filter_dangerous)
        
        self.context_menu.addSeparator()
        
        show_all = QAction("📊 Показать все", self)
        show_all.triggered.connect(self.show_all_permissions)
        self.context_menu.addAction(show_all)
    
    def show_context_menu(self, position):
        """Показ контекстного меню"""
        self.context_menu.exec_(self.viewport().mapToGlobal(position))
    
    def add_permissions(self, permissions: list):
        """Добавление списка разрешений"""
        self.clear()
        self.all_permissions = permissions
        
        colors = {
            "Critical": QColor("#ff0000"),
            "High": QColor("#ff6b6b"),
            "Medium": QColor("#ffa500"),
            "Low": QColor("#90ee90")
        }
        
        fonts = {
            "Critical": QFont("Segoe UI", 10, QFont.Bold),
            "High": QFont("Segoe UI", 10, QFont.Bold),
            "Medium": QFont("Segoe UI", 10),
            "Low": QFont("Segoe UI", 10)
        }
        
        for perm in permissions:
            item = QTreeWidgetItem([
                perm.get("name", "Unknown"),
                perm.get("risk", "Low"),
                perm.get("category", "OTHER")
            ])
            
            risk = perm.get("risk", "Low")
            if risk in colors:
                item.setForeground(0, colors[risk])
                item.setForeground(1, colors[risk])
            if risk in fonts:
                item.setFont(0, fonts[risk])
            
            self.addTopLevelItem(item)
        
        self.resizeColumnToContents(1)
        self.resizeColumnToContents(2)
        self.sortByColumn(1, Qt.DescendingOrder)
    
    def filter_by_risk(self, risks: list):
        """Фильтрация по уровням риска"""
        self.clear()
        filtered = [p for p in self.all_permissions if p.get("risk") in risks]
        self.add_permissions(filtered)
    
    def show_all_permissions(self):
        """Показать все разрешения"""
        self.add_permissions(self.all_permissions)
    
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
    
    def get_statistics(self) -> dict:
        """Получение статистики по разрешениям"""
        stats = {
            "total": self.topLevelItemCount(),
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "categories": {}
        }
        
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item:
                risk = item.text(1)
                category = item.text(2)
                if risk in stats:
                    stats[risk] += 1
                if category:
                    stats["categories"][category] = stats["categories"].get(category, 0) + 1
        
        return stats