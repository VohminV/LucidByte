from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem, QMenu
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QAction

class ThreatList(QTreeWidget):
    """Список обнаруженных угроз безопасности с детальной статистикой"""
    
    threat_selected = Signal(dict)
    
    def __init__(self):
        super().__init__()
        self.setHeaderLabels(["Risk", "Category", "Description", "File"])
        self.setColumnWidth(0, 70)
        self.setColumnWidth(1, 120)
        self.setColumnWidth(2, 250)
        self.setColumnWidth(3, 300)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        
        self.all_threats = []
        self.threat_data = {}
        
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
            QScrollBar:vertical {
                background: #1e1e1e;
                width: 10px;
            }
            QScrollBar::handle:vertical {
                background: #4A90D9;
                border-radius: 5px;
            }
        """)
        
        # Контекстное меню
        self.context_menu = QMenu(self)
        filter_critical = QAction("🔴 Показать только Critical", self)
        filter_critical.triggered.connect(lambda: self.filter_by_risk("Critical"))
        self.context_menu.addAction(filter_critical)
        
        filter_high = QAction("🟠 Показать только High", self)
        filter_high.triggered.connect(lambda: self.filter_by_risk("High"))
        self.context_menu.addAction(filter_high)
        
        self.context_menu.addSeparator()
        
        show_all = QAction("📊 Показать все", self)
        show_all.triggered.connect(self.show_all_threats)
        self.context_menu.addAction(show_all)
        
        self.context_menu.addSeparator()
        
        export_action = QAction("📤 Экспорт угроз", self)
        export_action.triggered.connect(self.export_threats)
        self.context_menu.addAction(export_action)
    
    def show_context_menu(self, position):
        """Показ контекстного меню"""
        self.context_menu.exec_(self.viewport().mapToGlobal(position))
    
    def add_threats(self, threats: list):
        """Добавление списка угроз"""
        self.clear()
        self.all_threats = threats
        self.threat_data = {}
        
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
        
        for i, threat in enumerate(threats):
            item = QTreeWidgetItem([
                threat.get("risk", "Low"),
                threat.get("category", "Unknown"),
                threat.get("desc", "Unknown"),
                threat.get("file", "Unknown")[-60:] if len(threat.get("file", "")) > 60 else threat.get("file", "Unknown")
            ])
            
            risk = threat.get("risk", "Low")
            if risk in colors:
                item.setForeground(0, colors[risk])
                item.setForeground(1, colors[risk])
            if risk in fonts:
                item.setFont(0, fonts[risk])
            
            item.setData(0, Qt.UserRole, threat)
            self.threat_data[i] = threat
            self.addTopLevelItem(item)
        
        self.resizeColumnToContents(0)
        self.resizeColumnToContents(1)
        self.sortByColumn(0, Qt.DescendingOrder)
    
    def filter_by_risk(self, risk: str):
        """Фильтрация по уровню риска"""
        self.clear()
        filtered = [t for t in self.all_threats if t.get("risk") == risk]
        self.add_threats(filtered)
    
    def show_all_threats(self):
        """Показать все угрозы"""
        self.add_threats(self.all_threats)
    
    def export_threats(self):
        """Экспорт угроз в консоль (для дальнейшей реализации)"""
        print(f"Экспорт {len(self.all_threats)} угроз...")
    
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
    
    def get_statistics(self) -> dict:
        """Получение статистики по угрозам"""
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
                risk = item.text(0)
                category = item.text(1)
                if risk in stats:
                    stats[risk] += 1
                if category:
                    stats["categories"][category] = stats["categories"].get(category, 0) + 1
        
        return stats