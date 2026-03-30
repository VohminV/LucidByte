from PySide6.QtWidgets import QListWidget, QListWidgetItem, QLabel, QVBoxLayout, QWidget
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont

class ThreatList(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_interface()

    def setup_interface(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Заголовок списка
        header_label = QLabel("Обнаруженные угрозы")
        header_label.setFont(QFont("Arial", 11, QFont.Bold))
        header_label.setStyleSheet("color: #ff6b6b; padding: 5px;")
        layout.addWidget(header_label)
        
        # Список угроз
        self.threat_list = QListWidget()
        self.threat_list.setAlternatingRowColors(True)
        layout.addWidget(self.threat_list)
        
        self.setLayout(layout)

    def load_threats(self, threats: list):
        self.threat_list.clear()
        
        for threat in threats:
            item = QListWidgetItem()
            
            risk_level = threat.get("risk_level", 0)
            threat_name = threat.get("name", "Неизвестная угроза")
            threat_category = threat.get("category", "Неизвестно")
            
            item.setText(f"[{threat_category}] {threat_name}")
            
            # Цветовое кодирование по уровню риска
            if risk_level >= 8:
                item.setBackground(QColor("#ff6b6b"))
                item.setForeground(QColor("#ffffff"))
            elif risk_level >= 5:
                item.setBackground(QColor("#ffa500"))
                item.setForeground(QColor("#000000"))
            else:
                item.setBackground(QColor("#90ee90"))
                item.setForeground(QColor("#000000"))
            
            self.threat_list.addItem(item)

    def get_selected_threat(self) -> dict:
        selected_items = self.threat_list.selectedItems()
        if selected_items:
            return {"name": selected_items[0].text()}
        return {}

    def clear_threats(self):
        self.threat_list.clear()