from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import Qt

class PermissionTree(QTreeWidget):
    def __init__(self):
        super().__init__()
        self.setHeaderLabel("Разрешения приложения")
        self.setAlternatingRowColors(True)
        
        self.suspicious_category = None
        self.normal_category = None

    def load_permissions(self, permissions: list, suspicious_permissions: list):
        self.clear()
        
        self.suspicious_category = QTreeWidgetItem(["⚠ Подозрительные разрешения"])
        self.suspicious_category.setForeground(0, Qt.red)
        self.addTopLevelItem(self.suspicious_category)
        
        for permission in suspicious_permissions:
            item = QTreeWidgetItem([f"android.permission.{permission}"])
            item.setForeground(0, Qt.red)
            self.suspicious_category.addChild(item)
        
        self.normal_category = QTreeWidgetItem(["✓ Обычные разрешения"])
        self.normal_category.setForeground(0, Qt.green)
        self.addTopLevelItem(self.normal_category)
        
        normal_list = [p for p in permissions if p not in suspicious_permissions]
        for permission in normal_list:
            item = QTreeWidgetItem([f"android.permission.{permission}"])
            item.setForeground(0, Qt.green)
            self.normal_category.addChild(item)
        
        self.expandAll()

    def get_selected_permission(self) -> str:
        selected_items = self.selectedItems()
        if selected_items:
            return selected_items[0].text(0)
        return ""