import re
from pathlib import Path
from typing import List, Dict

class PermissionAnalyzer:
    def __init__(self, suspicious_permissions: List[str]):
        self.suspicious_permissions = suspicious_permissions
        self.found_permissions: List[str] = []
        self.suspicious_found: List[str] = []

    def parse_manifest(self, manifest_path: Path) -> bool:
        if not manifest_path.exists():
            print("Файл манифеста не найден")
            return False

        try:
            with open(manifest_path, "r", encoding="utf-8") as file:
                content = file.read()
            
            # Поиск всех объявлений разрешений
            permission_pattern = r'android\.permission\.([A-Z_]+)'
            matches = re.findall(permission_pattern, content)
            
            self.found_permissions = matches
            
            # Проверка на подозрительные разрешения
            self.suspicious_found = []
            for permission in matches:
                if permission in self.suspicious_permissions:
                    self.suspicious_found.append(permission)
            
            print(f"Найдено разрешений: {len(self.found_permissions)}")
            print(f"Подозрительных разрешений: {len(self.suspicious_found)}")
            return True
            
        except Exception as exception:
            print(f"Ошибка анализа манифеста: {exception}")
            return False

    def get_all_permissions(self) -> List[str]:
        return self.found_permissions

    def get_suspicious_permissions(self) -> List[str]:
        return self.suspicious_found

    def get_risk_score(self) -> int:
        # Расчет уровня риска на основе количества подозрительных разрешений
        base_score = len(self.suspicious_found) * 2
        
        # Дополнительные баллы за критические разрешения
        critical_permissions = [
            "SEND_SMS", "READ_SMS", "RECEIVE_SMS",
            "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"
        ]
        
        for permission in self.suspicious_found:
            if permission in critical_permissions:
                base_score += 3
        
        return min(base_score, 10)  # Максимум 10 баллов