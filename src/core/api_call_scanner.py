import re
from pathlib import Path
from typing import List, Dict, Tuple

class ApiCallScanner:
    def __init__(self, dangerous_api_calls: List[str]):
        self.dangerous_api_calls = dangerous_api_calls
        self.found_calls: Dict[str, List[Tuple[str, int]]] = {}

    def scan_files(self, file_paths: List[Path]) -> Dict[str, List[Tuple[str, int]]]:
        self.found_calls = {}
        
        for file_path in file_paths:
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    lines = file.readlines()
                
                for line_number, line_content in enumerate(lines, start=1):
                    for api_call in self.dangerous_api_calls:
                        if api_call in line_content:
                            if api_call not in self.found_calls:
                                self.found_calls[api_call] = []
                            self.found_calls[api_call].append(
                                (file_path.name, line_number)
                            )
                            
            except Exception as exception:
                print(f"Ошибка чтения файла {file_path}: {exception}")
                continue
        
        print(f"Найдено опасных вызовов API: {len(self.found_calls)}")
        return self.found_calls

    def get_all_dangerous_calls(self) -> Dict[str, List[Tuple[str, int]]]:
        return self.found_calls

    def get_risk_score(self) -> int:
        total_calls = sum(len(locations) for locations in self.found_calls.values())
        
        # Критические вызовы получают больший вес
        critical_calls = ["Runtime.exec", "ProcessBuilder", "SmsManager.getDefault"]
        critical_count = 0
        
        for call in critical_calls:
            if call in self.found_calls:
                critical_count += len(self.found_calls[call])
        
        score = total_calls + (critical_count * 3)
        return min(score, 10)

    def get_summary(self) -> str:
        summary = "=== Найденные опасные вызовы API ===\n\n"
        
        for api_call, locations in self.found_calls.items():
            summary += f"Вызов: {api_call}\n"
            summary += f"Количество обнаружений: {len(locations)}\n"
            summary += "Расположение:\n"
            
            for file_name, line_number in locations[:5]:  # Показываем первые 5
                summary += f"  - {file_name}, строка {line_number}\n"
            
            if len(locations) > 5:
                summary += f"  ... и еще {len(locations) - 5} обнаружений\n"
            
            summary += "\n"
        
        return summary