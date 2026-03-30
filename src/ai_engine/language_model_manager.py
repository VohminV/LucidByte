import requests
from typing import Optional

class LanguageModelManager:
    def __init__(self, base_url: str, model_name: str):
        self.base_url = base_url
        self.model_name = model_name

    def send_request(self, prompt: str, system_instruction: str = "") -> Optional[str]:
        endpoint = f"{self.base_url}/api/generate"
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_instruction,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 2048
            }
        }

        try:
            response = requests.post(endpoint, json=payload, timeout=120)
            response.raise_for_status()
            result_data = response.json()
            return result_data.get("response", "")
        except requests.exceptions.RequestException as exception:
            print(f"Ошибка подключения к модели: {exception}")
            return None

    def analyze_malware_threat(self, code_snippet: str, permissions: list, api_calls: dict) -> str:
        instruction = """Ты являешься экспертом по безопасности мобильных устройств Android. 
        Твоя задача — проанализировать предоставленный код и определить наличие вредоносного поведения.
        
        Ответь на следующие вопросы:
        1. Есть ли признаки кражи личных данных?
        2. Есть ли признаки скрытой передачи информации?
        3. Есть ли признаки получения несанкционированного контроля?
        4. Каков общий уровень угрозы от 1 до 10?
        5. Какие конкретные методы представляют опасность?
        
        Ответ должен быть структурированным и подробным."""
        
        context = f"""Разрешения приложения: {permissions}
        
        Опасные вызовы API: {api_calls}
        
        Фрагмент кода для анализа:
        {code_snippet}"""
        
        return self.send_request(prompt=context, system_instruction=instruction)

    def generate_threat_report(self, analysis_results: dict) -> str:
        instruction = """Сгенерируй профессиональный отчет об анализе безопасности мобильного приложения.
        Включи следующие разделы:
        1. Краткое резюме
        2. Обнаруженные угрозы
        3. Уровень риска
        4. Рекомендации по устранению
        5. Техническая детализация
        
        Используй формальный технический стиль."""
        
        return self.send_request(
            prompt=str(analysis_results), 
            system_instruction=instruction
        )

    def explain_code_behavior(self, code_snippet: str) -> str:
        instruction = """Объясни поведение этого кода простыми словами. 
        Что делает этот код? Какие данные он может получить? 
        Есть ли скрытые функции?"""
        
        return self.send_request(prompt=code_snippet, system_instruction=instruction)