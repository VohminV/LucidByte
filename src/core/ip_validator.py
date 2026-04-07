import re
import ipaddress
from typing import List, Tuple

class IPValidator:
    """Валидация IP-адресов для отсеивания ложных срабатываний"""
    
    # Строгий regex для IPv4 (каждый октет 0-255)
    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    # Regex для IPv6
    IPV6_PATTERN = re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|'
        r'\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|'
        r'\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|'
        r'\b::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    @staticmethod
    def is_valid_ipv4(ip_string: str) -> bool:
        """Проверяет валидность IPv4 адреса"""
        try:
            # Проверяем формат через regex
            if not IPValidator.IPV4_PATTERN.match(ip_string):
                return False
            # Дополнительная проверка через ipaddress
            ipaddress.IPv4Address(ip_string)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False
    
    @staticmethod
    def is_valid_ipv6(ip_string: str) -> bool:
        """Проверяет валидность IPv6 адреса"""
        try:
            if not IPValidator.IPV6_PATTERN.match(ip_string):
                return False
            ipaddress.IPv6Address(ip_string)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False
    
    @staticmethod
    def is_valid_ip(ip_string: str) -> bool:
        """Проверяет валидность любого IP (IPv4 или IPv6)"""
        return IPValidator.is_valid_ipv4(ip_string) or IPValidator.is_valid_ipv6(ip_string)
    
    @staticmethod
    def filter_valid_ips(ip_list: List[str]) -> List[str]:
        """Фильтрует список, оставляя только валидные IP"""
        return [ip for ip in ip_list if IPValidator.is_valid_ip(ip)]
    
    @staticmethod
    def validate_indicators(indicators: List[dict]) -> Tuple[List[dict], List[dict]]:
        """
        Разделяет индикаторы на валидные и невалидные.
        Возвращает: (валидные, отклонённые)
        """
        valid = []
        invalid = []
        
        for item in indicators:
            pattern = item.get('pattern', '')
            
            # Проверяем если это IP индикатор
            if 'hardcoded_ip' in pattern.lower() or 'ip' in item.get('category', '').lower():
                # Извлекаем IP из паттерна
                ip_candidate = pattern.replace('hardcoded_ip:', '').strip()
                
                if IPValidator.is_valid_ip(ip_candidate):
                    valid.append(item)
                else:
                    invalid.append({
                        **item,
                        'rejection_reason': f'Невалидный IP: {ip_candidate}'
                    })
            else:
                valid.append(item)
        
        return valid, invalid