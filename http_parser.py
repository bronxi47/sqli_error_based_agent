#!/usr/bin/env python3
"""
Módulo para manejo de requests HTTP, payloads y responses
"""

import requests
import time
import os
from typing import Dict, List
from urllib.parse import parse_qs, urlencode
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

class HttpRequest:
    """Clase para parsear requests HTTP raw"""
    
    def __init__(self, raw_request: str):
        self.raw_request = raw_request
        self.method = ""
        self.url = ""
        self.headers = {}
        self.body = ""
        self.params = {}
        self._parse_request()
    
    def _parse_request(self):
        """Parsea la request HTTP raw"""
        lines = self.raw_request.strip().split('\n')
        
        # Primera línea: método, URL, versión
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        self.method = parts[0]
        full_url = parts[1]
        
        # Separar URL y parámetros GET
        if '?' in full_url:
            base_url, query_string = full_url.split('?', 1)
            self.params.update(parse_qs(query_string, keep_blank_values=True))
        else:
            base_url = full_url
        
        # Procesar headers
        header_end = 1
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                header_end = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                self.headers[key.strip()] = value.strip()
        
        # Host header para construir URL completa
        host = self.headers.get('Host', 'localhost')
        self.url = f"http://{host}{base_url}"
        
        # Body (si existe)
        if header_end < len(lines):
            self.body = '\n'.join(lines[header_end:])
            # Parsear parámetros POST si es form-encoded
            if 'application/x-www-form-urlencoded' in self.headers.get('Content-Type', ''):
                self.params.update(parse_qs(self.body, keep_blank_values=True))

class PayloadManager:
    """Maneja los payloads para SQL injection desde archivo externo"""
    
    def __init__(self, payload_file: str = "payloads.txt"):
        self.payloads = self._load_payloads_from_file(payload_file)
        if not self.payloads:
            self.payloads = ["'", '"', "' OR '1'='1"]
    
    def _load_payloads_from_file(self, filename: str) -> List[str]:
        """Carga payloads desde archivo externo"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                payloads = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
                return payloads
        except FileNotFoundError:
            return []
        except Exception as e:
            return []

class RequestHandler:
    """Maneja las requests HTTP y responses"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_parameter(self, request: HttpRequest, param_name: str, payload: str) -> Dict:
        """Prueba un parámetro específico con un payload"""
        test_params = request.params.copy()
        
        # Aplicar payload al parámetro
        if isinstance(test_params[param_name], list):
            test_params[param_name] = [payload]
        else:
            test_params[param_name] = payload
        
        # Reconstruir URL con parámetros
        query_string = urlencode({k: v[0] if isinstance(v, list) else v for k, v in test_params.items()})
        test_url = f"{request.url.split('?')[0]}?{query_string}"
        
        try:
            response = self.session.request(
                method=request.method,
                url=test_url,
                headers=request.headers,
                data=request.body,
                timeout=int(os.getenv("REQUEST_TIMEOUT", "10"))
            )
            
            return {
                'url': test_url,
                'payload': payload,
                'status_code': response.status_code,
                'response_text': response.text,
                'response_size': len(response.text)
            }
        except requests.exceptions.ConnectionError as e:
            return {
                'url': test_url,
                'payload': payload,
                'error': 'connection_error',
                'error_details': f"Servidor no responde: {str(e)}"
            }
        except requests.exceptions.Timeout as e:
            return {
                'url': test_url,
                'payload': payload,
                'error': 'timeout_error',
                'error_details': f"Timeout: {str(e)}"
            }
        except Exception as e:
            return {
                'url': test_url,
                'payload': payload,
                'error': 'general_error',
                'error_details': f"Error general: {str(e)}"
            } 