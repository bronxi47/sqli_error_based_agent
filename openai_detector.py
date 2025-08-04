#!/usr/bin/env python3
"""
Módulo para detección de SQL injection usando OpenAI
"""

import json
import os
import openai
from typing import Dict
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

class OpenAIDetector:
    """Detección usando OpenAI"""
    
    def __init__(self):
        self.client = openai.OpenAI()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    def detect(self, content: str, parameter: str = "unknown", payload: str = "unknown") -> Dict:
        """Detección usando OpenAI"""
        prompt = f"""
        Analiza esta respuesta HTTP para detectar errores de SQL injection.

        Parámetro probado: {parameter}
        Payload usado: {payload}
        Contenido de respuesta: {content[:4000]}

        Busca específicamente:
        1. "You have an error in your SQL syntax"
        2. "MySQL server version"
        3. "syntax to use near"
        4. Errores de PostgreSQL, Oracle, SQL Server, SQLite
        5. Mensajes que mencionen SQL, database, query

        IMPORTANTE: Responde ÚNICAMENTE en formato JSON válido, sin texto adicional.
        Ejemplo de respuesta válida:
        {{
            "contains_sql_error": true,
            "error_type": "MySQL syntax error",
            "confidence": 0.9,
            "details": "Error de sintaxis SQL detectado"
        }}

        Responde SOLO el JSON:
        """

        try:
            # Hacer llamada a OpenAI
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1
            )

            # Obtener respuesta raw
            raw_response = response.choices[0].message.content

            # Limpiar markdown code blocks
            if raw_response.startswith("```json"):
                raw_response = raw_response.replace("```json", "").replace("```", "").strip()
            elif raw_response.startswith("```"):
                raw_response = raw_response.replace("```", "").strip()

            # Parsear JSON
            result = json.loads(raw_response)
            
            # Verificar que tenga la estructura esperada
            if 'confidence' not in result:
                result['confidence'] = 0.0
            if 'error_type' not in result:
                result['error_type'] = None
            if 'details' not in result:
                result['details'] = "Respuesta incompleta de OpenAI"
                
            return result

        except json.JSONDecodeError as e:
            return {
                "contains_sql_error": False,
                "error_type": "json_decode_error",
                "confidence": 0.0,
                "details": f"Error parseando JSON de OpenAI: {str(e)}"
            }
        except Exception as e:
            return {
                "contains_sql_error": False,
                "error_type": "openai_error",
                "confidence": 0.0,
                "details": f"Error en OpenAI: {str(e)}"
            }
    
    def is_available(self) -> bool:
        """Verifica si OpenAI está disponible"""
        return bool(os.getenv("OPENAI_API_KEY")) 