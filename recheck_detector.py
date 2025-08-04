#!/usr/bin/env python3
"""
Módulo para recheck de vulnerabilidades SQL injection usando OpenAI
"""

import json
import os
import openai
from typing import Dict
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

class RecheckDetector:
    """Detección de recheck usando OpenAI para confirmar vulnerabilidades"""
    
    def __init__(self):
        self.client = openai.OpenAI()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    def generate_recheck_prompt(self, error_response: str, original_payload: str) -> str:
        """Genera prompt para OpenAI para analizar si es Error-Based SQL Injection real y sugerir payload específico"""
        return f"""
        Según esta respuesta de error SQL, ¿qué payload de SQLi error-based puedo usar para obtener información no sensible (como nombre de base de datos o versión) que me permita confirmar que hay una inyección? El payload debe ser específico para el motor de base de datos que se deduce de la respuesta.

        ERROR COMPLETO:
        {error_response}

        PAYLOAD ORIGINAL: {original_payload}

        ANÁLISIS REQUERIDO:
        1. Determina si es Error-Based SQL Injection real
        2. Identifica el motor de base de datos (MySQL, PostgreSQL, Oracle, SQL Server, etc.)
        3. Sugiere un payload específico para ese motor que obtenga información útil
        4. El payload debe ser diferente al original y aprovechar las características del motor detectado

        EJEMPLOS DE PAYLOADS ESPECÍFICOS POR MOTOR:
        - MySQL: "SELECT database()", "SELECT version()", "SELECT user()"
        - PostgreSQL: "SELECT current_database()", "SELECT version()"
        - Oracle: "SELECT banner FROM v$version", "SELECT user FROM dual"
        - SQL Server: "SELECT @@version", "SELECT DB_NAME()"

        CRITERIOS PARA CONFIRMAR SQL INJECTION:
        - DEBE contener errores de sintaxis SQL específicos
        - DEBE mostrar información del motor de base de datos
        - NO debe ser un error HTTP genérico (500, 404, etc.)
        - NO debe ser un error de conexión o timeout

        Responde ÚNICAMENTE en formato JSON:
        {{
            "is_sql_injection": true/false,
            "confidence": 0.0-1.0,
            "recheck_payload": "payload_específico_para_el_motor",
            "database_engine": "MySQL/PostgreSQL/Oracle/SQLServer/etc",
            "reasoning": "explicación del motor detectado y por qué ese payload es apropiado"
        }}
        """
    
    def analyze_with_openai(self, error_response: str, original_payload: str) -> Dict:
        """Analiza el error con OpenAI para determinar si es SQL injection real"""
        
        prompt = self.generate_recheck_prompt(error_response, original_payload)
        
        try:
            # Llamar a OpenAI
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
            
            return {
                'success': True,
                'is_sql_injection': result.get('is_sql_injection', False),
                'confidence': result.get('confidence', 0.0),
                'recheck_payload': result.get('recheck_payload', ''),
                'database_engine': result.get('database_engine', 'Unknown'),
                'reasoning': result.get('reasoning', ''),
                'raw_response': raw_response
            }
            
        except json.JSONDecodeError as e:
            return {
                'success': False,
                'error': f'Error parseando JSON de OpenAI: {str(e)}',
                'raw_response': raw_response if 'raw_response' in locals() else 'No response'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error en OpenAI recheck: {str(e)}',
                'raw_response': raw_response if 'raw_response' in locals() else 'No response'
            }
    
    def is_available(self) -> bool:
        """Verifica si OpenAI está disponible"""
        return bool(os.getenv("OPENAI_API_KEY")) 