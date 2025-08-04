#!/usr/bin/env python3
"""
Módulo para detección manual de SQL injection usando patrones regex
"""

import re
from typing import Dict

class ManualDetector:
    """Detección manual de patrones de error SQL"""
    
    def __init__(self):
        # Patrones específicos de errores SQL
        self.error_patterns = [
            (r"You have an error in your SQL syntax", "MySQL Syntax Error"),
            (r"check the manual that corresponds to your MySQL server version", "MySQL Version Error"),
            (r"MySQL server version for the right syntax to use near", "MySQL Near Syntax Error"),
            (r"Warning.*mysql_fetch", "MySQL Fetch Warning"),
            (r"MySQL result index", "MySQL Result Error"),
            (r"PostgreSQL query failed", "PostgreSQL Query Error"),
            (r"pg_query\(\) expects", "PostgreSQL Function Error"),
            (r"ORA-\d{5}", "Oracle Error Code"),
            (r"Microsoft.*ODBC.*SQL Server", "SQL Server ODBC Error"),
            (r"SQLite.*error", "SQLite Error"),
            (r"sqlite3\.OperationalError", "SQLite Operational Error")
        ]
    
    def detect(self, content: str) -> Dict:
        """Detección manual de patrones de error SQL"""
        indicators = []
        
        for pattern, description in self.error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                indicators.append(description)
        
        return {
            "contains_sql_error": len(indicators) > 0,
            "error_type": "Manual Detection",
            "confidence": 0.9 if indicators else 0.0,
            "details": f"Detectado manualmente: {', '.join(indicators)}" if indicators else "No se detectaron errores SQL manualmente"
        }
    
    def get_patterns(self) -> list:
        """Retorna la lista de patrones para debugging"""
        return self.error_patterns 