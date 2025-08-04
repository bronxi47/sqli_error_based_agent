#!/usr/bin/env python3
"""
Script principal para detección de SQL injection
"""

import json
import time
import os
import sys
from typing import Dict
from dotenv import load_dotenv

# Importar módulos
from http_parser import HttpRequest, PayloadManager, RequestHandler
from manual_detector import ManualDetector
from openai_detector import OpenAIDetector
from recheck_detector import RecheckDetector

# Cargar variables de entorno
load_dotenv()

class SQLInjectionScanner:
    """Agente principal para detectar SQL injection"""
    
    def __init__(self, enable_recheck=False):
        self.request_handler = RequestHandler()
        self.manual_detector = ManualDetector()
        self.openai_detector = OpenAIDetector()
        self.enable_recheck = enable_recheck
        if enable_recheck:
            self.recheck_detector = RecheckDetector()
    
    def analyze_sql_error(self, response_text: str, payload: str, parameter: str, request=None) -> Dict:
        """Analiza la respuesta usando detección manual y OpenAI"""
        print(f"[ANALIZANDO] {parameter} | {payload} | {len(response_text)} chars")
        
        # Análisis manual y OpenAI
        manual_detection_result = self.manual_detector.detect(response_text)
        openai_detection_result = self.openai_detector.detect(response_text, parameter, payload)
        
        # Lógica de decisión mejorada
        manual_found = manual_detection_result['contains_sql_error']
        openai_found = openai_detection_result['contains_sql_error']
        
        # Crear resultado combinado
        combined_result = {
            'contains_sql_error': manual_found or openai_found,  # Si al menos una detecta
            'error_type': 'Combined Detection',
            'confidence': max(manual_detection_result['confidence'], openai_detection_result['confidence']),
            'details': f"Manual: {manual_detection_result['details']} | OpenAI: {openai_detection_result['details']}",
            'manual_detection': manual_detection_result,
            'openai_detection': openai_detection_result,
            'both_detected': manual_found and openai_found
        }
        
        # Lógica de decisión mejorada
        
        # Si recheck está habilitado y se detectó vulnerabilidad, hacer recheck
        if self.enable_recheck and combined_result.get('contains_sql_error', False) and combined_result.get('confidence', 0) > 0.7:
            print(f"[RECHECK] Verificando...")
            recheck_result = self.recheck_detector.analyze_with_openai(response_text, payload)
            
            if recheck_result['success'] and recheck_result['is_sql_injection'] and recheck_result['recheck_payload']:
                suggested_payload = recheck_result['recheck_payload']
                database_engine = recheck_result.get('database_engine', 'Unknown')
                print(f"[RECHECK] {suggested_payload} | {database_engine}")
                
                # Paso 2: Hacer un nuevo test con el payload sugerido
                
                # Necesitamos el request para hacer el nuevo test
                if request is not None:
                    recheck_test_result = self.request_handler.test_parameter(
                        request,  # Usar el request pasado como parámetro
                        parameter, 
                        suggested_payload
                    )
                else:
                    print(f"[ERROR RECHECK] No se puede hacer recheck sin request")
                    combined_result['openai_recheck'] = recheck_result
                    combined_result['confirmed_vulnerability'] = False
                    return combined_result
                
                if 'error' not in recheck_test_result:
                    # Paso 3: Analizar la nueva respuesta
                    recheck_analysis = self.manual_detector.detect(recheck_test_result['response_text'])
                    
                    if recheck_analysis['contains_sql_error']:
                        print(f"[CONFIRMADO] Payload sugerido también da error SQL")
                        
                        # Actualizar análisis con confirmación
                        combined_result['openai_recheck'] = recheck_result
                        combined_result['recheck_test'] = {
                            'suggested_payload': suggested_payload,
                            'database_engine': database_engine,
                            'test_result': recheck_test_result,
                            'analysis': recheck_analysis
                        }
                        combined_result['confirmed_vulnerability'] = True
                        
                    else:
                        print(f"[FALSO POSITIVO] Payload sugerido NO da error SQL")
                        
                        # Marcar como posible falso positivo
                        combined_result['openai_recheck'] = recheck_result
                        combined_result['recheck_test'] = {
                            'suggested_payload': suggested_payload,
                            'database_engine': database_engine,
                            'test_result': recheck_test_result,
                            'analysis': recheck_analysis
                        }
                        combined_result['confirmed_vulnerability'] = False
                else:
                    print(f"[ERROR RECHECK] Error al probar payload sugerido: {recheck_test_result['error']}")
                    combined_result['openai_recheck'] = recheck_result
                    combined_result['confirmed_vulnerability'] = False
                    
            elif recheck_result['success'] and not recheck_result['is_sql_injection']:
                print(f"[FALSO POSITIVO] OpenAI detecta posible falso positivo")
                print(f"   Confianza: {recheck_result['confidence']}")
                print(f"   Razón: {recheck_result['reasoning']}")
                
                # Marcar como posible falso positivo
                combined_result['openai_recheck'] = recheck_result
                combined_result['confirmed_vulnerability'] = False
            else:
                print(f"[ERROR RECHECK] {recheck_result.get('error', 'Error desconocido')}")
                combined_result['openai_recheck'] = recheck_result
                combined_result['confirmed_vulnerability'] = False
        
        return combined_result
    
    def scan_for_sql_injection(self, request_file: str, payload_file: str) -> Dict:
        """Escanea una request en busca de vulnerabilidades SQL injection"""
        print("[INICIANDO SCAN] SQL Injection Scanner")

        # Cargar request
        with open(request_file, 'r', encoding='utf-8') as f:
            raw_request = f.read()

        request = HttpRequest(raw_request)
        print(f"[TARGET] URL: {request.url}")
        print(f"[PARÁMETROS] {list(request.params.keys())}")

        # Cargar payloads
        payload_manager = PayloadManager(payload_file)
        print(f"[PAYLOADS] Cargados: {len(payload_manager.payloads)}")

        vulnerabilities = []
        start_time = time.time()
        vulnerability_found = False  # Flag para parada temprana
        connection_errors = 0  # Contador de errores de conexión
        total_tests = 0  # Contador total de tests

        for param_name in request.params.keys():
            if vulnerability_found:
                print(f"[SALTANDO] Vulnerabilidad ya encontrada, parámetro: {param_name}")
                break
                
            param_vulnerabilities = []

            for i, payload in enumerate(payload_manager.payloads):
                if vulnerability_found:
                    print(f"[SALTANDO] Vulnerabilidad ya encontrada, payload: {payload}")
                    break
                    
                print(f"\n--- Test {i+1}/{len(payload_manager.payloads)} ---")

                # Test con payload
                test_result = self.request_handler.test_parameter(request, param_name, payload)
                total_tests += 1
                
                if 'error' in test_result:
                    error_type = test_result['error']
                    error_details = test_result.get('error_details', 'Error desconocido')
                    
                    if error_type == 'connection_error':
                        connection_errors += 1
                        print(f"[ERROR] Servidor no responde: {error_details}")
                        print(f"   URL: {test_result['url']}")
                        print(f"   Payload: {payload}")
                        # Si el servidor no responde, continuar con el siguiente payload
                        continue
                    elif error_type == 'timeout_error':
                        print(f"[TIMEOUT] {error_details}")
                        print(f"   URL: {test_result['url']}")
                        print(f"   Payload: {payload}")
                        # Si hay timeout, continuar con el siguiente payload
                        continue
                    else:
                        print(f"[ERROR] General: {error_details}")
                        print(f"   URL: {test_result['url']}")
                        print(f"   Payload: {payload}")
                        # Si hay error general, continuar con el siguiente payload
                        continue
                else:
                    # Analizar respuesta con ambas detecciones
                    analysis = self.analyze_sql_error(
                        test_result['response_text'], 
                        payload, 
                        param_name,
                        request  # Pasar el request para el recheck
                    )

                    confidence_threshold = float(os.getenv("CONFIDENCE_THRESHOLD", "0.7"))
                    if analysis.get('contains_sql_error', False) and analysis.get('confidence', 0) > confidence_threshold:
                        print(f"[VULNERABILIDAD] ¡DETECTADA! Parando scan...")
                        print(f"   Parámetro: {param_name}")
                        print(f"   Payload: {payload}")
                        print(f"   Confianza: {analysis.get('confidence', 0)}")

                        # Crear objeto de vulnerabilidad con información del recheck
                        vuln_data = {
                            'payload': payload,
                            'url': test_result['url'],
                            'confidence': analysis.get('confidence', 0),
                            'details': analysis.get('details', ''),
                            'status_code': test_result['status_code'],
                            'manual_detection': analysis.get('manual_detection', {}),
                            'openai_detection': analysis.get('openai_detection', {})
                        }
                        
                        # Agregar información del recheck si está disponible
                        if analysis.get('openai_recheck'):
                            vuln_data['recheck'] = {
                                'suggested_payload': analysis['openai_recheck'].get('recheck_payload', ''),
                                'database_engine': analysis['openai_recheck'].get('database_engine', ''),
                                'confirmed_vulnerability': analysis.get('confirmed_vulnerability', False),
                                'recheck_test': analysis.get('recheck_test', {})
                            }
                        
                        param_vulnerabilities.append(vuln_data)

                        vulnerability_found = True  # Activar parada temprana
                        break  # Salir del loop de payloads

            if param_vulnerabilities:
                # Simplificar: agregar directamente las vulnerabilidades sin anidación extra
                for vuln in param_vulnerabilities:
                    vuln['parameter'] = param_name
                    vulnerabilities.append(vuln)
                break  # Salir del loop de parámetros

        execution_time = time.time() - start_time

        # Detectar si el servidor no responde
        server_unreachable = False
        if total_tests > 0:
            server_unreachable = connection_errors >= total_tests * 0.8  # Si 80% o más fallan por conexión
        
        return {
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'target_url': request.url,
            'method': request.method,
            'parameters_tested': list(request.params.keys()),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'execution_time': round(execution_time, 2),
            'status': 'vulnerable' if vulnerabilities else 'secure'
        }

def main():
    """Función principal"""
    # Verificar argumentos de línea de comandos
    if len(sys.argv) < 2:
        print("[ERROR] Debes especificar el archivo de request")
        print("Uso: python3 main.py <archivo_request.txt> [--recheck]")
        print("Ejemplo: python3 main.py example_request.txt")
        print("Ejemplo: python3 main.py example_request.txt --recheck")
        return
    
    # Obtener archivo de request desde argumentos
    request_file = sys.argv[1]
    payload_file = 'payloads.txt'  # Siempre usar payloads.txt por defecto
    
    # Verificar si se habilitó recheck
    enable_recheck = '--recheck' in sys.argv
    
    # Verificar que el archivo de request existe
    if not os.path.exists(request_file):
        print(f"[ERROR] El archivo '{request_file}' no existe")
        return
    
    # Verificar que el archivo de payloads existe
    if not os.path.exists(payload_file):
        print(f"[ERROR] El archivo '{payload_file}' no existe")
        return
    
    # Verificar API key
    if not os.getenv("OPENAI_API_KEY"):
        print("[ERROR] OPENAI_API_KEY no encontrada en variables de entorno")
        print("Crea un archivo .env con: OPENAI_API_KEY=tu_api_key")
        return

    print(f"[REQUEST] Archivo: {request_file}")
    print(f"[PAYLOADS] Archivo: {payload_file}")
    if enable_recheck:
        print(f"[RECHECK] Habilitado")

    # Crear scanner
    scanner = SQLInjectionScanner(enable_recheck=enable_recheck)

    # Ejecutar scan
    result = scanner.scan_for_sql_injection(
        request_file=request_file,
        payload_file=payload_file
    )

    # Guardar resultado
    with open('sql_injection_report.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    # Mostrar resumen
    if result['vulnerabilities_found'] > 0:
        print(f"\n[VULNERABILIDADES] DETECTADAS: {result['vulnerabilities_found']}")
        for vuln in result['vulnerabilities']:
            print(f"  - Parámetro: {vuln['parameter']}")
            print(f"    Payload: {vuln['payload']}")
            print(f"    Confianza: {vuln['confidence']}")
            print(f"    URL: {vuln['url']}")
    else:
        print(f"\n[SEGURO] No se detectaron vulnerabilidades SQL injection")
        print(f"   Estado: {result['status']}")

    print(f"Tiempo de ejecución: {result['execution_time']} segundos")
    print(f"Reporte guardado en: sql_injection_report.json")

if __name__ == "__main__":
    main() 