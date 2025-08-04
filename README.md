# SQL Injection Error-Based Agent

Agente autónomo en Python para detectar vulnerabilidades SQL Injection (Error-Based) con recheck inteligente usando OpenAI.

## Características

- ✅ **Input:** Toma requests HTTP raw desde archivo `.txt`
- ✅ **Identificación:** Detecta parámetros injectables automáticamente
- ✅ **Payloads:** Usa payloads desde archivo externo `payloads.txt`
- ✅ **Análisis:** Analiza respuestas con detección manual + OpenAI (se utiliza un análisis manual y un análisis con LLM)
- ✅ **Detección:** Identifica errores SQL injection específicos
- ✅ **Recheck:** Confirmación inteligente con payloads específicos por motor de BD (opcional recheck, esto puede ayudar si solo un análisis lo confirma)
- ✅ **Optimización:** Detiene el análisis si se considera vulnerable
- ✅ **Output:** Genera reporte JSON detallado

## Arquitectura:

- `main.py` - Script principal y orquestador
- `http_parser.py` - Parsing de requests HTTP y manejo de payloads
- `manual_detector.py` - Detección manual con regex patterns
- `openai_detector.py` - Detección usando OpenAI
- `recheck_detector.py` - Recheck inteligente con payloads específicos por motor

## Configuración

### 1. Clonar el repositorio
```bash
# Clonar el repositorio
git clone <url_del_repositorio>
cd sqli_error_agent
```

### 2. Crear entorno virtual
```bash
# Crear el entorno virtual
python3 -m venv venv

# Activar el entorno virtual
source venv/bin/activate
```

### 3. Instalar dependencias
```bash
# Instalar las dependencias del proyecto
pip install -r requirements.txt
```

### 4. Configurar variables de entorno
```bash
# Copiar el archivo de ejemplo
cp env.example .env

# Editar el archivo .env con tu API key
vi .env
```

Contenido del archivo `.env`:
```
OPENAI_API_KEY=tu_api_key_aqui
OPENAI_MODEL=gpt-4o-mini
REQUEST_TIMEOUT=10
CONFIDENCE_THRESHOLD=0.7
```

### 5. Activar entorno virtual (en futuras sesiones)
```bash
source venv/bin/activate
```

## Uso

```bash
# Scan básico
python3 main.py example_request.txt

# Scan con recheck habilitado
python3 main.py example_request.txt --recheck
```

## Ejemplo de Request

```
GET /artists.php?artist=1 HTTP/1.1
Host: testphp.vulnweb.com
User-Agent: Mozilla/5.0
Accept: */*
```

## Recheck Inteligente (OpenAI)

Es recheck opcional analiza la response y:
- Identifica el motor de base de datos (MySQL, PostgreSQL, Oracle, SQL Server)
- Sugiere payloads específicos para cada motor
- Confirma la vulnerabilidad con un segundo test

## Reporte JSON

El agente genera un reporte JSON con:
- Timestamp de ejecución
- Payload utilizado
- URL objetivo y parámetros disponibles
- Resultados del recheck (si está habilitado)
- Tiempo de ejecución y estado del servidor
