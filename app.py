from flask import Flask, request, jsonify
from pymongo import MongoClient
import datetime
import sys
from functools import wraps
import os
from dotenv import load_dotenv
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS

# --- Carrega variáveis de ambiente do arquivo .env ---
load_dotenv()

# --- Configuração da Aplicação Flask ---
app = Flask(__name__, static_url_path='/static', static_folder='static')
CORS(app)

# =================================================================
#           CONFIGURAÇÃO SWAGGER/OPENAPI
# =================================================================
# (Este bloco assume que 'static/swagger.yaml' foi atualizado
# com a definição unificada para /logs.)
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.yaml'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL, API_URL, config={'app_name': "Deltabots Unified Log API"}
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# --- Configuração de Segurança ---
REAL_API_KEY = os.getenv('API_KEY', 'CHAVE_PADRAO_EM_CASO_DE_FALHA_NAO_SEGURA')
if REAL_API_KEY == 'CHAVE_PADRAO_EM_CASO_DE_FALHA_NAO_SEGURA':
    print("AVISO: API_KEY não carregada do .env. Usando chave insegura. VERIFIQUE SEU .env!")

def require_api_key(view_function):
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({
                "error": "Acesso negado",
                "message": "Header 'X-API-Key' ausente na requisição."
            }), 401
        if api_key != REAL_API_KEY:
            return jsonify({
                "error": "Acesso negado",
                "message": "Chave de API inválida."
            }), 403
        return view_function(*args, **kwargs)
    return decorated_function


# --- Configuração do MongoDB ---
MONGO_URI = os.getenv('MONGO_URI', "mongodb://mongo:09fd25324780e7342779@116.203.134.255:27017/?tls=false")
DB_NAME = "deltabots_logs" 
RPA_COLLECTION_NAME = "rpa_events" # Coleção para logs RPA
IPAAS_COLLECTION_NAME = "ipaas_events" # Coleção para logs iPaaS

# Variáveis globais para coleções
rpa_collection = None
ipaas_collection = None
client = None

# --- Inicializa a Conexão com o MongoDB ---
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client[DB_NAME]
    
    # As coleções são "inicializadas" como referências.
    # O MongoDB só as cria ao receber a primeira inserção.
    rpa_collection = db[RPA_COLLECTION_NAME] 
    ipaas_collection = db[IPAAS_COLLECTION_NAME]
    
    print(f"Conectado ao MongoDB em {DB_NAME} com sucesso!", file=sys.stdout)
    print(f" - Coleção RPA: {RPA_COLLECTION_NAME}", file=sys.stdout)
    print(f" - Coleção iPaaS: {IPAAS_COLLECTION_NAME}", file=sys.stdout)
except Exception as e:
    print(f"ERRO CRÍTICO: Não foi possível conectar ao MongoDB.", file=sys.stderr)
    print(f"Erro: {e}", file=sys.stderr)
    client = None


# =================================================================
#              FUNÇÃO AUXILIAR DE PARSE DE DATA
# =================================================================
def parse_date(date_str):
    """
    Tenta converter uma string ISO 8601 em um objeto datetime (naive UTC).
    """
    if not date_str:
        return None, False
    try:
        # Tenta parsear com timezone
        dt = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        # Converte para naive UTC (necessário se o mongo armazena naive)
        dt_utc = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        
        # Verifica se o tempo foi fornecido (ou seja, não é apenas YYYY-MM-DD)
        time_provided = dt.hour != 0 or dt.minute != 0 or dt.second != 0 or dt.microsecond != 0
        return dt_utc, time_provided
    except ValueError:
        try:
            # Tenta parsear apenas a data
            dt = datetime.datetime.strptime(date_str, '%Y-%m-%d')
            return dt, False 
        except ValueError:
            return None, False

# =================================================================
#                 ROTA UNIFICADA DE LOGS (POST)
# =================================================================

@app.route('/logs', methods=['POST'])
@require_api_key
def receive_unified_log():
    """Recebe e armazena um log (RPA ou iPaaS) baseado no campo 'type'."""
    if rpa_collection is None or ipaas_collection is None:
        return jsonify({"error": "Serviço indisponível. Conexão com o banco de dados falhou."}), 503

    try:
        data = request.json
        log_type = data.get('type')

        if not log_type:
            return jsonify({"error": "Requisição inválida.", "message": "O campo 'type' é obrigatório no JSON ('rpa' ou 'ipaas')."}), 400

        log_type = str(log_type).lower() 
        log_document = {
            "timestamp_utc": datetime.datetime.utcnow(),
            "source_ip": request.remote_addr,
            "log_type": log_type # Adiciona o tipo ao documento para referência
        }

        if log_type == 'rpa':
            # --- Lógica para RPA ---
            if 'message' not in data or 'level' not in data:
                return jsonify({
                    "error": "Requisição inválida para type='rpa'.",
                    "message": "Logs do tipo 'rpa' devem conter 'level' e 'message'."
                }), 400
            
            log_document['level'] = data.get('level')
            log_document['message'] = data.get('message')
            collection_to_insert = rpa_collection

        elif log_type == 'ipaas':
            # --- Lógica para iPaaS ---
            if 'ipaas_codigo' not in data or 'data' not in data:
                 return jsonify({
                     "error": "Requisição inválida para type='ipaas'.",
                     "message": "Logs do tipo 'ipaas' devem conter 'ipaas_codigo' e 'data'."
                 }), 400

            ipaas_codigo = data.get('ipaas_codigo')
            execution_data = data.get('data')

            if not isinstance(ipaas_codigo, str) or not ipaas_codigo:
                 return jsonify({"error": "Requisição inválida.", "message": "'ipaas_codigo' deve ser uma string não vazia."}), 400
            if not isinstance(execution_data, dict):
                 # Permite que 'data' seja vazio, mas deve ser um objeto.
                 pass 

            log_document['ipaas_codigo'] = ipaas_codigo
            log_document['execution_details'] = execution_data
            collection_to_insert = ipaas_collection

        else:
            return jsonify({"error": "Tipo de log inválido.", "message": "O campo 'type' deve ser 'rpa' ou 'ipaas'."}), 400

    except Exception as e:
        print(f"Erro no processamento da requisição POST /logs: {e}", file=sys.stderr)
        return jsonify({"error": "Corpo da requisição não é um JSON válido ou erro interno."}), 400

    # --- Inserção: PyMongo cria a collection se ela não existir ---
    try:
        result = collection_to_insert.insert_one(log_document)
        return jsonify({
            "status": "sucesso",
            "log_type_processed": log_type,
            "log_id": str(result.inserted_id)
        }), 201
    except Exception as e:
        print(f"Erro ao inserir log (tipo: {log_type}) no MongoDB: {e}", file=sys.stderr)
        return jsonify({"error": "Falha ao escrever no banco de dados.", "details": str(e)}), 500


# =================================================================
#                 ROTA UNIFICADA DE LOGS (GET)
# =================================================================

@app.route('/logs', methods=['GET'])
@require_api_key
def get_unified_logs():
    """Busca logs (RPA ou iPaaS) baseado no parâmetro de query 'type'."""
    log_type = request.args.get('type')

    if not log_type:
        return jsonify({"error": "Parâmetro ausente.", "message": "O parâmetro de query 'type' é obrigatório ('rpa' ou 'ipaas')."}), 400

    log_type = str(log_type).lower()

    if log_type == 'rpa':
        collection_to_query = rpa_collection
        code_filter_key = "robo_codigo"
        code_db_field = "message.summary.robo_codigo"
        if collection_to_query is None:
             return jsonify({"error": "Serviço indisponível (RPA). Conexão com o banco de dados falhou."}), 503
    elif log_type == 'ipaas':
        collection_to_query = ipaas_collection
        code_filter_key = "ipaas_codigo"
        code_db_field = "ipaas_codigo"
        if collection_to_query is None:
             return jsonify({"error": "Serviço indisponível (iPaaS). Conexão com o banco de dados falhou."}), 503
    else:
        return jsonify({"error": "Tipo de log inválido.", "message": "O parâmetro 'type' deve ser 'rpa' ou 'ipaas'."}), 400

    # --- Lógica de Filtros ---
    code_filter_value = request.args.get(code_filter_key)
    data_inicio_str = request.args.get('data_inicio')
    data_fim_str = request.args.get('data_fim')

    query = {}
    applied_filters = {"type": log_type}

    if code_filter_value:
        query[code_db_field] = code_filter_value
        applied_filters[code_filter_key] = code_filter_value

    # --- Aplicar Filtros de Data ---
    date_query = {}
    if data_inicio_str:
        applied_filters["data_inicio"] = data_inicio_str
        data_inicio, time_provided = parse_date(data_inicio_str)
        if data_inicio:
            date_query['$gte'] = data_inicio
        else:
            return jsonify({"error": f"Formato de data inválido para 'data_inicio'."}), 400

    if data_fim_str:
        applied_filters["data_fim"] = data_fim_str
        data_fim, time_provided = parse_date(data_fim_str)
        if data_fim:
            if not time_provided:
                data_fim_end_of_day = data_fim + datetime.timedelta(days=1)
                date_query['$lt'] = data_fim_end_of_day
            else:
                date_query['$lte'] = data_fim
        else:
            return jsonify({"error": f"Formato de data inválido para 'data_fim'."}), 400

    if date_query:
        query["timestamp_utc"] = date_query

    # --- Consulta ao Banco de Dados ---
    try:
        logs_cursor = collection_to_query.find(query).limit(100).sort("timestamp_utc", -1)
        results = []
        for log in logs_cursor:
            log['_id'] = str(log['_id'])
            # Formata a data de volta para ISO 8601 com 'Z' (UTC)
            if isinstance(log.get('timestamp_utc'), datetime.datetime):
                log['timestamp_utc'] = log['timestamp_utc'].isoformat() + "Z"
            results.append(log)

        return jsonify({
            "status": "sucesso",
            "total_resultados": len(results),
            "filtros_aplicados": applied_filters,
            "logs": results
        }), 200

    except Exception as e:
        print(f"Erro ao consultar logs ({log_type}) no MongoDB: {e}", file=sys.stderr)
        return jsonify({"error": "Falha ao consultar o banco de dados.", "details": str(e)}), 500


# =================================================================
#                 ROTA DE HEALTH CHECK
# =================================================================
@app.route('/', methods=['GET'])
def health_check():
    """Verifica se a API está no ar."""
    # Verifica a conexão com o cliente
    db_status = "conectado" if client is not None else "desconectado"
    # Se a conexão inicial falhou, o client será None.
    if db_status == "conectado":
        try:
            # Tenta uma operação leve para reconfirmar (ex: obter nomes das coleções)
            client.admin.command('ping') 
        except Exception:
            db_status = "desconectado"
            
    return jsonify({
        "current_time": datetime.datetime.now().isoformat(),
        "api_status": "operacional",
        "mongodb_status": db_status
        }), 200

# --- Execução do Servidor ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"\n===============================================================")
    print(f" SERVIDOR FLASK INICIADO NA PORTA: {port}")
    print(f" DOCUMENTAÇÃO SWAGGER/OPENAPI DISPONÍVEL EM: /swagger")
    print(f" ROTAS UNIFICADAS: /logs (POST e GET) - use o parâmetro 'type'")
    print(f"===============================================================\n")
    app.run(host='0.0.0.0', port=port)
