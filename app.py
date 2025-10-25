from flask import Flask, request, jsonify
from pymongo import MongoClient
import datetime
import sys
from functools import wraps
import yaml
import os
from dotenv import load_dotenv
from flask_swagger_ui import get_swaggerui_blueprint
# Importação da biblioteca Flask-CORS
from flask_cors import CORS 

# --- Carrega variáveis de ambiente do arquivo .env ---
# Garantir que o .env seja carregado
load_dotenv() 

# --- Configuração da Aplicação Flask ---
app = Flask(__name__, static_url_path='/static', static_folder='static') # Garante que a pasta static seja reconhecida

# --- CONFIGURAÇÃO CORS ---
# Inicializa o CORS na aplicação para permitir requisições de qualquer origem.
# Se precisar restringir a origens específicas, use: CORS(app, resources={r"/*": {"origins": ["http://seu-dominio.com"]}})
CORS(app)


# =================================================================
#            CONFIGURAÇÃO SWAGGER/OPENAPI 
# =================================================================

# Carrega a especificação OpenAPI diretamente do arquivo estático
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.yaml' # Assumimos que static/swagger.yaml existe no repositório

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Deltabots RPA Log API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)


# --- Configuração de Segurança ---
# Lendo a chave de API da variável de ambiente
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
DB_NAME = "deltabots_rpa_logs"  
COLLECTION_NAME = "events"       

# --- Inicializa a Conexão com o MongoDB ---
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()  
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    print(f"Conectado ao MongoDB em {DB_NAME}.{COLLECTION_NAME} com sucesso!", file=sys.stdout)
except Exception as e:
    print(f"ERRO CRÍTICO: Não foi possível conectar ao MongoDB.", file=sys.stderr)
    print(f"Erro: {e}", file=sys.stderr)
    client = None
    collection = None

# =================================================================
#                FUNÇÃO AUXILIAR DE PARSE DE DATA
# =================================================================

def parse_date(date_str):
    """
    Tenta converter uma string ISO 8601 em um objeto datetime.
    Retorna o objeto datetime e um flag indicando se o tempo foi fornecido.
    """
    if not date_str:
        return None, False
    try:
        # 1. Tenta parsear a string completa (com tempo)
        dt = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt, dt.hour != 0 or dt.minute != 0 or dt.second != 0 or dt.microsecond != 0
    except ValueError:
        try:
            # 2. Tenta parsear apenas a data (sem tempo)
            dt = datetime.datetime.strptime(date_str, '%Y-%m-%d')
            return dt, False # Tempo não foi fornecido
        except ValueError:
            return None, False

# =================================================================
#                ROTAS DA API
# =================================================================

@app.route('/logs', methods=['GET'])
@require_api_key
def get_logs():
    """Implementação da rota GET /logs."""
    if collection is None:
        return jsonify({"error": "Serviço indisponível. Conexão com o banco de dados falhou."}), 503
    
    # 1. Obter Filtros
    robo_codigo_filter = request.args.get('robo_codigo')
    data_inicio_str = request.args.get('data_inicio')
    data_fim_str = request.args.get('data_fim')
    
    query = {}
    
    if robo_codigo_filter:
        query["message.summary.robo_codigo"] = robo_codigo_filter
        
    # 2. Aplicar Filtros de Data
    date_query = {}
    
    if data_inicio_str:
        data_inicio, time_provided = parse_date(data_inicio_str)
        if data_inicio:
            date_query['$gte'] = data_inicio
        else:
            return jsonify({"error": "Formato de data inválido para 'data_inicio'. Use YYYY-MM-DD ou YYYY-MM-DDTHH:MM:SS."}), 400

    if data_fim_str:
        data_fim, time_provided = parse_date(data_fim_str)
        if data_fim:
            if not time_provided:
                # Se apenas a data foi fornecida, queremos logs até o final daquele dia.
                data_fim = data_fim + datetime.timedelta(days=1)
                date_query['$lt'] = data_fim # Usa $lt para pegar até o início do próximo dia
            else:
                date_query['$lte'] = data_fim # Usa $lte para o exato timestamp
        else:
            return jsonify({"error": "Formato de data inválido para 'data_fim'. Use YYYY-MM-DD ou YYYY-MM-DDTHH:MM:SS."}), 400
    
    if date_query:
        query["timestamp_utc"] = date_query

    try:
        print(f"MongoDB Query: {query}")
        
        logs_cursor = collection.find(query).limit(100).sort("timestamp_utc", -1)
        
        results = []
        for log in logs_cursor:
            log['_id'] = str(log['_id'])
            if isinstance(log['timestamp_utc'], datetime.datetime):
                log['timestamp_utc'] = log['timestamp_utc'].isoformat() 
            
            results.append(log)
            
        return jsonify({
            "status": "sucesso",
            "total_resultados": len(results),
            "filtros_aplicados": {
                "robo_codigo": robo_codigo_filter,
                "data_inicio": data_inicio_str,
                "data_fim": data_fim_str
            },
            "logs": results
        }), 200
        
    except Exception as e:
        print(f"Erro ao consultar o MongoDB: {e}", file=sys.stderr)
        return jsonify({"error": "Falha ao consultar o banco de dados.", "details": str(e)}), 500


@app.route('/log', methods=['POST'])
@require_api_key
def receive_log():
    """Implementação da rota POST /log."""
    if collection is None:
        return jsonify({"error": "Serviço indisponível. Conexão com o banco de dados falhou."}), 503

    try:
        data = request.json
        if not data or 'message' not in data or 'level' not in data:
              return jsonify({
                  "error": "Requisição inválida.", 
                  "message": "O JSON deve ser um documento contendo as chaves 'message' (o log) e 'level' (o status)."
              }), 400
    except Exception:
        return jsonify({"error": "Corpo da requisição não é um JSON válido."}), 400

    log_message = data.get('message')
    log_level = data.get('level') 
    
    log_document = {
        "timestamp_utc": datetime.datetime.utcnow(), 
        "source_ip": request.remote_addr,  
        "level": log_level,
        "message": log_message
    }

    try:
        result = collection.insert_one(log_document)
        return jsonify({
            "status": "sucesso",  
            "log_id": str(result.inserted_id)
        }), 201
    except Exception as e:
        print(f"Erro ao inserir no MongoDB: {e}", file=sys.stderr)
        return jsonify({"error": "Falha ao escrever no banco de dados."}), 500

@app.route('/', methods=['GET'])
def health_check():
    """Verifica se a API está no ar."""
    return jsonify({"status": "API de Logs está operacional"}), 200

# --- Execução do Servidor ---
if __name__ == '__main__':
    # Obtém a porta do ambiente (padrão EasyPanel/Nixpacks) ou usa 5000 como fallback.
    port = int(os.environ.get("PORT", 5000)) 
    
    # Esta seção de criação de arquivo foi removida para garantir que o container não falhe por permissão
    # O arquivo static/swagger.yaml deve ser fornecido no seu deploy.
    
    print(f"\n===============================================================")
    print(f" SERVIDOR FLASK INICIADO NA PORTA: {port}")
    print(f" DOCUMENTAÇÃO SWAGGER/OPENAPI DISPONÍVEL EM: /swagger")
    print(f"===============================================================\n")

    # Inicia o servidor usando a porta do ambiente
    app.run(host='0.0.0.0', port=port)
