import os
import re
import json
import time
import uuid
import logging
import hashlib
import redis
import jwt
import psycopg2
import psycopg2.extras
import requests
from psycopg2 import pool
from decimal import Decimal
from datetime import date, datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from dotenv import load_dotenv

load_dotenv("/app/.env")
# ==============================================================================
# 1. CONFIGURAÇÃO INICIAL E AMBIENTE
# ==============================================================================
load_dotenv()
app = Flask(__name__)

# Logs estruturados
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s'
)
logger = logging.getLogger("SQLBot")

# Desabilita warnings de SSL inseguro (apenas se necessário, ideal é corrigir o certificado)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurações de Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# Configurações de IA
IA_URL = os.getenv("IA_URL")
MODEL_NAME = "llama-4-maverick"
IA_TIMEOUT = 45

CORS(app, resources={r"/*": {"origins": "*"}})

# Configurações de Banco de Dados (Connection Pool)
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
MIN_CONN = 1
MAX_CONN = 20

# Criação do Pool de Conexões (Crucial para performance)
try:
    pg_pool = psycopg2.pool.ThreadedConnectionPool(
        MIN_CONN, MAX_CONN,
        host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASS
    )
    logger.info("Connection Pool do PostgreSQL iniciado com sucesso.")
except Exception as e:
    logger.critical(f"Falha ao criar Pool de Conexão: {e}")
    exit(1)

# Configurações JWT
JWT_SECRET = os.getenv("JWT_SECRET", "default_secret_change_me")
JWT_ALGORITHM = "HS256"

# Rate Limiting
RATE_LIMIT_WINDOW = 10
RATE_LIMIT_MAX = 5

# Whitelist de Tabelas (Segurança)
ALLOWED_TABLES = {
    "auth_user", "seletivo_userdata", "seletivo_address", 
    "seletivo_guardian", "student_data_studentdata",
    "seletivo_exam", "seletivo_process", 
    "seletivo_examlocal", "seletivo_examdate", "seletivo_examhour",
    "seletivo_registrationdata", "candidate_candidatedocument", 
    "seletivo_academicmeritdocument", "candidate_quota",
    "faq", "tenant_city"
}

# ==============================================================================
# 2. FUNÇÕES UTILITÁRIAS E SEGURANÇA
# ==============================================================================

def get_db_connection():
    """Obtém conexão do Pool."""
    return pg_pool.getconn()

def release_db_connection(conn):
    """Devolve conexão ao Pool."""
    if conn:
        pg_pool.putconn(conn)

def normalize_value(v):
    if isinstance(v, Decimal): return float(v)
    if isinstance(v, (datetime, date)): return v.isoformat()
    if isinstance(v, uuid.UUID): return str(v)
    return v

def clean_sql(sql_text: str) -> str:
    """Limpa formatação Markdown do SQL."""
    sql = re.sub(r'```sql|```', '', sql_text, flags=re.IGNORECASE).strip()
    return sql.split(';')[0].strip() # Remove múltiplos comandos

def is_safe_sql(sql: str, tenant_id: str, is_admin: bool) -> bool:
    """Validação de segurança para impedir comandos destrutivos."""
    sql_clean = " ".join(sql.split())
    sql_upper = sql_clean.upper()
    
    if not sql_upper.startswith("SELECT"):
        return False
        
    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "GRANT", "EXEC", "pg_sleep"]
    if any(re.search(rf"\b{cmd}\b", sql_upper) for cmd in forbidden):
        return False

    if not is_admin:
        # Verifica se o tenant_id do usuário aparece no WHERE do SQL
        if f"'{tenant_id}'" not in sql:
            logger.warning(f"⛔ BLOQUEIO: Tentativa de burlar filtro de tenant. SQL: {sql}")
            return False

    # Remove funções inofensivas para verificar tabelas
    check_sql = re.sub(r"(EXTRACT|SUBSTRING|TRIM|COALESCE)\s*\(.*?\)", "", sql_clean, flags=re.IGNORECASE)
    
    tables_found = re.findall(r"(?i)\b(?:FROM|JOIN)\s+([a-z0-9_]+)", check_sql)
    sql_reserved = {'lateral', 'unnest', 'select', 'current_date', 'values', 'distinct', 'as', 'on', 'where', 'limit', 'group', 'order', 'left', 'right', 'inner', 'outer', 'join'}
    
    tables_to_validate = [t.lower() for t in tables_found if t.lower() not in sql_reserved]
    
    if not tables_to_validate:
        return False 

    for tbl in tables_to_validate:
        if tbl not in ALLOWED_TABLES:
            logger.warning(f"⛔ BLOQUEIO: Tabela '{tbl}' não permitida.")
            return False

    return True

# Configuração da Sessão HTTP com Retry
session = requests.Session()
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))

def call_ai_service(messages, temperature=0.1):
    """Chamada robusta à API de IA."""
    try:
        payload = {
            "model": MODEL_NAME,
            "messages": messages,
            "temperature": temperature
        }
        # Verify=False apenas se o certificado do mycoach for auto-assinado. 
        # Em prod, tente resolver o certificado e usar verify=True.
        response = session.post(IA_URL, json=payload, verify=False, timeout=IA_TIMEOUT)
        
        if response.status_code != 200:
            logger.error(f"Erro API IA: {response.status_code} - {response.text}")
            return None

        body = response.json()
        return body['choices'][0]['message']['content']

    except Exception as e:
        logger.error(f"Exceção na chamada IA: {str(e)}")
        return None

def classify_intent(user_msg):
    """
    Analisa se a mensagem requer uma consulta SQL ao banco de dados.
    Retorna: True (é SQL) ou False (é papo furado/ajuda/data atual).
    """
    
    # 1. Regra rápida para saudações curtas (economia de token)
    greetings = ['oi', 'olá', 'bom dia', 'boa tarde', 'boa noite', 'ajuda', 'help', 'quem é você']
    if user_msg.lower().strip() in greetings:
        return False

    # 2. Análise via IA
    prompt = f"""
    Atue como um classificador de intenção. Analise a mensagem do usuário.
    Responda APENAS com um JSON válido: {{"is_sql": true}} ou {{"is_sql": false}}.

    Regras:
    - Se o usuário pedir dados, contagens, listas, informações de cadastro -> is_sql: true
    - Se o usuário cumprimentar, perguntar data/hora atual, pedir ajuda, ou falar de coisas fora do contexto de 'sistema de gestão' -> is_sql: false
    - "Que dia é hoje?" -> is_sql: false (isso é conhecimento geral)
    - "Qual a data da prova?" -> is_sql: true (isso é dado do banco)

    Mensagem: "{user_msg}"
    """
    
    response = call_ai_service([{"role": "system", "content": prompt}], temperature=0.0)
    
    try:
        # Tenta limpar markdown caso a IA coloque ```json
        clean_resp = response.replace("```json", "").replace("```", "").strip()
        data = json.loads(clean_resp)
        return data.get("is_sql", True) # Na dúvida, assume que é SQL
    except:
        return True # Fallback seguro

def execute_sql_with_autocorrect(conn, initial_sql, user_msg, system_prompt_base, tenant_id, is_admin):
    """
    Tenta executar o SQL. Se der erro no Postgres, devolve o erro para a IA
    e pede uma correção (máximo de 2 tentativas de correção).
    """
    current_sql = initial_sql
    max_retries = 2 
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            # TENTATIVA DE EXECUÇÃO
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(current_sql)
                # Se funcionar, converte e retorna
                rows = [dict((k, normalize_value(v)) for k, v in r.items()) for r in cur.fetchall()]
                
                # Se corrigiu, logamos para monitoria
                if attempt > 0:
                    logger.info(f"✅ SQL Auto-corrigido com sucesso na tentativa {attempt}")
                
                return rows, current_sql

        except psycopg2.Error as db_err:
            # OBRIGATÓRIO: Fazer rollback para limpar a transação falha
            conn.rollback()
            last_error = db_err
            
            if attempt == max_retries:
                logger.error(f"❌ Falha Final após {max_retries} tentativas. Erro: {db_err}")
                break # Sai do loop e vai lançar o erro
            
            logger.warning(f"⚠️ Erro SQL (Tentativa {attempt+1}/{max_retries + 1}): {db_err}. Solicitando correção à IA...")

            # --- PROMPT DE CORREÇÃO (A Mágica) ---
            # Passamos o histórico: Prompt Original + Pergunta + SQL Errado + Mensagem de Erro
            repair_messages = [
                {"role": "system", "content": system_prompt_base},
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": current_sql},
                {"role": "user", "content": f"ERRO CRÍTICO NO BANCO: {db_err}\n\nAnalise o erro. Corrija a sintaxe SQL imediatamente. Retorne APENAS o SQL corrigido, sem explicações."}
            ]

            # Chama a IA com temperatura 0 (máxima precisão)
            fixed_sql_raw = call_ai_service(repair_messages, temperature=0.0)
            
            if not fixed_sql_raw:
                break # Se a IA cair, para tudo

            current_sql = clean_sql(fixed_sql_raw)

            # Validação de segurança novamente (vai que a IA alucina um DROP na correção)
            if not is_safe_sql(current_sql, tenant_id, is_admin):
                logger.warning("⛔ Correção gerou SQL inseguro. Abortando.")
                break

    # Se saiu do loop, falhou
    raise last_error

def analyze_context_relevance(user_msg, context):
    """
    Decide o destino da conversa: Refinamento (True) ou Nova Busca (False).
    Usa análise léxica (Python) + análise semântica (IA).
    """
    if not context:
        return False

    msg = user_msg.lower().strip()

    reset_triggers = [
        # Comandos Explícitos
        "nova busca", "novo filtro", "limpar", "limpar filtro", "esquece", 
        "começar de novo", "do zero", "resetar", "apagar",
        
        # Verbos de Ação (Geralmente iniciam frases de busca)
        "listar", "lista", "listagem", 
        "buscar", "busque", "procurar", "procure", 
        "pesquisar", "pesquise", "encontrar", "encontre",
        "traz", "traga", "mostre todos", "mostrar todos",
        "quem é", "quem são", "quais são", # Ex: "Quem é o aluno X?" (Geralmente é busca direta)
        
        # Mudança de Sujeito / Intenção
        "agora quero", "agora busca", "muda para", "troca para",
        "quero ver", "gostaria de saber", "preciso saber",
        
        # Generalizações (Quebram filtros específicos anteriores)
        "todos os", "todas as", "tudo", "geral", "banco todo"
    ]

    continuation_triggers = [
        # Pronomes (A chave principal)
        "dele", "dela", "deles", "delas", "ele", "ela", "eles", "elas",
        "desse", "dessa", "desses", "dessas",
        "este", "esta", "estes", "estas",
        "ele", "ela", "eles", "elas",
        "o mesmo", "a mesma",
        
        # Conectivos Aditivos
        "e o", "e a", "e os", "e as", # Ex: "E o telefone?"
        "também", "alem disso", "incluindo", "com", "sem",
        
        # Pedidos de Detalhes (Colunas comuns)
        "telefone", "celular", "email", "e-mail", "endereço", "cpf", 
        "data", "nascimento", "idade", "nome completo", "status",
        "nota", "pontuação", "resultado",
        
        # Filtros e Ordenação
        "filtre", "filtra", "filtrar",
        "ordene", "ordena", "ordenar", "classifique",
        "agrupe", "agrupa",
        "apenas", "somente", "só os", "só as", "tire", "remova",
        "mais recente", "mais antigo", "maior", "menor", "melhor", "pior",
        "primeiro", "último",
        
        # Agregações / Quantidade (Onde você teve erro antes)
        "quantos", "quantas", "qual o total", "total", 
        "contagem", "são quantos", "numero de", "quantidade",
        "resuma", "resumo", "media"
    ]
    
    # 1. VERIFICAÇÃO DE RESET (Prioridade Alta)
    # Se o usuário mandou "Listar todos", não importa se tem "dele" no meio, é reset.
    if any(msg.startswith(t) for t in reset_triggers):
        logger.info(f"🧹 Contexto RESETADO por gatilho de início: '{user_msg}'")
        return False
        
    # Verificação de reset no meio da frase (menos rígida)
    # Ex: "Não, agora busca por X"
    if any(f" {t} " in f" {msg} " for t in ["nova busca", "esquece", "do zero", "listar todos"]):
        logger.info(f"🧹 Contexto RESETADO por gatilho interno: '{user_msg}'")
        return False

    # 2. VERIFICAÇÃO DE CONTINUAÇÃO (Economia de Token)
    # Se a frase for curta (< 15 palavras) e tiver gatilho claro, aprova direto.
    is_short = len(msg.split()) < 15
    has_continuation = any(t in msg for t in continuation_triggers)
    
    if is_short and has_continuation:
        logger.info(f"⚡ Contexto MANTIDO por gatilho rápido: '{user_msg}'")
        return True

    # 3. ANÁLISE SEMÂNTICA (IA) - O Desempate
    # Se não caiu em nenhum gatilho óbvio, a IA decide.
    last_msg = context.get('last_message', '')
    last_sql = context.get('last_sql', '')

    prompt = f"""
    Classifique a intenção para SQL.
    
    [HISTÓRICO]
    Busca Anterior: "{last_msg}"
    SQL Anterior: {last_sql}
    
    [NOVA PERGUNTA]
    User: "{user_msg}"
    
    [REGRA]
    Responda JSON {{"is_related": true}} SE:
    - É um detalhamento ("e o telefone?", "qual o cpf?").
    - É um filtro sobre o resultado ATUAL ("só os aprovados", "quem tirou zero").
    - É uma agregação ("quantos são?", "qual a média?").
    
    Responda JSON {{"is_related": false}} SE:
    - Muda o foco principal (ex: estava vendo 'alunos', agora pede 'financeiro').
    - Muda o sujeito da busca (ex: buscou 'João', agora pede 'Maria').
    - Parece uma nova consulta independente.
    
    Na dúvida, FALSE (Melhor pecar por segurança e fazer nova busca).
    """

    response = call_ai_service([{"role": "system", "content": prompt}], temperature=0.0)
    
    try:
        clean_resp = response.replace("```json", "").replace("```", "").strip()
        data = json.loads(clean_resp)
        return data.get("is_related", False)
    except:
        return False

# ==============================================================================
# 3. GESTÃO DE ESTADO (REDIS)
# ==============================================================================

def rate_limit(tenant_id: str, user_id: int):
    key = f"rate:chat:{tenant_id}:{user_id}"
    current = redis_client.incr(key)
    if current == 1:
        redis_client.expire(key, RATE_LIMIT_WINDOW)
    return current <= RATE_LIMIT_MAX

def get_user_is_admin(user_id: int):
    """Verifica se é admin com cache."""
    cache_key = f"user:admin:{user_id}"
    cached = redis_client.get(cache_key)
    if cached: return cached == "1"

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(is_superuser, false) OR COALESCE(is_staff, false) FROM auth_user WHERE id = %s", (user_id,))
            res = cur.fetchone()
            is_admin = bool(res[0]) if res else False
    finally:
        release_db_connection(conn)

    redis_client.setex(cache_key, 300, "1" if is_admin else "0")
    return is_admin

def get_user_name_from_db(user_id):
    """Busca o nome do usuário para dar contexto à IA no chat geral."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT first_name FROM auth_user WHERE id = %s", (user_id,))
            res = cur.fetchone()
            return res[0] if res else "usuário"
    except:
        return "usuário"
    finally:
        release_db_connection(conn)

def set_chat_context(user_id, message, sql, rows):
    """Salva o contexto para permitir perguntas de seguimento."""
    key = f"chat:context:{user_id}"
    context = {
        "last_message": message,
        "last_sql": sql,  # Guardamos o SQL para refinamento
        "row_count": len(rows),
        "preview": rows[:10]
    }
    redis_client.setex(key, 400, json.dumps(context, ensure_ascii=False))

def get_chat_context(user_id):
    data = redis_client.get(f"chat:context:{user_id}")
    return json.loads(data) if data else None

# ==============================================================================
# 4. PROMPT ENGINEERING (A Mágica)
# ==============================================================================

def get_system_prompt(user_id, tenant_id, is_admin, limit_value, previous_sql=None):
    if is_admin:
        privacy_filter = "1=1"
        admin_note = "ADMIN: Pode ver todos os tenants. NÃO filtre tenant_city_id."
    else:
        privacy_filter = f"u.tenant_city_id = '{tenant_id}' AND u.id = {user_id}"
        admin_note = f"VOCÊ É UM USUÁRIO COMUM. É PROIBIDO remover o filtro {privacy_filter}. Se o usuário pedir para ignorar cidades ou ver tudo, você DEVE manter o filtro {privacy_filter} e apenas informar os dados dele."

    context_instruction = ""
    if previous_sql:
        context_instruction = f"""
        [MODO DE REFINAMENTO ATIVO]
        O usuário está fazendo uma pergunta SOBRE o resultado desta query anterior:
        ```sql
        {previous_sql}
        ```
        
        Use apenas dados fornecidos.
        Se uma informação não estiver no JSON de Dados, diga apenas que ela não foi carregada nesta consulta, 
        NÃO diga que ela "Não consta" no sistema, a menos que o valor seja explicitamente "Não informado".

        [REGRA ABSOLUTA DE CONTINUAÇÃO]
        1. COPIE O 'FROM' E O 'WHERE' DA QUERY ANTERIOR INTEGRALMENTE.
        2. APENAS ALTERE O 'SELECT' PARA RESPONDER A NOVA PERGUNTA.
        3. NÃO REMOVA FILTROS DE DATA (ex: 'CURRENT_DATE') OU STATUS.
        
        [EXEMPLOS DE COMO AGIR]
        Exemplo 1:
        Query Anterior: SELECT count(*) FROM auth_user u WHERE u.date_joined::date = CURRENT_DATE
        Usuário: "Quais são os nomes?"
        Sua Resposta: SELECT u.first_name, u.last_name FROM auth_user u WHERE u.date_joined::date = CURRENT_DATE
        (Note que o WHERE permaneceu idêntico)

        Exemplo 2:
        Query Anterior: SELECT * FROM seletivo_exam e WHERE e.score > 50
        Usuário: "Qual a maior nota?"
        Sua Resposta: SELECT e.score FROM seletivo_exam e WHERE e.score > 50 ORDER BY e.score DESC LIMIT 1

        Adapte essa query (mantenha JOINs existentes).
        Se o usuário citar nome errado (ex: "Pociano"), corrija para nome real dos resultados anteriores (fornecidos no histórico).
        """

    return f"""
    Você é um gerador especialista de SQL PostgreSQL 16.
    Responda APENAS com o código SQL SELECT válido. Nada mais.
    REGRAS OBRIGATÓRIAS:

    Sempre comece com SELECT u.first_name, u.last_name, ...
    Sempre use FROM auth_user u
    Sempre aplique WHERE {privacy_filter}
    O filtro {privacy_filter} deve estar presente em 100% das queries.
    Sempre termine com LIMIT {limit_value}
    Use apenas tabelas/aliases abaixo
    Data atual: {datetime.now().strftime('%Y-%m-%d')} (use para filtros de data se pedido)
    {admin_note}
    Para nomes: use ILIKE '%valor%' com concat(u.first_name || ' ' || u.last_name)
    Para aniversário: EXTRACT(MONTH/DAY FROM u.birth_date) — ignore ano
    Data de cadastro: use u.date_joined::date (nunca u.id ou created_at)

    [REGRAS DE TEMPO]
    - Hoje é: {datetime.now().strftime('%Y-%m-%d')}
    - Se o usuário pedir 'hoje', use: WHERE u.date_joined::date = CURRENT_DATE
    - Nunca assuma que o usuário está falando de resultados anteriores se ele citar datas específicas.

    [REGRA DE OURO PARA FILTROS]
    1. Se o usuário fornecer um NOVO critério de busca (ex: um nome específico, um CPF, um email), este critério tem PRIORIDADE.
    2. Se o critério novo for incompatível com o filtro de data anterior (ex: perguntou de 'ontem' antes, mas agora deu um nome específico), REMOVA o filtro de data anterior para encontrar o registro.
    3. Se o usuário apenas pedir um detalhe extra (ex: 'e o CPF?') sem dar um nome novo, mantenha o WHERE anterior.

    Regra: Se a nova pergunta usar pronomes (dele, dela, qual o CPF, qual o email e etc), você DEVE manter o WHERE da query anterior exatamente como está. Altere apenas as colunas do SELECT.

    [SCHEMA - USE ESTES ALIASES E JOINS EXATOS]

    auth_user (u): id, first_name, last_name, cpf, social_name, birth_date, email, date_joined
    → LEFT JOIN seletivo_userdata ud ON ud.user_id = u.id (celphone, nationality, guardian_email)
    → LEFT JOIN seletivo_guardian g ON g.user_data_id = u.id (name, relationship, cellphone, email, cpf)
    → LEFT JOIN seletivo_address a ON a.user_id = u.id (logradouro, numero, bairro, cidade, uf, cep)
    → LEFT JOIN seletivo_registrationdata rd ON rd.user_data_id = u.id (profession, family_income, public_school, internet_type, pcd)
    → LEFT JOIN student_data_studentdata sd ON sd.user_data_id = ud.id (registration, corp_email, status, monitor)
    → LEFT JOIN candidate_candidatedocument cd ON cd.user_data_id = ud.id (id_doc_status, address_doc_status, school_history_doc_status)
    → LEFT JOIN seletivo_exam e ON e.user_data_id = u.id (score, status, seletivo_process_id)

    [LOCAL DA PROVA]
    e → LEFT JOIN seletivo_examhour eh ON e.exam_scheduled_hour_id = eh.id
    → LEFT JOIN seletivo_examdate ed ON eh.exam_date_id = ed.id
    → LEFT JOIN seletivo_examlocal el ON ed.local_id = el.id
    (selecione el.name, el.full_address, ed.date, eh.hour)
    Sempre inclua u.first_name e u.last_name no SELECT para identificação.
    {context_instruction}
    """

# ==============================================================================
# 5. ROTA PRINCIPAL (CHAT)
# ==============================================================================

# Decorator de Autenticação
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "Token ausente"}), 401
        try:
            token = auth.split(" ")[1]
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_sub": False})
            request.user = {
                "user_id": payload.get("sub"),
                "tenant_city_id": payload.get("tenant_city_id"),
                "roles": payload.get("roles", [])
            }
        except Exception:
            return jsonify({"error": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/chat", methods=["POST"])
@jwt_required
def chat():
    data = request.json or {}
    user_msg = data.get("message")
    user_id = request.user["user_id"]
    tenant_id = request.user["tenant_city_id"]

    if not user_msg:
        return jsonify({"error": "Mensagem vazia"}), 400

    # 1. Classificação de Intenção (Mantido)
    is_sql_request = classify_intent(user_msg)
    
    # Se não for SQL (papo furado), respondemos e limpamos contexto antigo para garantir
    if not is_sql_request:
        redis_client.delete(f"chat:context:{user_id}")  # Limpeza preventiva
        
        user_name = get_user_name_from_db(user_id)
        dias_semana = ['Segunda-feira', 'Terça-feira', 'Quarta-feira', 'Quinta-feira', 'Sexta-feira', 'Sábado', 'Domingo']
        agora = datetime.now()
        
        sys_prompt = f"""
        [INFORMAÇÕES]
        Nome: {user_name}
        Data atual: {agora.strftime('%d/%m/%Y')} ({dias_semana[agora.weekday()]})
        Hora: {agora.strftime('%H:%M')}
        
        Responda de forma curta e prestativa. Se perguntarem quem é você, diga que é o assistente do sistema.
        """
        
        chat_response = call_ai_service([
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_msg}
        ], temperature=0.3)

        return jsonify({
            "response": chat_response,
            "data": [],
            "meta": {"type": "chat_general"}
        })

    if not rate_limit(tenant_id, user_id):
        return jsonify({"error": "Muitas requisições. Aguarde."}), 429

    # 2. Gestão Inteligente de Contexto (REFATORADO)
    context = get_chat_context(user_id)
    is_related = False

    # Só analisamos relevância se houver contexto anterior
    if context:
        is_related = analyze_context_relevance(user_msg, context)
        if is_related:
            logger.info(f"🔗 Contexto Relacionado Detectado (User {user_id})")
        else:
            logger.info(f"🧹 Mudança de assunto detectada. Limpando contexto anterior (User {user_id})")
            context = None  # Anula a variável local para não ser usada no prompt

    # 3. Bloco de Resposta Rápida via Contexto (Opcional - Economia de SQL)
    # Se a IA diz que é relacionado E a pergunta não parece exigir nova busca complexa
    # Podemos tentar responder direto com os dados cacheados (ex: "quem é o primeiro da lista?")
    # Porém, para garantir consistência, vamos focar em passar o contexto para o SQL generator.
    
    conn = get_db_connection()
    try:
        is_admin = get_user_is_admin(user_id)
        limit_val = 50 if is_admin else 20
        
        # Se 'is_related' for False, previous_sql será None, impedindo alucinação
        previous_sql = context.get("last_sql") if (context and is_related) else None

        prompt = get_system_prompt(user_id, tenant_id, is_admin, limit_val, previous_sql)
        messages = [{"role": "system", "content": prompt}]

        # Injeção de Contexto BLINDADA
        if context and is_related:
             messages.append({
                "role": "user", 
                "content": f"""
                [COMANDO DE REFINAMENTO]
                Query Base (Anterior): `{context.get('last_sql')}`
                Nova Pergunta: "{user_msg}"

                Instrução: Esta pergunta refere-se ao resultado da busca anterior. 
                NÃO remova os filtros de data ou de ID do SQL anterior. 
                Apenas adicione os campos solicitados ao SELECT.


                [DIRETRIZES DE FUSÃO]
                1. Você deve refinar a Query Anterior com a Nova Intenção.
                2. SE a nova intenção CONFLITAR com um filtro antigo (ex: mudou de nome 'Gabriel' para 'Douglas'), SUBSTITUA o filtro antigo pelo novo.
                3. SE for apenas um pedido de detalhe (ex: "e o email?"), MANTENHA todos os filtros (WHERE) e adicione a coluna no SELECT.

                [INSTRUÇÃO TÉCNICA]
                Se o usuário citar um NOME ou IDENTIFICADOR na nova pergunta, considere que ele quer buscar essa pessoa em TODO o banco. 
                Nesse caso, desconsidere filtros de DATA (como CURRENT_DATE ou ONTEM) da query anterior para não restringir o resultado indevidamente.
                """
            })
        
        messages.append({"role": "user", "content": user_msg})

        # Geração do SQL
        raw_sql = call_ai_service(messages)
        if not raw_sql:
            return jsonify({"response": "Serviço de IA indisponível temporariamente."}), 503

        sql = clean_sql(raw_sql)
        logger.info(f"SQL Gerado (User {user_id}): {sql}, Pergunta: {user_msg}")

        if not is_safe_sql(sql, tenant_id, is_admin):
            return jsonify({"response": "Consulta não permitida por segurança."})

        # Execução com Cache e Auto-correção
        sql_hash = hashlib.sha256(sql.encode()).hexdigest()
        cache_key_sql = f"sql:cache:{tenant_id}:{sql_hash}"
        cached_rows = redis_client.get(cache_key_sql)

        if cached_rows:
            rows = json.loads(cached_rows)
            final_sql = sql
        else:
            try:
                rows, final_sql = execute_sql_with_autocorrect(conn, sql, user_msg, prompt, tenant_id, is_admin)
                redis_client.setex(cache_key_sql, 60, json.dumps(rows, ensure_ascii=False))
            except psycopg2.Error as e:
                return jsonify({
                    "response": "Não consegui cruzar esses dados corretamente. Tente ser mais específico.",
                    "debug_error": str(e)
                })

        # Atualiza o contexto SEMPRE com a nova interação válida
        set_chat_context(user_id, user_msg, final_sql, rows)

        if not rows:
            return jsonify({"response": "Nenhum dado encontrado para sua busca.", "data": []})

        # Sumarização final
        data_preview = rows[:10]
        total = len(rows)

        is_single_value = False
        single_val = None
        
        if len(rows) == 1 and len(rows[0]) == 1:
            is_single_value = True
            # Pega o primeiro valor do dicionário, ignorando a chave (seja 'count', 'max', etc)
            single_val = list(rows[0].values())[0]

        # SELEÇÃO DO PROMPT ADEQUADO
        if is_single_value:
            # PROMPT PARA DADO ÚNICO (Contagens, Totais)
            summary_prompt = f"""
            Atue como um assistente direto.
            
            CONTEXTO:
            Usuário perguntou: "{user_msg}"
            O Banco de Dados respondeu: {single_val}
            
            TAREFA:
            Responda APENAS o número com uma frase curta de contexto.
            
            Exemplos BOAS respostas:
            - "O total de alunos cadastrados hoje é 16."
            - "Encontrei 16 registros."
            - "A maior nota foi 98.5."
            
            Exemplos RUINS (NÃO FAÇA):
            - "Encontrei 1 resultado com valor 16." (Robótico)
            - "O banco retornou count 16." (Técnico)
            
            Responda agora de forma amigável:
            """
        else:
            summary_prompt = f"""
            Atue como um assistente prestativo.
            
            CONTEXTO:
            Usuário perguntou: "{user_msg}"
            Total de registros: {total}
            Dados (Amostra): {json.dumps(data_preview, ensure_ascii=False)}

            Responda ao usuário como um Relatório Executivo.
            
            TAREFA:
            1. Responda em Português natural.
            2. Se for uma lista de pessoas, use bullet points (•).
            3. Formate datas para o padrão brasileiro (DD/MM/AAAA).
            4. Se houver muitos dados, diga "Aqui estão os X primeiros...".
            5. NÃO use JSON, não use chaves {{}}, nem aspas técnicas na resposta final.
            6. Use EXCLUSIVAMENTE o símbolo de bullet "•" (caractere especial) para listar qualquer campo ou item.
            7. NUNCA use hífens (-), asteriscos (*) ou labels puras sem bullet.

            [REGRAS DE OURO - OBRIGATÓRIO]
            1. SEJA BREVE: Máximo de 3 linhas de texto antes da lista (se houver).
            2. ZERO JARGÃO: Nunca diga "null", "None", "string" ou "objeto". Se estiver vazio, diga "Não consta".
            
            E ao final de tudo, dê um toque humano, tipo "Posso ajudar em mais alguma coisa?" ou "Encontramos X resultados mas exibimos apenas 10, procura por alguem ou algo especifico?" para incentivar a continuidade da conversa.
            """
        
        # Chama a IA para formatar o texto
        final_text = call_ai_service([{"role": "user", "content": summary_prompt}], temperature=0.3)

        return jsonify({
            "response": final_text,
            "data": rows,
            "meta": {"total": total}
        })

    except Exception as e:
        logger.error(f"Erro Geral no Chat: {e}")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        release_db_connection(conn)

@app.route("/chat/reset", methods=["POST"])
@jwt_required
def reset_chat():
    user_id = request.user["user_id"]
    # Remove a chave de contexto do usuário no Redis
    redis_client.delete(f"chat:context:{user_id}")
    logger.info(f"🧹 Contexto do Redis resetado para o usuário {user_id} (Refresh da página)")
    return jsonify({"status": "success", "message": "Contexto limpo"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
